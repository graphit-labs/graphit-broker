use crate::{
    AdminBrokerSessionError as Error, AdminBrokerSessionLimits, AdminSession, BrokerAccessError,
    CompletedLocalLogin, ControlError, LocalIdentityKind, SessionPrincipal, SessionProfile,
    SystemAction, SystemPermission, VerifiedLocalBearer,
    admin_cookie_session::CookieWindow,
    identity::{safe_identity_segment, valid_identity_subject},
    sqlite::executor::Work,
};
use broker_security::CredentialDigester;
use rusqlite::{Transaction, params};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    time::{Instant, SystemTime},
};

// Genuine opaque credentials, completed logins and stored cookies share current SQL.
pub(super) enum LocalProof<'a> {
    // Captured data only; the caller retains and rechecks the genuine borrowed JWT proof.
    Broker {
        username: &'a str,
        subject: &'a str,
        digester: &'a CredentialDigester,
        expiry: (SystemTime, Instant),
    },
    Opaque(&'a VerifiedLocalBearer),
    Login(&'a CompletedLocalLogin, &'a CookieWindow),
    Cookie(&'a AdminSession, &'a CookieWindow),
}
impl LocalProof<'_> {
    fn check(&self) -> Result<(), Error> {
        match self {
            Self::Broker { expiry, .. } => {
                if SystemTime::now() >= expiry.0 || Instant::now() >= expiry.1 {
                    return Err(BrokerAccessError::Expired.into());
                }
                Ok(())
            }
            Self::Opaque(p) => crate::admin_local_bearer_session::check_authentication(p),
            Self::Login(_, w) | Self::Cookie(_, w) => w.check().map_err(Into::into),
        }
    }
    fn kind(&self) -> &str {
        match self {
            Self::Broker { .. } => "",
            Self::Opaque(p) => match p.current_local_user().kind() {
                LocalIdentityKind::Human => "human",
                LocalIdentityKind::Service => "service",
            },
            Self::Login(..) | Self::Cookie(..) => "human",
        }
    }
    fn username(&self) -> &str {
        match self {
            Self::Broker { username, .. } => username,
            Self::Opaque(p) => p.current_local_user().username(),
            Self::Login(p, _) => p.username(),
            Self::Cookie(p, _) => &p.principal().username,
        }
    }
    fn subject(&self) -> &str {
        match self {
            Self::Broker { subject, .. } => subject,
            Self::Opaque(p) => p.current_local_user().subject(),
            Self::Login(p, _) => p.subject(),
            Self::Cookie(p, _) => &p.profile().subject,
        }
    }
    fn revision(&self) -> i64 {
        match self {
            Self::Broker { .. } => 0,
            Self::Opaque(p) => p.current_local_user().revision(),
            Self::Login(p, _) => p.revision(),
            Self::Cookie(p, _) => p.principal().local_user_revision,
        }
    }
}
#[derive(Serialize)]
struct ProfileProjection<'a> {
    subject: &'a str,
    username: &'a str,
    name: &'a str,
    email: &'a str,
    organization: &'a str,
    teams: &'a [String],
}
pub(super) type LocalData = (
    SessionProfile,
    SessionPrincipal,
    Vec<String>,
    Vec<SystemPermission>,
);
// Each selected text field is capped in SQL before the driver allocates it.
const SELECT: &str = "SELECT
 CASE WHEN typeof(u.username)='text' AND length(CAST(u.username AS BLOB))<=?1 THEN u.username END,
 CASE WHEN typeof(u.subject)='text' AND length(CAST(u.subject AS BLOB))<=?2 THEN u.subject END,
 CASE WHEN typeof(u.identity_kind)='text' AND length(CAST(u.identity_kind AS BLOB))<=16 THEN u.identity_kind END,
 u.enabled,u.revision,
 CASE WHEN typeof(u.name)='text' AND length(CAST(u.name AS BLOB))<=2048 AND length(CAST(u.name AS BLOB))<=?4 THEN u.name END,
 CASE WHEN typeof(u.email)='text' AND length(CAST(u.email AS BLOB))<=2048 AND length(CAST(u.email AS BLOB))<=?4 THEN u.email END,
 CASE WHEN typeof(u.organization)='text' AND length(CAST(u.organization AS BLOB))<=2048 AND length(CAST(u.organization AS BLOB))<=?4 THEN u.organization END,
 CASE WHEN typeof(u.teams_json)='text' AND length(CAST(u.teams_json AS BLOB))<=?4 THEN u.teams_json END,
 CASE WHEN typeof(a.role)='text' AND length(CAST(a.role AS BLOB))<=?3 THEN a.role END,
 CASE WHEN typeof(p.action)='text' AND length(CAST(p.action AS BLOB))<=128 THEN p.action END,
 a.role IS NOT NULL,p.role IS NOT NULL,u.password_change_required
 FROM local_users u
 LEFT JOIN (SELECT role FROM role_assignments WHERE subject='local|'||(SELECT subject FROM local_users WHERE username=?5) UNION SELECT 'user') a ON 1
 LEFT JOIN roles r ON r.name=a.role LEFT JOIN role_permissions p ON p.role=r.name
 WHERE u.username=?5 ORDER BY a.role,p.action LIMIT ?6";
pub(super) fn observe(
    tx: &Transaction<'_>,
    work: &Work,
    proof: LocalProof<'_>,
    limits: AdminBrokerSessionLimits,
    action: SystemAction,
    end: Instant,
) -> Result<LocalData, Error> {
    work.check().map_err(ControlError::from)?;
    proof.check()?;
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    let l = limits.identity;
    if !safe_identity_segment(proof.username(), l.username_bytes.get()) {
        return Err(if matches!(proof, LocalProof::Broker { .. }) {
            Error::Forbidden
        } else {
            Error::Authentication(BrokerAccessError::InvalidToken)
        });
    }
    let mut statement = tx
        .prepare(SELECT)
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut rows = statement
        .query(params![
            l.username_bytes.get() as i64,
            l.subject_bytes.get() as i64,
            l.role_bytes.get() as i64,
            limits.profile_json_bytes.get() as i64,
            proof.username(),
            (l.rows.get() + 1) as i64
        ])
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut data = None;
    let mut roles = BTreeSet::new();
    let mut permissions = Vec::new();
    let mut count = 0usize;
    while let Some(row) = rows.next().map_err(|e| ControlError::from(work.sql(e)))? {
        count += 1;
        if count > l.rows.get() {
            return Err(ControlError::IdentityLimitExceeded.into());
        }
        work.check().map_err(ControlError::from)?;
        proof.check()?;
        let text = |index| -> Result<&str, ControlError> {
            row.get_ref(index)
                .map_err(|_| ControlError::CorruptIdentity)?
                .as_str()
                .map_err(|_| ControlError::CorruptIdentity)
        };
        if data.is_none() {
            let username = text(0)?;
            let subject = text(1)?;
            let kind = text(2)?;
            let enabled: i64 = row.get(3).map_err(|_| ControlError::CorruptIdentity)?;
            let revision: i64 = row.get(4).map_err(|_| ControlError::CorruptIdentity)?;
            if username != proof.username()
                || !safe_identity_segment(username, l.username_bytes.get())
                || !valid_identity_subject(subject, l.subject_bytes.get())
                || !matches!(kind, "human" | "service")
                || !matches!(enabled, 0 | 1)
                || revision < 1
            {
                return Err(ControlError::CorruptIdentity.into());
            }
            let bound = match &proof {
                LocalProof::Broker {
                    subject: signed,
                    digester,
                    ..
                } => {
                    enabled == 1
                        && digester
                            .oidc_subject(b"local", subject.as_bytes())
                            .map_err(|_| ControlError::CorruptIdentity)?
                            .as_str()
                            == *signed
                }
                _ => {
                    enabled == 1
                        && kind == proof.kind()
                        && subject == proof.subject()
                        && revision == proof.revision()
                }
            };
            if !bound {
                return Err(if matches!(proof, LocalProof::Broker { .. }) {
                    Error::Forbidden
                } else {
                    Error::Authentication(BrokerAccessError::InvalidToken)
                });
            }
            if !matches!(proof, LocalProof::Opaque(_) | LocalProof::Broker { .. }) {
                let change: i64 = row.get(13).map_err(|_| ControlError::CorruptIdentity)?;
                if !matches!(change, 0 | 1) {
                    return Err(ControlError::CorruptIdentity.into());
                }
                if change != 0 {
                    return Err(Error::Authentication(BrokerAccessError::InvalidToken));
                }
            }
            let profile_field = |i| -> Result<String, ControlError> {
                let value = text(i)?;
                if value.chars().count() > 512 {
                    return Err(ControlError::CorruptIdentity);
                }
                Ok(value.to_owned())
            };
            let teams: Vec<String> =
                serde_json::from_str(text(8)?).map_err(|_| ControlError::CorruptIdentity)?;
            let teams = teams
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let profile = SessionProfile {
                subject: subject.into(),
                name: profile_field(5)?,
                email: profile_field(6)?,
            };
            let principal = SessionPrincipal {
                issuer: "local".into(),
                username: username.into(),
                organization: profile_field(7)?,
                teams,
                local_user_revision: revision,
            };
            let encoded = serde_json::to_vec(&ProfileProjection {
                subject: &profile.subject,
                username: &principal.username,
                name: &profile.name,
                email: &profile.email,
                organization: &principal.organization,
                teams: &principal.teams,
            })
            .map_err(|_| ControlError::CorruptIdentity)?;
            if encoded.len() > limits.profile_json_bytes.get() {
                return Err(ControlError::IdentityLimitExceeded.into());
            }
            data = Some((profile, principal));
        }
        let role_present: bool = row.get(11).map_err(|_| ControlError::CorruptRbac)?;
        let action_present: bool = row.get(12).map_err(|_| ControlError::CorruptRbac)?;
        let role: String = row.get(9).map_err(|_| ControlError::CorruptRbac)?;
        if !role_present || !safe_identity_segment(&role, l.role_bytes.get()) {
            return Err(ControlError::CorruptRbac.into());
        }
        if !roles.contains(&role) {
            if roles.len() >= l.roles.get() {
                return Err(ControlError::IdentityLimitExceeded.into());
            }
            roles.insert(role);
        }
        let stored: Option<String> = row.get(10).map_err(|_| ControlError::CorruptRbac)?;
        match (action_present, stored) {
            (false, None) => {}
            (true, Some(stored)) => {
                let permission =
                    SystemPermission::stored(&stored).ok_or(ControlError::CorruptRbac)?;
                if !permissions.contains(&permission) {
                    permissions.push(permission);
                }
            }
            _ => return Err(ControlError::CorruptRbac.into()),
        }
    }
    let (profile, principal) = data.ok_or(if matches!(proof, LocalProof::Broker { .. }) {
        Error::Forbidden
    } else {
        Error::Authentication(BrokerAccessError::InvalidToken)
    })?;
    if !permissions.contains(&SystemPermission::All)
        && !permissions.contains(&SystemPermission::Action(action))
    {
        return Err(Error::Forbidden);
    }
    permissions.sort_unstable_by_key(|p| p.as_str());
    work.check().map_err(ControlError::from)?;
    proof.check()?;
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok((profile, principal, roles.into_iter().collect(), permissions))
}
