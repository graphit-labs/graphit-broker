//! Administrative session metadata. Consumers must revalidate current authorization policy.
use crate::{ControlError, PostgresControlStore};
use broker_store::time::TimestampMicros;
use std::{
    fmt, io,
    num::NonZeroUsize,
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    pub text_bytes: NonZeroUsize,
    pub csrf_bytes: NonZeroUsize,
    pub team_bytes: NonZeroUsize,
    pub role_bytes: NonZeroUsize,
    pub max_teams: NonZeroUsize,
    pub max_roles: NonZeroUsize,
    pub teams_json_bytes: NonZeroUsize,
    pub roles_json_bytes: NonZeroUsize,
    pub max_lifetime: Duration,
}
impl SessionLimits {
    pub fn validate(&self) -> Result<(), ControlError> {
        for cap in [
            self.text_bytes,
            self.csrf_bytes,
            self.team_bytes,
            self.role_bytes,
            self.max_teams,
            self.max_roles,
            self.teams_json_bytes,
            self.roles_json_bytes,
        ] {
            if isize::try_from(cap.get()).is_err() || i64::try_from(cap.get()).is_err() {
                return Err(ControlError::Configuration);
            }
        }
        for count in [self.max_teams, self.max_roles] {
            let allocation = count
                .get()
                .checked_mul(std::mem::size_of::<String>())
                .ok_or(ControlError::Configuration)?;
            if isize::try_from(allocation).is_err() {
                return Err(ControlError::Configuration);
            }
        }
        for (count, bytes) in [
            (self.max_teams, self.team_bytes),
            (self.max_roles, self.role_bytes),
        ] {
            let upper = bytes
                .get()
                .checked_mul(6)
                .and_then(|v| v.checked_add(3))
                .and_then(|v| v.checked_mul(count.get()))
                .and_then(|v| v.checked_add(2))
                .ok_or(ControlError::Configuration)?;
            if isize::try_from(upper).is_err() {
                return Err(ControlError::Configuration);
            }
        }
        self.lifetime_micros()?;
        Ok(())
    }
    pub(crate) fn lifetime_micros(&self) -> Result<i64, ControlError> {
        let micros = i64::try_from(self.max_lifetime.as_micros())
            .map_err(|_| ControlError::Configuration)?;
        if micros == 0 {
            Err(ControlError::Configuration)
        } else {
            Ok(micros)
        }
    }
}
pub struct SessionProfile {
    pub subject: String,
    pub name: String,
    pub email: String,
}
pub struct SessionPrincipal {
    pub issuer: String,
    pub username: String,
    pub organization: String,
    pub teams: Vec<String>,
    pub local_user_revision: i64,
}
pub struct SessionClaimRoles {
    pub selector: String,
    pub roles: Vec<String>,
}
macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => {$ (impl fmt::Debug for $ty {
        fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str(concat!(stringify!($ty),"([REDACTED])")) }
    })+};
}
redacted_debug!(
    SessionProfile,
    SessionPrincipal,
    SessionClaimRoles,
    NewAdminSession,
    AdminSession,
    AdminSessions<'_>
);

pub struct NewAdminSession {
    profile: SessionProfile,
    principal: SessionPrincipal,
    csrf_token: Zeroizing<String>,
    claimed_roles: Option<SessionClaimRoles>,
    expires_at: SystemTime,
}
impl NewAdminSession {
    pub fn new(
        profile: SessionProfile,
        mut principal: SessionPrincipal,
        csrf_token: Zeroizing<String>,
        mut claimed_roles: Option<SessionClaimRoles>,
        expires_at: SystemTime,
        limits: &SessionLimits,
    ) -> Result<Self, ControlError> {
        limits.validate()?;
        validate_raw(
            &profile,
            &principal,
            &csrf_token,
            claimed_roles.as_ref(),
            limits,
        )?;
        positive_expiry(expires_at)?;
        canonicalize(&mut principal.teams);
        if let Some(claims) = claimed_roles.as_mut() {
            canonicalize(&mut claims.roles);
        }
        let result = Self {
            profile,
            principal,
            csrf_token,
            claimed_roles,
            expires_at,
        };
        result.validate(limits)?;
        Ok(result)
    }
    pub fn profile(&self) -> &SessionProfile {
        &self.profile
    }
    pub fn principal(&self) -> &SessionPrincipal {
        &self.principal
    }
    pub fn claimed_roles(&self) -> Option<&SessionClaimRoles> {
        self.claimed_roles.as_ref()
    }
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub(crate) fn validate(&self, limits: &SessionLimits) -> Result<SessionJson, ControlError> {
        limits.validate()?;
        validate_raw(
            &self.profile,
            &self.principal,
            &self.csrf_token,
            self.claimed_roles.as_ref(),
            limits,
        )?;
        positive_expiry(self.expires_at)?;
        validate_canonical(&self.principal, self.claimed_roles.as_ref())?;
        Ok(SessionJson {
            teams: bounded_json(&self.principal.teams, limits.teams_json_bytes.get())?,
            roles: self
                .claimed_roles
                .as_ref()
                .map(|v| bounded_json(&v.roles, limits.roles_json_bytes.get()))
                .transpose()?,
        })
    }
}
pub(crate) struct SessionJson {
    pub teams: String,
    pub roles: Option<String>,
}
pub struct AdminSession {
    profile: SessionProfile,
    principal: SessionPrincipal,
    csrf_token: Zeroizing<String>,
    claimed_roles: Option<SessionClaimRoles>,
    created_at: TimestampMicros,
    expires_at: TimestampMicros,
}
impl AdminSession {
    pub fn profile(&self) -> &SessionProfile {
        &self.profile
    }
    pub fn principal(&self) -> &SessionPrincipal {
        &self.principal
    }
    pub fn claimed_roles(&self) -> Option<&SessionClaimRoles> {
        self.claimed_roles.as_ref()
    }
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
    pub fn created_at(&self) -> TimestampMicros {
        self.created_at
    }
    pub fn expires_at(&self) -> TimestampMicros {
        self.expires_at
    }
    pub(crate) fn stored(
        profile: SessionProfile,
        mut principal: SessionPrincipal,
        csrf: Zeroizing<String>,
        claims: Option<(String, String)>,
        teams: &str,
        times: (i64, i64),
        limits: &SessionLimits,
    ) -> Result<Self, ControlError> {
        let (created, expiry) = times;
        let decode = || -> Result<Self, ControlError> {
            if created < 0 || expiry <= created || expiry - created > limits.lifetime_micros()? {
                return Err(ControlError::InvalidSession);
            }
            principal.teams = parse_array(teams, limits.teams_json_bytes.get())?;
            let claimed_roles = claims
                .map(|(selector, roles)| {
                    Ok::<_, ControlError>(SessionClaimRoles {
                        selector,
                        roles: parse_array(&roles, limits.roles_json_bytes.get())?,
                    })
                })
                .transpose()?;
            validate_raw(&profile, &principal, &csrf, claimed_roles.as_ref(), limits)?;
            validate_canonical(&principal, claimed_roles.as_ref())?;
            Ok(Self {
                profile,
                principal,
                csrf_token: csrf,
                claimed_roles,
                created_at: TimestampMicros::new(created)
                    .map_err(|_| ControlError::InvalidSession)?,
                expires_at: TimestampMicros::new(expiry)
                    .map_err(|_| ControlError::InvalidSession)?,
            })
        };
        decode().map_err(|_| ControlError::CorruptSession)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRevocation {
    Revoked,
    Absent,
}
/// A borrowed capability with caller-supplied policy limits; no pool or digest export.
pub struct AdminSessions<'a> {
    pub(crate) owner: &'a PostgresControlStore,
    pub(crate) limits: SessionLimits,
}
impl AdminSessions<'_> {
    pub async fn create_session(
        &self,
        raw_token: &str,
        session: &NewAdminSession,
        deadline: Instant,
    ) -> Result<(), ControlError> {
        self.owner
            .create_admin_session(raw_token, session, &self.limits, deadline)
            .await
    }
    pub async fn session(
        &self,
        raw_token: &str,
        deadline: Instant,
    ) -> Result<AdminSession, ControlError> {
        self.owner
            .read_admin_session(raw_token, &self.limits, deadline)
            .await
    }
    pub async fn revoke_session(
        &self,
        raw_token: &str,
        deadline: Instant,
    ) -> Result<SessionRevocation, ControlError> {
        self.owner.revoke_admin_session(raw_token, deadline).await
    }
}
pub(crate) fn positive_expiry(time: SystemTime) -> Result<i64, ControlError> {
    let micros = TimestampMicros::try_from(time)
        .map_err(|_| ControlError::InvalidSession)?
        .as_i64();
    if micros == 0 {
        Err(ControlError::InvalidSession)
    } else {
        Ok(micros)
    }
}
fn text(value: &str, bytes: usize, chars: usize, required: bool) -> Result<(), ControlError> {
    if (required && value.is_empty())
        || value.len() > bytes
        || value.contains('\0')
        || value.chars().count() > chars
    {
        Err(ControlError::InvalidSession)
    } else {
        Ok(())
    }
}
fn list(
    values: &[String],
    count: usize,
    bytes: usize,
    chars: Option<usize>,
) -> Result<(), ControlError> {
    if values.len() > count {
        return Err(ControlError::InvalidSession);
    }
    for value in values {
        text(value, bytes, chars.unwrap_or(usize::MAX), false)?;
    }
    Ok(())
}
fn validate_raw(
    profile: &SessionProfile,
    principal: &SessionPrincipal,
    csrf: &str,
    claims: Option<&SessionClaimRoles>,
    limits: &SessionLimits,
) -> Result<(), ControlError> {
    text(&profile.subject, limits.text_bytes.get(), 512, true)?;
    for value in [
        &profile.name,
        &profile.email,
        &principal.username,
        &principal.organization,
    ] {
        text(value, limits.text_bytes.get(), 512, false)?;
    }
    text(&principal.issuer, limits.text_bytes.get(), 1024, true)?;
    text(csrf, limits.csrf_bytes.get(), 128, true)?;
    if principal.local_user_revision < 0 {
        return Err(ControlError::InvalidSession);
    }
    list(
        &principal.teams,
        limits.max_teams.get(),
        limits.team_bytes.get(),
        None,
    )?;
    if let Some(claims) = claims {
        text(&claims.selector, limits.text_bytes.get(), 4096, true)?;
        list(
            &claims.roles,
            limits.max_roles.get(),
            limits.role_bytes.get(),
            None,
        )?;
    }
    Ok(())
}
fn canonicalize(values: &mut Vec<String>) {
    for value in values.iter_mut() {
        if value.trim() != value.as_str() {
            *value = value.trim().to_owned();
        }
    }
    values.retain(|v| !v.is_empty());
    values.sort_unstable();
    values.dedup();
}
fn canonical(values: &[String]) -> bool {
    values.iter().all(|v| !v.is_empty() && v.trim() == v) && values.windows(2).all(|v| v[0] < v[1])
}
fn validate_canonical(
    principal: &SessionPrincipal,
    claims: Option<&SessionClaimRoles>,
) -> Result<(), ControlError> {
    if !canonical(&principal.teams) {
        return Err(ControlError::InvalidSession);
    }
    if let Some(claims) = claims
        && (claims.selector.is_empty()
            || !canonical(&claims.roles)
            || claims.roles.iter().any(|v| v.chars().count() > 128))
    {
        return Err(ControlError::InvalidSession);
    }
    Ok(())
}
struct JsonWriter {
    bytes: Vec<u8>,
    cap: usize,
}
impl io::Write for JsonWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.cap.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("session JSON limit"));
        }
        self.bytes
            .try_reserve(buf.len())
            .map_err(|_| io::Error::other("session JSON allocation"))?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_json(values: &[String], cap: usize) -> Result<String, ControlError> {
    let mut writer = JsonWriter {
        bytes: Vec::new(),
        cap,
    };
    serde_json::to_writer(&mut writer, values).map_err(|_| ControlError::InvalidSession)?;
    String::from_utf8(writer.bytes).map_err(|_| ControlError::InvalidSession)
}
fn parse_array(json: &str, cap: usize) -> Result<Vec<String>, ControlError> {
    if json.len() > cap {
        return Err(ControlError::InvalidSession);
    }
    serde_json::from_str(json).map_err(|_| ControlError::InvalidSession)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> SessionLimits {
        let n = |v| NonZeroUsize::new(v).unwrap();
        SessionLimits {
            text_bytes: n(64),
            csrf_bytes: n(64),
            team_bytes: n(64),
            role_bytes: n(64),
            max_teams: n(4),
            max_roles: n(4),
            teams_json_bytes: n(128),
            roles_json_bytes: n(128),
            max_lifetime: Duration::from_secs(60),
        }
    }
    #[test]
    fn independent_limits_revalidation_and_stored_canonicality() {
        let l = limits();
        let new = NewAdminSession::new(
            SessionProfile {
                subject: "subject".into(),
                name: String::new(),
                email: String::new(),
            },
            SessionPrincipal {
                issuer: "issuer".into(),
                username: String::new(),
                organization: String::new(),
                teams: vec!["a".into(), "b".into()],
                local_user_revision: 0,
            },
            Zeroizing::new("csrf".into()),
            None,
            SystemTime::now() + Duration::from_secs(30),
            &l,
        )
        .unwrap();
        let mut narrower = l;
        narrower.max_teams = NonZeroUsize::new(1).unwrap();
        assert!(matches!(
            new.validate(&narrower),
            Err(ControlError::InvalidSession)
        ));
        for json in [
            "null",
            "{}",
            "[1]",
            "[null]",
            "[\"a\"] trailing",
            "[\" b \"]",
            "[\"b\",\"a\"]",
            "[\"a\",\"a\"]",
            "[\"\"]",
            "[\"a\\u0000\"]",
        ] {
            let stored = AdminSession::stored(
                SessionProfile {
                    subject: "s".into(),
                    name: String::new(),
                    email: String::new(),
                },
                SessionPrincipal {
                    issuer: "i".into(),
                    username: String::new(),
                    organization: String::new(),
                    teams: Vec::new(),
                    local_user_revision: 0,
                },
                Zeroizing::new("csrf".into()),
                None,
                json,
                (1, 2),
                &l,
            );
            assert!(
                matches!(stored, Err(ControlError::CorruptSession)),
                "{json}"
            );
        }
    }
}
