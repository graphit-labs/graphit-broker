use super::super::{admin_rbac, local_auth};
use crate::{
    AdminRbacError, AdminUsersError as Error, AdminUsersLimits, AdminUsersRequest, ControlError,
    admin_users::validation::{valid_credential_id, values},
    flow::now_micros,
    identity::{safe_identity_segment, valid_identity_subject},
    sqlite::executor::Work,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_security::{CredentialDigester, TokenKind};
use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use std::{collections::BTreeSet, io::Write, time::Instant};
use zeroize::Zeroizing;

pub(super) struct Output {
    pub(super) status: u16,
    pub(super) body: Zeroizing<Vec<u8>>,
}
impl Output {
    pub(super) fn empty(status: u16) -> Self {
        Self {
            status,
            body: Zeroizing::new(Vec::new()),
        }
    }
}
struct JsonBody {
    bytes: Zeroizing<Vec<u8>>,
    cap: usize,
}
impl Write for JsonBody {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.cap.saturating_sub(self.bytes.len()) {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| std::io::Error::other("administrative response allocation"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode(
    value: &impl Serialize,
    maximum: usize,
    status: u16,
    error: Error,
) -> Result<Output, Error> {
    let mut out = JsonBody {
        bytes: Zeroizing::new(Vec::new()),
        cap: maximum,
    };
    serde_json::to_writer(&mut out, value).map_err(|_| error)?;
    Ok(Output {
        status,
        body: out.bytes,
    })
}
fn timestamp(value: i64) -> Result<String, Error> {
    DateTime::<Utc>::from_timestamp_micros(value)
        .filter(|d| value >= 0 && d.year() <= 9999)
        .map(|d| d.to_rfc3339_opts(SecondsFormat::AutoSi, true))
        .ok_or_else(|| ControlError::CorruptIdentity.into())
}
fn gate(work: &Work, end: Instant) -> Result<(), Error> {
    work.check().map_err(ControlError::from)?;
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
}
fn sql(work: &Work, error: rusqlite::Error) -> Error {
    ControlError::from(work.sql(error)).into()
}
fn mutation_sql(work: &Work, error: rusqlite::Error, fallback: Error) -> Error {
    match ControlError::from(work.sql(error)) {
        e @ (ControlError::Deadline | ControlError::Closed | ControlError::OutcomeUncertain) => {
            e.into()
        }
        _ => fallback,
    }
}
struct User {
    username: String,
    subject: String,
    kind: String,
    phc: Zeroizing<String>,
    enabled: bool,
    change: bool,
    revision: i64,
}
fn target(tx: &Transaction<'_>, work: &Work, username: &str, error: Error) -> Result<User, Error> {
    let username = username.trim();
    if !safe_identity_segment(username, 128) {
        return Err(error);
    }
    let user = tx.query_row(
        "SELECT CASE WHEN typeof(username)='text' AND length(CAST(username AS BLOB))<=128 THEN username END,
                CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=512 THEN subject END,
                CASE WHEN typeof(identity_kind)='text' AND length(CAST(identity_kind AS BLOB))<=16 THEN identity_kind END,
                CASE WHEN typeof(password_hash)='text' AND length(CAST(password_hash AS BLOB))<=512 THEN password_hash END,
                CASE WHEN typeof(enabled)='integer' THEN enabled END,
                CASE WHEN typeof(password_change_required)='integer' THEN password_change_required END,
                CASE WHEN typeof(revision)='integer' THEN revision END FROM local_users WHERE username=?1",
        [username],
        |row| Ok((
            row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?, row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Option<i64>>(6)?,
        )),
    ).optional().map_err(|e| sql(work, e))?.ok_or(error)?;
    let text = |v: Option<String>| v.ok_or_else(|| Error::from(ControlError::CorruptIdentity));
    let flag = |v| match v {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(Error::from(ControlError::CorruptIdentity)),
    };
    let user = User {
        username: text(user.0)?,
        subject: text(user.1)?,
        kind: text(user.2)?,
        phc: Zeroizing::new(text(user.3)?),
        enabled: flag(user.4)?,
        change: flag(user.5)?,
        revision: user.6.ok_or(ControlError::CorruptIdentity)?,
    };
    if !safe_identity_segment(&user.username, 128)
        || !valid_identity_subject(&user.subject, 512)
        || !matches!(user.kind.as_str(), "human" | "service")
        || user.revision < 1
        || user.kind == "service" && (!user.phc.is_empty() || user.change)
    {
        return Err(ControlError::CorruptIdentity.into());
    }
    Ok(user)
}
pub(super) fn preflight(
    tx: &Transaction<'_>,
    work: &Work,
    request: AdminUsersRequest<'_>,
) -> Result<(), Error> {
    match request {
        AdminUsersRequest::Create(input) => {
            let kind = if input.kind.is_empty() {
                "human"
            } else {
                &input.kind
            };
            values(input, kind, true, request.error())?;
        }
        AdminUsersRequest::Update {
            username,
            user: input,
        } => {
            let current = target(tx, work, username, request.error())?;
            let kind = if input.kind.is_empty() {
                &current.kind
            } else {
                &input.kind
            };
            let v = values(input, kind, false, request.error())?;
            if v.subject != current.subject || v.kind != current.kind {
                return Err(request.error());
            }
        }
        _ => return Err(ControlError::Configuration.into()),
    }
    Ok(())
}
fn replace_roles(
    tx: &Transaction<'_>,
    work: &Work,
    subject: &str,
    roles: &BTreeSet<&str>,
    now: i64,
    error: Error,
) -> Result<(), Error> {
    let canonical = format!("local|{subject}");
    tx.execute(
        "DELETE FROM role_assignments WHERE subject=?1",
        [&canonical],
    )
    .map_err(|e| mutation_sql(work, e, error))?;
    for &role in roles {
        work.check().map_err(ControlError::from)?;
        tx.execute(
            "INSERT INTO role_assignments(subject,role,created_at) VALUES(?1,?2,?3)",
            params![&canonical, role, now],
        )
        .map_err(|e| mutation_sql(work, e, error))?;
    }
    Ok(())
}
fn last_admin(tx: &Transaction<'_>, work: &Work, subject: &str, error: Error) -> Result<(), Error> {
    let canonical = format!("local|{subject}");
    let assigned: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM role_assignments WHERE subject=?1 AND role='admin')",
            [&canonical],
            |row| row.get(0),
        )
        .map_err(|e| sql(work, e))?;
    if assigned {
        admin_rbac::another_admin(tx, work, &canonical).map_err(|e| match e {
            AdminRbacError::Authorization(e) => Error::Authorization(e),
            _ => error,
        })?;
    }
    Ok(())
}
fn invalidate(
    tx: &Transaction<'_>,
    work: &Work,
    subject: &str,
    now: i64,
    end: Instant,
) -> Result<(), Error> {
    local_auth::invalidate_local_user(tx, subject, false, now, end, work).map_err(|e| match e {
        crate::LocalAuthError::Control(e) => Error::from(e),
        _ => Error::from(ControlError::Storage),
    })
}
fn changed(
    tx: &Transaction<'_>,
    work: &Work,
    statement: &str,
    args: impl rusqlite::Params,
    error: Error,
) -> Result<(), Error> {
    if tx
        .execute(statement, args)
        .map_err(|e| mutation_sql(work, e, error))?
        != 1
    {
        return Err(error);
    }
    Ok(())
}
pub(super) fn apply(
    tx: &Transaction<'_>,
    work: &Work,
    digester: &CredentialDigester,
    limits: &AdminUsersLimits,
    request: AdminUsersRequest<'_>,
    hash: Option<&str>,
    end: Instant,
) -> Result<Output, Error> {
    gate(work, end)?;
    let error = request.error();
    match request {
        AdminUsersRequest::Create(input) => {
            let kind = if input.kind.is_empty() {
                "human"
            } else {
                &input.kind
            };
            let u = values(input, kind, true, error)?;
            let phc = if kind == "human" {
                hash.ok_or(error)?
            } else {
                ""
            };
            let teams = serde_json::to_string(&u.teams).map_err(|_| error)?;
            let now = now_micros()?;
            tx.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?11)",
                params![u.username,u.subject,kind,phc,u.name,u.email,u.organization,teams,i64::from(u.enabled),i64::from(kind=="human"),now])
                .map_err(|e| mutation_sql(work,e,error))?;
            replace_roles(tx, work, u.subject, &u.roles, now, error)?;
            Ok(Output::empty(201))
        }
        AdminUsersRequest::Update {
            username,
            user: input,
        } => {
            let current = target(tx, work, username, error)?;
            let kind = if input.kind.is_empty() {
                &current.kind
            } else {
                &input.kind
            };
            let u = values(input, kind, false, error)?;
            if u.subject != current.subject || u.kind != current.kind {
                return Err(error);
            }
            if !u.enabled || !u.roles.contains("admin") {
                last_admin(tx, work, &current.subject, error)?;
            }
            let revision = current.revision.checked_add(1).ok_or(error)?;
            let teams = serde_json::to_string(&u.teams).map_err(|_| error)?;
            let phc = hash.unwrap_or(&current.phc);
            let change = kind == "human"
                && (current.change || input.password_change_required || hash.is_some());
            let now = now_micros()?;
            changed(
                tx,
                work,
                "UPDATE local_users SET username=?1,password_hash=?2,name=?3,email=?4,organization=?5,teams_json=?6,enabled=?7,password_change_required=?8,revision=?9,updated_at=?10 WHERE username=?11 AND subject=?12 AND revision=?13",
                params![
                    u.username,
                    phc,
                    u.name,
                    u.email,
                    u.organization,
                    teams,
                    i64::from(u.enabled),
                    i64::from(change),
                    revision,
                    now,
                    &current.username,
                    &current.subject,
                    current.revision
                ],
                error,
            )?;
            replace_roles(tx, work, &current.subject, &u.roles, now, error)?;
            invalidate(tx, work, &current.subject, now, end)?;
            Ok(Output::empty(204))
        }
        AdminUsersRequest::Delete { username } => {
            let current = target(tx, work, username, error)?;
            last_admin(tx, work, &current.subject, error)?;
            let now = now_micros()?;
            invalidate(tx, work, &current.subject, now, end)?;
            tx.execute("DELETE FROM admin_sessions WHERE token_hash IN (SELECT s.token_hash FROM admin_sessions s JOIN admin_session_principals p ON s.token_hash=p.token_hash WHERE s.subject=?1 AND p.issuer='local')",[&current.subject])
                .map_err(|e|mutation_sql(work,e,error))?;
            tx.execute(
                "DELETE FROM local_tokens WHERE subject=?1 AND local_user_revision>=1",
                [&current.subject],
            )
            .map_err(|e| mutation_sql(work, e, error))?;
            tx.execute(
                "DELETE FROM role_assignments WHERE subject=?1",
                [format!("local|{}", current.subject)],
            )
            .map_err(|e| mutation_sql(work, e, error))?;
            changed(
                tx,
                work,
                "DELETE FROM local_users WHERE username=?1 AND subject=?2 AND revision=?3",
                params![&current.username, &current.subject, current.revision],
                error,
            )?;
            Ok(Output::empty(204))
        }
        AdminUsersRequest::ResetMfa { username } => {
            let current = target(tx, work, username, error)?;
            if current.kind != "human" {
                return Err(error);
            }
            let revision = current.revision.checked_add(1).ok_or(error)?;
            let now = now_micros()?;
            for statement in [
                "DELETE FROM local_mfa WHERE subject=?1",
                "DELETE FROM local_mfa_recovery_codes WHERE subject=?1",
            ] {
                tx.execute(statement, [&current.subject])
                    .map_err(|e| mutation_sql(work, e, error))?;
            }
            changed(
                tx,
                work,
                "UPDATE local_users SET revision=?1,updated_at=?2 WHERE username=?3 AND subject=?4 AND revision=?5",
                params![
                    revision,
                    now,
                    &current.username,
                    &current.subject,
                    current.revision
                ],
                error,
            )?;
            invalidate(tx, work, &current.subject, now, end)?;
            Ok(Output::empty(204))
        }
        AdminUsersRequest::Credentials { username } => {
            let current = target(tx, work, username, Error::ServiceIdentityNotFound)?;
            if current.kind != "service" {
                return Err(Error::ServiceIdentityNotFound);
            }
            inventory(
                tx,
                work,
                &current.subject,
                limits.response_json_bytes.get(),
                end,
            )
        }
        AdminUsersRequest::IssueCredential { username, input } => {
            let current = target(tx, work, username, Error::ServiceIdentityNotFound)?;
            if current.kind != "service" {
                return Err(Error::ServiceIdentityNotFound);
            }
            if !current.enabled {
                return Err(error);
            }
            let client = if input.client_id.trim().is_empty() {
                &current.username
            } else {
                input.client_id.trim()
            };
            if !safe_identity_segment(client, 128) {
                return Err(Error::InvalidCredential);
            }
            let seconds = if input.expires_in == 0 {
                limits.service_credential_max_ttl.as_secs().min(90 * 86400)
            } else {
                u64::try_from(input.expires_in).map_err(|_| Error::InvalidCredential)?
            };
            if seconds < 3600 || seconds > limits.service_credential_max_ttl.as_secs() {
                return Err(Error::InvalidCredential);
            }
            let now = now_micros()?;
            let expires = now
                .checked_add(
                    i64::try_from(seconds)
                        .map_err(|_| Error::InvalidCredential)?
                        .checked_mul(1_000_000)
                        .ok_or(Error::InvalidCredential)?,
                )
                .ok_or(Error::InvalidCredential)?;
            let expires_at = timestamp(expires)?;
            let scopes = input
                .scopes
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<BTreeSet<_>>();
            let scopes_json = serde_json::to_string(&scopes).map_err(|_| error)?;
            let mut bytes = Zeroizing::new([0u8; 32]);
            getrandom::fill(bytes.as_mut()).map_err(|_| Error::CredentialGenerationFailed)?;
            let raw = Zeroizing::new(format!("gb_sc_{}", URL_SAFE_NO_PAD.encode(bytes.as_ref())));
            let mut id = [0u8; 12];
            getrandom::fill(&mut id).map_err(|_| Error::CredentialGenerationFailed)?;
            let id = URL_SAFE_NO_PAD.encode(id);
            let digest = Zeroizing::new(
                digester
                    .token(TokenKind::ServiceCredential, raw.as_bytes())
                    .map_err(|_| Error::CredentialGenerationFailed)?
                    .to_sql_hex(),
            );
            #[derive(Serialize)]
            struct Principal<'a> {
                issuer: &'a str,
                subject: &'a str,
                username: &'a str,
                auth_method: &'a str,
                local_user_revision: i64,
            }
            let principal = serde_json::to_string(&Principal {
                issuer: "local",
                subject: &current.subject,
                username: &current.username,
                auth_method: "service-credential",
                local_user_revision: current.revision,
            })
            .map_err(|_| error)?;
            tx.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,'service',?3,'',?4,?5,?6,'',?7,?8,'',?9,?10,?9)",
                params![digest.as_str(),&id,&current.subject,principal,client,&limits.service_credential_audience,scopes_json,current.revision,now,expires])
                .map_err(|e|mutation_sql(work,e,error))?;
            #[derive(Serialize)]
            struct Issued<'a> {
                id: &'a str,
                token: &'a str,
                token_type: &'a str,
                expires_at: &'a str,
                scopes: &'a BTreeSet<&'a str>,
            }
            encode(
                &Issued {
                    id: &id,
                    token: &raw,
                    token_type: "Bearer",
                    expires_at: &expires_at,
                    scopes: &scopes,
                },
                limits.response_json_bytes.get(),
                201,
                error,
            )
        }
        AdminUsersRequest::RevokeCredential { username, id } => {
            let current = target(tx, work, username, Error::ServiceIdentityNotFound)?;
            if current.kind != "service" {
                return Err(Error::ServiceIdentityNotFound);
            }
            if !valid_credential_id(id) {
                return Err(error);
            }
            let now = now_micros()?;
            changed(
                tx,
                work,
                "UPDATE local_tokens SET revoked_at=?1 WHERE subject=?2 AND token_kind='service' AND token_id=?3 AND local_user_revision>=1 AND revoked_at IS NULL",
                params![now, &current.subject, id],
                error,
            )?;
            Ok(Output::empty(204))
        }
    }
}
#[derive(Serialize)]
struct Credential<'a> {
    id: &'a str,
    client_id: &'a str,
    scopes: Vec<String>,
    created_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
}
fn inventory(
    tx: &Transaction<'_>,
    work: &Work,
    subject: &str,
    maximum: usize,
    end: Instant,
) -> Result<Output, Error> {
    let error = Error::CredentialsReadFailed;
    let mut out = JsonBody {
        bytes: Zeroizing::new(Vec::new()),
        cap: maximum,
    };
    out.write_all(b"{\"credentials\":[").map_err(|_| error)?;
    let mut statement=tx.prepare(
        "SELECT CASE WHEN typeof(token_id)='text' AND length(CAST(token_id AS BLOB))<=128 THEN token_id END,
                CASE WHEN typeof(client_id)='text' AND length(CAST(client_id AS BLOB))<=128 THEN client_id END,
                CASE WHEN typeof(scopes_json)='text' AND length(CAST(scopes_json AS BLOB))<=?2 THEN scopes_json END,
                created_at,expires_at,revoked_at
         FROM local_tokens WHERE subject=?1 AND token_kind='service' AND local_user_revision>=1 ORDER BY created_at,token_id"
    ).map_err(|e|mutation_sql(work,e,error))?;
    let mut rows = statement
        .query(params![subject, maximum as i64])
        .map_err(|e| mutation_sql(work, e, error))?;
    let mut first = true;
    while let Some(row) = rows.next().map_err(|e| mutation_sql(work, e, error))? {
        gate(work, end)?;
        let text = |i| {
            row.get_ref(i)
                .map_err(|_| error)?
                .as_str()
                .map_err(|_| error)
        };
        let id = text(0)?;
        let client = text(1)?;
        let scopes: Vec<String> = serde_json::from_str(text(2)?).map_err(|_| error)?;
        if !valid_credential_id(id)
            || !safe_identity_segment(client, 128)
            || scopes.iter().any(|s| s.is_empty() || s.trim() != s)
            || scopes.windows(2).any(|s| s[0] >= s[1])
        {
            return Err(error);
        }
        let created: i64 = row.get(3).map_err(|_| error)?;
        let expiry: i64 = row.get(4).map_err(|_| error)?;
        let revoked: Option<i64> = row.get(5).map_err(|_| error)?;
        if expiry <= created {
            return Err(error);
        }
        let credential = Credential {
            id,
            client_id: client,
            scopes,
            created_at: timestamp(created)?,
            expires_at: timestamp(expiry)?,
            revoked_at: revoked.map(timestamp).transpose()?,
        };
        if !first {
            out.write_all(b",").map_err(|_| error)?;
        }
        first = false;
        serde_json::to_writer(&mut out, &credential).map_err(|_| error)?;
    }
    out.write_all(b"]}").map_err(|_| error)?;
    Ok(Output {
        status: 200,
        body: out.bytes,
    })
}
