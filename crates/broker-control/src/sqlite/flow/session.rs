use super::SqliteControlStore;
use crate::{
    AdminSession, ControlError, NewAdminSession, SessionLimits, SessionPrincipal, SessionProfile,
    SessionRevocation,
    flow::now_micros,
    session::positive_expiry,
    sqlite::executor::{State, Work},
};
use broker_security::TokenKind;
use rusqlite::{OptionalExtension, Row, params};
use std::{fmt, time::Instant};
use zeroize::Zeroizing;

/// Borrowed administrative session metadata. Callers revalidate current authority.
///
/// ```compile_fail
/// use broker_control::{SessionLimits, SqliteAdminSessions, SqliteControlStore};
/// fn escape(store: SqliteControlStore, limits: SessionLimits) -> SqliteAdminSessions<'static> {
///     store.admin_sessions(limits).unwrap()
/// }
/// ```
pub struct SqliteAdminSessions<'a> {
    owner: &'a SqliteControlStore,
    limits: SessionLimits,
}
impl fmt::Debug for SqliteAdminSessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminSessions([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_sessions(
        &self,
        limits: SessionLimits,
    ) -> Result<SqliteAdminSessions<'_>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminSessions {
            owner: self,
            limits,
        })
    }
}
impl SqliteAdminSessions<'_> {
    fn hash(&self, raw_token: &str) -> Result<String, ControlError> {
        self.owner
            .digester
            .token(TokenKind::AdminSession, raw_token.as_bytes())
            .map_err(|_| ControlError::InvalidSession)
            .map(|digest| digest.to_sql_hex())
    }
    async fn run<T: Send + 'static>(
        &self,
        end: Instant,
        body: impl FnOnce(&mut State, &Work) -> Result<T, ControlError> + Send + 'static,
    ) -> Result<T, ControlError> {
        self.owner
            .executor
            .execute(end, move |owner, work| Ok(body(owner, work)))
            .await
            .map_err(ControlError::from)?
    }
    pub async fn create_session(
        &self,
        raw_token: &str,
        session: &NewAdminSession,
        caller: Instant,
    ) -> Result<(), ControlError> {
        let end = self.owner.executor.deadline(caller)?;
        let json = session.validate(&self.limits)?;
        let expiry = positive_expiry(session.expires_at())?;
        let hash = self.hash(raw_token)?;
        let session = NewAdminSession::new(
            SessionProfile {
                subject: session.profile().subject.clone(),
                name: session.profile().name.clone(),
                email: session.profile().email.clone(),
            },
            SessionPrincipal {
                issuer: session.principal().issuer.clone(),
                username: session.principal().username.clone(),
                organization: session.principal().organization.clone(),
                teams: session.principal().teams.clone(),
                local_user_revision: session.principal().local_user_revision,
            },
            Zeroizing::new(session.csrf_token().to_owned()),
            session.claimed_roles().map(|c| crate::SessionClaimRoles {
                selector: c.selector.clone(),
                roles: c.roles.clone(),
            }),
            session.expires_at(),
            &self.limits,
        )?;
        let limits = self.limits;
        self.run(end, move |owner, work| {
            let tx = owner.begin(work)?;
            let created = now_micros()?;
            if expiry <= created || expiry - created > limits.lifetime_micros()? {
                return Err(ControlError::InvalidSession);
            }
            insert(&tx, work, &hash, &session, json, expiry, created)?;
            if expiry <= now_micros()? {
                return Err(ControlError::SessionExpired);
            }
            work.commit(tx)?;
            Ok(())
        })
        .await
    }
    pub async fn session(
        &self,
        raw_token: &str,
        caller: Instant,
    ) -> Result<AdminSession, ControlError> {
        let end = self.owner.executor.deadline(caller)?;
        let hash = self.hash(raw_token)?;
        let limits = self.limits;
        self.run(end, move |owner, work| {
            let tx = owner.begin(work)?;
            let session =
                load(&tx, work, &hash, &limits)?.ok_or(ControlError::SessionUnavailable)?;
            let observed_at = now_micros()?;
            let expiry = session.expires_at().as_i64();
            let observed_expired = expiry <= observed_at;
            let before_commit = now_micros()?;
            let expired = observed_expired || expiry <= before_commit;
            if expired {
                let deleted = tx
                    .execute("DELETE FROM admin_sessions WHERE token_hash=?1", [&hash])
                    .map_err(|error| work.sql(error))?;
                if deleted != 1 {
                    return Err(ControlError::Storage);
                }
            }
            work.commit(tx)?;
            if expired {
                Err(ControlError::SessionExpired)
            } else {
                Ok(session)
            }
        })
        .await
    }
    pub async fn revoke_session(
        &self,
        raw_token: &str,
        caller: Instant,
    ) -> Result<SessionRevocation, ControlError> {
        let end = self.owner.executor.deadline(caller)?;
        let hash = self.hash(raw_token)?;
        self.run(end, move |owner, work| {
            let tx = owner.begin(work)?;
            let deleted = tx
                .execute("DELETE FROM admin_sessions WHERE token_hash=?1", [hash])
                .map_err(|error| work.sql(error))?;
            let result = match deleted {
                0 => SessionRevocation::Absent,
                1 => SessionRevocation::Revoked,
                _ => return Err(ControlError::Storage),
            };
            work.commit(tx)?;
            Ok(result)
        })
        .await
    }
}

// Operate only on the caller's transaction; ownership and COMMIT stay with that caller.
pub(super) fn insert(
    tx: &rusqlite::Transaction<'_>,
    work: &Work,
    hash: &str,
    session: &NewAdminSession,
    json: crate::session::SessionJson,
    expiry: i64,
    created: i64,
) -> Result<(), ControlError> {
    let inserted = tx.execute(
                "INSERT INTO admin_sessions(token_hash,subject,name,email,csrf_token,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![hash, session.profile().subject, session.profile().name, session.profile().email, session.csrf_token(), expiry, created],
            ).map_err(|error| {
                if let rusqlite::Error::SqliteFailure(code, _) = &error
                    && matches!(code.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY | rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
                {
                    ControlError::SessionExists
                } else {
                    work.sql(error).into()
                }
            })?;
    if inserted != 1 {
        return Err(ControlError::Storage);
    }
    work.check()?;
    let inserted = tx.execute(
                "INSERT INTO admin_session_principals(token_hash,issuer,username,organization,teams_json,local_user_revision) VALUES(?1,?2,?3,?4,?5,?6)",
                params![hash, session.principal().issuer, session.principal().username, session.principal().organization, json.teams, session.principal().local_user_revision],
            ).map_err(|error| work.sql(error))?;
    if inserted != 1 {
        return Err(ControlError::Storage);
    }
    if let Some(claims) = session.claimed_roles() {
        work.check()?;
        let inserted = tx.execute(
                    "INSERT INTO admin_session_claim_roles(token_hash,claim_selector,roles_json) VALUES(?1,?2,?3)",
                    params![hash, claims.selector, json.roles.ok_or(ControlError::InvalidSession)?],
                ).map_err(|error| work.sql(error))?;
        if inserted != 1 {
            return Err(ControlError::Storage);
        }
    }

    Ok(())
}
pub(super) fn load(
    tx: &rusqlite::Transaction<'_>,
    work: &Work,
    hash: &str,
    limits: &SessionLimits,
) -> Result<Option<AdminSession>, ControlError> {
    work.check()?;
    let session = tx
        .query_row(
            SESSION_SELECT,
            params![
                hash,
                limits.text_bytes.get() as i64,
                limits.csrf_bytes.get() as i64,
                limits.teams_json_bytes.get() as i64,
                limits.roles_json_bytes.get() as i64
            ],
            |row| Ok(decode(row, limits)),
        )
        .optional()
        .map_err(|error| work.sql(error))?
        .transpose()?;
    if let Some(session) = &session
        && session.created_at().as_i64() > now_micros()?
    {
        return Err(ControlError::CorruptSession);
    }
    Ok(session)
}
const SESSION_SELECT: &str = "SELECT
 CASE WHEN typeof(s.subject)='text' AND length(CAST(s.subject AS BLOB))<=?2 THEN s.subject END,
 CASE WHEN typeof(s.name)='text' AND length(CAST(s.name AS BLOB))<=?2 THEN s.name END,
 CASE WHEN typeof(s.email)='text' AND length(CAST(s.email AS BLOB))<=?2 THEN s.email END,
 CASE WHEN typeof(s.csrf_token)='text' AND length(CAST(s.csrf_token AS BLOB))<=?3 THEN s.csrf_token END,
 s.created_at,s.expires_at,p.token_hash IS NOT NULL,
 CASE WHEN typeof(p.issuer)='text' AND length(CAST(p.issuer AS BLOB))<=?2 THEN p.issuer END,
 CASE WHEN typeof(p.username)='text' AND length(CAST(p.username AS BLOB))<=?2 THEN p.username END,
 CASE WHEN typeof(p.organization)='text' AND length(CAST(p.organization AS BLOB))<=?2 THEN p.organization END,
 CASE WHEN typeof(p.teams_json)='text' AND length(CAST(p.teams_json AS BLOB))<=?4 THEN p.teams_json END,
 p.local_user_revision,c.token_hash IS NOT NULL,
 CASE WHEN typeof(c.claim_selector)='text' AND length(CAST(c.claim_selector AS BLOB))<=?2 THEN c.claim_selector END,
 CASE WHEN typeof(c.roles_json)='text' AND length(CAST(c.roles_json AS BLOB))<=?5 THEN c.roles_json END
 FROM admin_sessions s LEFT JOIN admin_session_principals p ON p.token_hash=s.token_hash
 LEFT JOIN admin_session_claim_roles c ON c.token_hash=s.token_hash WHERE s.token_hash=?1";
fn decode(row: &Row<'_>, limits: &SessionLimits) -> Result<AdminSession, ControlError> {
    let corrupt = |_| ControlError::CorruptSession;
    let text = |index| -> Result<String, ControlError> {
        row.get::<_, Option<String>>(index)
            .map_err(corrupt)?
            .ok_or(ControlError::CorruptSession)
    };
    if row.get::<_, i64>(6).map_err(corrupt)? != 1 {
        return Err(ControlError::CorruptSession);
    }
    let csrf = Zeroizing::new(text(3)?);
    let profile = SessionProfile {
        subject: text(0)?,
        name: text(1)?,
        email: text(2)?,
    };
    let principal = SessionPrincipal {
        issuer: text(7)?,
        username: text(8)?,
        organization: text(9)?,
        teams: Vec::new(),
        local_user_revision: row.get(11).map_err(corrupt)?,
    };
    let claims = match row.get::<_, i64>(12).map_err(corrupt)? {
        0 => None,
        1 => Some((text(13)?, text(14)?)),
        _ => return Err(ControlError::CorruptSession),
    };
    AdminSession::stored(
        profile,
        principal,
        csrf,
        claims,
        &text(10)?,
        (row.get(4).map_err(corrupt)?, row.get(5).map_err(corrupt)?),
        limits,
    )
}
