//! Administrative metadata; callers must evaluate current identity and authorization.
use super::{MySqlControlStore, clock};
use crate::{
    AdminSession, NewAdminSession, SessionLimits, SessionPrincipal, SessionProfile,
    SessionRevocation,
    mysql::{
        MySqlControlError, RequiredCapability, Result,
        bootstrap::CommitState,
        capability::{Operation, session_select},
        config,
        executor::{Work, native_error},
    },
    session::positive_expiry,
};
use broker_security::TokenKind;
use sqlx_core::{row::Row, sql_str::AssertSqlSafe};
use sqlx_mysql::MySqlRow;
use std::{fmt, num::NonZeroUsize, time::Instant};
use zeroize::Zeroizing;

/// Borrows the store's admission and digester; limits never grant authorization.
///
/// The capability exposes no raw connection or SQL:
/// ```compile_fail
/// use broker_control::MySqlAdminSessions;
/// fn escape(view: &MySqlAdminSessions<'_>) { let _ = view.owner; }
/// ```
pub struct MySqlAdminSessions<'a> {
    owner: &'a MySqlControlStore,
    limits: SessionLimits,
}
impl fmt::Debug for MySqlAdminSessions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MySqlAdminSessions([REDACTED])")
    }
}
impl MySqlControlStore {
    pub fn admin_sessions(&self, limits: SessionLimits) -> Result<MySqlAdminSessions<'_>> {
        Ok(MySqlAdminSessions {
            owner: self,
            limits: physical_limits(limits)?,
        })
    }
}
impl MySqlAdminSessions<'_> {
    pub async fn create_session(
        &self,
        raw_token: &str,
        input: &NewAdminSession,
        caller: Instant,
    ) -> Result<()> {
        let end = self.deadline(caller)?;
        // The view has already validated its immutable configuration. These
        // pure Common APIs cannot return storage or transport failures.
        let json = input
            .validate(&self.limits)
            .map_err(|_| MySqlControlError::InvalidSession)?;
        let expiry =
            positive_expiry(input.expires_at()).map_err(|_| MySqlControlError::InvalidSession)?;
        let hash = self.hash(raw_token)?;
        let lifetime = self.lifetime()?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = self.owner.operation(end, Operation::CreateSession).await?;
            let created = clock()?;
            if expiry <= created || expiry - created > lifetime {
                return Err(MySqlControlError::InvalidSession);
            }
            let database = config::identifier(
                &lease.observation.database,
                lease.work.limits.statement_bytes.get(),
            )?;
            let profile = input.profile();
            let principal = input.principal();
            let sql = format!("INSERT INTO {database}.`admin_sessions`(token_hash,subject,name,email,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?,?,?)");
            lease.work.statement(&sql)?;
            let parent = sqlx_core::query::query(AssertSqlSafe(sql))
                .bind(&hash).bind(&profile.subject).bind(&profile.name).bind(&profile.email)
                .bind(input.csrf_token()).bind(expiry).bind(created)
                .execute(&mut lease.connection).await;
            let parent = parent.map_err(|error| {
                if error.as_database_error()
                    .and_then(|error| error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>())
                    .map(sqlx_mysql::MySqlDatabaseError::number) == Some(1062)
                {
                    MySqlControlError::SessionExists
                } else {
                    native_error(&error, RequiredCapability::Insert)
                }
            })?;
            if parent.rows_affected() != 1 {
                return Err(MySqlControlError::Storage);
            }
            let sql = format!("INSERT INTO {database}.`admin_session_principals`(token_hash,issuer,username,organization,teams_json,local_user_revision) VALUES(?,?,?,?,?,?)");
            lease.work.statement(&sql)?;
            let changed = sqlx_core::query::query(AssertSqlSafe(sql))
                .bind(&hash).bind(&principal.issuer).bind(&principal.username)
                .bind(&principal.organization).bind(json.teams).bind(principal.local_user_revision)
                .execute(&mut lease.connection).await
                .map_err(|error| native_error(&error, RequiredCapability::Insert))?
                .rows_affected();
            if changed != 1 {
                return Err(MySqlControlError::Storage);
            }
            if let Some(claims) = input.claimed_roles() {
                let sql = format!("INSERT INTO {database}.`admin_session_claim_roles`(token_hash,claim_selector,roles_json) VALUES(?,?,?)");
                lease.work.statement(&sql)?;
                let changed = sqlx_core::query::query(AssertSqlSafe(sql))
                    .bind(&hash).bind(&claims.selector)
                    .bind(json.roles.ok_or(MySqlControlError::InvalidSession)?)
                    .execute(&mut lease.connection).await
                    .map_err(|error| native_error(&error, RequiredCapability::Insert))?
                    .rows_affected();
                if changed != 1 {
                    return Err(MySqlControlError::Storage);
                }
            }
            tracing::trace!(target: "broker_control::mysql::session_create_staged", "administrative session inserts staged in current transaction");
            lease.unchanged().await?;
            let before_commit = clock()?;
            if before_commit < created {
                return Err(MySqlControlError::Clock);
            }
            if expiry <= before_commit {
                return Err(MySqlControlError::SessionExpired);
            }
            tracing::trace!(target: "broker_control::mysql::session_commit_starting", "administrative session context confirmed before commit attempt");
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(())
        }).await.map_err(|_| commit.timeout(false))?
    }

    pub async fn session(&self, raw_token: &str, caller: Instant) -> Result<AdminSession> {
        let end = self.deadline(caller)?;
        let hash = self.hash(raw_token)?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = self.owner.operation(end, Operation::ReadSession).await?;
            let database = config::identifier(
                &lease.observation.database,
                lease.work.limits.statement_bytes.get(),
            )?;
            let sql = session_select(&database, false);
            lease.work.statement(&sql)?;
            let text = self.limits.text_bytes.get() as u64;
            let row = sqlx_core::query::query(AssertSqlSafe(sql))
                .bind(text).bind(text).bind(text).bind(self.limits.csrf_bytes.get() as u64)
                .bind(text).bind(text).bind(text).bind(self.limits.teams_json_bytes.get() as u64)
                .bind(text).bind(self.limits.roles_json_bytes.get() as u64).bind(&hash)
                .fetch_optional(&mut lease.connection).await
                .map_err(|error| native_error(&error, RequiredCapability::Select))?
                .ok_or(MySqlControlError::SessionUnavailable)?;
            let after_lock = clock()?;
            if !present(&row, "principal_present")? {
                return Err(MySqlControlError::CorruptSession);
            }
            let mut get_text = |column, cap| stored_text(&row, column, cap, &mut lease.work);
            let profile = SessionProfile {
                subject: get_text("subject", self.limits.text_bytes.get())?,
                name: get_text("name", self.limits.text_bytes.get())?,
                email: get_text("email", self.limits.text_bytes.get())?,
            };
            let csrf = Zeroizing::new(get_text("csrf", self.limits.csrf_bytes.get())?);
            let principal = SessionPrincipal {
                issuer: get_text("issuer", self.limits.text_bytes.get())?,
                username: get_text("username", self.limits.text_bytes.get())?,
                organization: get_text("organization", self.limits.text_bytes.get())?,
                teams: Vec::new(),
                local_user_revision: row.try_get::<Option<i64>, _>("local_user_revision")
                    .map_err(|_| MySqlControlError::CorruptSession)?
                    .ok_or(MySqlControlError::CorruptSession)?,
            };
            let teams = get_text("teams", self.limits.teams_json_bytes.get())?;
            let claims = if present(&row, "claims_present")? {
                Some((get_text("selector", self.limits.text_bytes.get())?,
                    get_text("roles", self.limits.roles_json_bytes.get())?))
            } else {
                None
            };
            let created = row.try_get::<i64, _>("created_at")
                .map_err(|_| MySqlControlError::CorruptSession)?;
            let expiry = row.try_get::<i64, _>("expires_at")
                .map_err(|_| MySqlControlError::CorruptSession)?;
            let session = AdminSession::stored(profile, principal, csrf, claims, &teams,
                (created, expiry), &self.limits).map_err(|_| MySqlControlError::CorruptSession)?;
            if created > after_lock {
                return Err(MySqlControlError::CorruptSession);
            }
            let observed_expired = expiry <= after_lock;
            if !observed_expired {
                tracing::trace!(target: "broker_control::mysql::session_locked_live", "locked administrative session remains live");
            }
            lease.unchanged().await?;
            let expired = read_expired(created, expiry, observed_expired, clock()?)?;
            if expired {
                let sql = delete_sql(&database);
                lease.work.statement(&sql)?;
                if sqlx_core::query::query(AssertSqlSafe(sql)).bind(&hash)
                    .execute(&mut lease.connection).await
                    .map_err(|error| native_error(&error, RequiredCapability::Delete))?
                    .rows_affected() != 1
                {
                    return Err(MySqlControlError::Storage);
                }
            }
            tracing::trace!(target: "broker_control::mysql::session_commit_starting", "administrative session context confirmed before commit attempt");
            commit.commit(&mut lease).await?;
            drop(lease);
            if expired { Err(MySqlControlError::SessionExpired) } else { Ok(session) }
        }).await.map_err(|_| commit.timeout(false))?
    }

    pub async fn revoke_session(
        &self,
        raw_token: &str,
        caller: Instant,
    ) -> Result<SessionRevocation> {
        let end = self.deadline(caller)?;
        let hash = self.hash(raw_token)?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = self.owner.operation(end, Operation::RevokeSession).await?;
            let database = config::identifier(
                &lease.observation.database,
                lease.work.limits.statement_bytes.get(),
            )?;
            let sql = delete_sql(&database);
            lease.work.statement(&sql)?;
            let changed = sqlx_core::query::query(AssertSqlSafe(sql)).bind(&hash)
                .execute(&mut lease.connection).await
                .map_err(|error| native_error(&error, RequiredCapability::Delete))?
                .rows_affected();
            let result = match changed {
                0 => SessionRevocation::Absent,
                1 => SessionRevocation::Revoked,
                _ => return Err(MySqlControlError::Storage),
            };
            lease.unchanged().await?;
            tracing::trace!(target: "broker_control::mysql::session_commit_starting", "administrative session context confirmed before commit attempt");
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(result)
        }).await.map_err(|_| commit.timeout(false))?
    }
    fn deadline(&self, caller: Instant) -> Result<Instant> {
        config::deadline(caller, self.owner.config.admission.budgets.operation)
    }
    fn lifetime(&self) -> Result<i64> {
        self.limits
            .lifetime_micros()
            .map_err(|_| MySqlControlError::Configuration)
    }
    fn hash(&self, raw: &str) -> Result<String> {
        self.owner
            .digester
            .token(TokenKind::AdminSession, raw.as_bytes())
            .map_err(|_| MySqlControlError::InvalidSession)
            .map(|v| v.to_sql_hex())
    }
}
fn physical_limits(limits: SessionLimits) -> Result<SessionLimits> {
    limits
        .validate()
        .map_err(|_| MySqlControlError::Configuration)?;
    let maximum = |table_name, column_name| {
        broker_store::schema::TABLES
            .iter()
            .find(|table| table.name() == table_name)
            .and_then(|table| {
                table
                    .mysql_shape()
                    .columns()
                    .iter()
                    .find(|column| column.name() == column_name)
                    .and_then(|column| column.character_octet_length())
            })
            .and_then(|value| usize::try_from(value).ok())
            .and_then(NonZeroUsize::new)
            .ok_or(MySqlControlError::Configuration)
    };
    Ok(SessionLimits {
        teams_json_bytes: limits
            .teams_json_bytes
            .min(maximum("admin_session_principals", "teams_json")?),
        roles_json_bytes: limits
            .roles_json_bytes
            .min(maximum("admin_session_claim_roles", "roles_json")?),
        ..limits
    })
}
fn stored_text(row: &MySqlRow, column: &str, cap: usize, work: &mut Work) -> Result<String> {
    let text = row
        .try_get::<Option<&str>, _>(column)
        .map_err(|_| MySqlControlError::CorruptSession)?
        .ok_or(MySqlControlError::CorruptSession)?;
    if text.len() > cap {
        return Err(MySqlControlError::CorruptSession);
    }
    work.bytes(text.len())?;
    Ok(text.to_owned())
}
fn present(row: &MySqlRow, column: &str) -> Result<bool> {
    match row
        .try_get::<i64, _>(column)
        .map_err(|_| MySqlControlError::CorruptSession)?
    {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MySqlControlError::CorruptSession),
    }
}
fn delete_sql(database: &str) -> String {
    format!("DELETE FROM {database}.`admin_sessions` WHERE token_hash=?")
}
fn read_expired(created: i64, expiry: i64, observed: bool, before_commit: i64) -> Result<bool> {
    if before_commit < created {
        Err(MySqlControlError::Clock)
    } else {
        Ok(observed || expiry <= before_commit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ControlError, SessionClaimRoles};
    use std::time::{Duration, SystemTime};
    const MYSQL_SESSION_TEXT_ORACLE: usize = 65_535;
    fn n(v: usize) -> NonZeroUsize {
        NonZeroUsize::new(v).unwrap()
    }
    fn limits() -> SessionLimits {
        SessionLimits {
            text_bytes: n(16_384),
            csrf_bytes: n(512),
            team_bytes: n(100_000),
            role_bytes: n(512),
            max_teams: n(4096),
            max_roles: n(4096),
            teams_json_bytes: n(100_000),
            roles_json_bytes: n(100_000),
            max_lifetime: Duration::from_secs(7200),
        }
    }
    fn input(teams: Vec<String>, claims: Option<SessionClaimRoles>) -> NewAdminSession {
        NewAdminSession::new(
            SessionProfile {
                subject: "subject".into(),
                name: String::new(),
                email: String::new(),
            },
            SessionPrincipal {
                issuer: "issuer".into(),
                username: String::new(),
                organization: String::new(),
                teams,
                local_user_revision: 0,
            },
            Zeroizing::new("csrf".into()),
            claims,
            SystemTime::now() + Duration::from_secs(3600),
            &limits(),
        )
        .unwrap()
    }
    #[test]
    fn session_physical_cap_uses_shape_before_serialization() {
        let original = limits();
        let effective = physical_limits(original).unwrap();
        assert_eq!(
            effective.teams_json_bytes.get(),
            MYSQL_SESSION_TEXT_ORACLE,
            "MYSQL_SESSION_TEXT_ORACLE"
        );
        assert_eq!(
            effective.roles_json_bytes.get(),
            MYSQL_SESSION_TEXT_ORACLE,
            "MYSQL_SESSION_TEXT_ORACLE"
        );
        assert_eq!(original.teams_json_bytes.get(), 100_000);
        assert_eq!(effective.max_lifetime, original.max_lifetime);
        let exact = input(vec!["x".repeat(65_531)], None);
        assert_eq!(exact.validate(&effective).unwrap().teams.len(), 65_535);
        let over = input(vec!["x".repeat(65_532)], None);
        assert!(matches!(
            over.validate(&effective),
            Err(ControlError::InvalidSession)
        ));
        let escaped = input(vec!["\"".repeat(32_766)], None);
        assert!(escaped.validate(&effective).is_err());
        let claims = SessionClaimRoles {
            selector: "roles".into(),
            roles: (0..1000)
                .map(|i| format!("{i:04}{}", "r".repeat(124)))
                .collect(),
        };
        // Original JSON cap must admit this input before the view rejects it.
        let mut original = limits();
        original.roles_json_bytes = n(200_000);
        let with_roles = NewAdminSession::new(
            SessionProfile {
                subject: "s".into(),
                name: String::new(),
                email: String::new(),
            },
            SessionPrincipal {
                issuer: "i".into(),
                username: String::new(),
                organization: String::new(),
                teams: vec![],
                local_user_revision: 0,
            },
            Zeroizing::new("csrf".into()),
            Some(claims),
            SystemTime::now() + Duration::from_secs(3600),
            &original,
        )
        .unwrap();
        assert!(
            with_roles
                .validate(&physical_limits(original).unwrap())
                .is_err()
        );
    }
    #[test]
    fn original_invalid_limits_are_not_hidden_by_physical_minimum() {
        let mut invalid = limits();
        invalid.teams_json_bytes = n(usize::MAX);
        assert!(matches!(
            physical_limits(invalid),
            Err(MySqlControlError::Configuration)
        ));
        invalid = limits();
        invalid.max_lifetime = Duration::ZERO;
        assert!(physical_limits(invalid).is_err());
        let mut strict = limits();
        strict.teams_json_bytes = n(3);
        assert_eq!(physical_limits(strict).unwrap().teams_json_bytes.get(), 3);
        assert!(
            input(vec!["x".into()], None)
                .validate(&physical_limits(strict).unwrap())
                .is_err()
        );
    }
    #[test]
    fn expiry_observation_cannot_be_revived_by_clock_reversal() {
        assert_eq!(read_expired(10, 20, false, 19), Ok(false));
        assert_eq!(read_expired(10, 20, false, 20), Ok(true));
        assert_eq!(read_expired(10, 20, true, 19), Ok(true));
        assert_eq!(read_expired(10, 20, true, 9), Err(MySqlControlError::Clock));
    }
    #[test]
    fn session_projection_is_bounded_and_probe_never_mutates() {
        let sql = session_select("`literal``database`", false);
        assert_eq!(sql.matches("CASE WHEN OCTET_LENGTH(").count(), 10);
        assert_eq!(sql.matches('?').count(), 11);
        assert!(sql.ends_with("WHERE s.token_hash=? FOR UPDATE OF s"));
        for name in [
            "admin_sessions",
            "admin_session_principals",
            "admin_session_claim_roles",
        ] {
            assert!(sql.contains(&format!("`literal``database`.`{name}`")));
        }
        let probe = session_select("`broker`", true);
        assert!(!probe.contains('?'));
        assert!(probe.ends_with("AND FALSE FOR UPDATE OF s"));
        assert!(probe.starts_with("SELECT "));
    }
    #[test]
    fn public_session_errors_are_finite_and_redacted() {
        for error in [
            MySqlControlError::InvalidSession,
            MySqlControlError::SessionExists,
            MySqlControlError::SessionUnavailable,
            MySqlControlError::SessionExpired,
            MySqlControlError::CorruptSession,
        ] {
            let message = error.to_string();
            assert!(!message.contains("SELECT"));
            assert!(!message.contains("token_hash"));
            assert!(message.contains("session"));
        }
    }
}
