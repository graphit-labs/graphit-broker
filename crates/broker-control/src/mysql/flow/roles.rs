use super::{
    CommitState, Lease, MySqlControlError, MySqlControlStore, RequiredCapability, Result, clock,
    config, native_error,
};
use crate::{
    SystemPermission,
    identity::{safe_identity_segment, valid_identity_subject},
};
use broker_store::seeds::BuiltinRole;
use sqlx_core::{row::Row, sql_str::AssertSqlSafe};
use std::time::Instant;

impl MySqlControlStore {
    /// Persist a system role after the caller authenticates and authorizes the mutation.
    ///
    /// This SQL primitive does not establish caller authority. Built-ins keep their official
    /// bundles, and an uncertain commit must not be replayed automatically.
    pub async fn set_role(
        &self,
        name: &str,
        permissions: &[SystemPermission],
        deadline: Instant,
    ) -> Result<()> {
        let end = config::deadline(deadline, self.config.admission.budgets.operation)?;
        let (name, permissions) = role_values(name, permissions)?;
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = Lease::open(&self.config, &self.admission, end).await?;
            lease.begin().await?;
            let database = config::identifier(
                &lease.observation.database,
                lease.work.limits.statement_bytes.get(),
            )?;
            let insert = format!(
                "INSERT INTO {database}.`roles`(name,created_at) VALUES(?,?) ON DUPLICATE KEY UPDATE name=name"
            );
            sqlx_core::query::query(AssertSqlSafe(insert))
                .bind(name)
                .bind(clock()?)
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Insert))?;
            let lock = format!("SELECT 1 FROM {database}.`roles` WHERE name=? FOR UPDATE");
            if sqlx_core::query::query(AssertSqlSafe(lock))
                .bind(name)
                .fetch_optional(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Select))?
                .is_none()
            {
                return Err(MySqlControlError::Storage);
            }
            let delete = format!("DELETE FROM {database}.`role_permissions` WHERE role=?");
            sqlx_core::query::query(AssertSqlSafe(delete))
                .bind(name)
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Delete))?;
            let permission_sql =
                format!("INSERT INTO {database}.`role_permissions`(role,action) VALUES(?,?)");
            for action in permissions {
                sqlx_core::query::query(AssertSqlSafe(permission_sql.as_str()))
                    .bind(name)
                    .bind(action)
                    .execute(&mut lease.connection)
                    .await
                    .map_err(|error| native_error(&error, RequiredCapability::Insert))?;
            }
            lease.unchanged().await?;
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(())
        })
        .await
        .map_err(|_| commit.timeout(false))?
    }
    /// Assign an existing system role after caller authentication and authorization.
    ///
    /// Repeating the pair preserves its creation time. An uncertain commit must not
    /// be replayed automatically; this storage primitive does not establish authority.
    pub async fn assign_role(&self, subject: &str, role: &str, deadline: Instant) -> Result<()> {
        let end = config::deadline(deadline, self.config.admission.budgets.operation)?;
        let subject = subject.trim();
        let role = role.trim();
        if subject.is_empty() || subject.chars().count() > 512 || !safe_identity_segment(role, 128)
        {
            return Err(MySqlControlError::InvalidAssignment);
        }
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = Lease::open(&self.config, &self.admission, end).await?;
            lease.begin().await?;
            let database = config::identifier(
                &lease.observation.database,
                lease.work.limits.statement_bytes.get(),
            )?;
            let lock = format!("SELECT 1 FROM {database}.`roles` WHERE name=? FOR UPDATE");
            if sqlx_core::query::query(AssertSqlSafe(lock))
                .bind(role)
                .fetch_optional(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Select))?
                .is_none()
            {
                return Err(MySqlControlError::RoleNotFound);
            }
            let insert = format!(
                "INSERT INTO {database}.`role_assignments`(subject,role,created_at) VALUES(?,?,?) ON DUPLICATE KEY UPDATE subject=subject"
            );
            sqlx_core::query::query(AssertSqlSafe(insert))
                .bind(subject)
                .bind(role)
                .bind(clock()?)
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Insert))?;
            lease.unchanged().await?;
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(())
        })
        .await
        .map_err(|_| commit.timeout(false))?
    }
    /// Revoke one exact assignment after caller authentication and authorization.
    ///
    /// The last eligible, explicitly assigned administrator is protected under the
    /// shared parent-role lock. Uncertain commits must not be replayed automatically.
    pub async fn revoke_role(&self, subject: &str, role: &str, deadline: Instant) -> Result<()> {
        let end = config::deadline(deadline, self.config.admission.budgets.operation)?;
        let subject = subject.trim();
        let role = role.trim();
        let commit = CommitState::new();
        tokio::time::timeout_at(end.into(), async {
            let mut lease = Lease::open(&self.config, &self.admission, end).await?;
            lease.begin().await?;
            let database = config::identifier(
                &lease.observation.database,
                lease.work.limits.statement_bytes.get(),
            )?;
            let lock = format!("SELECT 1 FROM {database}.`roles` WHERE name=? FOR UPDATE");
            let _ = sqlx_core::query::query(AssertSqlSafe(lock))
                .bind(role)
                .fetch_optional(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Select))?;
            if role == "admin" {
                let target = format!(
                    "SELECT 1 FROM {database}.`role_assignments` WHERE subject=? AND role=? AND CAST(subject AS BINARY)=CAST(? AS BINARY) AND CAST(role AS BINARY)=CAST(? AS BINARY)"
                );
                let present = sqlx_core::query::query(AssertSqlSafe(target))
                    .bind(subject)
                    .bind(role)
                    .bind(subject)
                    .bind(role)
                    .fetch_optional(&mut lease.connection)
                    .await
                    .map_err(|error| native_error(&error, RequiredCapability::Select))?
                    .is_some();
                if present && !other_assigned_admin(&mut lease, &database, subject).await? {
                    return Err(MySqlControlError::LastAssignedAdmin);
                }
            }
            let delete = format!(
                "DELETE FROM {database}.`role_assignments` WHERE subject=? AND role=? AND CAST(subject AS BINARY)=CAST(? AS BINARY) AND CAST(role AS BINARY)=CAST(? AS BINARY)"
            );
            sqlx_core::query::query(AssertSqlSafe(delete))
                .bind(subject)
                .bind(role)
                .bind(subject)
                .bind(role)
                .execute(&mut lease.connection)
                .await
                .map_err(|error| native_error(&error, RequiredCapability::Delete))?;
            lease.unchanged().await?;
            commit.commit(&mut lease).await?;
            drop(lease);
            Ok(())
        })
        .await
        .map_err(|_| commit.timeout(false))?
    }
}

async fn other_assigned_admin(lease: &mut Lease, database: &str, subject: &str) -> Result<bool> {
    let external = format!(
        "SELECT 1 FROM {database}.`role_assignments` WHERE role=? AND CAST(role AS BINARY)=CAST(? AS BINARY) AND CAST(subject AS BINARY)<>CAST(? AS BINARY) AND CAST(LEFT(subject,6) AS BINARY)<>CAST('local|' AS BINARY) LIMIT 1"
    );
    if sqlx_core::query::query(AssertSqlSafe(external))
        .bind("admin")
        .bind("admin")
        .bind(subject)
        .fetch_optional(&mut lease.connection)
        .await
        .map_err(|error| native_error(&error, RequiredCapability::Select))?
        .is_some()
    {
        return Ok(true);
    }
    let local = format!(
        "SELECT CASE WHEN OCTET_LENGTH(u.username)<=128 THEN u.username ELSE NULL END,CASE WHEN OCTET_LENGTH(u.subject)<=512 THEN u.subject ELSE NULL END,CASE WHEN OCTET_LENGTH(u.identity_kind)<=16 THEN u.identity_kind ELSE NULL END,u.enabled,u.revision,a.subject FROM {database}.`role_assignments` a JOIN {database}.`local_users` u ON a.subject=CONCAT('local|',u.subject) WHERE a.role=? AND CAST(a.role AS BINARY)=CAST(? AS BINARY) AND CAST(a.subject AS BINARY)<>CAST(? AS BINARY) AND CAST(LEFT(a.subject,6) AS BINARY)=CAST('local|' AS BINARY) AND u.enabled=1 LIMIT 1"
    );
    let Some(row) = sqlx_core::query::query(AssertSqlSafe(local))
        .bind("admin")
        .bind("admin")
        .bind(subject)
        .fetch_optional(&mut lease.connection)
        .await
        .map_err(|error| native_error(&error, RequiredCapability::Select))?
    else {
        return Ok(false);
    };
    let username = row
        .try_get::<Option<String>, _>(0)
        .map_err(|_| MySqlControlError::CorruptIdentity)?
        .ok_or(MySqlControlError::CorruptIdentity)?;
    let local_subject = row
        .try_get::<Option<String>, _>(1)
        .map_err(|_| MySqlControlError::CorruptIdentity)?
        .ok_or(MySqlControlError::CorruptIdentity)?;
    let kind = row
        .try_get::<Option<String>, _>(2)
        .map_err(|_| MySqlControlError::CorruptIdentity)?
        .ok_or(MySqlControlError::CorruptIdentity)?;
    let enabled = row
        .try_get::<i64, _>(3)
        .map_err(|_| MySqlControlError::CorruptIdentity)?;
    let revision = row
        .try_get::<i64, _>(4)
        .map_err(|_| MySqlControlError::CorruptIdentity)?;
    let assignment = row
        .try_get::<String, _>(5)
        .map_err(|_| MySqlControlError::CorruptIdentity)?;
    if !safe_identity_segment(&username, 128)
        || !valid_identity_subject(&local_subject, 512)
        || !matches!(kind.as_str(), "human" | "service")
        || enabled != 1
        || revision < 1
        || assignment != format!("local|{local_subject}")
    {
        return Err(MySqlControlError::CorruptIdentity);
    }
    Ok(true)
}

fn role_values<'a>(
    name: &'a str,
    permissions: &[SystemPermission],
) -> Result<(&'a str, Vec<&'static str>)> {
    let name = name.trim();
    if !safe_identity_segment(name, 128) {
        return Err(MySqlControlError::InvalidRole);
    }
    let mut values = Vec::new();
    if let Some(builtin) = BuiltinRole::ALL.iter().find(|role| role.name() == name) {
        values.extend(builtin.actions().iter().map(|action| action.as_str()));
    } else {
        for permission in permissions {
            let action = permission.as_str();
            if !values.contains(&action) {
                values.push(action);
            }
        }
    }
    if values.is_empty() {
        return Err(MySqlControlError::InvalidRole);
    }
    values.sort_unstable();
    Ok((name, values))
}
