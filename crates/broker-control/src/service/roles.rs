use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError, SystemPermission, flow::now_micros, identity::safe_identity_segment, schema,
};
use broker_store::seeds::BuiltinRole;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

impl PostgresControlStore {
    /// Persist a role definition after the caller has authenticated and authorized the operation.
    ///
    /// This is a SQL primitive, not an authority or an HTTP authorization decision.
    /// Built-in roles retain their official bundles. An uncertain result must not be replayed
    /// automatically.
    pub async fn set_role(
        &self,
        name: &str,
        permissions: &[SystemPermission],
        deadline: Instant,
    ) -> Result<(), ControlError> {
        let deadline = bounded_deadline(deadline, self.budgets.operation_timeout)?;
        let (name, permissions) = role_values(name, permissions)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard =
                ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            replace_role(&mut tx, name, &permissions).await?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            Ok(())
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }
}

pub(crate) fn role_values<'a>(
    name: &'a str,
    permissions: &[SystemPermission],
) -> Result<(&'a str, Vec<&'static str>), ControlError> {
    let name = name.trim();
    if !safe_identity_segment(name, 128) {
        return Err(ControlError::InvalidRole);
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
        return Err(ControlError::InvalidRole);
    }
    values.sort_unstable();
    Ok((name, values))
}

pub(super) async fn replace_role(
    connection: &mut sqlx_postgres::PgConnection,
    name: &str,
    permissions: &[&str],
) -> Result<(), ControlError> {
    sqlx_core::query::query(
        "INSERT INTO public.roles(name,created_at) VALUES($1,$2) ON CONFLICT(name) DO NOTHING",
    )
    .bind(name)
    .bind(now_micros()?)
    .execute(&mut *connection)
    .await
    .map_err(|_| ControlError::Storage)?;
    let role = sqlx_core::query::query("SELECT 1 FROM public.roles WHERE name=$1 FOR UPDATE")
        .bind(name)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| ControlError::Storage)?;
    if role.is_none() {
        return Err(ControlError::Storage);
    }
    sqlx_core::query::query("DELETE FROM public.role_permissions WHERE role=$1")
        .bind(name)
        .execute(&mut *connection)
        .await
        .map_err(|_| ControlError::Storage)?;
    for &action in permissions {
        sqlx_core::query::query("INSERT INTO public.role_permissions(role,action) VALUES($1,$2)")
            .bind(name)
            .bind(action)
            .execute(&mut *connection)
            .await
            .map_err(|_| ControlError::Storage)?;
    }
    Ok(())
}
