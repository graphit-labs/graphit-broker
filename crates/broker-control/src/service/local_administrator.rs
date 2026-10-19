use super::{
    ConnectionGuard, PostgresControlStore, admin_rbac::lock_admin, bounded_deadline, storage_error,
    timeout_error,
};
use crate::{
    ControlError, LocalAdministratorBootstrapError as Error, flow::now_micros,
    local_administrator::validate_hash,
};
use sqlx_core::connection::Connection;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

impl PostgresControlStore {
    /// Create the fixed first LOCAL administrator with a genuine prepared PHC.
    /// Any existing LOCAL user prevents creation. No session or token is issued.
    pub async fn bootstrap_local_administrator(
        &self,
        password_hash: &str,
        original: Instant,
    ) -> Result<(), Error> {
        validate_hash(password_hash)?;
        let end = bounded_deadline(original, self.budgets.operation_timeout)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            // Serialize with every participating administrative user writer.
            lock_admin(&mut tx).await?;
            let exists: bool = sqlx_core::query_scalar::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM public.local_users)",
            )
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            if exists {
                tx.rollback().await.map_err(storage_error)?;
                guard.confirmed();
                return Err(Error::AlreadyInitialized);
            }
            let now = now_micros()?;
            sqlx_core::query::query(
                "INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('admin','admin','human',$1,'','','','[]',1,1,1,$2,$2)",
            )
            .bind(password_hash)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            sqlx_core::query::query(
                "INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|admin','admin',$1) ON CONFLICT(subject,role) DO NOTHING",
            )
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
            if Instant::now() >= end {
                return Err(ControlError::Deadline.into());
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            // A known COMMIT is not converted to a failure by a later clock read.
            Ok(())
        })
        .await
        .unwrap_or_else(|_| Err(timeout_error(&commit_started).into()))
    }
}
