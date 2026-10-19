use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    ControlError, InstanceInventory, InstanceOwner, InstanceRegistryError, RegistrationChange,
    RegistrationResult,
    flow::now_micros,
    instance_registry::{canonical_project_id, canonical_version, valid_owner_value},
    schema,
};
use broker_store::time::TimestampMicros;
use futures_util::TryStreamExt;
use sqlx_core::row::Row;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

fn persistence_error(_: sqlx_core::error::Error) -> InstanceRegistryError {
    ControlError::Storage.into()
}
impl PostgresControlStore {
    /// Replace durable inventory after server authentication and project authorization.
    ///
    /// Owner and inventory are data, not authority. The server must derive the literal
    /// owner from the verified principal and authorize all projects before calling.
    /// An uncertain transaction must not be replayed automatically.
    pub async fn replace_instance_inventory(
        &self,
        owner: &InstanceOwner,
        inventory: &InstanceInventory,
        deadline: Instant,
    ) -> Result<RegistrationResult, InstanceRegistryError> {
        let deadline = bounded_deadline(deadline, self.budgets.operation_timeout)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.pool.acquire().await.map_err(storage_error)?));
            let mut tx = schema::transaction(guard.connection()?).await?;
            let stamp = now_micros()?;
            let inserted = sqlx_core::query::query("INSERT INTO public.broker_instances(instance_id,owner_issuer,owner_subject,created_at,updated_at) VALUES($1,$2,$3,$4,$4) ON CONFLICT(instance_id) DO NOTHING")
                .bind(inventory.instance_id()).bind(owner.issuer()).bind(owner.subject()).bind(stamp)
                .execute(&mut *tx).await.map_err(persistence_error)?;
            let created = inserted.rows_affected() == 1;
            let parent = sqlx_core::query::query("SELECT owner_issuer,owner_subject,created_at,updated_at FROM public.broker_instances WHERE instance_id=$1 FOR UPDATE")
                .bind(inventory.instance_id()).fetch_one(&mut *tx).await.map_err(persistence_error)?;
            let issuer: String = parent.try_get("owner_issuer").map_err(|_| InstanceRegistryError::MalformedStored)?;
            let subject: String = parent.try_get("owner_subject").map_err(|_| InstanceRegistryError::MalformedStored)?;
            let created_at: i64 = parent.try_get("created_at").map_err(|_| InstanceRegistryError::MalformedStored)?;
            let mut updated_at: i64 = parent.try_get("updated_at").map_err(|_| InstanceRegistryError::MalformedStored)?;
            TimestampMicros::new(created_at).map_err(|_| InstanceRegistryError::MalformedStored)?;
            TimestampMicros::new(updated_at).map_err(|_| InstanceRegistryError::MalformedStored)?;
            if !valid_owner_value(&issuer, 1024) || !valid_owner_value(&subject, 512) {
                return Err(InstanceRegistryError::MalformedStored);
            }
            if issuer != owner.issuer() || subject != owner.subject() {
                return Err(InstanceRegistryError::OwnerConflict);
            }
            // Stream the current set: retain only one preceding version to validate order,
            // rather than collecting a second complete copy of the inventory.
            let (same, stored_count) = {
                let mut expected_project_index = 0;
                let mut expected_version_index = 0;
                let mut rows = sqlx_core::query::query("SELECT project_id,position,version FROM public.broker_instance_project_versions WHERE instance_id=$1 ORDER BY project_id COLLATE \"C\",position")
                    .bind(inventory.instance_id()).fetch(&mut *tx);
                let mut same = true;
                let mut stored_count = 0_u64;
                let mut previous_project = String::new();
                let mut previous_position = 0_i64;
                let mut previous_version = String::new();
                while let Some(row) = rows.try_next().await.map_err(persistence_error)? {
                    stored_count = stored_count.checked_add(1).ok_or(InstanceRegistryError::MalformedStored)?;
                    let project: String = row.try_get("project_id").map_err(|_| InstanceRegistryError::MalformedStored)?;
                    let position: i64 = row.try_get("position").map_err(|_| InstanceRegistryError::MalformedStored)?;
                    let version: String = row.try_get("version").map_err(|_| InstanceRegistryError::MalformedStored)?;
                    if !canonical_project_id(&project) || !canonical_version(&version) { return Err(InstanceRegistryError::MalformedStored); }
                    if project != previous_project {
                        if (!previous_project.is_empty() && project <= previous_project) || position != 1 {
                            return Err(InstanceRegistryError::MalformedStored);
                        }
                    } else if previous_position.checked_add(1) != Some(position) || version <= previous_version {
                        return Err(InstanceRegistryError::MalformedStored);
                    }
                    if let Some(expected_project) = inventory.projects().get(expected_project_index) {
                        if expected_project.project_id() != project
                            || i64::try_from(expected_version_index).ok().and_then(|v| v.checked_add(1)) != Some(position)
                            || expected_project.versions()[expected_version_index] != version {
                            same = false;
                        }
                        expected_version_index += 1;
                        if expected_version_index == expected_project.versions().len() {
                            expected_project_index += 1;
                            expected_version_index = 0;
                        }
                    } else {
                        same = false;
                    }
                    previous_project = project;
                    previous_position = position;
                    previous_version = version;
                }
                (same && expected_project_index == inventory.projects().len(), stored_count)
            };
            if !same {
                let deleted = sqlx_core::query::query("DELETE FROM public.broker_instance_project_versions WHERE instance_id=$1")
                    .bind(inventory.instance_id()).execute(&mut *tx).await.map_err(persistence_error)?;
                if deleted.rows_affected() != stored_count { return Err(ControlError::Storage.into()); }
                for project in inventory.projects() {
                    for (index, version) in project.versions().iter().enumerate() {
                        let position = i64::try_from(index).ok().and_then(|v| v.checked_add(1)).ok_or(InstanceRegistryError::InvalidInventory)?;
                        let inserted = sqlx_core::query::query("INSERT INTO public.broker_instance_project_versions(instance_id,project_id,position,version) VALUES($1,$2,$3,$4)")
                            .bind(inventory.instance_id()).bind(project.project_id()).bind(position).bind(version)
                            .execute(&mut *tx).await.map_err(persistence_error)?;
                        if inserted.rows_affected() != 1 { return Err(ControlError::Storage.into()); }
                    }
                }
                if !created {
                    updated_at = now_micros()?;
                    let updated = sqlx_core::query::query("UPDATE public.broker_instances SET updated_at=$2 WHERE instance_id=$1")
                        .bind(inventory.instance_id()).bind(updated_at).execute(&mut *tx).await.map_err(persistence_error)?;
                    if updated.rows_affected() != 1 { return Err(ControlError::Storage.into()); }
                }
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| InstanceRegistryError::Control(ControlError::OutcomeUncertain))?;
            guard.confirmed();
            Ok(RegistrationResult { change: if created { RegistrationChange::Created } else if same { RegistrationChange::Unchanged } else { RegistrationChange::Updated },
                instance_id: inventory.instance_id().to_owned(), created_at, updated_at })
        }).await.map_err(|_| InstanceRegistryError::Control(timeout_error(&commit_started)))?
    }
}
