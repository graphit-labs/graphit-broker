use super::SqliteControlStore;
use crate::sqlite::executor::Work;
use crate::{ControlError, SystemPermission, flow::now_micros, service::role_values};
use rusqlite::{Transaction, params};
use std::time::Instant;

impl SqliteControlStore {
    /// Replace one SQL role definition after the caller authorizes the operation.
    /// Built-ins keep their official bundles; an uncertain commit must not be replayed.
    pub async fn set_role(
        &self,
        name: &str,
        permissions: &[SystemPermission],
        caller: Instant,
    ) -> Result<(), ControlError> {
        let (name, permissions) = role_values(name, permissions)?;
        let name = name.to_owned();
        self.executor
            .execute(caller, move |owner, work| {
                let tx = owner.begin(work)?;
                if let Err(error) = replace_role(&tx, work, &name, &permissions) {
                    return Ok(Err(error));
                }
                work.commit(tx)?;
                Ok(Ok(()))
            })
            .await
            .map_err(ControlError::from)?
    }
}

pub(super) fn replace_role(
    tx: &Transaction<'_>,
    work: &Work,
    name: &str,
    permissions: &[&str],
) -> Result<(), ControlError> {
    work.check().map_err(ControlError::from)?;
    let created = now_micros()?;
    tx.execute(
        "INSERT INTO roles(name,created_at) VALUES(?1,?2) ON CONFLICT(name) DO NOTHING",
        params![name, created],
    )
    .map_err(|e| ControlError::from(work.sql(e)))?;
    tx.execute("DELETE FROM role_permissions WHERE role=?1", [name])
        .map_err(|e| ControlError::from(work.sql(e)))?;
    for permission in permissions {
        work.check().map_err(ControlError::from)?;
        tx.execute(
            "INSERT INTO role_permissions(role,action) VALUES(?1,?2)",
            params![name, permission],
        )
        .map_err(|e| ControlError::from(work.sql(e)))?;
    }
    work.check().map_err(ControlError::from)?;
    Ok(())
}
