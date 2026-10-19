use super::{SqliteControlStore, admin_rbac};
use crate::{
    AdminBrokerSessionError, AdminRbacError, ControlError,
    LocalAdministratorBootstrapError as Error, flow::now_micros,
    local_administrator::validate_hash,
};
use rusqlite::params;
use std::time::Instant;
use zeroize::Zeroizing;

impl SqliteControlStore {
    /// Create the fixed first LOCAL administrator in one physical transaction.
    /// Any existing LOCAL user prevents creation. No session or token is issued.
    pub async fn bootstrap_local_administrator(
        &self,
        password_hash: &str,
        original: Instant,
    ) -> Result<(), Error> {
        validate_hash(password_hash)?;
        let hash = Zeroizing::new(password_hash.to_owned());
        self.executor
            .execute(original, move |owner, work| {
                let tx = owner.begin(work)?;
                let outcome = (|| -> Result<(), Error> {
                    admin_rbac::parent(&tx, work).map_err(|error| match error {
                        AdminRbacError::Authorization(AdminBrokerSessionError::Control(error)) => {
                            Error::Control(error)
                        }
                        _ => Error::Control(ControlError::CorruptRbac),
                    })?;
                    let exists: bool = tx
                        .query_row("SELECT EXISTS(SELECT 1 FROM local_users)", [], |row| row.get(0))
                        .map_err(|error| ControlError::from(work.sql(error)))?;
                    if exists {
                        return Err(Error::AlreadyInitialized);
                    }
                    let now = now_micros()?;
                    tx.execute(
                        "INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('admin','admin','human',?1,'','','','[]',1,1,1,?2,?2)",
                        params![hash.as_str(), now],
                    )
                    .map_err(|error| ControlError::from(work.sql(error)))?;
                    tx.execute(
                        "INSERT INTO role_assignments(subject,role,created_at) VALUES('local|admin','admin',?1) ON CONFLICT(subject,role) DO NOTHING",
                        [now],
                    )
                    .map_err(|error| ControlError::from(work.sql(error)))?;
                    work.check().map_err(ControlError::from)?;
                    Ok(())
                })();
                match outcome {
                    Ok(()) => {
                        work.commit(tx)?;
                        Ok(Ok(()))
                    }
                    Err(error) => Ok(Err(error)),
                }
            })
            .await
            .map_err(ControlError::from)?
    }
}
