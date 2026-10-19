use super::SqliteControlStore;
use crate::{
    ControlError, InstanceInventory, InstanceOwner, InstanceRegistryError as Error,
    RegistrationChange, RegistrationResult,
    instance_registry::{canonical_project_id, canonical_version, valid_owner_value},
    sqlite::executor::{State, Work},
};
use broker_store::time::TimestampMicros;
use rusqlite::params;
use std::time::Instant;

struct OwnedInventory {
    instance: String,
    issuer: String,
    subject: String,
    projects: Vec<(String, Vec<String>)>,
}

impl SqliteControlStore {
    /// Replace installation data after authentication and authorization of every project.
    ///
    /// Owner data grants no authority. An uncertain outcome must not be replayed
    /// automatically; reconcile current state through an authorized consumer.
    pub async fn replace_instance_inventory(
        &self,
        owner: &InstanceOwner,
        inventory: &InstanceInventory,
        caller: Instant,
    ) -> Result<RegistrationResult, Error> {
        let end = self.executor.deadline(caller).map_err(ControlError::from)?;
        let owned = OwnedInventory {
            instance: inventory.instance_id().to_owned(),
            issuer: owner.issuer().to_owned(),
            subject: owner.subject().to_owned(),
            projects: inventory
                .projects()
                .iter()
                .map(|p| (p.project_id().to_owned(), p.versions().to_vec()))
                .collect(),
        };
        self.executor
            .execute(end, move |state, work| Ok(replace(state, work, owned)))
            .await
            .map_err(ControlError::from)?
    }
}

fn checked<T>(value: super::Result<T>) -> Result<T, Error> {
    value.map_err(ControlError::from).map_err(Into::into)
}

fn replace(
    state: &mut State,
    work: &Work,
    input: OwnedInventory,
) -> Result<RegistrationResult, Error> {
    let tx = checked(state.begin(work))?;
    let stamp = checked(super::clock())?;
    let sql = |e| Error::Control(ControlError::from(work.sql(e)));
    let inserted = tx.execute(
        "INSERT INTO broker_instances(instance_id,owner_issuer,owner_subject,created_at,updated_at) VALUES(?1,?2,?3,?4,?4) ON CONFLICT(instance_id) DO NOTHING",
        params![input.instance, input.issuer, input.subject, stamp],
    ).map_err(sql)?;
    if inserted > 1 {
        return Err(ControlError::Storage.into());
    }
    let created = inserted == 1;
    // These byte bounds follow the maximum UTF-8 size of valid character-bounded
    // owners; they also reject a large suffix hidden by SQLite length at NUL.
    let (issuer, subject, created_at, mut updated_at) = tx.query_row(
        "SELECT CASE WHEN length(CAST(owner_issuer AS BLOB))<=4096 THEN owner_issuer END,CASE WHEN length(CAST(owner_subject AS BLOB))<=2048 THEN owner_subject END,created_at,updated_at FROM broker_instances WHERE instance_id=?1",
        [&input.instance],
        |row| Ok((|| -> Result<_, Error> {
            Ok((
                row.get::<_, String>(0).map_err(|_| Error::MalformedStored)?,
                row.get::<_, String>(1).map_err(|_| Error::MalformedStored)?,
                row.get::<_, i64>(2).map_err(|_| Error::MalformedStored)?,
                row.get::<_, i64>(3).map_err(|_| Error::MalformedStored)?,
            ))
        })()),
    ).map_err(sql)??;
    TimestampMicros::new(created_at).map_err(|_| Error::MalformedStored)?;
    TimestampMicros::new(updated_at).map_err(|_| Error::MalformedStored)?;
    if !valid_owner_value(&issuer, 1024) || !valid_owner_value(&subject, 512) {
        return Err(Error::MalformedStored);
    }
    if issuer != input.issuer || subject != input.subject {
        return Err(Error::OwnerConflict);
    }
    let (same, stored_count) = {
        let mut query = tx.prepare(
            "SELECT CASE WHEN length(CAST(project_id AS BLOB))<=26 THEN project_id END,position,version FROM broker_instance_project_versions WHERE instance_id=?1 ORDER BY project_id COLLATE BINARY,position"
        ).map_err(sql)?;
        let mut rows = query.query([&input.instance]).map_err(sql)?;
        let mut expected = input.projects.iter().flat_map(|(project, versions)| {
            versions
                .iter()
                .enumerate()
                .map(move |(index, version)| (project, index, version))
        });
        let mut same = true;
        let mut stored_count = 0_usize;
        let mut previous_project = String::new();
        let mut previous_position = 0_i64;
        let mut previous_version = String::new();
        while let Some(row) = rows.next().map_err(sql)? {
            checked(work.check())?;
            stored_count = stored_count.checked_add(1).ok_or(Error::MalformedStored)?;
            let project: String = row.get(0).map_err(|_| Error::MalformedStored)?;
            let position: i64 = row.get(1).map_err(|_| Error::MalformedStored)?;
            let version: String = row.get(2).map_err(|_| Error::MalformedStored)?;
            if !canonical_project_id(&project) || !canonical_version(&version) {
                return Err(Error::MalformedStored);
            }
            if project != previous_project {
                if (!previous_project.is_empty() && project <= previous_project) || position != 1 {
                    return Err(Error::MalformedStored);
                }
            } else if previous_position.checked_add(1) != Some(position)
                || version <= previous_version
            {
                return Err(Error::MalformedStored);
            }
            same &= expected.next().is_some_and(|(p, index, v)| {
                p == &project
                    && v == &version
                    && i64::try_from(index).ok().and_then(|v| v.checked_add(1)) == Some(position)
            });
            previous_project = project;
            previous_position = position;
            previous_version = version;
        }
        (same && expected.next().is_none(), stored_count)
    };
    if !same {
        if tx
            .execute(
                "DELETE FROM broker_instance_project_versions WHERE instance_id=?1",
                [&input.instance],
            )
            .map_err(sql)?
            != stored_count
        {
            return Err(ControlError::Storage.into());
        }
        for (project, versions) in &input.projects {
            for (index, version) in versions.iter().enumerate() {
                checked(work.check())?;
                let position = i64::try_from(index)
                    .ok()
                    .and_then(|v| v.checked_add(1))
                    .ok_or(Error::InvalidInventory)?;
                if tx.execute(
                    "INSERT INTO broker_instance_project_versions(instance_id,project_id,position,version) VALUES(?1,?2,?3,?4)",
                    params![input.instance, project, position, version],
                ).map_err(sql)? != 1 {
                    return Err(ControlError::Storage.into());
                }
            }
        }
        if !created {
            updated_at = checked(super::clock())?;
            if tx
                .execute(
                    "UPDATE broker_instances SET updated_at=?2 WHERE instance_id=?1",
                    params![input.instance, updated_at],
                )
                .map_err(sql)?
                != 1
            {
                return Err(ControlError::Storage.into());
            }
        }
    }
    checked(work.commit(tx))?;
    Ok(RegistrationResult {
        change: if created {
            RegistrationChange::Created
        } else if same {
            RegistrationChange::Unchanged
        } else {
            RegistrationChange::Updated
        },
        instance_id: input.instance,
        created_at,
        updated_at,
    })
}
