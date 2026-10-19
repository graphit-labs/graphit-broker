use super::{Result, SqliteControlError, executor::Work};
use crate::flow::now_micros;
use broker_store::{
    schema::{Dialect, SchemaVersion, TABLES},
    seeds::InitialSeeds,
    time::TimestampMicros,
};
use rusqlite::{Connection, TransactionBehavior};

#[derive(Debug, Eq, PartialEq)]
struct Shape {
    kind: String,
    name: String,
    table: String,
    sql: Option<String>,
}
fn inventory(
    connection: &Connection,
    expected_count: usize,
    sql_bytes: usize,
) -> Result<Vec<Shape>> {
    let mut statement = connection.prepare("SELECT CASE WHEN length(CAST(type AS BLOB))<=16 THEN type END,CASE WHEN length(CAST(name AS BLOB))<=256 THEN name END,CASE WHEN length(CAST(tbl_name AS BLOB))<=256 THEN tbl_name END,CASE WHEN sql IS NULL OR length(CAST(sql AS BLOB))<=?1 THEN sql END,sql IS NULL OR length(CAST(sql AS BLOB))<=?1 FROM sqlite_schema ORDER BY type,name LIMIT ?2")
        .map_err(|_| SqliteControlError::SchemaRejected)?;
    let mut rows = statement
        .query(rusqlite::params![
            sql_bytes as i64,
            (expected_count + 1) as i64
        ])
        .map_err(|_| SqliteControlError::SchemaRejected)?;
    let mut values = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| SqliteControlError::SchemaRejected)?
    {
        if !row
            .get::<_, bool>(4)
            .map_err(|_| SqliteControlError::SchemaRejected)?
        {
            return Err(SqliteControlError::SchemaRejected);
        }
        values.push(Shape {
            kind: row.get(0).map_err(|_| SqliteControlError::SchemaRejected)?,
            name: row.get(1).map_err(|_| SqliteControlError::SchemaRejected)?,
            table: row.get(2).map_err(|_| SqliteControlError::SchemaRejected)?,
            sql: row.get(3).map_err(|_| SqliteControlError::SchemaRejected)?,
        });
    }
    Ok(values)
}
fn expected() -> Result<(Vec<Shape>, usize)> {
    let connection = Connection::open_in_memory().map_err(|_| SqliteControlError::Storage)?;
    let mut max_sql = 0;
    for table in TABLES {
        let ddl = table.create_statement(Dialect::Sqlite);
        max_sql = max_sql.max(ddl.len());
        connection
            .execute_batch(&ddl)
            .map_err(|_| SqliteControlError::Storage)?;
    }
    // UNIQUE constraints also create implicit indexes. Derive the complete
    // catalog count from the engine instead of assuming one index per table.
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| row.get(0))
        .map_err(|_| SqliteControlError::Storage)?;
    let inventory = inventory(
        &connection,
        usize::try_from(count).map_err(|_| SqliteControlError::Storage)?,
        max_sql,
    )?;
    Ok((inventory, max_sql))
}
pub(crate) fn initialize(connection: &mut Connection, work: &Work) -> Result<()> {
    let (expected, max_sql) = expected()?;
    work.check()?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| work.sql(error))?;
    work.check()?;
    let actual = inventory(&tx, expected.len(), max_sql)?;
    let fresh = actual.is_empty();
    if fresh {
        for table in TABLES {
            work.check()?;
            tx.execute_batch(&table.create_statement(Dialect::Sqlite))
                .map_err(|error| work.sql(error))?;
        }
    } else {
        if actual != expected {
            return Err(SqliteControlError::SchemaRejected);
        }
        let (format, epoch): (String, i64) = tx.query_row("SELECT CASE WHEN length(CAST(format AS BLOB))<=64 THEN format END,epoch FROM schema_meta WHERE id=1", [], |row| Ok((row.get(0)?,row.get(1)?))).map_err(|_| SqliteControlError::SchemaRejected)?;
        SchemaVersion::validate(&format, epoch).map_err(|_| SqliteControlError::SchemaRejected)?;
        let one: bool = tx
            .query_row(
                "SELECT COUNT(*)=1 AND MAX(id)=1 FROM schema_meta",
                [],
                |row| row.get(0),
            )
            .map_err(|_| SqliteControlError::SchemaRejected)?;
        if !one {
            return Err(SqliteControlError::SchemaRejected);
        }
    }
    if inventory(&tx, expected.len(), max_sql)? != expected {
        return Err(SqliteControlError::SchemaRejected);
    }
    let violations = tx
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()
        .map_err(|_| SqliteControlError::SchemaRejected)?;
    if violations.is_some() {
        return Err(SqliteControlError::SchemaRejected);
    }
    let now = now_micros().map_err(|_| SqliteControlError::Clock)?;
    let seeds =
        InitialSeeds::new(TimestampMicros::new(now).map_err(|_| SqliteControlError::Clock)?);
    for role in seeds.roles() {
        tx.execute(
            "INSERT INTO roles(name,created_at) VALUES(?1,?2) ON CONFLICT(name) DO NOTHING",
            rusqlite::params![role.name(), now],
        )
        .map_err(|error| work.sql(error))?;
        tx.execute("DELETE FROM role_permissions WHERE role=?1", [role.name()])
            .map_err(|error| work.sql(error))?;
        for action in role.actions() {
            tx.execute(
                "INSERT INTO role_permissions(role,action) VALUES(?1,?2)",
                rusqlite::params![role.name(), action.as_str()],
            )
            .map_err(|error| work.sql(error))?;
        }
    }
    tx.execute("INSERT INTO resource_acl_state(id,revision,updated_at) VALUES(1,?1,?2) ON CONFLICT(id) DO NOTHING", rusqlite::params![seeds.acl_revision(),now]).map_err(|error| work.sql(error))?;
    if fresh {
        tx.execute(
            "INSERT INTO schema_meta(id,format,epoch) VALUES(1,?1,?2)",
            rusqlite::params![SchemaVersion::FORMAT, SchemaVersion::EPOCH],
        )
        .map_err(|error| work.sql(error))?;
    }
    work.commit(tx)
}
use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sqlite_exact_catalog_projection_uses_the_real_engine() {
        let (expected, cap) = expected().expect("expected producer catalog");
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        connection
            .pragma_update(None, "trusted_schema", "OFF")
            .unwrap();
        assert!(
            inventory(&connection, expected.len(), cap)
                .expect("empty catalog")
                .is_empty()
        );
        for table in TABLES {
            connection
                .execute_batch(&table.create_statement(Dialect::Sqlite))
                .unwrap();
        }
        assert_eq!(
            inventory(&connection, expected.len(), cap).expect("fresh catalog"),
            expected
        );
        let mut check = connection.prepare("PRAGMA foreign_key_check").unwrap();
        assert!(check.query([]).unwrap().next().unwrap().is_none());
    }
}
