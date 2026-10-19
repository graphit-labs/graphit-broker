use super::{
    MySqlControlError, RequiredCapability, Result, SchemaReason, UnprovenReason,
    capability::{self, Grants, Operation},
    config::identifier,
    executor::{Lease, native_error},
};
use broker_store::schema::{MysqlTableShape, TABLES};
use futures_util::TryStreamExt;
use sqlparser::tokenizer::Token;
use sqlx_core::{row::Row, sql_str::AssertSqlSafe};
use std::collections::{BTreeMap, BTreeSet};

struct DataRow(Vec<Option<String>>);
impl DataRow {
    fn value(&self, index: usize) -> Result<&str> {
        self.0
            .get(index)
            .and_then(Option::as_deref)
            .ok_or(MySqlControlError::Unproven(UnprovenReason::Visibility))
    }
    fn optional(&self, index: usize) -> Result<Option<&str>> {
        self.0
            .get(index)
            .map(Option::as_deref)
            .ok_or(MySqlControlError::Unproven(UnprovenReason::Visibility))
    }
}
struct Query {
    from: &'static str,
    fields: &'static [&'static str],
    schema: &'static str,
    table: &'static str,
    filter: &'static str,
    order: &'static str,
}
const TABLE_QUERY: Query = Query {
    from: "information_schema.TABLES t LEFT JOIN information_schema.COLLATIONS c ON c.COLLATION_NAME=t.TABLE_COLLATION",
    fields: &[
        "t.TABLE_NAME",
        "t.TABLE_TYPE",
        "t.ENGINE",
        "t.ROW_FORMAT",
        "t.TABLE_COLLATION",
        "c.CHARACTER_SET_NAME",
        "t.CREATE_OPTIONS",
    ],
    schema: "t.TABLE_SCHEMA",
    table: "t.TABLE_NAME",
    filter: "",
    order: "t.TABLE_NAME",
};
const COLUMN_QUERY: Query = Query {
    from: "information_schema.COLUMNS c",
    fields: &[
        "c.TABLE_NAME",
        "c.ORDINAL_POSITION",
        "c.COLUMN_NAME",
        "c.COLUMN_TYPE",
        "c.DATA_TYPE",
        "c.IS_NULLABLE",
        "c.COLUMN_DEFAULT",
        "c.CHARACTER_MAXIMUM_LENGTH",
        "c.CHARACTER_OCTET_LENGTH",
        "c.CHARACTER_SET_NAME",
        "c.COLLATION_NAME",
        "c.EXTRA",
        "c.GENERATION_EXPRESSION",
    ],
    schema: "c.TABLE_SCHEMA",
    table: "c.TABLE_NAME",
    filter: "",
    order: "c.TABLE_NAME,c.ORDINAL_POSITION",
};
const INDEX_QUERY: Query = Query {
    from: "information_schema.STATISTICS s",
    fields: &[
        "s.TABLE_NAME",
        "s.INDEX_NAME",
        "s.SEQ_IN_INDEX",
        "s.COLUMN_NAME",
        "s.NON_UNIQUE",
        "s.INDEX_TYPE",
        "s.IS_VISIBLE",
        "s.COLLATION",
        "s.SUB_PART",
        "s.EXPRESSION",
    ],
    schema: "s.TABLE_SCHEMA",
    table: "s.TABLE_NAME",
    filter: "",
    order: "s.TABLE_NAME,s.INDEX_NAME,s.SEQ_IN_INDEX",
};
const FOREIGN_QUERY: Query = Query {
    from: "information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME AND r.TABLE_NAME=k.TABLE_NAME",
    fields: &[
        "k.TABLE_NAME",
        "k.CONSTRAINT_NAME",
        "k.ORDINAL_POSITION",
        "k.COLUMN_NAME",
        "k.REFERENCED_TABLE_SCHEMA",
        "k.REFERENCED_TABLE_NAME",
        "k.REFERENCED_COLUMN_NAME",
        "r.DELETE_RULE",
        "r.UPDATE_RULE",
    ],
    schema: "k.TABLE_SCHEMA",
    table: "k.TABLE_NAME",
    filter: " AND k.REFERENCED_TABLE_NAME IS NOT NULL",
    order: "k.TABLE_NAME,k.CONSTRAINT_NAME,k.ORDINAL_POSITION",
};
const CHECK_QUERY: Query = Query {
    from: "information_schema.TABLE_CONSTRAINTS t JOIN information_schema.CHECK_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME",
    fields: &[
        "t.TABLE_NAME",
        "t.CONSTRAINT_NAME",
        "t.ENFORCED",
        "c.CHECK_CLAUSE",
    ],
    schema: "t.TABLE_SCHEMA",
    table: "t.TABLE_NAME",
    filter: " AND t.CONSTRAINT_TYPE='CHECK'",
    order: "t.TABLE_NAME,t.CONSTRAINT_NAME",
};
const PARTITION_QUERY: Query = Query {
    from: "information_schema.PARTITIONS p",
    fields: &[
        "p.TABLE_NAME",
        "p.PARTITION_NAME",
        "p.PARTITION_METHOD",
        "p.SUBPARTITION_NAME",
        "p.SUBPARTITION_METHOD",
    ],
    schema: "p.TABLE_SCHEMA",
    table: "p.TABLE_NAME",
    filter: "",
    order: "p.TABLE_NAME,p.PARTITION_ORDINAL_POSITION,p.SUBPARTITION_ORDINAL_POSITION",
};
const TRIGGER_QUERY: Query = Query {
    from: "information_schema.TRIGGERS t",
    fields: &["t.EVENT_OBJECT_TABLE", "t.TRIGGER_NAME"],
    schema: "t.TRIGGER_SCHEMA",
    table: "t.EVENT_OBJECT_TABLE",
    filter: "",
    order: "t.EVENT_OBJECT_TABLE,t.TRIGGER_NAME",
};
const EXTENSION_QUERY: Query = Query {
    from: "information_schema.TABLES_EXTENSIONS t",
    fields: &[
        "t.TABLE_NAME",
        "t.ENGINE_ATTRIBUTE",
        "t.SECONDARY_ENGINE_ATTRIBUTE",
    ],
    schema: "t.TABLE_SCHEMA",
    table: "t.TABLE_NAME",
    filter: "",
    order: "t.TABLE_NAME",
};

/// All identifiers/expressions are internal constants or the immutable producer.
/// CASE bounds logical metadata before owned decoding; SQLx receive buffers are
/// deliberately outside this allocation contract.
async fn capture(lease: &mut Lease, query: &Query, owned: bool) -> Result<Vec<DataRow>> {
    let cap = lease.work.limits.cell_bytes.get();
    let row_cap = lease.work.limits.rows_per_category.get();
    let projection = query.fields.iter().map(|field| format!(
        "CASE WHEN OCTET_LENGTH(CAST({field} AS CHAR))<={cap} THEN CAST({field} AS CHAR) ELSE NULL END,CAST(OCTET_LENGTH(CAST({field} AS CHAR)) AS UNSIGNED)"
    )).collect::<Vec<_>>().join(",");
    let names = if owned {
        let names = TABLES
            .iter()
            .map(|table| format!("'{}'", table.name()))
            .collect::<Vec<_>>()
            .join(",");
        format!(" AND {} IN ({names})", query.table)
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT {projection} FROM {} WHERE {}=?{names}{} ORDER BY {} LIMIT {}",
        query.from,
        query.schema,
        query.filter,
        query.order,
        row_cap
            .checked_add(1)
            .ok_or(MySqlControlError::Configuration)?
    );
    lease.work.statement(&sql)?;
    let mut stream = sqlx_core::query::query(AssertSqlSafe(sql))
        .bind(&lease.observation.database)
        .fetch(&mut lease.connection);
    let mut rows = Vec::new();
    while let Some(row) = stream
        .try_next()
        .await
        .map_err(|error| native_error(&error, RequiredCapability::Select))?
    {
        if rows.len() >= row_cap {
            return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
        }
        let mut values = Vec::with_capacity(query.fields.len());
        for index in 0..query.fields.len() {
            let length: Option<u64> = row
                .try_get(index * 2 + 1)
                .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
            if length.is_some_and(|length| length > cap as u64) {
                return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
            }
            let value = lease.work.text(&row, index * 2, cap)?;
            if value.as_ref().map(|s| s.len() as u64) != length {
                return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
            }
            values.push(value);
        }
        rows.push(DataRow(values));
    }
    Ok(rows)
}
struct InboundForeignKey {
    id: String,
    child: String,
    parent: String,
    columns: u64,
    kind: u64,
}
fn inbound_actions(kind: u64) -> Result<(&'static str, &'static str)> {
    // Validate the complete native TYPE before interpreting its closed flags.
    // Unknown bits or two mutually exclusive rules are never masked away.
    if !matches!(
        kind,
        0 | 1 | 2 | 4 | 5 | 6 | 8 | 9 | 10 | 16 | 20 | 24 | 32 | 33 | 34 | 48
    ) {
        return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
    }
    let delete = match kind & 19 {
        0 => "RESTRICT",
        1 => "CASCADE",
        2 => "SET NULL",
        16 => "NO ACTION",
        _ => return Err(MySqlControlError::Unproven(UnprovenReason::Visibility)),
    };
    let update = match kind & 44 {
        0 => "RESTRICT",
        4 => "CASCADE",
        8 => "SET NULL",
        32 => "NO ACTION",
        _ => return Err(MySqlControlError::Unproven(UnprovenReason::Visibility)),
    };
    Ok((delete, update))
}
fn validate_inbound(rows: &[InboundForeignKey], parents: &[String]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for row in rows {
        if row.id.is_empty()
            || row.child.is_empty()
            || row.columns == 0
            || !parents.contains(&row.parent)
            || !ids.insert(row.id.as_str())
        {
            return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
        }
        inbound_actions(row.kind)?;
    }
    if rows.iter().any(|row| !parents.contains(&row.child)) {
        return rejected(SchemaReason::ForeignKeys);
    }
    Ok(())
}
async fn inbound_absent(lease: &mut Lease, grants: &Grants) -> Result<()> {
    grants.process()?;
    let cap = lease.work.limits.cell_bytes.get();
    let row_cap = lease.work.limits.rows_per_category.get();
    let mut parents = Vec::with_capacity(TABLES.len());
    for table in TABLES {
        let length = lease
            .observation
            .database
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(table.name().len()))
            .ok_or(MySqlControlError::Unproven(UnprovenReason::Truncated))?;
        if length > cap {
            return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
        }
        lease.work.bytes(length)?;
        parents.push(format!("{}/{}", lease.observation.database, table.name()));
    }
    let projection = ["ID", "FOR_NAME", "REF_NAME"].iter().map(|field| format!(
        "CASE WHEN OCTET_LENGTH({field})<={cap} THEN {field} ELSE NULL END,CAST(OCTET_LENGTH({field}) AS UNSIGNED)"
    )).collect::<Vec<_>>().join(",");
    let placeholders = vec!["?"; TABLES.len()].join(",");
    let limit = row_cap
        .checked_add(1)
        .ok_or(MySqlControlError::Unproven(UnprovenReason::Truncated))?;
    let sql = format!(
        "SELECT {projection},CAST(N_COLS AS UNSIGNED),CAST(TYPE AS UNSIGNED) FROM information_schema.INNODB_FOREIGN WHERE CAST(REF_NAME AS BINARY) IN ({placeholders}) ORDER BY CAST(ID AS BINARY) LIMIT {limit}"
    );
    lease.work.statement(&sql)?;
    let mut query = sqlx_core::query::query(AssertSqlSafe(sql));
    for parent in &parents {
        query = query.bind(parent.as_bytes());
    }
    let mut stream = query.fetch(&mut lease.connection);
    let mut rows = Vec::new();
    while let Some(row) = stream
        .try_next()
        .await
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?
    {
        if rows.len() >= row_cap {
            return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
        }
        // Verify original lengths before bounded owned string decoding.
        for index in 0..3 {
            let length: u64 = row
                .try_get(index * 2 + 1)
                .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
            if length > cap as u64 {
                return Err(MySqlControlError::Unproven(UnprovenReason::Truncated));
            }
            let value: Option<&str> = row
                .try_get(index * 2)
                .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
            if value.map(|value| value.len() as u64) != Some(length) {
                return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
            }
        }
        let columns: u64 = row
            .try_get(6)
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
        let kind: u64 = row
            .try_get(7)
            .map_err(|_| MySqlControlError::Unproven(UnprovenReason::Visibility))?;
        let mut text = |index| {
            lease
                .work
                .text(&row, index, cap)?
                .ok_or(MySqlControlError::Unproven(UnprovenReason::Visibility))
        };
        rows.push(InboundForeignKey {
            id: text(0)?,
            child: text(2)?,
            parent: text(4)?,
            columns,
            kind,
        });
    }
    // Completion precedes classification: cap overflow cannot masquerade as a
    // fully observed foreign schema, and KCU child visibility is irrelevant.
    validate_inbound(&rows, &parents)
}
pub(crate) async fn fresh(lease: &mut Lease, grants: &Grants) -> Result<bool> {
    inbound_absent(lease, grants).await?;
    let tables = capture(lease, &TABLE_QUERY, true).await?;
    if tables.len() == TABLES.len() {
        for table in TABLES {
            if tables
                .iter()
                .filter(|row| row.value(0).ok() == Some(table.name()))
                .count()
                != 1
            {
                return rejected(SchemaReason::Relations);
            }
        }
        return Ok(false);
    }
    grants.relations(&lease.observation.database)?;
    if !capture(lease, &TABLE_QUERY, false).await?.is_empty() {
        return rejected(SchemaReason::Relations);
    }
    Ok(true)
}
/// Called inside a transaction on its sole private physical connection.
pub(crate) async fn inspect(lease: &mut Lease, operation: Operation) -> Result<()> {
    let grants = Grants::read(lease).await?;
    grants.triggers(&lease.observation.database)?;
    capability::events_absent(lease).await?;
    let database = identifier(
        &lease.observation.database,
        lease.work.limits.statement_bytes.get(),
    )?;
    for table in TABLES {
        let name = identifier(table.name(), lease.work.limits.statement_bytes.get())?;
        let show = format!("SHOW CREATE TABLE {database}.{name}");
        lease.work.statement(&show)?;
        let row = sqlx_core::query::query(AssertSqlSafe(show))
            .fetch_one(&mut lease.connection)
            .await
            .map_err(|error| native_error(&error, RequiredCapability::Select))?;
        let ddl = lease
            .work
            .text(&row, 1, lease.work.limits.cell_bytes.get())?
            .ok_or(MySqlControlError::Unproven(UnprovenReason::Visibility))?;
        if ddl.starts_with("CREATE TEMPORARY TABLE ") {
            return rejected(SchemaReason::Temporary);
        }
        if !ddl.starts_with("CREATE TABLE ") {
            return rejected(SchemaReason::Table);
        }
        let columns = table
            .definition()
            .columns()
            .iter()
            .map(|column| identifier(column.name(), lease.work.limits.statement_bytes.get()))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        // Opens the real base object, checks every required column SELECT and
        // retains its metadata lock until this transaction ends.
        let sql = format!("SELECT {columns} FROM {database}.{name} LIMIT 0");
        lease.work.statement(&sql)?;
        sqlx_core::query::query(AssertSqlSafe(sql))
            .execute(&mut lease.connection)
            .await
            .map_err(|error| {
                if error
                    .as_database_error()
                    .and_then(|error| error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>())
                    .map(sqlx_mysql::MySqlDatabaseError::number)
                    == Some(1054)
                {
                    MySqlControlError::SchemaRejected(SchemaReason::Columns)
                } else {
                    native_error(&error, RequiredCapability::Select)
                }
            })?;
    }
    inbound_absent(lease, &grants).await?;
    let tables = capture(lease, &TABLE_QUERY, true).await?;
    let columns = capture(lease, &COLUMN_QUERY, true).await?;
    let indexes = capture(lease, &INDEX_QUERY, true).await?;
    let foreign = capture(lease, &FOREIGN_QUERY, true).await?;
    let checks = capture(lease, &CHECK_QUERY, true).await?;
    let partitions = capture(lease, &PARTITION_QUERY, true).await?;
    let triggers = capture(lease, &TRIGGER_QUERY, true).await?;
    let extensions = capture(lease, &EXTENSION_QUERY, true).await?;
    if !triggers.is_empty() {
        return rejected(SchemaReason::Trigger);
    }
    if tables.len() != TABLES.len() || extensions.len() != TABLES.len() {
        return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
    }
    // A partitioned table contributes multiple native rows. Missing required
    // tables remain unproven before any partition classification.
    for table in TABLES {
        if for_table(&partitions, table.name())?.is_empty() {
            return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
        }
    }
    for table in TABLES {
        let expected = table.mysql_shape();
        let rows = for_table(&tables, table.name())?;
        if rows.len() != 1 {
            return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
        }
        let actual = rows[0];
        if actual.value(1)? != "BASE TABLE"
            || actual.value(2)? != expected.engine()
            || !actual.value(3)?.eq_ignore_ascii_case(expected.row_format())
            || actual.value(4)? != expected.collation()
            || actual.value(5)? != expected.character_set()
        {
            return rejected(SchemaReason::Table);
        }
        storage_options(actual.value(6)?, lease.work.limits.grant_tokens.get())?;
        compare_columns(&expected, for_table(&columns, table.name())?)?;
        compare_indexes(&expected, for_table(&indexes, table.name())?)?;
        compare_foreign(
            &expected,
            &lease.observation.database,
            for_table(&foreign, table.name())?,
        )?;
        compare_checks(&expected, for_table(&checks, table.name())?)?;
        let rows = for_table(&partitions, table.name())?;
        if rows.len() != 1 {
            return rejected(SchemaReason::Partition);
        }
        for index in 1..=4 {
            if rows[0].optional(index)?.is_some() {
                return rejected(SchemaReason::Partition);
            }
        }
        let rows = for_table(&extensions, table.name())?;
        if rows.len() != 1 {
            return Err(MySqlControlError::Unproven(UnprovenReason::Visibility));
        }
        for index in [1, 2] {
            storage_extension(rows[0].optional(index)?)?;
        }
    }
    capability::explain(lease, operation).await?;
    lease.unchanged().await
}

fn storage_extension(value: Option<&str>) -> Result<()> {
    if let Some(value) = value
        && !serde_json::from_str::<serde_json::Value>(value)
            .ok()
            .is_some_and(|v| v.as_object().is_some_and(|map| map.is_empty()))
    {
        return Err(MySqlControlError::Unproven(UnprovenReason::StorageOptions));
    }
    Ok(())
}
fn for_table<'a>(rows: &'a [DataRow], table: &str) -> Result<Vec<&'a DataRow>> {
    let mut selected = Vec::new();
    for row in rows {
        if row.value(0)? == table {
            selected.push(row);
        }
    }
    Ok(selected)
}
fn compare_columns(expected: &MysqlTableShape, actual: Vec<&DataRow>) -> Result<()> {
    if actual.len() != expected.columns().len() {
        return rejected(SchemaReason::Columns);
    }
    for (column, row) in expected.columns().iter().zip(actual) {
        if row.value(1)? != column.ordinal().to_string()
            || row.value(2)? != column.name()
            || row.value(3)? != column.full_type()
            || row.value(4)? != column.data_type()
            || row.value(5)? != if column.nullable() { "YES" } else { "NO" }
            || row.optional(6)? != column.column_default()
            || row.optional(7)?
                != column
                    .character_maximum_length()
                    .map(|v| v.to_string())
                    .as_deref()
            || row.optional(8)?
                != column
                    .character_octet_length()
                    .map(|v| v.to_string())
                    .as_deref()
            || row.optional(9)? != column.character_set()
            || row.optional(10)? != column.collation()
            || row.value(11)? != column.extra()
            || row.value(12)? != column.generation_expression()
        {
            return rejected(SchemaReason::Columns);
        }
    }
    Ok(())
}
fn compare_indexes(expected: &MysqlTableShape, actual: Vec<&DataRow>) -> Result<()> {
    let mut groups: BTreeMap<&str, Vec<&DataRow>> = BTreeMap::new();
    for row in actual {
        groups.entry(row.value(1)?).or_default().push(row);
    }
    if groups.len() != expected.indexes().len() {
        return rejected(SchemaReason::Indexes);
    }
    let mut unmatched: Vec<_> = expected.indexes().iter().collect();
    for (name, parts) in groups {
        if name.is_empty() {
            return rejected(SchemaReason::Indexes);
        }
        for (index, row) in parts.iter().enumerate() {
            if row.value(2)? != (index + 1).to_string()
                || row.value(5)? != "BTREE"
                || row.value(6)? != "YES"
                || row.value(7)? != "A"
                || row.optional(8)?.is_some()
                || row.optional(9)?.is_some()
                || !["0", "1"].contains(&row.value(4)?)
            {
                return rejected(SchemaReason::Indexes);
            }
        }
        let columns = parts
            .iter()
            .map(|row| row.value(3))
            .collect::<Result<Vec<_>>>()?;
        let unique = parts[0].value(4)? == "0";
        if parts
            .iter()
            .any(|row| row.value(4).ok() != Some(if unique { "0" } else { "1" }))
        {
            return rejected(SchemaReason::Indexes);
        }
        let matched = unmatched.iter().position(|index| {
            index.primary() == (name == "PRIMARY")
                && index.unique() == unique
                && index.columns() == columns
        });
        let Some(matched) = matched else {
            return rejected(SchemaReason::Indexes);
        };
        unmatched.remove(matched);
    }
    Ok(())
}
fn compare_foreign(
    expected: &MysqlTableShape,
    database: &str,
    actual: Vec<&DataRow>,
) -> Result<()> {
    if actual.len() != expected.foreign_keys().len() {
        return rejected(SchemaReason::ForeignKeys);
    }
    let mut names = std::collections::BTreeSet::new();
    let mut unmatched: Vec<_> = expected.foreign_keys().iter().collect();
    for row in actual {
        if row.value(1)?.is_empty()
            || !names.insert(row.value(1)?)
            || row.value(2)? != "1"
            || row.value(4)? != database
        {
            return rejected(SchemaReason::ForeignKeys);
        }
        let column = row.value(3)?;
        let target = row.value(5)?;
        let target_column = row.value(6)?;
        let delete = row.value(7)?;
        let update = row.value(8)?;
        let matched = unmatched.iter().position(|key| {
            key.column() == column
                && key.target_table() == target
                && key.target_column() == target_column
                && key.delete_action() == delete
                && (key.update_action() == update
                    || (key.update_action() == "RESTRICT" && update == "NO ACTION"))
        });
        let Some(matched) = matched else {
            return rejected(SchemaReason::ForeignKeys);
        };
        unmatched.remove(matched);
    }
    Ok(())
}
fn compare_checks(expected: &MysqlTableShape, actual: Vec<&DataRow>) -> Result<()> {
    if actual.len() != expected.checks().len() {
        return rejected(SchemaReason::Checks);
    }
    let mut names = std::collections::BTreeSet::new();
    let mut unmatched: Vec<_> = expected
        .checks()
        .iter()
        .map(|check| check.native_clause())
        .collect();
    for row in actual {
        if row.value(1)?.is_empty() || !names.insert(row.value(1)?) || row.value(2)? != "YES" {
            return rejected(SchemaReason::Checks);
        }
        let clause = row.value(3)?;
        let matched = unmatched.iter().position(|value| value == clause);
        let Some(matched) = matched else {
            return rejected(SchemaReason::Checks);
        };
        unmatched.remove(matched);
    }
    Ok(())
}
fn rejected<T>(reason: SchemaReason) -> Result<T> {
    Err(MySqlControlError::SchemaRejected(reason))
}

/// Only the native 8.4.11 CREATE_OPTIONS renderer vocabulary is accepted. The
/// effective engine/format is checked separately. An absent encryption field
/// says nothing about encryption and never requests an ALTER or default.
fn storage_options(value: &str, maximum: usize) -> Result<()> {
    let tokens = capability::tokens(value, maximum)
        .map_err(|_| MySqlControlError::Unproven(UnprovenReason::StorageOptions))?;
    let mut index = 0;
    let mut seen = std::collections::BTreeSet::new();
    while index < tokens.len() {
        let key = match &tokens[index] {
            Token::Word(word) if word.quote_style.is_none() => word.value.as_str(),
            _ => return options_unknown(),
        };
        if !seen.insert(key) {
            return options_unknown();
        }
        index += 1;
        if key == "partitioned" {
            return rejected(SchemaReason::Partition);
        }
        if matches!(key, "SECONDARY_ENGINE" | "SECONDARY_LOAD") {
            return Err(MySqlControlError::Unproven(
                UnprovenReason::SecondaryExecution,
            ));
        }
        if tokens.get(index) != Some(&Token::Eq) {
            return options_unknown();
        }
        index += 1;
        let Some(token) = tokens.get(index) else {
            return if key == "row_format" {
                Ok(())
            } else {
                options_unknown()
            };
        };
        if key == "row_format"
            && matches!(token,Token::Word(w) if w.quote_style.is_none())
            && tokens.get(index + 1) == Some(&Token::Eq)
        {
            // The native renderer spells requested DEFAULT as an empty value;
            // a subsequent assignment belongs to the next option.
            continue;
        }
        let valid = match key {
            "max_rows" | "min_rows" | "avg_row_length" | "stats_sample_pages"
            | "KEY_BLOCK_SIZE" => {
                matches!(token,Token::Number(v,false) if v.parse::<u32>().ok().is_some_and(|v| v>0))
            }
            "stats_auto_recalc" | "stats_persistent" | "pack_keys" => {
                matches!(token,Token::Number(v,false) if v=="0" || v=="1")
            }
            "checksum" | "delay_key_write" => matches!(token,Token::Number(v,false) if v=="1"),
            "row_format" => {
                matches!(token,Token::Word(w) if w.quote_style.is_none() && ["FIXED","DYNAMIC","COMPRESSED","REDUNDANT","COMPACT"].contains(&w.value.as_str()))
            }
            "COMPRESSION" => {
                matches!(token,Token::DoubleQuotedString(v) if ["","none","zlib","lz4"].contains(&v.as_str()))
            }
            "ENCRYPTION" => matches!(token,Token::SingleQuotedString(v) if v=="Y" || v=="N"),
            _ => false,
        };
        if !valid {
            return options_unknown();
        }
        index += 1;
    }
    Ok(())
}
fn options_unknown<T>() -> Result<T> {
    Err(MySqlControlError::Unproven(UnprovenReason::StorageOptions))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn storage_extensions_require_absence_or_an_empty_json_object() {
        for value in [None, Some("{}"), Some(" { } ")] {
            assert_eq!(storage_extension(value), Ok(()));
        }
        for value in [
            "{\"unknown\":1}",
            "{\"secondary\":{}}",
            "[]",
            "null",
            "1",
            "\"\"",
            "",
            "{",
        ] {
            assert_eq!(
                storage_extension(Some(value)),
                Err(MySqlControlError::Unproven(UnprovenReason::StorageOptions))
            );
        }
    }
    #[test]
    fn storage_options_preserve_native_hints_and_reject_unknown_authority() {
        for value in [
            "",
            "row_format=DYNAMIC",
            "row_format=",
            "row_format= stats_persistent=1",
            "max_rows=4294967295 min_rows=1 avg_row_length=9 stats_sample_pages=4 stats_auto_recalc=0 stats_persistent=1 pack_keys=0 KEY_BLOCK_SIZE=8 checksum=1 delay_key_write=1",
            "COMPRESSION=\"zlib\" ENCRYPTION='Y'",
            "COMPRESSION=\"lz4\" ENCRYPTION='N'",
        ] {
            assert_eq!(storage_options(value, 256), Ok(()));
        }
        for value in [
            "max_rows=0",
            "max_rows=4294967296",
            "row_format=?",
            "row_format=DYNAMIC row_format=DYNAMIC",
            "ENCRYPTION='n'",
            "COMPRESSION=\"truncat\"",
            "ENGINE_ATTRIBUTE='{}'",
            "stats_persistent=2",
        ] {
            assert!(storage_options(value, 256).is_err());
        }
        assert_eq!(
            storage_options("partitioned", 256),
            Err(MySqlControlError::SchemaRejected(SchemaReason::Partition))
        );
        assert_eq!(
            storage_options("SECONDARY_ENGINE=\"RAPID\"", 256),
            Err(MySqlControlError::Unproven(
                UnprovenReason::SecondaryExecution
            ))
        );
    }
    #[test]
    fn inbound_type_checks_the_whole_native_word() {
        let deletes = [
            (0, "RESTRICT"),
            (1, "CASCADE"),
            (2, "SET NULL"),
            (16, "NO ACTION"),
        ];
        let updates = [
            (0, "RESTRICT"),
            (4, "CASCADE"),
            (8, "SET NULL"),
            (32, "NO ACTION"),
        ];
        for (delete_bit, delete) in deletes {
            for (update_bit, update) in updates {
                assert_eq!(
                    inbound_actions(delete_bit + update_bit),
                    Ok((delete, update))
                );
            }
        }
        assert_eq!(inbound_actions(33), Ok(("CASCADE", "NO ACTION")));
        assert_eq!(inbound_actions(32), Ok(("RESTRICT", "NO ACTION")));
        for unknown in [3, 12, 17, 18, 36, 40, 63, 64, 97, u64::MAX] {
            assert_eq!(
                inbound_actions(unknown),
                Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
            );
        }
    }
    #[test]
    fn inbound_membership_is_exact_and_bad_evidence_precedes_classification() {
        let parents = TABLES
            .iter()
            .map(|t| format!("broker/{}", t.name()))
            .collect::<Vec<_>>();
        let row = |child: &str, id: &str, kind| InboundForeignKey {
            id: id.into(),
            child: child.into(),
            parent: "broker/roles".into(),
            columns: 1,
            kind,
        };
        assert_eq!(
            validate_inbound(
                &[row("broker/role_permissions", "broker/internal", 48)],
                &parents
            ),
            Ok(())
        );
        for child in [
            "other/role_permissions",
            "broker/external",
            "Broker/roles",
            "broker/roles/extra",
        ] {
            assert_eq!(
                validate_inbound(&[row(child, "external/key", 32)], &parents),
                Err(MySqlControlError::SchemaRejected(SchemaReason::ForeignKeys))
            );
        }
        assert_eq!(
            validate_inbound(&[row("other/child", "", 33)], &parents),
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        );
        assert_eq!(
            validate_inbound(&[row("other/child", "other/key", 97)], &parents),
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        );
        assert_eq!(
            validate_inbound(
                &[
                    row("broker/roles", "broker/same", 32),
                    row("broker/roles", "broker/same", 32)
                ],
                &parents
            ),
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        );
        let mut invalid = row("other/child", "other/key", 33);
        invalid.columns = 0;
        assert_eq!(
            validate_inbound(&[invalid], &parents),
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        );
        let mut invalid = row("broker/roles", "broker/key", 32);
        invalid.parent = "other/roles".into();
        assert_eq!(
            validate_inbound(&[invalid], &parents),
            Err(MySqlControlError::Unproven(UnprovenReason::Visibility))
        );
    }
}
