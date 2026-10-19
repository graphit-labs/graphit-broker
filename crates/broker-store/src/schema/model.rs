//! Readonly declarations for the Broker's fixed schema.
use super::{Dialect, Table};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColumnType {
    SmallInt,
    BigInt,
    Varchar(u16),
    Text,
    LargeText,
}
impl ColumnType {
    pub(super) fn sql(self, dialect: Dialect) -> String {
        match self {
            Self::SmallInt => "SMALLINT".into(),
            Self::BigInt => "BIGINT".into(),
            Self::Varchar(width) => format!("VARCHAR({width})"),
            Self::Text => "TEXT".into(),
            Self::LargeText if dialect == Dialect::Mysql => "LONGTEXT".into(),
            Self::LargeText => "TEXT".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColumnDefault {
    Absent,
    EmptyString,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckCondition {
    EqualOne,
    Positive,
}
impl CheckCondition {
    pub(super) fn sql(self, name: &str) -> String {
        match self {
            Self::EqualOne => format!("{name} = 1"),
            Self::Positive => format!("{name} > 0"),
        }
    }
}

/// Only the producer can construct a column. Getters describe schema, not authority.
///
/// ```compile_fail
/// use broker_store::schema::{ColumnDefinition, ColumnType};
/// let column = ColumnDefinition::new("external", ColumnType::Text, true);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnDefinition {
    name: &'static str,
    column_type: ColumnType,
    not_null: bool,
    unique: bool,
    default: ColumnDefault,
    check: Option<CheckCondition>,
}
impl ColumnDefinition {
    pub(super) const fn new(name: &'static str, column_type: ColumnType, not_null: bool) -> Self {
        Self {
            name,
            column_type,
            not_null,
            unique: false,
            default: ColumnDefault::Absent,
            check: None,
        }
    }
    pub(super) const fn with_unique(mut self) -> Self {
        self.unique = true;
        self
    }
    pub(super) const fn with_empty_default(mut self) -> Self {
        self.default = ColumnDefault::EmptyString;
        self
    }
    pub(super) const fn with_check(mut self, check: CheckCondition) -> Self {
        self.check = Some(check);
        self
    }
    pub const fn name(&self) -> &'static str {
        self.name
    }
    pub const fn column_type(&self) -> ColumnType {
        self.column_type
    }
    pub const fn declared_not_null(&self) -> bool {
        self.not_null
    }
    pub const fn unique(&self) -> bool {
        self.unique
    }
    pub const fn default(&self) -> ColumnDefault {
        self.default
    }
    pub const fn check(&self) -> Option<CheckCondition> {
        self.check
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimaryKeyDefinition {
    columns: &'static [&'static str],
    inline: bool,
}
impl PrimaryKeyDefinition {
    pub(super) const fn new(columns: &'static [&'static str], inline: bool) -> Self {
        Self { columns, inline }
    }
    pub const fn columns(&self) -> &'static [&'static str] {
        self.columns
    }
    pub const fn inline(&self) -> bool {
        self.inline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForeignKeyDefinition {
    column: &'static str,
    target: Table,
    target_column: &'static str,
}
impl ForeignKeyDefinition {
    pub(super) const fn new(
        column: &'static str,
        target: Table,
        target_column: &'static str,
    ) -> Self {
        Self {
            column,
            target,
            target_column,
        }
    }
    pub const fn column(&self) -> &'static str {
        self.column
    }
    pub const fn target(&self) -> Table {
        self.target
    }
    pub const fn target_column(&self) -> &'static str {
        self.target_column
    }
}

/// Fixed MySQL options owned by the canonical table declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MysqlTableOptions {
    engine: &'static str,
    row_format: &'static str,
    character_set: &'static str,
    collation: &'static str,
    max_character_bytes: u8,
}

const MYSQL_TABLE_OPTIONS: MysqlTableOptions = MysqlTableOptions {
    engine: "InnoDB",
    row_format: "Dynamic",
    character_set: "utf8mb4",
    collation: "utf8mb4_bin",
    max_character_bytes: 4,
};

impl MysqlTableOptions {
    pub(super) const fn engine(&self) -> &'static str {
        self.engine
    }
    pub(super) const fn row_format(&self) -> &'static str {
        self.row_format
    }
    pub(super) const fn character_set(&self) -> &'static str {
        self.character_set
    }
    pub(super) const fn collation(&self) -> &'static str {
        self.collation
    }
    pub(super) const fn max_character_bytes(&self) -> u8 {
        self.max_character_bytes
    }
}

/// Immutable canonical declaration, shared by all renderers and physical projections.
///
/// ```compile_fail
/// use broker_store::schema::Table;
/// Table::Roles.definition().columns = &[];
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableDefinition {
    name: &'static str,
    columns: &'static [ColumnDefinition],
    primary_key: PrimaryKeyDefinition,
    foreign_keys: &'static [ForeignKeyDefinition],
    mysql_options: MysqlTableOptions,
}
impl TableDefinition {
    pub(super) const fn new(
        name: &'static str,
        columns: &'static [ColumnDefinition],
        primary_key: PrimaryKeyDefinition,
        foreign_keys: &'static [ForeignKeyDefinition],
    ) -> Self {
        Self {
            name,
            columns,
            primary_key,
            foreign_keys,
            mysql_options: MYSQL_TABLE_OPTIONS,
        }
    }
    pub const fn name(&self) -> &'static str {
        self.name
    }
    pub const fn columns(&self) -> &'static [ColumnDefinition] {
        self.columns
    }
    pub const fn primary_key(&self) -> &PrimaryKeyDefinition {
        &self.primary_key
    }
    pub const fn foreign_keys(&self) -> &'static [ForeignKeyDefinition] {
        self.foreign_keys
    }
    pub(super) const fn mysql_options(&self) -> &MysqlTableOptions {
        &self.mysql_options
    }
    pub(super) fn render(&self, dialect: Dialect) -> String {
        let mut items = self
            .columns
            .iter()
            .map(|column| {
                let mut sql = format!("{} {}", column.name, column.column_type.sql(dialect));
                if column.not_null {
                    sql.push_str(" NOT NULL");
                }
                if self.primary_key.inline && self.primary_key.columns.contains(&column.name) {
                    sql.push_str(" PRIMARY KEY");
                }
                if column.unique {
                    sql.push_str(" UNIQUE");
                }
                if column.default == ColumnDefault::EmptyString {
                    sql.push_str(" DEFAULT ''");
                }
                if let Some(check) = column.check {
                    sql.push_str(&format!(" CHECK({})", check.sql(column.name)));
                }
                sql
            })
            .collect::<Vec<_>>();
        if !self.primary_key.inline {
            items.push(format!(
                "PRIMARY KEY({})",
                self.primary_key.columns.join(", ")
            ));
        }
        for key in self.foreign_keys {
            items.push(format!(
                "FOREIGN KEY({}) REFERENCES {}({}) ON DELETE CASCADE",
                key.column,
                key.target.name(),
                key.target_column
            ));
        }
        let mut sql = format!(
            "CREATE TABLE IF NOT EXISTS {} ({})",
            self.name,
            items.join(", ")
        );
        if dialect == Dialect::Mysql {
            let options = self.mysql_options();
            sql.push_str(&format!(
                " ENGINE={} ROW_FORMAT={} DEFAULT CHARSET={} COLLATE={}",
                options.engine(),
                options.row_format().to_ascii_uppercase(),
                options.character_set(),
                options.collation(),
            ));
        }
        sql
    }
}
