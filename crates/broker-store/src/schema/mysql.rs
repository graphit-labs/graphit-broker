//! Expected declared structure for MySQL 8.4.11. This is not captured or validated SQL state.
use super::model::MysqlTableOptions;
use super::{CheckCondition, ColumnDefault, ColumnDefinition, ColumnType, TableDefinition};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MysqlColumnShape {
    declaration: &'static ColumnDefinition,
    options: &'static MysqlTableOptions,
    ordinal: usize,
    nullable: bool,
}
impl MysqlColumnShape {
    pub fn name(&self) -> &'static str {
        self.declaration.name()
    }
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub fn column_type(&self) -> ColumnType {
        self.declaration.column_type()
    }
    pub fn full_type(&self) -> String {
        match self.column_type() {
            ColumnType::SmallInt => "smallint".into(),
            ColumnType::BigInt => "bigint".into(),
            ColumnType::Varchar(width) => format!("varchar({width})"),
            ColumnType::Text => "text".into(),
            ColumnType::LargeText => "longtext".into(),
        }
    }
    pub fn data_type(&self) -> &'static str {
        match self.column_type() {
            ColumnType::SmallInt => "smallint",
            ColumnType::BigInt => "bigint",
            ColumnType::Varchar(_) => "varchar",
            ColumnType::Text => "text",
            ColumnType::LargeText => "longtext",
        }
    }
    pub fn signed_integer_bits(&self) -> Option<u16> {
        match self.column_type() {
            ColumnType::SmallInt => Some(16),
            ColumnType::BigInt => Some(64),
            _ => None,
        }
    }
    pub fn character_maximum_length(&self) -> Option<u64> {
        match self.column_type() {
            ColumnType::Varchar(width) => Some(u64::from(width)),
            ColumnType::Text => Some(u64::from(u16::MAX)),
            ColumnType::LargeText => Some(u64::from(u32::MAX)),
            _ => None,
        }
    }
    pub fn character_octet_length(&self) -> Option<u64> {
        match self.column_type() {
            ColumnType::Varchar(width) => {
                Some(u64::from(width) * u64::from(self.options.max_character_bytes()))
            }
            // MySQL's INTERNAL_DD_CHAR_LENGTH divides TEXT bytes by mbminlen=1.
            ColumnType::Text => Some(u64::from(u16::MAX)),
            ColumnType::LargeText => Some(u64::from(u32::MAX)),
            _ => None,
        }
    }
    pub fn nullable(&self) -> bool {
        self.nullable
    }
    /// Native COLUMN_DEFAULT cannot distinguish absence from an explicit NULL default.
    pub fn column_default(&self) -> Option<&'static str> {
        match self.declaration.default() {
            ColumnDefault::Absent => None,
            ColumnDefault::EmptyString => Some(""),
        }
    }
    pub fn character_set(&self) -> Option<&'static str> {
        self.character_maximum_length()
            .map(|_| self.options.character_set())
    }
    pub fn collation(&self) -> Option<&'static str> {
        self.character_maximum_length()
            .map(|_| self.options.collation())
    }
    pub fn extra(&self) -> &'static str {
        ""
    }
    pub fn generation_expression(&self) -> &'static str {
        ""
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MysqlIndexShape {
    columns: Vec<&'static str>,
    primary: bool,
    unique: bool,
}
impl MysqlIndexShape {
    pub fn columns(&self) -> &[&'static str] {
        &self.columns
    }
    pub fn primary(&self) -> bool {
        self.primary
    }
    pub fn unique(&self) -> bool {
        self.unique
    }
    pub fn index_type(&self) -> &'static str {
        "BTREE"
    }
    pub fn visible(&self) -> bool {
        true
    }
    pub fn ascending(&self) -> bool {
        true
    }
    pub fn prefix_length(&self) -> Option<u64> {
        None
    }
    pub fn expression(&self) -> Option<&'static str> {
        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MysqlForeignKeyShape {
    column: &'static str,
    target_table: &'static str,
    target_column: &'static str,
}
impl MysqlForeignKeyShape {
    pub fn column(&self) -> &'static str {
        self.column
    }
    pub fn target_table(&self) -> &'static str {
        self.target_table
    }
    pub fn target_column(&self) -> &'static str {
        self.target_column
    }
    pub fn delete_action(&self) -> &'static str {
        "CASCADE"
    }
    /// InnoDB treats omitted NO ACTION and RESTRICT identically.
    pub fn update_action(&self) -> &'static str {
        "RESTRICT"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MysqlCheckShape {
    column: &'static str,
    condition: CheckCondition,
}
impl MysqlCheckShape {
    pub fn column(&self) -> &'static str {
        self.column
    }
    pub fn condition(&self) -> CheckCondition {
        self.condition
    }
    pub fn enforced(&self) -> bool {
        true
    }
    /// Strict reference for MySQL 8.4.11 DDL created with sql_quote_show_create=ON.
    /// Does not recognize arbitrary expressions or session-dependent spellings.
    pub fn native_clause(&self) -> String {
        match self.condition {
            CheckCondition::EqualOne => format!("(`{}` = 1)", self.column),
            CheckCondition::Positive => format!("(`{}` > 0)", self.column),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MysqlTableShape {
    name: &'static str,
    options: &'static MysqlTableOptions,
    columns: Vec<MysqlColumnShape>,
    indexes: Vec<MysqlIndexShape>,
    foreign_keys: Vec<MysqlForeignKeyShape>,
    checks: Vec<MysqlCheckShape>,
}
impl MysqlTableShape {
    pub(super) fn derive(definition: &'static TableDefinition) -> Self {
        let primary = definition.primary_key().columns();
        let columns = definition
            .columns()
            .iter()
            .enumerate()
            .map(|(offset, declaration)| MysqlColumnShape {
                declaration,
                options: definition.mysql_options(),
                ordinal: offset + 1,
                nullable: !(declaration.declared_not_null()
                    || primary.contains(&declaration.name())),
            })
            .collect();
        let mut indexes = vec![MysqlIndexShape {
            columns: primary.to_vec(),
            primary: true,
            unique: true,
        }];
        for column in definition.columns().iter().filter(|column| column.unique()) {
            indexes.push(MysqlIndexShape {
                columns: vec![column.name()],
                primary: false,
                unique: true,
            });
        }
        for foreign in definition.foreign_keys() {
            if !indexes
                .iter()
                .any(|index| index.columns.first() == Some(&foreign.column()))
            {
                indexes.push(MysqlIndexShape {
                    columns: vec![foreign.column()],
                    primary: false,
                    unique: false,
                });
            }
        }
        let foreign_keys = definition
            .foreign_keys()
            .iter()
            .map(|key| MysqlForeignKeyShape {
                column: key.column(),
                target_table: key.target().name(),
                target_column: key.target_column(),
            })
            .collect();
        let checks = definition
            .columns()
            .iter()
            .filter_map(|column| {
                column.check().map(|condition| MysqlCheckShape {
                    column: column.name(),
                    condition,
                })
            })
            .collect();
        Self {
            name: definition.name(),
            options: definition.mysql_options(),
            columns,
            indexes,
            foreign_keys,
            checks,
        }
    }
    pub fn name(&self) -> &'static str {
        self.name
    }
    pub fn columns(&self) -> &[MysqlColumnShape] {
        &self.columns
    }
    pub fn indexes(&self) -> &[MysqlIndexShape] {
        &self.indexes
    }
    pub fn foreign_keys(&self) -> &[MysqlForeignKeyShape] {
        &self.foreign_keys
    }
    pub fn checks(&self) -> &[MysqlCheckShape] {
        &self.checks
    }
    pub fn engine(&self) -> &'static str {
        self.options.engine()
    }
    pub fn row_format(&self) -> &'static str {
        self.options.row_format()
    }
    pub fn character_set(&self) -> &'static str {
        self.options.character_set()
    }
    pub fn collation(&self) -> &'static str {
        self.options.collation()
    }
}
