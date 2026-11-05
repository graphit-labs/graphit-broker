//! Opt-in real-server schema qualification; no application pool or private file is exercised.
#[path = "../../broker-control/tests/support/command.rs"]
mod command;
use broker_store::{
    schema::{Dialect, SchemaVersion, schema_statements},
    seeds::InitialSeeds,
    time::TimestampMicros,
};
use std::{
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

fn bounded(command: &mut Command, input: &[u8]) -> std::io::Result<Output> {
    command::output(command, input, Instant::now() + Duration::from_secs(60))
}

const MYSQL: &str = "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242";
const POSTGRES: &str =
    "postgres@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";

struct Server {
    id: String,
    dialect: Dialect,
    _private: tempfile::TempDir,
}
impl Drop for Server {
    fn drop(&mut self) {
        let result = bounded(
            Command::new("docker").args(["rm", "--force", "--volumes", &self.id]),
            &[],
        );
        let removed = result.is_ok_and(|output| output.status.success());
        let absent =
            bounded(Command::new("docker").args(["inspect", &self.id]), &[]).is_ok_and(|output| {
                output.status.code() == Some(1)
                    && String::from_utf8_lossy(&output.stderr)
                        .contains(&format!("No such object: {}", self.id))
            });
        if !thread::panicking() {
            assert!(
                removed && absent,
                "owned SQL fixture cleanup/absence failed"
            );
        } else if !(removed && absent) {
            eprintln!("owned SQL fixture cleanup/absence failed during test unwinding");
        }
    }
}
impl Server {
    fn start(dialect: Dialect) -> Self {
        let private = tempfile::tempdir().unwrap();
        let id = format!(
            "broker-schema-{}",
            private.path().file_name().unwrap().to_str().unwrap()
        );
        // Own the cleanup name before Docker can create a container or lose its ACK.
        let server = Self {
            id,
            dialect,
            _private: private,
        };
        let mut command = Command::new("docker");
        command.args([
            "run",
            "--detach",
            "--rm",
            "--network",
            "none",
            "--name",
            &server.id,
        ]);
        match dialect {
            Dialect::Mysql => {
                command.args([
                    "--env",
                    "MYSQL_ALLOW_EMPTY_PASSWORD=yes",
                    "--env",
                    "MYSQL_DATABASE=fixture",
                    MYSQL,
                ]);
            }
            Dialect::Postgres => {
                command.args([
                    "--env",
                    "POSTGRES_HOST_AUTH_METHOD=trust",
                    "--env",
                    "POSTGRES_DB=fixture",
                    POSTGRES,
                ]);
            }
            Dialect::Sqlite => unreachable!("SQLite has a separate in-memory fixture"),
        }
        let output = bounded(&mut command, &[]).expect("Docker required");
        assert!(
            output.status.success(),
            "start SQL fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let id = String::from_utf8(output.stdout).unwrap().trim().to_owned();
        assert!(id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        // TCP excludes the image entrypoints' temporary socket-only servers.
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if server.sql("SELECT 1;").status.success() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "SQL fixture startup deadline exceeded"
            );
            thread::sleep(Duration::from_millis(200));
        }
        server
    }
    fn sql(&self, sql: &str) -> Output {
        let mut command = Command::new("docker");
        command.args(["exec", "--interactive"]);
        if self.dialect == Dialect::Postgres {
            command.args(["--env", "PGCONNECT_TIMEOUT=1"]);
        }
        command.arg(&self.id);
        match self.dialect {
            Dialect::Mysql => {
                command.args([
                    "mysql",
                    "--connect-timeout=1",
                    "--protocol=TCP",
                    "--host=127.0.0.1",
                    "--batch",
                    "--raw",
                    "--skip-column-names",
                    "--default-character-set=utf8mb4",
                    "--user=root",
                    "fixture",
                ]);
            }
            Dialect::Postgres => {
                command.args([
                    "psql",
                    "--host=127.0.0.1",
                    "-U",
                    "postgres",
                    "-d",
                    "fixture",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-At",
                ]);
            }
            Dialect::Sqlite => unreachable!(),
        }
        bounded(&mut command, sql.as_bytes()).unwrap()
    }
    #[track_caller]
    fn good(&self, sql: &str) -> String {
        let output = self.sql(sql);
        assert!(
            output.status.success(),
            "SQL fixture statement: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
}

fn qualify(dialect: Dialect) {
    let server = Server::start(dialect);
    let ddl = schema_statements(dialect)
        .map(|s| format!("{s};\n"))
        .collect::<String>();
    if dialect == Dialect::Mysql {
        server.good("ALTER DATABASE fixture CHARACTER SET latin1 COLLATE latin1_bin;");
        assert_eq!(server.good("SELECT DEFAULT_CHARACTER_SET_NAME,DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=DATABASE();"),"latin1\tlatin1_bin");
        assert_eq!(
            server.good(&format!("SELECT @@session.sql_quote_show_create;{ddl}")),
            "1",
            "reference CHECK creation session"
        );
    } else {
        server.good(&ddl);
    }
    server.good(&ddl);
    let count = match dialect {
        Dialect::Mysql => {
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE();"
        }
        Dialect::Postgres => {
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';"
        }
        Dialect::Sqlite => unreachable!(),
    };
    assert_eq!(server.good(count), "25");
    if dialect == Dialect::Mysql {
        assert_eq!(server.good("SELECT @@innodb_page_size;"), "16384");
        assert_eq!(server.good("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND engine='InnoDB' AND row_format='Dynamic' AND table_collation='utf8mb4_bin';"), "25");
        assert_eq!(server.good("SELECT data_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='embedding_cache' AND column_name='embedding_json';"), "longtext");
    }
    if dialect == Dialect::Mysql {
        qualify_mysql_projection_and_mutants(&server, &ddl);
    }
    qualify_instance_inventory(&server);
    let version = server.good("SELECT VERSION();");
    println!("qualified {dialect:?} server: {version}");
    server.good(&format!(
        "INSERT INTO schema_meta VALUES (1,'{}',{});",
        SchemaVersion::FORMAT,
        SchemaVersion::EPOCH
    ));
    let seeds = InitialSeeds::new(TimestampMicros::new(123).unwrap());
    for role in seeds.roles() {
        server.good(&format!(
            "INSERT INTO roles VALUES ('{}',123);",
            role.name()
        ));
    }
    for (role, action) in seeds.permissions() {
        server.good(&format!(
            "INSERT INTO role_permissions VALUES ('{}','{}');",
            role.name(),
            action.as_str()
        ));
    }
    server.good("INSERT INTO resource_acl_state VALUES (1,1,123);");
    assert_eq!(server.good("SELECT COUNT(*) FROM role_permissions;"), "11");
    assert!(
        !server
            .sql("INSERT INTO role_permissions VALUES ('absent','session.read');")
            .status
            .success()
    );
    server.good("INSERT INTO roles VALUES ('temporary',123); INSERT INTO role_permissions VALUES ('temporary','grants.read'); DELETE FROM roles WHERE name='temporary';");
    assert_eq!(
        server.good("SELECT COUNT(*) FROM role_permissions WHERE role='temporary';"),
        "0"
    );
    let embedding =
        "INSERT INTO embedding_cache VALUES ('compat','input','p','r','m','query','[1]');";
    server.good(embedding);
    assert!(!server.sql(embedding).status.success());
    assert_eq!(
        server.good("SELECT created_at FROM roles WHERE name='admin';"),
        "123"
    );
}

#[test]
#[ignore = "requires Docker and pinned PostgreSQL image"]
fn postgres_executes_schema_seeds_and_constraints() {
    qualify(Dialect::Postgres);
}

#[test]
#[ignore = "requires Docker and pinned MySQL image"]
fn mysql_executes_schema_seeds_and_constraints() {
    qualify(Dialect::Mysql);
}

const MYSQL_TYPED_TABLE_ORACLE: usize = 25;
type NativeRow = Vec<Option<String>>;
type TableRows = std::collections::BTreeMap<String, Vec<NativeRow>>;
type TableGroups = std::collections::BTreeMap<String, Vec<Vec<NativeRow>>>;

#[derive(Debug, Eq, PartialEq)]
struct DeclaredMysqlCatalog {
    tables: TableRows,
    columns: TableRows,
    indexes: TableGroups,
    foreign_keys: TableGroups,
    checks: TableRows,
}

fn text(value: impl ToString) -> Option<String> {
    Some(value.to_string())
}
fn optional(value: Option<impl ToString>) -> Option<String> {
    value.map(|value| value.to_string())
}

// Test-only transport framing, not a SQL parser or a public catalog validation API.
// Each scalar is NULL-tagged or hexadecimal UTF-8, so tabs/newlines cannot split fields.
fn mysql_rows(server: &Server, expressions: &[&str], suffix: &str) -> Vec<NativeRow> {
    let fields = expressions.iter().map(|expression| format!("CASE WHEN ({expression}) IS NULL THEN '-' ELSE CONCAT('x',HEX(CAST(({expression}) AS CHAR CHARACTER SET utf8mb4))) END")).collect::<Vec<_>>().join(",");
    let output = server.good(&format!("SELECT {fields} {suffix};"));
    if output.is_empty() {
        return Vec::new();
    }
    output
        .lines()
        .map(|line| {
            let fields = line
                .split('\t')
                .map(|field| {
                    if field == "-" {
                        return None;
                    }
                    let hex = field.strip_prefix('x').expect("fixture scalar tag");
                    assert!(
                        hex.len().is_multiple_of(2)
                            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    );
                    let bytes = (0..hex.len())
                        .step_by(2)
                        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
                        .collect::<Vec<_>>();
                    Some(String::from_utf8(bytes).expect("fixture UTF-8"))
                })
                .collect::<Vec<_>>();
            assert_eq!(fields.len(), expressions.len(), "native field framing");
            fields
        })
        .collect()
}

fn table_rows(rows: Vec<NativeRow>) -> TableRows {
    let mut tables = TableRows::new();
    for mut row in rows {
        let table = row.remove(0).expect("native table name");
        tables.entry(table).or_default().push(row);
    }
    tables
}

fn table_groups(rows: Vec<NativeRow>) -> TableGroups {
    let mut groups = std::collections::BTreeMap::<(String, String), Vec<NativeRow>>::new();
    for mut row in rows {
        let table = row.remove(0).expect("native table name");
        let group = row.remove(0).expect("native grouping name");
        groups.entry((table, group)).or_default().push(row);
    }
    let mut tables = TableGroups::new();
    for ((table, _name), rows) in groups {
        tables.entry(table).or_default().push(rows);
    }
    for groups in tables.values_mut() {
        groups.sort();
    }
    tables
}

fn captured_mysql(server: &Server) -> DeclaredMysqlCatalog {
    let tables = table_rows(mysql_rows(
        server,
        &[
            "t.TABLE_NAME",
            "t.ENGINE",
            "t.ROW_FORMAT",
            "c.CHARACTER_SET_NAME",
            "t.TABLE_COLLATION",
            "t.TABLE_TYPE",
        ],
        "FROM information_schema.TABLES t JOIN information_schema.COLLATIONS c ON c.COLLATION_NAME=t.TABLE_COLLATION WHERE t.TABLE_SCHEMA=DATABASE() AND t.TABLE_TYPE='BASE TABLE' ORDER BY t.TABLE_NAME",
    ));
    let columns = table_rows(mysql_rows(
        server,
        &[
            "TABLE_NAME",
            "COLUMN_NAME",
            "ORDINAL_POSITION",
            "DATA_TYPE",
            "COLUMN_TYPE",
            "IS_NULLABLE",
            "COLUMN_DEFAULT",
            "CHARACTER_MAXIMUM_LENGTH",
            "CHARACTER_OCTET_LENGTH",
            "CHARACTER_SET_NAME",
            "COLLATION_NAME",
            "EXTRA",
            "GENERATION_EXPRESSION",
        ],
        "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION",
    ));
    let indexes = table_groups(mysql_rows(
        server,
        &[
            "TABLE_NAME",
            "INDEX_NAME",
            "INDEX_NAME='PRIMARY'",
            "NON_UNIQUE",
            "SEQ_IN_INDEX",
            "COLUMN_NAME",
            "COLLATION",
            "SUB_PART",
            "INDEX_TYPE",
            "IS_VISIBLE",
            "EXPRESSION",
            "NULLABLE",
            "INDEX_COMMENT",
            "COMMENT",
        ],
        "FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX",
    ));
    let foreign_keys = table_groups(mysql_rows(
        server,
        &[
            "k.TABLE_NAME",
            "k.CONSTRAINT_NAME",
            "k.ORDINAL_POSITION",
            "k.COLUMN_NAME",
            "k.POSITION_IN_UNIQUE_CONSTRAINT",
            "k.REFERENCED_TABLE_SCHEMA=DATABASE()",
            "k.REFERENCED_TABLE_NAME",
            "k.REFERENCED_COLUMN_NAME",
            "r.DELETE_RULE",
            "CASE r.UPDATE_RULE WHEN 'NO ACTION' THEN 'RESTRICT' ELSE r.UPDATE_RULE END",
            "r.MATCH_OPTION",
        ],
        "FROM information_schema.KEY_COLUMN_USAGE k JOIN information_schema.REFERENTIAL_CONSTRAINTS r ON r.CONSTRAINT_SCHEMA=k.CONSTRAINT_SCHEMA AND r.TABLE_NAME=k.TABLE_NAME AND r.CONSTRAINT_NAME=k.CONSTRAINT_NAME WHERE k.TABLE_SCHEMA=DATABASE() AND k.REFERENCED_TABLE_NAME IS NOT NULL ORDER BY k.TABLE_NAME,k.CONSTRAINT_NAME,k.ORDINAL_POSITION",
    ));
    let mut checks = table_rows(mysql_rows(
        server,
        &["t.TABLE_NAME", "c.CHECK_CLAUSE", "t.ENFORCED"],
        "FROM information_schema.TABLE_CONSTRAINTS t JOIN information_schema.CHECK_CONSTRAINTS c ON c.CONSTRAINT_SCHEMA=t.CONSTRAINT_SCHEMA AND c.CONSTRAINT_NAME=t.CONSTRAINT_NAME WHERE t.TABLE_SCHEMA=DATABASE() AND t.CONSTRAINT_TYPE='CHECK' ORDER BY t.TABLE_NAME,t.CONSTRAINT_NAME",
    ));
    for rows in checks.values_mut() {
        rows.sort();
    }
    DeclaredMysqlCatalog {
        tables,
        columns,
        indexes,
        foreign_keys,
        checks,
    }
}

fn expected_mysql() -> DeclaredMysqlCatalog {
    use broker_store::schema::TABLES;
    let mut expected = DeclaredMysqlCatalog {
        tables: TableRows::new(),
        columns: TableRows::new(),
        indexes: TableGroups::new(),
        foreign_keys: TableGroups::new(),
        checks: TableRows::new(),
    };
    for table in TABLES {
        let shape = table.mysql_shape();
        let name = shape.name().to_owned();
        expected.tables.insert(
            name.clone(),
            vec![vec![
                text(shape.engine()),
                text(shape.row_format()),
                text(shape.character_set()),
                text(shape.collation()),
                text("BASE TABLE"),
            ]],
        );
        let columns = shape
            .columns()
            .iter()
            .map(|column| {
                vec![
                    text(column.name()),
                    text(column.ordinal()),
                    text(column.data_type()),
                    text(column.full_type()),
                    text(if column.nullable() { "YES" } else { "NO" }),
                    optional(column.column_default()),
                    optional(column.character_maximum_length()),
                    optional(column.character_octet_length()),
                    optional(column.character_set()),
                    optional(column.collation()),
                    text(column.extra()),
                    text(column.generation_expression()),
                ]
            })
            .collect();
        expected.columns.insert(name.clone(), columns);
        let mut indexes = shape
            .indexes()
            .iter()
            .map(|index| {
                index
                    .columns()
                    .iter()
                    .enumerate()
                    .map(|(offset, name)| {
                        let column = shape
                            .columns()
                            .iter()
                            .find(|column| column.name() == *name)
                            .unwrap();
                        vec![
                            text(u8::from(index.primary())),
                            text(u8::from(!index.unique())),
                            text(offset + 1),
                            text(name),
                            text(if index.ascending() { "A" } else { "D" }),
                            optional(index.prefix_length()),
                            text(index.index_type()),
                            text(if index.visible() { "YES" } else { "NO" }),
                            optional(index.expression()),
                            text(if column.nullable() { "YES" } else { "" }),
                            text(""),
                            text(""),
                        ]
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        indexes.sort();
        expected.indexes.insert(name.clone(), indexes);
        let mut foreign_keys = shape
            .foreign_keys()
            .iter()
            .map(|key| {
                vec![vec![
                    text(1),
                    text(key.column()),
                    text(1),
                    text(1),
                    text(key.target_table()),
                    text(key.target_column()),
                    text(key.delete_action()),
                    text(key.update_action()),
                    text("NONE"),
                ]]
            })
            .collect::<Vec<_>>();
        foreign_keys.sort();
        if !foreign_keys.is_empty() {
            expected.foreign_keys.insert(name.clone(), foreign_keys);
        }
        let mut checks = shape
            .checks()
            .iter()
            .map(|check| {
                vec![
                    text(check.native_clause()),
                    text(if check.enforced() { "YES" } else { "NO" }),
                ]
            })
            .collect::<Vec<_>>();
        checks.sort();
        if !checks.is_empty() {
            expected.checks.insert(name, checks);
        }
    }
    expected
}

fn reset_mysql_reference(server: &Server, ddl: &str) {
    server.good(
        "DROP DATABASE fixture; CREATE DATABASE fixture CHARACTER SET latin1 COLLATE latin1_bin;",
    );
    assert_eq!(
        server.good(&format!("SELECT @@session.sql_quote_show_create;{ddl}")),
        "1",
        "reference CHECK creation session"
    );
    assert_eq!(
        captured_mysql(server),
        expected_mysql(),
        "restored declared MySQL reference"
    );
}

fn native_constraint(server: &Server, table: &str, kind: &str) -> String {
    let name = server.good(&format!("SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='{table}' AND CONSTRAINT_TYPE='{kind}' ORDER BY CONSTRAINT_NAME LIMIT 1;"));
    assert!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "fixture-only native grouping identifier"
    );
    format!("`{name}`")
}

fn qualify_mysql_projection_and_mutants(server: &Server, ddl: &str) {
    assert_eq!(
        captured_mysql(server),
        expected_mysql(),
        "declared MySQL projection"
    );
    let count = server.good("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE';").parse::<usize>().unwrap();
    assert_eq!(
        count, MYSQL_TYPED_TABLE_ORACLE,
        "typed MySQL native table inventory"
    );
    let mutants = [
        (
            "varchar width",
            "ALTER TABLE oidc_flows MODIFY purpose VARCHAR(33) NOT NULL",
        ),
        (
            "unsigned integer",
            "ALTER TABLE roles MODIFY created_at BIGINT UNSIGNED NOT NULL",
        ),
        (
            "integer type",
            "ALTER TABLE roles MODIFY created_at SMALLINT NOT NULL",
        ),
        (
            "nullable",
            "ALTER TABLE roles MODIFY created_at BIGINT NULL",
        ),
        (
            "empty default",
            "ALTER TABLE local_tokens ALTER resource SET DEFAULT 'changed'",
        ),
        (
            "ordinal",
            "ALTER TABLE roles MODIFY created_at BIGINT NOT NULL FIRST",
        ),
        (
            "extra column",
            "ALTER TABLE roles ADD extra_column BIGINT NOT NULL",
        ),
        ("missing column", "ALTER TABLE roles DROP COLUMN created_at"),
        (
            "generated column",
            "ALTER TABLE roles DROP COLUMN created_at, ADD COLUMN created_at BIGINT GENERATED ALWAYS AS (1) STORED",
        ),
        (
            "invisible column",
            "ALTER TABLE roles MODIFY created_at BIGINT NOT NULL INVISIBLE",
        ),
        (
            "column charset",
            "ALTER TABLE embedding_cache MODIFY provider TEXT CHARACTER SET latin1 COLLATE latin1_bin NOT NULL",
        ),
        (
            "column collation",
            "ALTER TABLE embedding_cache MODIFY input_type VARCHAR(16) COLLATE utf8mb4_general_ci NOT NULL",
        ),
        (
            "extra unique",
            "ALTER TABLE roles ADD UNIQUE INDEX mutant_unique (created_at)",
        ),
        (
            "extra nonunique",
            "ALTER TABLE roles ADD INDEX mutant_nonunique (created_at)",
        ),
        (
            "primary changed",
            "ALTER TABLE embedding_cache DROP PRIMARY KEY, ADD PRIMARY KEY(input_hash,compatibility_hash)",
        ),
        (
            "unique dropped",
            "ALTER TABLE local_tokens DROP INDEX token_id",
        ),
        (
            "unique changed",
            "ALTER TABLE local_tokens DROP INDEX token_id, ADD UNIQUE INDEX replacement_unique (client_id)",
        ),
        (
            "prefix index",
            "ALTER TABLE local_tokens DROP INDEX token_id, ADD UNIQUE INDEX replacement_unique (token_id(10))",
        ),
        (
            "descending index",
            "ALTER TABLE local_tokens DROP INDEX token_id, ADD UNIQUE INDEX replacement_unique (token_id DESC)",
        ),
        (
            "invisible index",
            "ALTER TABLE local_tokens ALTER INDEX token_id INVISIBLE",
        ),
        (
            "extra check",
            "ALTER TABLE schema_meta ADD CHECK(epoch < 999)",
        ),
        ("engine", "ALTER TABLE embedding_cache ENGINE=MyISAM"),
        ("row format", "ALTER TABLE roles ROW_FORMAT=COMPACT"),
        (
            "table collation",
            "ALTER TABLE roles DEFAULT CHARACTER SET latin1 COLLATE latin1_bin",
        ),
    ];
    for (label, sql) in mutants {
        reset_mysql_reference(server, ddl);
        server.good(sql); // Engine rejection is a fixture failure, never comparator evidence.
        assert_ne!(
            captured_mysql(server),
            expected_mysql(),
            "legal native mutant accepted: {label}"
        );
        println!("rejected native MySQL mutant: {label}");
        reset_mysql_reference(server, ddl);
    }
    for (label, clause) in [
        (
            "foreign key target",
            "REFERENCES local_users(username) ON DELETE CASCADE",
        ),
        (
            "foreign key delete",
            "REFERENCES roles(name) ON DELETE RESTRICT",
        ),
        (
            "foreign key update",
            "REFERENCES roles(name) ON DELETE CASCADE ON UPDATE CASCADE",
        ),
        ("foreign key missing", ""),
    ] {
        reset_mysql_reference(server, ddl);
        let name = native_constraint(server, "role_assignments", "FOREIGN KEY");
        let replacement = if clause.is_empty() {
            String::new()
        } else {
            format!(", ADD FOREIGN KEY(role) {clause}")
        };
        server.good(&format!(
            "ALTER TABLE role_assignments DROP FOREIGN KEY {name}{replacement}"
        ));
        assert_ne!(
            captured_mysql(server),
            expected_mysql(),
            "legal native mutant accepted: {label}"
        );
        println!("rejected native MySQL mutant: {label}");
        reset_mysql_reference(server, ddl);
    }
    for (label, action) in [
        ("weakened check", 0),
        ("not enforced check", 1),
        ("missing check", 2),
    ] {
        reset_mysql_reference(server, ddl);
        let name = native_constraint(server, "schema_meta", "CHECK");
        let sql = match action {
            0 => format!("ALTER TABLE schema_meta DROP CHECK {name}, ADD CHECK(id >= 0)"),
            1 => format!("ALTER TABLE schema_meta ALTER CHECK {name} NOT ENFORCED"),
            2 => format!("ALTER TABLE schema_meta DROP CHECK {name}"),
            _ => unreachable!(),
        };
        server.good(&sql);
        assert_ne!(
            captured_mysql(server),
            expected_mysql(),
            "legal native mutant accepted: {label}"
        );
        println!("rejected native MySQL mutant: {label}");
        reset_mysql_reference(server, ddl);
    }
}

fn qualify_instance_inventory(server: &Server) {
    if server.dialect == Dialect::Mysql {
        assert_eq!(server.good("SELECT data_type FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='broker_instance_project_versions' AND column_name='version';"), "longtext");
    }
    assert!(
        !server
            .sql("INSERT INTO broker_instances VALUES (NULL,'issuer','subject',1,1);")
            .status
            .success()
    );
    assert!(!server.sql("INSERT INTO broker_instance_project_versions VALUES ('absent','01KSH1CRFFG8Z74B5ZS78WW808',1,'main');").status.success());
    server.good(
        "INSERT INTO broker_instances VALUES ('instance','https://issuer.example','Subject ',1,2);",
    );
    assert!(
        !server
            .sql("INSERT INTO broker_instances VALUES ('instance','other','subject',3,3);")
            .status
            .success()
    );
    let version = "界😀".repeat(10_000);
    let insert = format!(
        "INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',1,'{version}');"
    );
    server.good(&insert);
    assert!(!server.sql(&insert).status.success());
    assert_eq!(
        server.good(
            "SELECT version FROM broker_instance_project_versions WHERE instance_id='instance';"
        ),
        version
    );
    assert_eq!(
        server.good("SELECT owner_issuer FROM broker_instances WHERE instance_id='instance';"),
        "https://issuer.example"
    );
    // HEX preserves trailing whitespace in the owner tuple across CLI transports.
    let subject_query = match server.dialect {
        Dialect::Mysql => {
            "SELECT HEX(owner_subject) FROM broker_instances WHERE instance_id='instance';"
        }
        Dialect::Postgres => {
            "SELECT upper(encode(convert_to(owner_subject,'UTF8'),'hex')) FROM broker_instances WHERE instance_id='instance';"
        }
        Dialect::Sqlite => unreachable!(),
    };
    assert_eq!(server.good(subject_query), "5375626A65637420");
    for position in [0, -1] {
        assert!(!server.sql(&format!("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',{position},'main');")).status.success());
    }
    server.good("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',2,'main'); DELETE FROM broker_instance_project_versions WHERE instance_id='instance';");
    assert_eq!(
        server.good("SELECT COUNT(*) FROM broker_instances WHERE instance_id='instance';"),
        "1"
    );
    server.good("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',1,'main'); DELETE FROM broker_instances WHERE instance_id='instance';");
    assert_eq!(
        server.good("SELECT COUNT(*) FROM broker_instance_project_versions;"),
        "0"
    );
}
