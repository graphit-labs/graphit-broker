use broker_store::{
    schema::{Dialect, SchemaVersion, TABLES, Table, schema_statements},
    seeds::{BuiltinRole, InitialSeeds},
    time::TimestampMicros,
};
use rusqlite::{Connection, params};
use std::{
    collections::BTreeSet,
    time::{Duration, UNIX_EPOCH},
};

fn database() -> Connection {
    let db = Connection::open_in_memory().expect("SQLite fixture");
    db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
    for _ in 0..2 {
        for sql in schema_statements(Dialect::Sqlite) {
            db.execute_batch(&sql).unwrap();
        }
    }
    db
}

#[test]
fn complete_schema_is_idempotent_and_matches_maintained_durable_fields() {
    let db = database();
    let mut stmt = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    let actual = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<BTreeSet<_>, _>>()
        .unwrap();
    let expected = TABLES
        .iter()
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 25);
    // Independent physical inventory for the current Rust schema.
    let fields: &[(&str, &[&str])] = &[
        ("schema_meta", &["id", "format", "epoch"]),
        ("roles", &["name", "created_at"]),
        ("role_permissions", &["role", "action"]),
        ("role_assignments", &["subject", "role", "created_at"]),
        (
            "admin_sessions",
            &[
                "token_hash",
                "subject",
                "name",
                "email",
                "csrf_token",
                "expires_at",
                "created_at",
            ],
        ),
        (
            "admin_session_principals",
            &[
                "token_hash",
                "issuer",
                "username",
                "organization",
                "teams_json",
                "local_user_revision",
            ],
        ),
        (
            "admin_session_claim_roles",
            &["token_hash", "claim_selector", "roles_json"],
        ),
        (
            "oidc_flows",
            &[
                "state_hash",
                "browser_binding_hash",
                "nonce",
                "pkce_verifier",
                "purpose",
                "continuation_json",
                "expires_at",
                "created_at",
            ],
        ),
        (
            "local_users",
            &[
                "username",
                "subject",
                "identity_kind",
                "password_hash",
                "name",
                "email",
                "organization",
                "teams_json",
                "enabled",
                "password_change_required",
                "revision",
                "created_at",
                "updated_at",
            ],
        ),
        (
            "local_mfa",
            &[
                "subject",
                "secret_ciphertext",
                "last_totp_step",
                "confirmed_at",
            ],
        ),
        (
            "local_mfa_recovery_codes",
            &["subject", "code_hash", "created_at"],
        ),
        (
            "local_auth_challenges",
            &[
                "challenge_hash",
                "subject",
                "local_user_revision",
                "purpose",
                "binding_hash",
                "stage",
                "secret_ciphertext",
                "expires_at",
                "created_at",
            ],
        ),
        (
            "local_tokens",
            &[
                "token_hash",
                "token_id",
                "token_kind",
                "subject",
                "oidc_subject",
                "principal_json",
                "client_id",
                "audience",
                "resource",
                "scopes_json",
                "local_user_revision",
                "family_id",
                "auth_time",
                "expires_at",
                "revoked_at",
                "consumed_at",
                "last_used_at",
                "created_at",
            ],
        ),
        (
            "oidc_auth_requests",
            &[
                "request_hash",
                "identity_subject",
                "request_json",
                "code_hash",
                "expires_at",
                "created_at",
            ],
        ),
        (
            "oauth_device_codes",
            &[
                "device_hash",
                "user_hash",
                "client_id",
                "scopes_json",
                "subject",
                "local_user_revision",
                "status",
                "interval_seconds",
                "last_poll_at",
                "expires_at",
                "created_at",
            ],
        ),
        (
            "oauth_dynamic_clients",
            &[
                "client_id",
                "client_name",
                "redirect_uris_json",
                "scopes_json",
                "application_type",
                "created_at",
            ],
        ),
        ("resource_acl_state", &["id", "revision", "updated_at"]),
        (
            "resource_grants",
            &[
                "id",
                "name",
                "access_kind",
                "principal",
                "s3_route",
                "created_at",
                "updated_at",
            ],
        ),
        ("grant_capabilities", &["grant_id", "value"]),
        ("grant_projects", &["grant_id", "value"]),
        ("grant_s3_operations", &["grant_id", "value"]),
        ("grant_s3_prefixes", &["grant_id", "value"]),
        (
            "broker_instances",
            &[
                "instance_id",
                "owner_issuer",
                "owner_subject",
                "created_at",
                "updated_at",
            ],
        ),
        (
            "broker_instance_project_versions",
            &["instance_id", "project_id", "position", "version"],
        ),
        (
            "embedding_cache",
            &[
                "compatibility_hash",
                "input_hash",
                "provider",
                "revision",
                "model",
                "input_type",
                "embedding_json",
            ],
        ),
    ];
    for (table, wanted) in fields {
        let found = db
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(found, *wanted, "durable fields: {table}");
        for forbidden in [
            "password",
            "pepper",
            "access_token",
            "refresh_token",
            "code",
            "recovery_code",
            "totp_secret",
        ] {
            assert!(!found.iter().any(|field| field == forbidden));
        }
    }
    assert!(!actual.contains("broker_config"));
}

#[test]
fn foreign_keys_reject_orphans_and_cascade_all_defined_relations() {
    let db = database();
    assert!(
        db.execute(
            "INSERT INTO role_permissions VALUES ('missing','session.read')",
            []
        )
        .is_err()
    );
    assert!(
        db.execute(
            "INSERT INTO role_assignments VALUES ('subject','missing',1)",
            []
        )
        .is_err()
    );
    db.execute("INSERT INTO roles VALUES ('auditor',1)", [])
        .unwrap();
    db.execute(
        "INSERT INTO role_permissions VALUES ('auditor','grants.read')",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO role_assignments VALUES ('subject','auditor',1)",
        [],
    )
    .unwrap();
    db.execute("DELETE FROM roles WHERE name='auditor'", [])
        .unwrap();
    for table in ["role_permissions", "role_assignments"] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    db.execute(
        "INSERT INTO admin_sessions VALUES ('h','sub','name','email','csrf',2,1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO admin_session_principals VALUES ('h','issuer','user','org','[]',0)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO admin_session_claim_roles VALUES ('h','$.roles','[]')",
        [],
    )
    .unwrap();
    db.execute("DELETE FROM admin_sessions", []).unwrap();
    for table in ["admin_session_principals", "admin_session_claim_roles"] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    db.execute(
        "INSERT INTO local_users VALUES ('user','sub','human','phc','n','e','o','[]',1,0,1,1,1)",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO local_mfa VALUES ('sub','ciphertext',1,1)", [])
        .unwrap();
    db.execute(
        "INSERT INTO local_mfa_recovery_codes VALUES ('sub','hash',1)",
        [],
    )
    .unwrap();
    db.execute("INSERT INTO local_auth_challenges VALUES ('hash','sub',1,'admin-login','binding','mfa','ciphertext',2,1)", []).unwrap();
    db.execute("DELETE FROM local_users", []).unwrap();
    for table in [
        "local_mfa",
        "local_mfa_recovery_codes",
        "local_auth_challenges",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    db.execute(
        "INSERT INTO resource_grants VALUES ('g','name','read','user','route',1,1)",
        [],
    )
    .unwrap();
    for table in [
        "grant_capabilities",
        "grant_projects",
        "grant_s3_operations",
        "grant_s3_prefixes",
    ] {
        db.execute(&format!("INSERT INTO {table} VALUES ('g','value')"), [])
            .unwrap();
        assert!(
            db.execute(
                &format!("INSERT INTO {table} VALUES ('absent','value')"),
                []
            )
            .is_err()
        );
    }
    db.execute("DELETE FROM resource_grants", []).unwrap();
    for table in [
        "grant_capabilities",
        "grant_projects",
        "grant_s3_operations",
        "grant_s3_prefixes",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
    // Exercise every declared relation rather than merely counting CREATE strings.
    let mut foreign_key_count = 0;
    for table in TABLES {
        let count = db
            .prepare(&format!("PRAGMA foreign_key_list({})", table.name()))
            .unwrap()
            .query_map([], |_| Ok(()))
            .unwrap()
            .count();
        foreign_key_count += count;
    }
    assert_eq!(foreign_key_count, 12);
}

#[test]
fn embedding_index_and_identity_uniqueness_are_enforced() {
    let db = database();
    let insert =
        "INSERT INTO embedding_cache VALUES (?1,?2,'provider','rev','model','query','[1]')";
    db.execute(insert, params!["a", "input"]).unwrap();
    assert!(db.execute(insert, params!["a", "input"]).is_err());
    db.execute(insert, params!["b", "input"]).unwrap();
    db.execute(insert, params!["a", "other"]).unwrap();
    db.execute(
        "INSERT INTO local_users VALUES ('a','subject','human','phc','','','','[]',1,0,1,1,1)",
        [],
    )
    .unwrap();
    assert!(
        db.execute(
            "INSERT INTO local_users VALUES ('b','subject','human','phc','','','','[]',1,0,1,1,1)",
            []
        )
        .is_err()
    );
    db.execute(
        "INSERT INTO oauth_dynamic_clients VALUES ('client','n','[]','[]','native',1)",
        [],
    )
    .unwrap();
    assert!(
        db.execute(
            "INSERT INTO oauth_dynamic_clients VALUES ('client','other','[]','[]','native',1)",
            []
        )
        .is_err()
    );
}

#[test]
fn timestamps_are_integer_and_absent_lifecycle_events_are_null() {
    let db = database();
    let large = 1_728_000_000_123_456_i64;
    db.execute("INSERT INTO roles VALUES ('time',?1)", [large])
        .unwrap();
    let (kind, value): (String, i64) = db
        .query_row("SELECT typeof(created_at),created_at FROM roles", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((kind.as_str(), value), ("integer", large));
    for table in TABLES {
        let columns = db
            .prepare(&format!("PRAGMA table_info({})", table.name()))
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for (name, kind, required) in columns {
            if name.ends_with("_at") || name == "auth_time" {
                assert_eq!(kind, "BIGINT", "{}.{name}", table.name());
                if ["revoked_at", "consumed_at", "last_used_at", "last_poll_at"]
                    .contains(&name.as_str())
                {
                    assert_eq!(required, 0);
                }
            }
        }
    }
    db.execute("INSERT INTO local_tokens VALUES ('hash','id','access','subject','oidc','{}','client','aud','', '[]',1,'family',1,2,NULL,NULL,NULL,1)",[]).unwrap();
    let absent: (Option<i64>, Option<i64>, Option<i64>) = db
        .query_row(
            "SELECT revoked_at,consumed_at,last_used_at FROM local_tokens",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(absent, (None, None, None));
}

#[test]
fn dialects_select_static_sql_without_placeholder_or_identifier_rewriting() {
    for table in TABLES {
        let sqlite = table.create_statement(Dialect::Sqlite);
        assert_eq!(sqlite, table.create_statement(Dialect::Postgres));
        assert!(sqlite.starts_with(&format!("CREATE TABLE IF NOT EXISTS {} (", table.name())));
        let mysql = table.create_statement(Dialect::Mysql);
        assert!(mysql.ends_with(
            " ENGINE=InnoDB ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
        ));
        assert!(!mysql.contains("VARCHAR(40)"));
        if matches!(
            table,
            Table::EmbeddingCache | Table::BrokerInstanceProjectVersions
        ) {
            assert!(sqlite.contains(" TEXT NOT NULL"));
            assert!(mysql.contains(" LONGTEXT NOT NULL"));
        } else {
            assert_eq!(
                mysql
                    .strip_suffix(" ENGINE=InnoDB ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin")
                    .unwrap(),
                sqlite
            );
        }
    }
}

#[test]
fn fresh_version_is_exact_and_errors_do_not_reflect_supplied_data() {
    assert!(SchemaVersion::validate("rust-broker-v1", 2).is_ok());
    for (format, epoch) in [
        ("rust-broker-v1", 0),
        ("rust-broker-v1", 11),
        ("rust-broker-v1", 1),
        ("rust-broker-v1", 3),
        ("rust-broker-v1", -1),
        ("go", 1),
        ("Rust-broker-v1", 1),
        ("rust-broker-v1 ", 1),
        ("", 1),
    ] {
        let error = SchemaVersion::validate(format, epoch).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported broker database schema; recreate the database"
        );
    }
    let db = database();
    assert!(
        db.execute("INSERT INTO schema_meta VALUES (2,'rust-broker-v1',1)", [])
            .is_err()
    );
    assert!(
        db.execute("INSERT INTO schema_meta VALUES (1,'rust-broker-v1',0)", [])
            .is_err()
    );
    db.execute("INSERT INTO schema_meta VALUES (1,'rust-broker-v1',2)", [])
        .unwrap();
    assert!(
        db.execute("INSERT INTO schema_meta VALUES (1,'rust-broker-v1',2)", [])
            .is_err()
    );
}

#[test]
fn seeds_match_builtin_contract_and_supply_one_captured_timestamp() {
    let db = database();
    let seeds = InitialSeeds::new(TimestampMicros::new(123).unwrap());
    assert_eq!(seeds.roles(), &[BuiltinRole::Admin, BuiltinRole::User]);
    for role in seeds.roles() {
        db.execute(
            "INSERT INTO roles VALUES (?1,?2)",
            params![role.name(), seeds.timestamp().as_i64()],
        )
        .unwrap();
    }
    for (role, action) in seeds.permissions() {
        db.execute(
            "INSERT INTO role_permissions VALUES (?1,?2)",
            params![role.name(), action.as_str()],
        )
        .unwrap();
        assert_ne!(action.as_str(), "*");
    }
    assert_eq!(BuiltinRole::Admin.actions().len(), 9);
    let expected_admin: BTreeSet<&str> = [
        "session.read",
        "configuration.read",
        "grants.read",
        "grants.write",
        "roles.read",
        "roles.write",
        "users.read",
        "users.write",
        "projects.read",
    ]
    .into_iter()
    .collect();
    assert_eq!(
        BuiltinRole::Admin
            .actions()
            .iter()
            .map(|v| v.as_str())
            .collect::<BTreeSet<_>>(),
        expected_admin
    );
    assert_eq!(
        BuiltinRole::User
            .actions()
            .iter()
            .map(|v| v.as_str())
            .collect::<Vec<_>>(),
        ["session.read", "projects.read"]
    );
    assert_eq!(seeds.permissions().count(), 11);
    assert_eq!(seeds.acl_revision(), 1);
    db.execute(
        "INSERT INTO resource_acl_state VALUES (1,?1,?2)",
        params![seeds.acl_revision(), seeds.timestamp().as_i64()],
    )
    .unwrap();
}

#[test]
fn timestamp_conversion_rejects_invalid_range_and_orders_numerically() {
    assert!(TimestampMicros::new(-1).is_err());
    assert_eq!(TimestampMicros::new(i64::MAX).unwrap().as_i64(), i64::MAX);
    assert_eq!(TimestampMicros::try_from(UNIX_EPOCH).unwrap().as_i64(), 0);
    assert!(TimestampMicros::try_from(UNIX_EPOCH - Duration::from_secs(1)).is_err());
    assert_eq!(
        TimestampMicros::try_from(UNIX_EPOCH + Duration::from_nanos(1999))
            .unwrap()
            .as_i64(),
        1
    );
    if let Some(out_of_range) = UNIX_EPOCH.checked_add(Duration::from_secs(i64::MAX as u64)) {
        assert!(TimestampMicros::try_from(out_of_range).is_err());
    }
    assert!(TimestampMicros::new(2).unwrap() > TimestampMicros::new(1).unwrap());
}

const TYPED_SCHEMA_ORACLE: usize = 138;

#[test]
fn typed_schema_projects_every_declared_column_and_constraint() {
    let definitions = TABLES
        .iter()
        .map(|table| table.definition())
        .collect::<Vec<_>>();
    assert_eq!(
        definitions
            .iter()
            .map(|table| table.columns().len())
            .sum::<usize>(),
        TYPED_SCHEMA_ORACLE,
        "typed schema column inventory"
    );
    assert_eq!(
        definitions
            .iter()
            .filter(|table| table.primary_key().inline())
            .count(),
        16
    );
    assert_eq!(
        definitions
            .iter()
            .filter(|table| !table.primary_key().inline())
            .count(),
        9
    );
    assert_eq!(
        definitions
            .iter()
            .flat_map(|table| table.columns())
            .filter(|column| column.unique())
            .count(),
        4
    );
    assert_eq!(
        definitions
            .iter()
            .map(|table| table.foreign_keys().len())
            .sum::<usize>(),
        12
    );
    assert_eq!(
        definitions
            .iter()
            .flat_map(|table| table.columns())
            .filter(|column| column.check().is_some())
            .count(),
        3
    );
    let shapes = TABLES
        .iter()
        .map(|table| table.mysql_shape())
        .collect::<Vec<_>>();
    assert_eq!(
        shapes
            .iter()
            .map(|table| table.indexes().len())
            .sum::<usize>(),
        31
    );
    assert_eq!(
        shapes
            .iter()
            .flat_map(|table| table.indexes())
            .map(|index| index.columns().len())
            .sum::<usize>(),
        41
    );
    for (definition, shape) in definitions.iter().zip(&shapes) {
        assert_eq!(definition.name(), shape.name());
        assert_eq!(definition.columns().len(), shape.columns().len());
        for (offset, (column, physical)) in
            definition.columns().iter().zip(shape.columns()).enumerate()
        {
            assert_eq!(column.name(), physical.name());
            assert_eq!(column.column_type(), physical.column_type());
            assert_eq!(physical.ordinal(), offset + 1);
            assert_eq!(
                physical.nullable(),
                !(column.declared_not_null()
                    || definition.primary_key().columns().contains(&column.name()))
            );
            assert_eq!(physical.extra(), "");
            assert_eq!(physical.generation_expression(), "");
        }
        for foreign in definition.foreign_keys() {
            assert!(
                shape
                    .indexes()
                    .iter()
                    .any(|index| index.columns().first() == Some(&foreign.column()))
            );
        }
    }
    assert!(
        Table::RoleAssignments
            .mysql_shape()
            .indexes()
            .iter()
            .any(|index| !index.unique() && index.columns() == ["role"])
    );
    assert!(
        Table::LocalAuthChallenges
            .mysql_shape()
            .indexes()
            .iter()
            .any(|index| !index.unique() && index.columns() == ["subject"])
    );
}

#[test]
fn sqlite_nullable_inline_primary_keys_and_explicit_composite_keys_remain_distinct() {
    let db = database();
    let not_null = |table: &str, column: &str| -> i64 {
        db.query_row(
            &format!("SELECT \"notnull\" FROM pragma_table_info('{table}') WHERE name=?1"),
            [column],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert_eq!(not_null("roles", "name"), 0);
    assert_eq!(not_null("role_permissions", "role"), 1);
    db.execute("INSERT INTO roles(name,created_at) VALUES (NULL,1)", [])
        .unwrap();
    db.execute("INSERT INTO roles(name,created_at) VALUES (NULL,2)", [])
        .unwrap();
    let null_keys: i64 = db
        .query_row("SELECT COUNT(*) FROM roles WHERE name IS NULL", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(null_keys, 2);
    let error = db
        .execute(
            "INSERT INTO role_permissions(role,action) VALUES (NULL,'session.read')",
            [],
        )
        .unwrap_err();
    assert_eq!(
        error.sqlite_error().unwrap().extended_code,
        rusqlite::ffi::SQLITE_CONSTRAINT_NOTNULL
    );
    assert!(!Table::Roles.mysql_shape().columns()[0].nullable());
    assert!(!Table::Roles.definition().columns()[0].declared_not_null());
}

#[test]
fn typed_dialects_preserve_large_text_empty_defaults_and_utf8_capacities() {
    use broker_store::schema::{ColumnDefault, ColumnType};
    let cache = Table::EmbeddingCache.definition();
    assert_eq!(
        cache.columns().last().unwrap().column_type(),
        ColumnType::LargeText
    );
    assert!(
        Table::EmbeddingCache
            .create_statement(Dialect::Mysql)
            .contains("embedding_json LONGTEXT NOT NULL")
    );
    for dialect in [Dialect::Sqlite, Dialect::Postgres] {
        assert!(
            Table::EmbeddingCache
                .create_statement(dialect)
                .contains("embedding_json TEXT NOT NULL")
        );
        assert!(
            !Table::EmbeddingCache
                .create_statement(dialect)
                .contains("LONGTEXT")
        );
    }
    let cache_shape = Table::EmbeddingCache.mysql_shape();
    assert_eq!(
        cache_shape
            .columns()
            .last()
            .unwrap()
            .character_maximum_length(),
        Some(4_294_967_295)
    );
    assert_eq!(
        cache_shape.columns()[2].character_maximum_length(),
        Some(65_535)
    );
    assert_eq!(
        cache_shape.columns()[2].character_octet_length(),
        Some(65_535)
    );
    let tokens = Table::LocalTokens.definition();
    let resource = tokens
        .columns()
        .iter()
        .find(|column| column.name() == "resource")
        .unwrap();
    assert_eq!(resource.default(), ColumnDefault::EmptyString);
    let token_shape = Table::LocalTokens.mysql_shape();
    let physical = token_shape
        .columns()
        .iter()
        .find(|column| column.name() == "resource")
        .unwrap();
    assert_eq!(physical.column_default(), Some(""));
    assert_eq!(physical.character_maximum_length(), Some(512));
    assert_eq!(physical.character_octet_length(), Some(2048));
    assert_eq!(physical.character_set(), Some("utf8mb4"));
    assert_eq!(physical.collation(), Some("utf8mb4_bin"));
    assert_eq!(token_shape.columns()[0].column_default(), None);
}

#[test]
fn instance_inventory_enforces_identity_positions_and_cascade() {
    let db = database();
    assert!(
        db.execute(
            "INSERT INTO broker_instances VALUES (NULL,'issuer','subject',1,1)",
            []
        )
        .is_err()
    );
    assert!(db.execute("INSERT INTO broker_instance_project_versions VALUES ('absent','01KSH1CRFFG8Z74B5ZS78WW808',1,'main')", []).is_err());
    db.execute(
        "INSERT INTO broker_instances VALUES ('instance','https://issuer.example','Subject ',1,2)",
        [],
    )
    .unwrap();
    assert!(
        db.execute(
            "INSERT INTO broker_instances VALUES ('instance','another','subject',3,3)",
            []
        )
        .is_err()
    );
    let version = "界😀".repeat(10_000);
    db.execute("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',1,?1)", [&version]).unwrap();
    let actual: (String, String, i64, i64, String) = db.query_row("SELECT i.owner_issuer,i.owner_subject,i.created_at,i.updated_at,v.version FROM broker_instances i JOIN broker_instance_project_versions v USING(instance_id)", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(
        actual,
        (
            "https://issuer.example".into(),
            "Subject ".into(),
            1,
            2,
            version
        )
    );
    for position in [0, -1, 1] {
        assert!(db.execute("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',?1,'main')", [position]).is_err());
    }
    db.execute("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',2,'main')", []).unwrap();
    db.execute(
        "DELETE FROM broker_instance_project_versions WHERE instance_id='instance'",
        [],
    )
    .unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM broker_instances", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    db.execute("INSERT INTO broker_instance_project_versions VALUES ('instance','01KSH1CRFFG8Z74B5ZS78WW808',1,'main')", []).unwrap();
    db.execute(
        "DELETE FROM broker_instances WHERE instance_id='instance'",
        [],
    )
    .unwrap();
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM broker_instance_project_versions",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
}
