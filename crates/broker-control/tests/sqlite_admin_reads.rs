#[path = "support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine ingress fixtures serve multiple targets"
)]
mod ingress;

#[path = "support/sqlite_admin_fixture.rs"]
mod fixture;

use broker_control::{
    AdminBrokerSessionError as AuthError, AdminReadError as Error, AdminReadKind as Kind,
    AdminReadLimits, AdminReadRequest as Request, AdminReadResult, BrokerAccessError, ControlError,
};
use fixture::{Fixture, end, limits, n, now};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const KINDS: [Kind; 7] = [
    Kind::Projects,
    Kind::Roles,
    Kind::Assignments,
    Kind::Users,
    Kind::Principals,
    Kind::Grants,
    Kind::Configuration,
];
fn read_limits() -> AdminReadLimits {
    AdminReadLimits {
        authorization: limits(),
        grants_json_bytes: n(65536),
        response_json_bytes: n(65536),
    }
}
fn request(kind: Kind) -> Request<'static> {
    match kind {
        Kind::Projects => Request::Projects {
            provider_command: "literal provider command",
        },
        Kind::Roles => Request::Roles,
        Kind::Assignments => Request::Assignments,
        Kind::Users => Request::Users,
        Kind::Principals => Request::Principals,
        Kind::Grants => Request::Grants,
        Kind::Configuration => Request::Configuration {
            yaml: "storage:\n  secret: '[configured-secret]'\n",
        },
    }
}
fn action(db: &Connection, value: &str) {
    db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    db.execute(
        "INSERT INTO role_permissions(role,action) VALUES('user',?1)",
        [value],
    )
    .unwrap();
}
fn normalize(db: &Connection) {
    db.execute("UPDATE local_users SET teams_json='[\"a\",\"z\"]'", [])
        .unwrap();
}
async fn read(f: &Fixture, raw: &str, kind: Kind) -> Result<AdminReadResult<'static>, Error> {
    f.store
        .local_admin_reads(read_limits())
        .unwrap()
        .read_opaque(
            raw,
            "admin-api",
            n(8192),
            &["admin:session".into()],
            request(kind),
            end(),
        )
        .await
}
fn value(result: &AdminReadResult<'_>) -> Value {
    result.check().unwrap();
    serde_json::from_slice(result.body()).unwrap()
}
fn grant(
    db: &Connection,
    id: &str,
    access: &str,
    principal: &str,
    capabilities: &[&str],
    projects: &[&str],
) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,?1,?2,?3,'',0,0)",params![id,access,principal]).unwrap();
    for capability in capabilities {
        db.execute(
            "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
            params![id, capability],
        )
        .unwrap();
    }
    for project in projects {
        db.execute(
            "INSERT INTO grant_projects(grant_id,value) VALUES(?1,?2)",
            params![id, project],
        )
        .unwrap();
    }
}

#[tokio::test]
async fn seven_actions_are_independent_for_real_human_and_service_bearers() {
    let f = Fixture::new().await;
    let db = f.db();
    normalize(&db);
    for (kind, permission) in [
        (Kind::Projects, "projects.read"),
        (Kind::Roles, "roles.read"),
        (Kind::Assignments, "roles.read"),
        (Kind::Users, "users.read"),
        (Kind::Principals, "grants.read"),
        (Kind::Grants, "grants.read"),
        (Kind::Configuration, "configuration.read"),
    ] {
        action(&db, permission);
        for raw in [&f.access, &f.service] {
            let result = read(&f, raw, kind).await.unwrap();
            assert!(value(&result).is_object());
            assert_eq!(format!("{result:?}"), "AdminReadResult([REDACTED])");
        }
        action(&db, "session.read");
        assert_eq!(
            read(&f, &f.access, kind).await.unwrap_err(),
            Error::Authorization(AuthError::Forbidden)
        );
    }
    // These genuine credentials were issued to users whose password-change flag
    // remains set. That flag is a cookie/login constraint, not an opaque gate.
    assert_eq!(
        db.query_row(
            "SELECT min(password_change_required) FROM local_users",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    action(&db, "*");
    for kind in KINDS {
        assert!(read(&f, &f.service, kind).await.is_ok());
    }
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn catalog_uses_complete_rules_raw_local_identity_and_current_snapshot() {
    let f = Fixture::new().await;
    let db = f.db();
    normalize(&db);
    action(&db, "*");
    let project = "01M1YEAE1WYMWG9KJKV1XQC4T4";
    let denied = "01KSH1CRFFG8Z74B5ZS78WW808";
    grant(
        &db,
        "one",
        "user",
        "alice",
        &["h*", "presence:read"],
        &[project],
    );
    grant(
        &db,
        "two",
        "subject",
        "local|alice-subject",
        &["hub", "s3:read"],
        &[project],
    );
    grant(
        &db,
        "foreign",
        "subject",
        "different-pseudonym",
        &["hub"],
        &[denied],
    );
    grant(&db, "literal", "team", "z*", &["hub"], &[denied]);
    grant(
        &db,
        "other-principal",
        "user",
        "someone",
        &["hub"],
        &[denied],
    );
    grant(
        &db,
        "other-capability",
        "user",
        "alice",
        &["presence:read"],
        &[denied],
    );
    db.execute("UPDATE resource_acl_state SET revision=7,updated_at=0", [])
        .unwrap();
    let p = value(&read(&f, &f.access, Kind::Projects).await.unwrap());
    assert_eq!(
        p,
        json!({"projects":[{"id":project,"capabilities":["h*","hub","presence:read","s3:read"]}],"all_projects":false,"authorization_revision":7,"provider_command":"literal provider command"})
    );
    grant(&db, "empty", "authenticated", "", &["hub"], &[]);
    assert_eq!(
        value(&read(&f, &f.access, Kind::Projects).await.unwrap())["all_projects"],
        true
    );
    db.execute("DELETE FROM resource_grants WHERE id='empty'", [])
        .unwrap();
    grant(&db, "wildcard", "authenticated", "", &["hub"], &["*"]);
    assert_eq!(
        value(&read(&f, &f.access, Kind::Projects).await.unwrap())["all_projects"],
        true
    );
    db.execute(
        "UPDATE resource_grants SET principal='current' WHERE id='literal'",
        [],
    )
    .unwrap();
    db.execute(
        "UPDATE local_users SET teams_json='[\"current\"]' WHERE username='alice'",
        [],
    )
    .unwrap();
    let p = value(&read(&f, &f.access, Kind::Projects).await.unwrap());
    assert!(
        p["projects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == denied)
    );
    let mut snapshot_cap = read_limits();
    snapshot_cap.grants_json_bytes = n(2);
    for kind in [Kind::Projects, Kind::Grants] {
        // Change only the ACL byte ceiling. Both complete projections otherwise
        // succeed, so a mistaken response-cap substitution cannot pass this case.
        assert!(read(&f, &f.access, kind).await.is_ok());
        assert_eq!(
            f.store
                .local_admin_reads(snapshot_cap)
                .unwrap()
                .read_opaque(&f.access, "admin-api", n(8192), &[], request(kind), end())
                .await
                .unwrap_err(),
            Error::Projection(kind)
        );
    }
    db.execute(
        "UPDATE resource_grants SET access_kind='unknown' WHERE id='one'",
        [],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Projects).await.unwrap_err(),
        Error::Projection(Kind::Projects)
    );
    let grants = read(&f, &f.access, Kind::Grants).await.unwrap();
    let g = value(&grants);
    assert_eq!(grants.revision(), Some(7));
    assert_eq!(g["v"], 1);
    assert_eq!(g["updated_at"], "1970-01-01T00:00:00Z");
    let first = g["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == "one")
        .unwrap();
    assert_eq!(first["access"], "unknown");
    assert!(first.get("access_kind").is_none());
    assert!(first.get("s3_route").is_none());
    assert!(first.get("s3_prefixes").is_none());
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn lists_preserve_unicode_assignments_empty_roles_and_secret_free_users() {
    let f = Fixture::new().await;
    let db = f.db();
    normalize(&db);
    action(&db, "*");
    db.execute("INSERT INTO roles(name,created_at) VALUES('empty',0)", [])
        .unwrap();
    let roles = value(&read(&f, &f.access, Kind::Roles).await.unwrap());
    assert!(
        roles["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "empty" && r["permissions"] == json!([]))
    );
    assert_eq!(roles["actions"].as_array().unwrap().len(), 9);
    assert!(!roles["actions"].as_array().unwrap().contains(&json!("*")));
    assert_eq!(
        value(&read(&f, &f.access, Kind::Assignments).await.unwrap()),
        json!({"assignments":[],"bootstrap_only":true})
    );
    let subject = format!(" {} ", "界".repeat(510));
    assert_eq!(subject.chars().count(), 512);
    assert!(subject.len() > 512);
    db.execute(
        "INSERT INTO role_assignments(subject,role,created_at) VALUES(?1,'empty',0)",
        [&subject],
    )
    .unwrap();
    let assignments = value(&read(&f, &f.access, Kind::Assignments).await.unwrap());
    assert_eq!(assignments["bootstrap_only"], false);
    assert_eq!(assignments["assignments"][0]["subject"], subject);
    assert_eq!(
        assignments["assignments"][0]["created_at"],
        "1970-01-01T00:00:00Z"
    );
    db.execute(
        "INSERT INTO role_assignments(subject,role,created_at) VALUES(?1,'empty',0)",
        ["界".repeat(513)],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Assignments).await.unwrap_err(),
        Error::Projection(Kind::Assignments)
    );
    db.execute("DELETE FROM role_assignments WHERE length(subject)>512", [])
        .unwrap();
    db.execute("UPDATE local_users SET enabled=0 WHERE username='bot'", [])
        .unwrap();
    db.execute("INSERT INTO local_mfa(subject,secret_ciphertext,last_totp_step,confirmed_at) VALUES('bot-subject',?1,0,1)",[format!("{:0<90}","synthetic-factor-must-not-be-selected")]).unwrap();
    db.execute("INSERT INTO local_mfa_recovery_codes(subject,code_hash,created_at) VALUES('bot-subject',?1,0)",["a".repeat(64)]).unwrap();
    let users = read(&f, &f.access, Kind::Users).await.unwrap();
    let u = value(&users);
    assert_eq!(u["users"][0]["username"], "alice");
    assert_eq!(u["users"][1]["username"], "bot");
    assert_eq!(u["users"][1]["kind"], "service");
    assert_eq!(u["users"][1]["enabled"], false);
    assert_eq!(u["users"][1]["mfa_enabled"], true);
    assert_eq!(u["users"][0]["mfa_enabled"], false);
    assert_eq!(u["users"][0]["roles"], json!(["user"]));
    assert_eq!(u["users"][0]["password_change_required"], true);
    let text = std::str::from_utf8(users.body()).unwrap();
    for hidden in [
        "password_hash",
        "not-selected",
        "secret_ciphertext",
        "synthetic-factor",
        "code_hash",
    ] {
        assert!(!text.contains(hidden));
    }
    assert!(!text.contains(&"a".repeat(64)));
    let hints = value(&read(&f, &f.access, Kind::Principals).await.unwrap());
    assert_eq!(hints["principals"][0]["type"], "anonymous");
    assert_eq!(hints["principals"][1]["type"], "authenticated");
    assert_eq!(hints["principals"][2]["id"], "alice-subject");
    assert_eq!(hints["principals"][3]["id"], "bot-subject");
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn whole_projection_caps_dynamic_types_and_clocks_fail_closed() {
    let f = Fixture::new().await;
    let db = f.db();
    normalize(&db);
    action(&db, "*");
    for kind in KINDS {
        let result = read(&f, &f.access, kind).await.unwrap();
        let exact = result.body().len();
        let mut cap = read_limits();
        cap.response_json_bytes = n(exact);
        // Principals share the complete, capped user aggregate. Its intermediate
        // representation may exceed the smaller hint response, just as in PG.
        if kind != Kind::Principals {
            assert!(
                f.store
                    .local_admin_reads(cap)
                    .unwrap()
                    .read_opaque(&f.access, "admin-api", n(8192), &[], request(kind), end())
                    .await
                    .is_ok()
            );
        }
        cap.response_json_bytes = n(exact - 1);
        assert_eq!(
            f.store
                .local_admin_reads(cap)
                .unwrap()
                .read_opaque(&f.access, "admin-api", n(8192), &[], request(kind), end())
                .await
                .unwrap_err(),
            Error::Projection(kind)
        );
    }
    db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    db.execute(
        "INSERT INTO roles(name,created_at) VALUES(?1,0)",
        [vec![0xffu8]],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Roles).await.unwrap_err(),
        Error::Projection(Kind::Roles)
    );
    db.execute("DELETE FROM roles WHERE typeof(name)='blob'", [])
        .unwrap();
    db.execute_batch("INSERT INTO roles(name,created_at) VALUES('corrupt',0);INSERT INTO role_permissions(role,action) VALUES('corrupt','unknown');").unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Roles).await.unwrap_err(),
        Error::Projection(Kind::Roles)
    );
    db.execute("DELETE FROM role_permissions WHERE role='corrupt'", [])
        .unwrap();
    db.execute("DELETE FROM roles WHERE name='corrupt'", [])
        .unwrap();
    db.execute(
        "INSERT INTO role_assignments(subject,role,created_at) VALUES('literal','user',-1)",
        [],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Assignments).await.unwrap_err(),
        Error::Projection(Kind::Assignments)
    );
    db.execute("DELETE FROM role_assignments WHERE subject='literal'", [])
        .unwrap();
    for (sql, reset) in [
        (
            "UPDATE local_users SET enabled=2 WHERE username='bot'",
            "UPDATE local_users SET enabled=1 WHERE username='bot'",
        ),
        (
            "UPDATE local_users SET updated_at=-1 WHERE username='bot'",
            "UPDATE local_users SET updated_at=0 WHERE username='bot'",
        ),
        (
            "UPDATE local_users SET teams_json='not JSON' WHERE username='bot'",
            "UPDATE local_users SET teams_json='[]' WHERE username='bot'",
        ),
    ] {
        db.execute(sql, []).unwrap();
        assert_eq!(
            read(&f, &f.access, Kind::Users).await.unwrap_err(),
            Error::Projection(Kind::Users)
        );
        assert_eq!(
            read(&f, &f.access, Kind::Principals).await.unwrap_err(),
            Error::Projection(Kind::Principals)
        );
        db.execute(reset, []).unwrap();
    }
    db.execute(
        "UPDATE local_users SET name=?1 WHERE username='bot'",
        [vec![0xffu8]],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Users).await.unwrap_err(),
        Error::Projection(Kind::Users)
    );
    db.execute(
        "UPDATE local_users SET name='Current' WHERE username='bot'",
        [],
    )
    .unwrap();
    db.execute("UPDATE resource_acl_state SET revision=0", [])
        .unwrap();
    assert_eq!(
        read(&f, &f.access, Kind::Grants).await.unwrap_err(),
        Error::Projection(Kind::Grants)
    );
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn current_identity_revocation_deadlines_closed_store_and_retained_factor_are_real() {
    let f = Fixture::new().await;
    let db = f.db();
    normalize(&db);
    action(&db, "*");
    for sql in [
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        "UPDATE local_users SET revision=2 WHERE username='alice'",
    ] {
        db.execute(sql, []).unwrap();
        assert_eq!(
            read(&f, &f.access, Kind::Roles).await.unwrap_err(),
            Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken))
        );
        db.execute(
            "UPDATE local_users SET enabled=1,revision=1 WHERE username='alice'",
            [],
        )
        .unwrap();
    }
    db.execute(
        "UPDATE local_tokens SET revoked_at=?1 WHERE token_kind='access'",
        [now()],
    )
    .unwrap();
    assert!(read(&f, &f.access, Kind::Roles).await.is_err());
    db.execute(
        "UPDATE local_tokens SET revoked_at=NULL WHERE token_kind='access'",
        [],
    )
    .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let denied = f
        .store
        .local_admin_reads(read_limits())
        .unwrap()
        .read_opaque(
            &f.access,
            "admin-api",
            n(8192),
            &[],
            Request::Roles,
            Instant::now() + Duration::from_millis(30),
        )
        .await
        .unwrap_err();
    assert_eq!(
        denied,
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    db.execute_batch("ROLLBACK").unwrap();
    let cutoff = Instant::now() + Duration::from_millis(500);
    db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_kind='access'",
        [now() + 250_000],
    )
    .unwrap();
    let protected = read(&f, &f.access, Kind::Roles).await.unwrap();
    tokio::time::sleep_until(cutoff.into()).await;
    assert_eq!(
        protected.check().unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::Expired))
    );
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        read(&f, &f.service, Kind::Roles).await.unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Closed))
    );
}

fn replace_snapshot(db: &mut Connection, revision: i64) {
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    action(
        &tx,
        if revision % 2 == 0 {
            "projects.read"
        } else {
            "roles.read"
        },
    );
    for table in [
        "grant_capabilities",
        "grant_projects",
        "grant_s3_operations",
        "grant_s3_prefixes",
    ] {
        tx.execute(&format!("DELETE FROM {table}"), []).unwrap();
    }
    tx.execute("DELETE FROM resource_grants", []).unwrap();
    let marker = if revision % 2 == 0 { "even" } else { "odd" };
    let project = if revision % 2 == 0 {
        "01M1YEAE1WYMWG9KJKV1XQC4T4"
    } else {
        "01KSH1CRFFG8Z74B5ZS78WW808"
    };
    grant(
        &tx,
        marker,
        "subject",
        "local|alice-subject",
        &["hub"],
        &[project],
    );
    tx.execute(
        "UPDATE resource_acl_state SET revision=?1,updated_at=?1",
        [revision],
    )
    .unwrap();
    tx.commit().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_physical_owners_keep_action_and_acl_projection_in_one_snapshot() {
    use broker_control::{FlowLimits, SqliteControlConfig, SqliteControlStore};
    use broker_security::{CredentialDigester, DigestLimits};
    use std::sync::{Arc, Barrier};
    use zeroize::Zeroizing;
    let f = Fixture::new().await;
    let mut db = f.db();
    normalize(&db);
    replace_snapshot(&mut db, 10);
    let other = SqliteControlStore::open(
        SqliteControlConfig::new(
            f.path.clone(),
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n(128),
                request_bytes: n(256),
                continuation_bytes: n(1024),
            },
        )
        .unwrap(),
        CredentialDigester::new(
            Zeroizing::new(vec![71; 32].into_boxed_slice()),
            DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
        )
        .unwrap(),
        end(),
    )
    .await
    .unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let ready = barrier.clone();
    let path = f.path.clone();
    let writer = std::thread::spawn(move || {
        let mut db = Connection::open(path).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        ready.wait();
        for revision in 11..=30 {
            replace_snapshot(&mut db, revision);
        }
    });
    barrier.wait();
    for _ in 0..25 {
        match read(&f, &f.access, Kind::Projects).await {
            Ok(result) => {
                let p = value(&result);
                assert_eq!(p["authorization_revision"].as_i64().unwrap() % 2, 0);
                assert_eq!(p["projects"][0]["id"], "01M1YEAE1WYMWG9KJKV1XQC4T4");
            }
            Err(Error::Authorization(AuthError::Forbidden)) => {}
            Err(error) => panic!("unexpected snapshot result: {error:?}"),
        }
        let snapshot = other
            .resource_grants(n(65536))
            .unwrap()
            .read(end())
            .await
            .unwrap();
        assert_eq!(snapshot.rules().len(), 1);
        assert_eq!(
            snapshot.rules()[0].id(),
            if snapshot.revision() % 2 == 0 {
                "even"
            } else {
                "odd"
            }
        );
    }
    writer.join().unwrap();
    assert_eq!(
        value(&read(&f, &f.access, Kind::Projects).await.unwrap())["authorization_revision"],
        30
    );
    other.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native Argon2 login and genuine LOCAL administrative cookie"]
async fn genuine_cookie_authorizes_each_read_without_session_read_and_checks_current_state() {
    use broker_control::{
        AdminCookieSessionLimits, AdminCookieSessionPolicy, FlowLimits, LocalAuthPolicy,
        LocalAuthStep, LocalPasswordEngine, PreparedAdminLogin, SessionLimits, SqliteControlConfig,
        SqliteControlStore,
    };
    use broker_security::{
        CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
    };
    use std::sync::Arc;
    use zeroize::Zeroizing;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private/broker.db");
    let digester = || {
        CredentialDigester::new(
            Zeroizing::new(vec![41; 32].into_boxed_slice()),
            DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
        )
        .unwrap()
    };
    let store = SqliteControlStore::open(
        SqliteControlConfig::new(
            path.clone(),
            Duration::from_secs(5),
            Duration::from_secs(10),
            Duration::from_secs(5),
            FlowLimits {
                provider_bytes: n(128),
                request_bytes: n(1024),
                continuation_bytes: n(4096),
            },
        )
        .unwrap(),
        digester(),
        end(),
    )
    .await
    .unwrap();
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "foreign_keys", true).unwrap();
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(vec![43; 32].into_boxed_slice())).unwrap(),
        n(1),
        end(),
    )
    .await
    .unwrap();
    let password = "synthetic AdminReads cookie password";
    let hash = engine.hash(password, end()).await.unwrap();
    db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',?1,'Current','','org','[]',1,0,1,0,0)",[hash.as_str()]).unwrap();
    action(&db, "session.read");
    let d = Arc::new(digester());
    let policy = Arc::new(
        LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120)).unwrap(),
    );
    let factor =
        Arc::new(LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap());
    let possession = store
        .local_password_verifier(&engine)
        .verify("alice", password, end())
        .await
        .unwrap();
    let login = match store
        .local_auth_service(d, factor, policy.clone())
        .begin(possession, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    {
        LocalAuthStep::Complete(login) => login,
        _ => panic!("genuine completed LOCAL login expected"),
    };
    let cookie_limits = AdminCookieSessionLimits {
        authorization: limits(),
        metadata: SessionLimits {
            text_bytes: n(2048),
            csrf_bytes: n(43),
            team_bytes: n(512),
            role_bytes: n(128),
            max_teams: n(16),
            max_roles: n(16),
            teams_json_bytes: n(8192),
            roles_json_bytes: n(8192),
            max_lifetime: Duration::from_secs(3600),
        },
    };
    let cookie_policy = AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(600),
    };
    let issued = store
        .local_admin_cookie_sessions(cookie_limits, cookie_policy)
        .unwrap()
        .issue_local(PreparedAdminLogin::try_from(login).unwrap(), &policy, end())
        .await
        .unwrap();
    for (kind, permission) in [
        (Kind::Projects, "projects.read"),
        (Kind::Roles, "roles.read"),
        (Kind::Assignments, "roles.read"),
        (Kind::Users, "users.read"),
        (Kind::Principals, "grants.read"),
        (Kind::Grants, "grants.read"),
        (Kind::Configuration, "configuration.read"),
    ] {
        action(&db, permission);
        let result = store
            .local_admin_reads(read_limits())
            .unwrap()
            .read_cookie(
                issued.secret(),
                cookie_limits,
                cookie_policy,
                request(kind),
                end(),
            )
            .await
            .unwrap();
        assert!(value(&result).is_object());
        action(&db, "session.read");
        assert_eq!(
            store
                .local_admin_reads(read_limits())
                .unwrap()
                .read_cookie(
                    issued.secret(),
                    cookie_limits,
                    cookie_policy,
                    request(kind),
                    end()
                )
                .await
                .unwrap_err(),
            Error::Authorization(AuthError::Forbidden)
        );
    }
    action(&db, "*");
    let mut mismatch = cookie_limits;
    mismatch.authorization.profile_json_bytes = n(8191);
    assert_eq!(
        store
            .local_admin_reads(read_limits())
            .unwrap()
            .read_cookie(
                issued.secret(),
                mismatch,
                cookie_policy,
                Request::Roles,
                end()
            )
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Configuration))
    );
    for sql in [
        "UPDATE local_users SET password_change_required=1",
        "UPDATE local_users SET revision=2",
        "UPDATE local_users SET enabled=0",
    ] {
        db.execute(sql, []).unwrap();
        assert_eq!(
            store
                .local_admin_reads(read_limits())
                .unwrap()
                .read_cookie(
                    issued.secret(),
                    cookie_limits,
                    cookie_policy,
                    Request::Roles,
                    end()
                )
                .await
                .unwrap_err(),
            Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken))
        );
        db.execute(
            "UPDATE local_users SET password_change_required=0,revision=1,enabled=1",
            [],
        )
        .unwrap();
    }
    db.execute("UPDATE admin_sessions SET expires_at=?1", [now() - 1])
        .unwrap();
    assert!(
        store
            .local_admin_reads(read_limits())
            .unwrap()
            .read_cookie(
                issued.secret(),
                cookie_limits,
                cookie_policy,
                Request::Roles,
                end()
            )
            .await
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM admin_sessions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    engine.close().await;
    store.shutdown(end()).await.unwrap();
}

async fn full_read<'a>(
    f: &ingress::fixture::Fixture,
    auth: broker_control::AdminReadAuthentication<'a, '_>,
    kind: Kind,
) -> Result<AdminReadResult<'a>, Error> {
    f.store
        .admin_reads(AdminReadLimits {
            authorization: ingress::limits().authorization,
            ..read_limits()
        })
        .unwrap()
        .read(auth, request(kind), end())
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine signed Broker JWT, HTTPS F1 and browser H2 with native SQLite"]
async fn full_ingresses_authorize_each_projection_without_session_lease() {
    use broker_control::{AdminReadAuthentication as A, FlowPurpose};
    let f = ingress::fixture::Fixture::new().await;
    normalize(&f.db);
    ingress::allow_session(&f);
    let jwt = ingress::jwt(&f).await;
    let verifier = f.verifier();
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let mut op = ingress::browser_op().await;
    let mut bearer_config = ingress::config(&bearer.issuer, &bearer.ca, false, Some("roles"));
    bearer_config.id = "bearer".into();
    let trust = ingress::trust(vec![
        ingress::config(&op.issuer, &op.ca, true, Some("roles")),
        bearer_config,
    ]);
    let raw = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    let login = ingress::h1(&f, &op, &trust, FlowPurpose::Admin, end()).await;
    let cookie = f
        .store
        .admin_cookie_sessions(ingress::limits(), ingress::policy(), Some(trust.clone()))
        .unwrap()
        .issue_upstream(login, end())
        .await
        .unwrap();
    let network = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    for (kind, permission) in [
        (Kind::Projects, "projects.read"),
        (Kind::Roles, "roles.read"),
        (Kind::Assignments, "roles.read"),
        (Kind::Users, "users.read"),
        (Kind::Principals, "grants.read"),
        (Kind::Grants, "grants.read"),
        (Kind::Configuration, "configuration.read"),
    ] {
        for (permission, allowed) in [(permission, true), ("session.read", false)] {
            action(&f.db, permission);
            let results = [
                full_read(
                    &f,
                    A::Broker {
                        verifier: &verifier,
                        proof: verifier.verify(&jwt, &[], end()).unwrap(),
                    },
                    kind,
                )
                .await,
                full_read(
                    &f,
                    A::Upstream {
                        raw: &raw,
                        verifier: &trust,
                    },
                    kind,
                )
                .await,
                full_read(
                    &f,
                    A::Cookie {
                        raw: cookie.secret(),
                        limits: ingress::limits(),
                        policy: ingress::policy(),
                        upstream: Some(trust.clone()),
                    },
                    kind,
                )
                .await,
            ];
            for result in results {
                if allowed {
                    assert!(value(&result.unwrap()).is_object());
                } else {
                    assert_eq!(
                        result.unwrap_err(),
                        Error::Authorization(AuthError::Forbidden)
                    );
                }
            }
        }
    }
    action(&f.db, "*");
    for kind in KINDS {
        full_read(
            &f,
            A::Broker {
                verifier: &verifier,
                proof: verifier.verify(&jwt, &[], end()).unwrap(),
            },
            kind,
        )
        .await
        .unwrap();
        full_read(
            &f,
            A::Upstream {
                raw: &raw,
                verifier: &trust,
            },
            kind,
        )
        .await
        .unwrap();
        full_read(
            &f,
            A::Cookie {
                raw: cookie.secret(),
                limits: ingress::limits(),
                policy: ingress::policy(),
                upstream: Some(trust.clone()),
            },
            kind,
        )
        .await
        .unwrap();
    }
    // The JWT predates the SQL identity and ACL update. Raw LOCAL identity must win.
    let project = "01M1YEAE1WYMWG9KJKV1XQC4T4";
    f.db.execute("UPDATE local_users SET name='Current SQL',teams_json='[\"current-team\"]' WHERE username='alice'",[]).unwrap();
    grant(
        &f.db,
        "jwt-current",
        "team",
        "current-team",
        &["hub"],
        &[project],
    );
    f.db.execute("UPDATE resource_acl_state SET revision=9", [])
        .unwrap();
    let observed = full_read(
        &f,
        A::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        Kind::Projects,
    )
    .await
    .unwrap();
    assert_eq!(value(&observed)["authorization_revision"], 9);
    assert_eq!(value(&observed)["projects"][0]["id"], project);
    // F1 username alice is external; it must not inherit the LOCAL SQL team.
    let external = full_read(
        &f,
        A::Upstream {
            raw: &raw,
            verifier: &trust,
        },
        Kind::Projects,
    )
    .await
    .unwrap();
    assert_eq!(value(&external)["projects"], json!([]));
    assert_eq!(
        network,
        (op.token_hits(), op.userinfo_hits(), op.jwks_hits())
    );
    f.store.shutdown(end()).await.unwrap();
    bearer.close().await;
    op.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "current SQL role definitions and genuine HTTPS/browser trust replacement"]
async fn full_external_roles_and_cookie_trust_are_current() {
    use broker_control::{AdminReadAuthentication as A, FlowPurpose};
    let f = ingress::fixture::Fixture::new().await;
    normalize(&f.db);
    ingress::allow_session(&f);
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let mut op = ingress::browser_op().await;
    let configured = ingress::trust(vec![ingress::config(
        &op.issuer,
        &op.ca,
        true,
        Some("roles"),
    )]);
    let login = ingress::h1(&f, &op, &configured, FlowPurpose::Admin, end()).await;
    let cookie_subject = format!("{}|{}", op.issuer, login.profile().subject);
    let cookie = f
        .store
        .admin_cookie_sessions(
            ingress::limits(),
            ingress::policy(),
            Some(configured.clone()),
        )
        .unwrap()
        .issue_upstream(login, end())
        .await
        .unwrap();
    let trust = ingress::trust(vec![ingress::config(
        &bearer.issuer,
        &bearer.ca,
        false,
        Some("roles"),
    )]);
    let mut claims = bearer.claims();
    claims["sub"] = json!("subject-for-assignment");
    let bearer_subject = format!("{}|subject-for-assignment", bearer.issuer);
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='user';INSERT INTO roles(name,created_at)VALUES('assigned',0);INSERT INTO role_permissions(role,action)VALUES('assigned','roles.read')").unwrap();
    for subject in [&cookie_subject, &bearer_subject] {
        f.db.execute(
            "INSERT INTO role_assignments(subject,role,created_at)VALUES(?1,'assigned',0)",
            [subject],
        )
        .unwrap();
    }
    claims["roles"] = json!([]);
    let empty = bearer.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        full_read(
            &f,
            A::Upstream {
                raw: &empty,
                verifier: &trust
            },
            Kind::Roles
        )
        .await
        .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    claims["roles"] = json!(["unknown"]);
    let unknown = bearer.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        full_read(
            &f,
            A::Upstream {
                raw: &unknown,
                verifier: &trust
            },
            Kind::Roles
        )
        .await
        .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    let no_selector = ingress::trust(vec![ingress::config(
        &bearer.issuer,
        &bearer.ca,
        false,
        None,
    )]);
    full_read(
        &f,
        A::Upstream {
            raw: &empty,
            verifier: &no_selector,
        },
        Kind::Roles,
    )
    .await
    .unwrap();
    let cookie_read = |upstream| A::Cookie {
        raw: cookie.secret(),
        limits: ingress::limits(),
        policy: ingress::policy(),
        upstream: Some(upstream),
    };
    assert_eq!(
        full_read(&f, cookie_read(configured.clone()), Kind::Roles)
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    f.db.execute_batch("INSERT INTO roles(name,created_at)VALUES('unknown',0);INSERT INTO role_permissions(role,action)VALUES('unknown','roles.read')").unwrap();
    full_read(
        &f,
        A::Upstream {
            raw: &unknown,
            verifier: &trust,
        },
        Kind::Roles,
    )
    .await
    .unwrap();
    full_read(&f, cookie_read(configured.clone()), Kind::Roles)
        .await
        .unwrap();
    let network = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    let no_browser = ingress::trust(vec![ingress::config(
        &op.issuer,
        &op.ca,
        false,
        Some("roles"),
    )]);
    full_read(&f, cookie_read(no_browser), Kind::Roles)
        .await
        .unwrap();
    f.db.execute("DELETE FROM role_permissions WHERE role='unknown'", [])
        .unwrap();
    assert_eq!(
        full_read(&f, cookie_read(configured.clone()), Kind::Roles)
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    let removed_selector = ingress::trust(vec![ingress::config(&op.issuer, &op.ca, false, None)]);
    full_read(&f, cookie_read(removed_selector), Kind::Roles)
        .await
        .unwrap();
    for changed in [
        ingress::trust(vec![ingress::config(
            &op.issuer,
            &op.ca,
            true,
            Some("other_roles"),
        )]),
        ingress::trust(vec![]),
    ] {
        assert!(
            full_read(&f, cookie_read(changed), Kind::Roles)
                .await
                .is_err()
        );
    }
    assert_eq!(
        network,
        (op.token_hits(), op.userinfo_hits(), op.jwks_hits())
    );
    f.store.shutdown(end()).await.unwrap();
    bearer.close().await;
    op.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native SQLite contention with genuine JWT/F1 and competing projection failure"]
async fn full_ingresses_keep_original_and_proof_expiry_ahead_of_projection_error() {
    use broker_control::AdminReadAuthentication as A;
    use std::time::SystemTime;
    let f = ingress::fixture::Fixture::new().await;
    normalize(&f.db);
    let jwt = ingress::jwt(&f).await;
    let verifier = f.verifier();
    action(&f.db, "projects.read");
    f.db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    f.db.execute("UPDATE resource_acl_state SET revision=0", [])
        .unwrap();
    let reader = f
        .store
        .admin_reads(AdminReadLimits {
            authorization: ingress::limits().authorization,
            ..read_limits()
        })
        .unwrap();
    let auth = || A::Broker {
        verifier: &verifier,
        proof: verifier.verify(&jwt, &[], end()).unwrap(),
    };
    assert_eq!(
        reader
            .read(auth(), request(Kind::Projects), end())
            .await
            .unwrap_err(),
        Error::Projection(Kind::Projects)
    );
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = reader
        .read(
            auth(),
            request(Kind::Projects),
            Instant::now() + Duration::from_millis(150),
        )
        .await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let trust = ingress::trust(vec![ingress::config(
        &bearer.issuer,
        &bearer.ca,
        false,
        None,
    )]);
    let mut claims = bearer.claims();
    claims["exp"] = json!(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2
    );
    let raw = bearer.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        reader
            .read(
                A::Upstream {
                    raw: &raw,
                    verifier: &trust
                },
                request(Kind::Projects),
                end()
            )
            .await
            .unwrap_err(),
        Error::Projection(Kind::Projects)
    );
    // Lock acquisition consumes the actual signed proof lifetime; no fake clock or proof.
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let read = reader.read(
        A::Upstream {
            raw: &raw,
            verifier: &trust,
        },
        request(Kind::Projects),
        end(),
    );
    let release = async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        f.db.execute_batch("ROLLBACK").unwrap();
    };
    let (result, ()) = tokio::join!(read, release);
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::Expired))
    );
    let fresh = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    assert_eq!(
        reader
            .read(
                A::Upstream {
                    raw: &fresh,
                    verifier: &trust
                },
                request(Kind::Projects),
                end()
            )
            .await
            .unwrap_err(),
        Error::Projection(Kind::Projects)
    );
    f.store.shutdown(end()).await.unwrap();
    bearer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine LOCAL cookie and causal native observer denial before expiry"]
async fn cookie_observer_late_rbac_denial_retains_the_loaded_session_cutoff() {
    use std::{
        future::Future,
        sync::Arc,
        task::{Context, Wake, Waker},
    };
    struct CompletionWake(tokio::sync::Notify);
    impl Wake for CompletionWake {
        fn wake(self: Arc<Self>) {
            self.0.notify_one();
        }
    }
    let f = ingress::fixture::Fixture::new().await;
    ingress::allow_session(&f);
    let issued = ingress::local_cookie(&f).await;
    let mut limits = read_limits();
    limits.authorization = ingress::limits().authorization;
    let reader = f.store.admin_reads(limits).unwrap();
    let authentication = || broker_control::AdminReadAuthentication::Cookie {
        raw: issued.secret(),
        limits: ingress::limits(),
        policy: ingress::policy(),
        upstream: None,
    };
    // session.read is present; roles.read is absent, so the negative result comes
    // from the shared observer after it has loaded the genuine SQL cookie window.
    assert_eq!(
        reader
            .read(authentication(), Request::Roles, end())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    let expiry = ingress::fixture::utc() + 2_000_000;
    let cutoff = Instant::now() + Duration::from_secs(2);
    f.db.execute("UPDATE admin_sessions SET expires_at=?1", [expiry])
        .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut future = Box::pin(reader.read(authentication(), Request::Roles, end()));
    let signal = Arc::new(CompletionWake(tokio::sync::Notify::new()));
    let waker = Waker::from(signal.clone());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    f.db.execute_batch("COMMIT").unwrap();
    tokio::time::timeout_at(cutoff.into(), signal.0.notified())
        .await
        .unwrap();
    assert!(
        Instant::now() < cutoff,
        "native denial must finish before cookie expiry"
    );
    tokio::time::sleep(
        cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(30),
    )
    .await;
    assert_eq!(
        future.await.unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken))
    );
    // Late denial neither issues nor disposes a cookie; cleanup still belongs to
    // the expired-session transaction on the next genuine observation.
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM admin_sessions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        reader
            .read(authentication(), Request::Roles, end())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken))
    );
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM admin_sessions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    f.engine.close().await;
    f.store.shutdown(end()).await.unwrap();
}
