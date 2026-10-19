use broker_control::{
    AdminSession, CleanupReason, FlowContinuation, FlowLimits, IdentityReadLimits,
    LocalIdentityKind, LocalIdentityRead, LocalIdentityReference, LocalIdentitySnapshot,
    LocalIdentityUnavailable, MySqlControlConfig, MySqlControlError, MySqlControlStore,
    MysqlAdmissionLimits, MysqlBudgets, MysqlCatalogLimits, MysqlConnectionLimits,
    MysqlCredentials, MysqlEndpoint, NewAdminSession, OidcFlow, RequiredCapability, SchemaReason,
    SessionClaimRoles, SessionLimits, SessionPrincipal, SessionProfile, SessionRevocation,
    SystemAction, SystemPermission, UnprovenReason,
};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use broker_store::schema::{Dialect, TABLES};
use futures_util::TryStreamExt;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use sqlx_core::{
    connection::{ConnectOptions, Connection},
    row::Row,
    sql_str::AssertSqlSafe,
};
use sqlx_mysql::{MySqlConnectOptions, MySqlConnection, MySqlSslMode};
use std::{
    fs,
    num::{NonZeroU16, NonZeroUsize},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context, SubscriberExt},
};
use zeroize::Zeroizing;

const IMAGE: &str = "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242";
const ACCOUNT: &str = "ordinary`@_%";
const PASSWORD: &str = "ephemeral-mysql-control-fixture";
const MYSQL_CONTROL_ORACLE: i64 = 25;
const MYSQL_SESSION_ORACLE: i64 = 3;
fn session_limits() -> SessionLimits {
    SessionLimits {
        text_bytes: n(16_384),
        csrf_bytes: n(512),
        team_bytes: n(100_000),
        role_bytes: n(512),
        max_teams: n(4096),
        max_roles: n(4096),
        teams_json_bytes: n(200_000),
        roles_json_bytes: n(200_000),
        max_lifetime: Duration::from_secs(7200),
    }
}
fn admin_input(ttl: Duration, claims: bool) -> NewAdminSession {
    admin_teams(
        ttl,
        claims,
        vec![
            " beta ".into(),
            "alpha".into(),
            "alpha".into(),
            String::new(),
        ],
    )
}
fn admin_teams(ttl: Duration, claims: bool, teams: Vec<String>) -> NewAdminSession {
    NewAdminSession::new(
        SessionProfile {
            subject: "synthetic-subject-ç".into(),
            name: String::new(),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: "https://synthetic-issuer.invalid".into(),
            username: "synthetic-user".into(),
            organization: String::new(),
            teams,
            local_user_revision: 7,
        },
        Zeroizing::new("synthetic-recoverable-csrf".into()),
        claims.then(|| SessionClaimRoles {
            selector: " roles ".into(),
            roles: vec![
                " opaque-role ".into(),
                "metadata-only".into(),
                "opaque-role".into(),
            ],
        }),
        SystemTime::now() + ttl,
        &session_limits(),
    )
    .unwrap()
}
fn session_hash(raw: &str) -> String {
    digester()
        .token(TokenKind::AdminSession, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
async fn session_rows(fixture: &Fixture, raw: &str) -> [i64; 3] {
    let hash = session_hash(raw);
    let mut rows = [0; 3];
    for (index, table) in [
        "admin_sessions",
        "admin_session_principals",
        "admin_session_claim_roles",
    ]
    .into_iter()
    .enumerate()
    {
        rows[index] = fixture
            .scalar(&format!(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.{table} WHERE token_hash='{hash}'"
            ))
            .await;
    }
    rows
}
fn assert_admin(session: &AdminSession, claims: bool) {
    assert_eq!(session.profile().subject, "synthetic-subject-ç");
    assert!(session.profile().name.is_empty());
    assert!(session.profile().email.is_empty());
    assert_eq!(
        session.principal().issuer,
        "https://synthetic-issuer.invalid"
    );
    assert_eq!(session.principal().username, "synthetic-user");
    assert!(session.principal().organization.is_empty());
    assert_eq!(session.principal().teams, ["alpha", "beta"]);
    assert_eq!(session.principal().local_user_revision, 7);
    assert_eq!(session.csrf_token(), "synthetic-recoverable-csrf");
    assert_eq!(session.claimed_roles().is_some(), claims);
    if let Some(roles) = session.claimed_roles() {
        assert_eq!(roles.selector, " roles ");
        assert_eq!(roles.roles, ["metadata-only", "opaque-role"]);
    }
    assert!(session.expires_at().as_i64() > session.created_at().as_i64());
    let debug = format!("{session:?}");
    for hidden in [
        "synthetic",
        "opaque-role",
        "alpha",
        "synthetic-recoverable-csrf",
    ] {
        assert!(!debug.contains(hidden), "session Debug must redact payload");
    }
}
const SESSION_CONNECTIONS: &str = "SELECT CAST(COALESCE(SUM(TOTAL_CONNECTIONS),0) AS SIGNED) FROM performance_schema.accounts WHERE USER='ordinary`@_%'";

#[tokio::test]
#[ignore = "real MySQL session roundtrip, physical caps and independent SQL oracle"]
async fn mysql_sessions_roundtrip_and_boundaries() {
    let started = Instant::now();
    let fixture = Fixture::new().await;
    let store = fixture.open(2).await;
    let sessions = store.admin_sessions(session_limits()).unwrap();
    assert_eq!(format!("{sessions:?}"), "MySqlAdminSessions([REDACTED])");
    let before = fixture.scalar(SESSION_CONNECTIONS).await;
    let mut strict = session_limits();
    strict.text_bytes = n(2);
    assert_eq!(
        store
            .admin_sessions(strict)
            .unwrap()
            .create_session(
                "invalid-view",
                &admin_input(Duration::from_secs(3600), true),
                deadline()
            )
            .await,
        Err(MySqlControlError::InvalidSession)
    );
    assert_eq!(
        sessions
            .create_session(
                &"x".repeat(257),
                &admin_input(Duration::from_secs(3600), true),
                deadline()
            )
            .await,
        Err(MySqlControlError::InvalidSession)
    );
    let mut invalid = session_limits();
    invalid.teams_json_bytes = n(usize::MAX);
    assert_eq!(
        store.admin_sessions(invalid).unwrap_err(),
        MySqlControlError::Configuration
    );
    assert_eq!(
        fixture.scalar(SESSION_CONNECTIONS).await,
        before,
        "invalid input must not open native connection"
    );

    for (raw, claims) in [("full-session", true), ("no-claim-session", false)] {
        sessions
            .create_session(
                raw,
                &admin_input(Duration::from_secs(3600), claims),
                deadline(),
            )
            .await
            .unwrap();
        let rows = session_rows(&fixture, raw).await;
        if claims {
            assert_eq!(
                rows.iter().sum::<i64>(),
                MYSQL_SESSION_ORACLE,
                "MYSQL_SESSION_ORACLE"
            );
        }
        assert_eq!(rows, [1, 1, i64::from(claims)]);
        assert_admin(&sessions.session(raw, deadline()).await.unwrap(), claims);
        assert_admin(&sessions.session(raw, deadline()).await.unwrap(), claims);
        assert_eq!(
            session_rows(&fixture, raw).await,
            rows,
            "read does not consume metadata"
        );
        let hash = session_hash(raw);
        let different = digester()
            .token(TokenKind::OidcFlowState, raw.as_bytes())
            .unwrap()
            .to_sql_hex();
        assert_ne!(hash, different);
        assert_eq!(fixture.scalar(&format!("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.admin_sessions WHERE token_hash='{different}'")).await, 0);
        assert_eq!(
            sessions
                .create_session(
                    raw,
                    &admin_input(Duration::from_secs(3600), !claims),
                    deadline()
                )
                .await,
            Err(MySqlControlError::SessionExists)
        );
        assert_admin(&sessions.session(raw, deadline()).await.unwrap(), claims);
    }
    assert_eq!(
        sessions
            .session("absent-session", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::SessionUnavailable
    );
    let exact = admin_teams(Duration::from_secs(3600), false, vec!["x".repeat(65_531)]);
    sessions
        .create_session("exact-json", &exact, deadline())
        .await
        .unwrap();
    let hash = session_hash("exact-json");
    assert_eq!(fixture.scalar(&format!("SELECT CAST(OCTET_LENGTH(teams_json) AS SIGNED) FROM broker.admin_session_principals WHERE token_hash='{hash}'")).await, 65_535);
    assert_eq!(
        sessions
            .session("exact-json", deadline())
            .await
            .unwrap()
            .principal()
            .teams[0]
            .len(),
        65_531
    );
    // JSON wrappers add four bytes. This includes a three-byte scalar and
    // confirms OCTET_LENGTH, rather than character count, controls TEXT.
    let multibyte = format!("{}xx", "€".repeat(21_843));
    assert_eq!(multibyte.len() + 4, 65_535);
    sessions
        .create_session(
            "utf8-exact-json",
            &admin_teams(Duration::from_secs(3600), false, vec![multibyte.clone()]),
            deadline(),
        )
        .await
        .unwrap();
    let hash = session_hash("utf8-exact-json");
    assert_eq!(fixture.scalar(&format!("SELECT CAST(OCTET_LENGTH(teams_json) AS SIGNED) FROM broker.admin_session_principals WHERE token_hash='{hash}'")).await, 65_535);
    assert_eq!(
        sessions
            .session("utf8-exact-json", deadline())
            .await
            .unwrap()
            .principal()
            .teams
            .as_slice(),
        std::slice::from_ref(&multibyte)
    );
    let before = fixture.scalar(SESSION_CONNECTIONS).await;
    for (raw, teams) in [
        ("utf8-over-json", vec![format!("{multibyte}x")]),
        ("over-json", vec!["x".repeat(65_532)]),
        ("escaped-json", vec!["\"".repeat(32_766)]),
    ] {
        assert_eq!(
            sessions
                .create_session(
                    raw,
                    &admin_teams(Duration::from_secs(3600), false, teams),
                    deadline()
                )
                .await,
            Err(MySqlControlError::InvalidSession)
        );
    }
    assert_eq!(fixture.scalar(SESSION_CONNECTIONS).await, before);
    let mut tight_lifetime = session_limits();
    tight_lifetime.max_lifetime = Duration::from_secs(1);
    assert_eq!(
        store
            .admin_sessions(tight_lifetime)
            .unwrap()
            .create_session(
                "long-lifetime",
                &admin_input(Duration::from_secs(3600), false),
                deadline()
            )
            .await,
        Err(MySqlControlError::InvalidSession)
    );
    assert_eq!(session_rows(&fixture, "long-lifetime").await, [0, 0, 0]);
    // Data-only metadata roundtrip: empty claims retain their row and literal selector.
    let empty = NewAdminSession::new(
        SessionProfile {
            subject: "empty-snapshot-data".into(),
            name: String::new(),
            email: String::new(),
        },
        SessionPrincipal {
            issuer: "https://metadata.example.invalid".into(),
            username: String::new(),
            organization: String::new(),
            teams: vec![],
            local_user_revision: 0,
        },
        Zeroizing::new("metadata-only-csrf".into()),
        Some(SessionClaimRoles {
            selector: " roles ".into(),
            roles: vec![],
        }),
        SystemTime::now() + Duration::from_secs(60),
        &session_limits(),
    )
    .unwrap();
    sessions
        .create_session("empty-claim-snapshot", &empty, deadline())
        .await
        .unwrap();
    let observed = sessions
        .session("empty-claim-snapshot", deadline())
        .await
        .unwrap();
    assert_eq!(observed.claimed_roles().unwrap().selector, " roles ");
    assert!(observed.claimed_roles().unwrap().roles.is_empty());
    assert_eq!(
        session_rows(&fixture, "empty-claim-snapshot").await,
        [1, 1, 1]
    );
    assert_eq!(
        sessions
            .revoke_session("empty-claim-snapshot", deadline())
            .await
            .unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(
        session_rows(&fixture, "empty-claim-snapshot").await,
        [0, 0, 0]
    );
    store.shutdown(deadline()).await.unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
    eprintln!(
        "native session roundtrip elapsed_ms={} domain=whole_fixture_and_service",
        started.elapsed().as_millis()
    );
}

#[tokio::test]
#[ignore = "real malformed session metadata preserves corruption, including expiry"]
async fn mysql_sessions_corruption_preserves_metadata() {
    let fixture = Fixture::new().await;
    let store = fixture.open(1).await;
    let sessions = store.admin_sessions(session_limits()).unwrap();
    sessions
        .create_session(
            "uncorrupted",
            &admin_input(Duration::from_secs(3600), true),
            deadline(),
        )
        .await
        .unwrap();
    let cases = [
        ("admin_session_principals", "teams_json='{}'"),
        ("admin_session_principals", "teams_json='[null]'"),
        ("admin_session_principals", "teams_json='[1]'"),
        (
            "admin_session_principals",
            "teams_json='[\"beta\",\"alpha\"]'",
        ),
        (
            "admin_session_principals",
            "teams_json='[\"alpha\",\"alpha\"]'",
        ),
        ("admin_session_principals", "teams_json='[\" alpha\"]'"),
        ("admin_session_principals", "teams_json='[] trailing'"),
        ("admin_session_principals", "local_user_revision=-1"),
        ("admin_session_principals", "issuer=''"),
        ("admin_session_claim_roles", "roles_json='[null]'"),
        (
            "admin_session_claim_roles",
            "roles_json='[\"metadata-only\",\"metadata-only\"]'",
        ),
        ("admin_session_claim_roles", "claim_selector=''"),
        ("admin_sessions", "subject=CONCAT('s',CHAR(0))"),
        ("admin_sessions", "created_at=expires_at+1"),
        ("admin_sessions", "created_at=expires_at-1"),
        ("admin_sessions", "created_at=0"),
    ];
    for (index, (table, assignment)) in cases.into_iter().enumerate() {
        let raw = format!("corrupt-{index}");
        sessions
            .create_session(
                &raw,
                &admin_input(Duration::from_secs(3600), true),
                deadline(),
            )
            .await
            .unwrap();
        let hash = session_hash(&raw);
        fixture
            .sql(&format!(
                "UPDATE broker.{table} SET {assignment} WHERE token_hash='{hash}'"
            ))
            .await;
        assert_eq!(
            sessions.session(&raw, deadline()).await.unwrap_err(),
            MySqlControlError::CorruptSession,
            "native corruption case {index}"
        );
        assert_eq!(session_rows(&fixture, &raw).await, [1, 1, 1]);
    }
    sessions
        .create_session(
            "missing-principal",
            &admin_input(Duration::from_secs(3600), true),
            deadline(),
        )
        .await
        .unwrap();
    fixture
        .sql(&format!(
            "DELETE FROM broker.admin_session_principals WHERE token_hash='{}'",
            session_hash("missing-principal")
        ))
        .await;
    assert_eq!(
        sessions
            .session("missing-principal", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::CorruptSession
    );
    assert_eq!(session_rows(&fixture, "missing-principal").await, [1, 0, 1]);
    // Every projected text field receives its own SQL byte cap before fetch.
    for (index, (table, field)) in [
        ("admin_sessions", "subject"),
        ("admin_sessions", "name"),
        ("admin_sessions", "email"),
        ("admin_sessions", "csrf_token"),
        ("admin_session_principals", "issuer"),
        ("admin_session_principals", "username"),
        ("admin_session_principals", "organization"),
        ("admin_session_principals", "teams_json"),
        ("admin_session_claim_roles", "claim_selector"),
        ("admin_session_claim_roles", "roles_json"),
    ]
    .into_iter()
    .enumerate()
    {
        let raw = format!("projected-cap-{index}");
        let minimal = NewAdminSession::new(
            SessionProfile {
                subject: "s".into(),
                name: String::new(),
                email: String::new(),
            },
            SessionPrincipal {
                issuer: "i".into(),
                username: String::new(),
                organization: String::new(),
                teams: vec!["t".into()],
                local_user_revision: 0,
            },
            Zeroizing::new("c".into()),
            Some(SessionClaimRoles {
                selector: "r".into(),
                roles: vec!["r".into()],
            }),
            SystemTime::now() + Duration::from_secs(3600),
            &session_limits(),
        )
        .unwrap();
        sessions
            .create_session(&raw, &minimal, deadline())
            .await
            .unwrap();
        let mut cap = session_limits();
        if field == "csrf_token" {
            cap.csrf_bytes = n(5);
        } else if field == "teams_json" {
            cap.teams_json_bytes = n(5);
        } else if field == "roles_json" {
            cap.roles_json_bytes = n(5);
        } else {
            cap.text_bytes = n(5);
        }
        assert!(
            store
                .admin_sessions(cap)
                .unwrap()
                .session(&raw, deadline())
                .await
                .is_ok(),
            "all non-target fields must pass the exact same view before mutation"
        );
        let value = if field.ends_with("json") {
            "[\"123456\"]"
        } else {
            "123456"
        };
        let mut c = fixture.connection().await;
        sqlx_core::query::query(AssertSqlSafe(format!(
            "UPDATE broker.{table} SET {field}=? WHERE token_hash=?"
        )))
        .bind(value)
        .bind(session_hash(&raw))
        .execute(&mut c)
        .await
        .unwrap();
        drop(c);
        assert_eq!(
            store
                .admin_sessions(cap)
                .unwrap()
                .session(&raw, deadline())
                .await
                .unwrap_err(),
            MySqlControlError::CorruptSession
        );
        assert_eq!(session_rows(&fixture, &raw).await, [1, 1, 1]);
    }
    sessions
        .create_session(
            "corrupt-expired",
            &admin_input(Duration::from_secs(3600), true),
            deadline(),
        )
        .await
        .unwrap();
    let hash = session_hash("corrupt-expired");
    fixture
        .sql(&format!(
            "UPDATE broker.admin_sessions SET created_at=1,expires_at=2 WHERE token_hash='{hash}'"
        ))
        .await;
    fixture
        .sql(&format!(
            "UPDATE broker.admin_session_principals SET teams_json='null' WHERE token_hash='{hash}'"
        ))
        .await;
    assert_eq!(
        sessions
            .session("corrupt-expired", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::CorruptSession
    );
    assert_eq!(session_rows(&fixture, "corrupt-expired").await, [1, 1, 1]);
    assert_eq!(
        sessions
            .revoke_session("corrupt-expired", deadline())
            .await
            .unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(session_rows(&fixture, "corrupt-expired").await, [0, 0, 0]);
    assert_admin(
        &sessions.session("uncorrupted", deadline()).await.unwrap(),
        true,
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real second/third INSERT rollback and three-table revocation"]
async fn mysql_sessions_atomicity_and_revocation() {
    let fixture = Fixture::new().await;
    let store = fixture.open(1).await;
    let sessions = store.admin_sessions(session_limits()).unwrap();
    for (raw, principal) in [("orphan-principal", true), ("orphan-claims", false)] {
        let hash = session_hash(raw);
        let mut root = fixture.connection().await;
        sqlx_core::query::query("SET SESSION foreign_key_checks=0")
            .execute(&mut root)
            .await
            .unwrap();
        let sql = if principal {
            "INSERT INTO broker.admin_session_principals(token_hash,issuer,username,organization,teams_json,local_user_revision) VALUES(?,'orphan','','','[]',0)"
        } else {
            "INSERT INTO broker.admin_session_claim_roles(token_hash,claim_selector,roles_json) VALUES(?,'roles','[\"orphan\"]')"
        };
        sqlx_core::query::query(sql)
            .bind(&hash)
            .execute(&mut root)
            .await
            .unwrap();
        sqlx_core::query::query("SET SESSION foreign_key_checks=1")
            .execute(&mut root)
            .await
            .unwrap();
        assert_eq!(
            sqlx_core::query_scalar::query_scalar::<_, i64>(
                "SELECT CAST(@@SESSION.foreign_key_checks AS SIGNED)"
            )
            .fetch_one(&mut root)
            .await
            .unwrap(),
            1
        );
        drop(root);
        let original = if principal { [0, 1, 0] } else { [0, 0, 1] };
        assert_eq!(session_rows(&fixture, raw).await, original);
        assert_eq!(
            sessions
                .create_session(
                    raw,
                    &admin_input(Duration::from_secs(3600), true),
                    deadline()
                )
                .await,
            Err(MySqlControlError::Storage)
        );
        wait_native(&fixture, NO_ORDINARY, 0).await;
        assert_eq!(
            session_rows(&fixture, raw).await,
            original,
            "native rollback must preserve preexisting orphan only"
        );
    }
    sessions
        .create_session(
            "revoked",
            &admin_input(Duration::from_secs(3600), true),
            deadline(),
        )
        .await
        .unwrap();
    sessions
        .create_session(
            "remaining",
            &admin_input(Duration::from_secs(3600), false),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        sessions.revoke_session("absent", deadline()).await.unwrap(),
        SessionRevocation::Absent
    );
    assert_eq!(
        sessions
            .revoke_session("revoked", deadline())
            .await
            .unwrap(),
        SessionRevocation::Revoked
    );
    assert_eq!(session_rows(&fixture, "revoked").await, [0, 0, 0]);
    assert_eq!(
        sessions
            .revoke_session("revoked", deadline())
            .await
            .unwrap(),
        SessionRevocation::Absent
    );
    assert_admin(
        &sessions.session("remaining", deadline()).await.unwrap(),
        false,
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "native session DML capabilities and fresh complete proof"]
async fn mysql_sessions_capabilities_and_current_proof() {
    let fixture = Fixture::new().await;
    let store = fixture.open(1).await;
    let sessions = store.admin_sessions(session_limits()).unwrap();
    sessions
        .create_session(
            "cap-existing",
            &admin_input(Duration::from_secs(3600), true),
            deadline(),
        )
        .await
        .unwrap();
    fixture
        .sql("REVOKE INSERT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    for missing in [
        "admin_sessions",
        "admin_session_principals",
        "admin_session_claim_roles",
    ] {
        for table in TABLES {
            if table.name() != missing {
                fixture
                    .sql(&format!(
                        "GRANT INSERT ON broker.{} TO 'ordinary`@_%'@'%'",
                        table.name()
                    ))
                    .await;
            }
        }
        assert_eq!(
            sessions
                .create_session(
                    "cap-denied",
                    &admin_input(Duration::from_secs(3600), true),
                    deadline()
                )
                .await,
            Err(MySqlControlError::Denied(RequiredCapability::Insert))
        );
        assert_eq!(
            session_rows(&fixture, "cap-denied").await,
            [0, 0, 0],
            "EXPLAIN must not stage parent writes"
        );
        for table in TABLES {
            if table.name() != missing {
                fixture
                    .sql(&format!(
                        "REVOKE INSERT ON broker.{} FROM 'ordinary`@_%'@'%'",
                        table.name()
                    ))
                    .await;
            }
        }
    }
    fixture
        .sql("GRANT INSERT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    for table in TABLES {
        if table.name() != "admin_session_principals" {
            fixture
                .sql(&format!(
                    "GRANT SELECT ON broker.{} TO 'ordinary`@_%'@'%'",
                    table.name()
                ))
                .await;
        }
    }
    fixture.sql("GRANT SELECT(token_hash,issuer,username,organization,local_user_revision) ON broker.admin_session_principals TO 'ordinary`@_%'@'%'").await;
    assert_eq!(
        sessions
            .session("cap-existing", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Denied(RequiredCapability::Select)
    );
    fixture
        .sql("GRANT SELECT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    // Lower table grants are deliberate fixtures; database scope now restores
    // the complete inventory contract while testing DELETE independently.
    fixture
        .sql("REVOKE DELETE ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        sessions.revoke_session("cap-existing", deadline()).await,
        Err(MySqlControlError::Denied(RequiredCapability::Delete))
    );
    assert!(matches!(
        sessions.session("cap-existing", deadline()).await,
        Err(MySqlControlError::Denied(
            RequiredCapability::Select | RequiredCapability::Delete
        ))
    ));
    assert_eq!(session_rows(&fixture, "cap-existing").await, [1, 1, 1]);
    fixture
        .sql("GRANT DELETE ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE PROCESS ON *.* FROM 'ordinary`@_%'@'%'")
        .await;
    let unproven = MySqlControlError::Unproven(UnprovenReason::Visibility);
    assert_eq!(
        sessions
            .create_session(
                "unproven",
                &admin_input(Duration::from_secs(3600), true),
                deadline()
            )
            .await,
        Err(unproven)
    );
    assert_eq!(
        sessions
            .session("cap-existing", deadline())
            .await
            .unwrap_err(),
        unproven
    );
    assert_eq!(
        sessions.revoke_session("cap-existing", deadline()).await,
        Err(unproven)
    );
    assert_eq!(session_rows(&fixture, "unproven").await, [0, 0, 0]);
    assert_eq!(session_rows(&fixture, "cap-existing").await, [1, 1, 1]);
    fixture
        .sql("GRANT PROCESS ON *.* TO 'ordinary`@_%'@'%'")
        .await;
    assert_admin(
        &sessions.session("cap-existing", deadline()).await.unwrap(),
        true,
    );
    store.shutdown(deadline()).await.unwrap();
}
const SESSION_LOCKED_LIVE: usize = 8;
const SESSION_CREATE_STAGED: usize = 16;
const SESSION_COMMIT_STARTING: usize = 32;
struct SessionPhaseLayer(Arc<FlowPhases>);
impl Layer<Registry> for SessionPhaseLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, Registry>) {
        let metadata = event.metadata();
        let bit = match metadata.target() {
            "broker_control::mysql::session_locked_live" => SESSION_LOCKED_LIVE,
            "broker_control::mysql::session_create_staged" => SESSION_CREATE_STAGED,
            "broker_control::mysql::session_commit_starting" => SESSION_COMMIT_STARTING,
            _ => return,
        };
        if *metadata.level() != tracing::Level::TRACE
            || metadata.fields().len() != 1
            || metadata
                .fields()
                .iter()
                .any(|field| field.name() != "message")
        {
            self.0.invalid_metadata.store(true, Ordering::SeqCst);
        }
        self.0.observed.fetch_or(bit, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}
async fn lock_session(fixture: &Fixture, raw: &str, principal_gap: bool) -> MySqlConnection {
    let mut root = fixture.connection().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        sqlx_core::raw_sql::raw_sql(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; START TRANSACTION",
        )
        .execute(&mut root)
        .await
        .unwrap();
        let table = if principal_gap {
            "admin_session_principals"
        } else {
            "admin_sessions"
        };
        sqlx_core::query::query(AssertSqlSafe(format!(
            "SELECT token_hash FROM broker.{table} WHERE token_hash=? FOR UPDATE"
        )))
        .bind(session_hash(raw))
        .fetch_optional(&mut root)
        .await
        .unwrap();
    })
    .await
    .expect("fixture native parent/gap lock budget");
    root
}
async fn release_session_lock(mut root: MySqlConnection) {
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx_core::raw_sql::raw_sql("ROLLBACK").execute(&mut root),
    )
    .await
    .expect("fixture rollback budget")
    .unwrap();
}
fn current_micros() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
async fn cross_expiry(expiry: i64) {
    let remaining = expiry - current_micros();
    if remaining > 0 {
        tokio::time::sleep(Duration::from_micros(remaining as u64) + Duration::from_millis(100))
            .await;
    }
}
const SESSION_NATIVE_X: &str = "SELECT CAST(COUNT(*)>=1 AS SIGNED) FROM performance_schema.data_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE t.PROCESSLIST_USER='ordinary`@_%' AND l.OBJECT_SCHEMA='broker' AND l.OBJECT_NAME='admin_sessions' AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED' AND l.LOCK_MODE LIKE 'X%'";
const SESSION_DELETE_WAIT: &str = "SELECT CAST(COUNT(*)>=1 AS SIGNED) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE=w.ENGINE JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE t.PROCESSLIST_USER='ordinary`@_%' AND t.PROCESSLIST_COMMAND='Execute' AND t.PROCESSLIST_INFO LIKE 'DELETE FROM `broker`.`admin_sessions`%' AND l.OBJECT_SCHEMA='broker' AND l.OBJECT_NAME='admin_sessions'";

#[tokio::test]
#[ignore = "real session parent locks, competing consumers and expiry after waiting"]
async fn mysql_sessions_concurrency_and_expiry_after_lock() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let mut config = fixture.config(2);
    config.admission.budgets.operation = Duration::from_secs(30);
    let store = Arc::new(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap(),
    );
    let mut creating = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let owner = store.clone();
        creating.spawn(async move {
            owner
                .admin_sessions(session_limits())
                .unwrap()
                .create_session(
                    "parallel-create",
                    &admin_input(Duration::from_secs(3600), true),
                    deadline(),
                )
                .await
        });
    }
    let mut results = Vec::new();
    while let Some(result) = creating.join_next().await {
        results.push(result.unwrap());
    }
    assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|v| **v == Err(MySqlControlError::SessionExists))
            .count(),
        1
    );
    let mut reading = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let owner = store.clone();
        reading.spawn(async move {
            owner
                .admin_sessions(session_limits())
                .unwrap()
                .session("parallel-create", deadline())
                .await
        });
    }
    while let Some(result) = reading.join_next().await {
        assert_admin(&result.unwrap().unwrap(), true);
    }
    assert_eq!(session_rows(&fixture, "parallel-create").await, [1, 1, 1]);
    let mut revoking = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let owner = store.clone();
        revoking.spawn(async move {
            owner
                .admin_sessions(session_limits())
                .unwrap()
                .revoke_session("parallel-create", deadline())
                .await
        });
    }
    let mut results = Vec::new();
    while let Some(result) = revoking.join_next().await {
        results.push(result.unwrap().unwrap());
    }
    assert_eq!(
        results
            .iter()
            .filter(|v| **v == SessionRevocation::Revoked)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|v| **v == SessionRevocation::Absent)
            .count(),
        1
    );
    assert_eq!(session_rows(&fixture, "parallel-create").await, [0, 0, 0]);

    store
        .admin_sessions(session_limits())
        .unwrap()
        .create_session(
            "lock-expiry",
            &admin_input(Duration::from_secs(5), true),
            deadline(),
        )
        .await
        .unwrap();
    let hash = session_hash("lock-expiry");
    let expiry = fixture
        .scalar(&format!(
            "SELECT expires_at FROM broker.admin_sessions WHERE token_hash='{hash}'"
        ))
        .await;
    let root = lock_session(&fixture, "lock-expiry", false).await;
    let owner = store.clone();
    let reading = tokio::spawn(async move {
        owner
            .admin_sessions(session_limits())
            .unwrap()
            .session("lock-expiry", Instant::now() + Duration::from_secs(30))
            .await
    });
    wait_statement(&fixture, StatementPhase::SessionRowLock).await;
    assert_eq!(session_rows(&fixture, "lock-expiry").await, [1, 1, 1]);
    cross_expiry(expiry).await;
    release_session_lock(root).await;
    assert_eq!(
        reading.await.unwrap().unwrap_err(),
        MySqlControlError::SessionExpired
    );
    assert_eq!(session_rows(&fixture, "lock-expiry").await, [0, 0, 0]);
    assert_eq!(
        store
            .admin_sessions(session_limits())
            .unwrap()
            .session("lock-expiry", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::SessionUnavailable
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real session read/revoke ordering and expiry before commit over opaque TLS"]
async fn mysql_sessions_ordering_and_precommit_expiry() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let relay = Relay::new(fixture.port).await;
    let mut config = relay.config(&fixture, 1);
    config.admission.budgets.operation = Duration::from_secs(30);
    let store = Arc::new(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap(),
    );
    let direct = Arc::new(fixture.open(1).await);
    for (raw, expire) in [
        ("read-before-revoke", false),
        ("read-precommit-expiry", true),
    ] {
        store
            .admin_sessions(session_limits())
            .unwrap()
            .create_session(
                raw,
                &admin_input(Duration::from_secs(if expire { 15 } else { 120 }), true),
                deadline(),
            )
            .await
            .unwrap();
        let hash = session_hash(raw);
        let expiry = fixture
            .scalar(&format!(
                "SELECT expires_at FROM broker.admin_sessions WHERE token_hash='{hash}'"
            ))
            .await;
        let root = lock_session(&fixture, raw, false).await;
        let owner = store.clone();
        let phases = FlowPhases::new();
        let subscriber = Registry::default().with(SessionPhaseLayer(phases.clone()));
        let reading = tokio::spawn(
            (async move {
                owner
                    .admin_sessions(session_limits())
                    .unwrap()
                    .session(raw, Instant::now() + Duration::from_secs(30))
                    .await
            })
            .with_subscriber(subscriber),
        );
        wait_statement(&fixture, StatementPhase::SessionRowLock).await;
        relay.request.block();
        release_session_lock(root).await;
        relay.request.held().await;
        phases.wait(SESSION_LOCKED_LIVE).await;
        wait_native(&fixture, SESSION_NATIVE_X, 1).await;
        assert!(
            expiry - current_micros() > 2_000_000,
            "session must still be live when native lock and phase are observed"
        );
        if expire {
            cross_expiry(expiry).await;
            relay.request.unblock();
            assert_eq!(
                reading.await.unwrap().unwrap_err(),
                MySqlControlError::SessionExpired
            );
            assert_eq!(session_rows(&fixture, raw).await, [0, 0, 0]);
        } else {
            let owner = direct.clone();
            let revoking = tokio::spawn(async move {
                owner
                    .admin_sessions(session_limits())
                    .unwrap()
                    .revoke_session(raw, deadline())
                    .await
            });
            wait_native(&fixture, SESSION_DELETE_WAIT, 1).await;
            assert!(
                !revoking.is_finished(),
                "revoke must wait for the actual parent X lock"
            );
            relay.request.unblock();
            assert_admin(&reading.await.unwrap().unwrap(), true);
            assert_eq!(revoking.await.unwrap().unwrap(), SessionRevocation::Revoked);
            assert_eq!(session_rows(&fixture, raw).await, [0, 0, 0]);
            assert_eq!(
                store
                    .admin_sessions(session_limits())
                    .unwrap()
                    .session(raw, deadline())
                    .await
                    .unwrap_err(),
                MySqlControlError::SessionUnavailable
            );
        }
        assert!(!phases.invalid_metadata.load(Ordering::SeqCst));
    }
    // Parent locking orders server-owned mutations. Existing external child
    // writers are characterized separately: an already fetched result is a
    // snapshot, not a promise that child metadata/current policy stays frozen.
    for (raw, action) in [
        ("child-update", 0),
        ("child-delete-claims", 1),
        ("child-delete-principal", 2),
        ("child-insert-claims", 3),
    ] {
        direct
            .admin_sessions(session_limits())
            .unwrap()
            .create_session(
                raw,
                &admin_input(Duration::from_secs(120), action != 3),
                deadline(),
            )
            .await
            .unwrap();
        let hash = session_hash(raw);
        let root = lock_session(&fixture, raw, false).await;
        let end = Instant::now() + Duration::from_secs(30);
        let owner = store.clone();
        let phases = FlowPhases::new();
        let subscriber = Registry::default().with(SessionPhaseLayer(phases.clone()));
        let reading = tokio::spawn(
            (async move {
                owner
                    .admin_sessions(session_limits())
                    .unwrap()
                    .session(raw, end)
                    .await
            })
            .with_subscriber(subscriber),
        );
        try_wait_statement_until(&fixture, StatementPhase::SessionRowLock, end)
            .await
            .expect("child snapshot native SELECT");
        relay.request.block();
        release_session_lock(root).await;
        relay.request.held_after(0, end).await;
        tokio::time::timeout_at(end.into(), phases.wait(SESSION_LOCKED_LIVE))
            .await
            .expect("child snapshot fetched phase");
        try_wait_native_until(&fixture, SESSION_NATIVE_X, 1, end)
            .await
            .expect("child snapshot native parent X");
        assert!(Instant::now() < end);
        let mut writer = try_observer_connection_until(&fixture, end)
            .await
            .expect("child writer original deadline");
        if action == 3 {
            let writer_id = tokio::time::timeout_at(
                end.into(),
                sqlx_core::query_scalar::query_scalar::<_, u64>("SELECT CONNECTION_ID()")
                    .fetch_one(&mut writer),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(writer_id > 0 && Instant::now() < end);
            let insertion = tokio::spawn(async move {
                let affected = tokio::time::timeout_at(end.into(), sqlx_core::query::query("INSERT INTO `broker`.`admin_session_claim_roles` (token_hash,claim_selector,roles_json) VALUES (?,'roles','[\"inserted-metadata\"]')").bind(hash).execute(&mut writer)).await.expect("child INSERT original deadline").unwrap().rows_affected();
                assert!(Instant::now() < end);
                affected
            });
            let wait = format!(
                "SELECT CAST(COUNT(*)>=1 AS SIGNED) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE=w.ENGINE JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE t.PROCESSLIST_ID={writer_id} AND t.PROCESSLIST_COMMAND='Execute' AND t.PROCESSLIST_INFO LIKE 'INSERT INTO `broker`.`admin_session_claim_roles`%' AND l.OBJECT_SCHEMA='broker' AND l.OBJECT_NAME='admin_sessions' AND l.LOCK_TYPE='RECORD' AND l.LOCK_MODE LIKE 'S%'"
            );
            try_wait_native_until(&fixture, &wait, 1, end)
                .await
                .expect("actual child INSERT FK wait on parent");
            assert!(
                !insertion.is_finished(),
                "claims INSERT must wait for fetched reader parent X"
            );
            assert_eq!(session_rows(&fixture, raw).await, [1, 1, 0]);
            relay.request.unblock();
            assert_admin(&reading.await.unwrap().unwrap(), false);
            assert_eq!(
                insertion.await.unwrap(),
                1,
                "claims INSERT native ACK after parent release"
            );
            let current = direct
                .admin_sessions(session_limits())
                .unwrap()
                .session(raw, deadline())
                .await
                .unwrap();
            assert_eq!(
                current.claimed_roles().unwrap().roles,
                ["inserted-metadata"]
            );
            assert_eq!(session_rows(&fixture, raw).await, [1, 1, 1]);
        } else {
            // UPDATEs share one external transaction, with its real COMMIT ACK
            // observed while the reader's actual parent X lock remains held.
            tokio::time::timeout_at(end.into(), async {
                if action == 0 {
                    sqlx_core::raw_sql::raw_sql("START TRANSACTION").execute(&mut writer).await.unwrap();
                    assert_eq!(sqlx_core::query::query("UPDATE `broker`.`admin_session_principals` SET username='updated-metadata' WHERE token_hash=?").bind(&hash).execute(&mut writer).await.unwrap().rows_affected(), 1);
                    assert_eq!(sqlx_core::query::query("UPDATE `broker`.`admin_session_claim_roles` SET roles_json='[\"updated-metadata\"]' WHERE token_hash=?").bind(&hash).execute(&mut writer).await.unwrap().rows_affected(), 1);
                    sqlx_core::raw_sql::raw_sql("COMMIT").execute(&mut writer).await.unwrap();
                } else if action == 1 {
                    assert_eq!(sqlx_core::query::query("DELETE FROM `broker`.`admin_session_claim_roles` WHERE token_hash=?").bind(&hash).execute(&mut writer).await.unwrap().rows_affected(), 1);
                } else {
                    assert_eq!(sqlx_core::query::query("DELETE FROM `broker`.`admin_session_principals` WHERE token_hash=?").bind(&hash).execute(&mut writer).await.unwrap().rows_affected(), 1);
                }
            }).await.expect("existing child writer must ACK while parent is locked");
            assert!(Instant::now() < end);
            assert_eq!(
                session_rows(&fixture, raw).await,
                match action {
                    0 => [1, 1, 1],
                    1 => [1, 1, 0],
                    _ => [1, 0, 1],
                }
            );
            try_wait_native_until(&fixture, SESSION_NATIVE_X, 1, end)
                .await
                .expect("parent X retained after external child ACK");
            relay.request.unblock();
            assert_admin(&reading.await.unwrap().unwrap(), true);
            let current = direct
                .admin_sessions(session_limits())
                .unwrap()
                .session(raw, deadline())
                .await;
            match action {
                0 => {
                    let current = current.unwrap();
                    assert_eq!(current.principal().username, "updated-metadata");
                    assert_eq!(current.claimed_roles().unwrap().roles, ["updated-metadata"]);
                }
                1 => assert!(current.unwrap().claimed_roles().is_none()),
                _ => assert_eq!(current.unwrap_err(), MySqlControlError::CorruptSession),
            }
        }
        assert!(!phases.invalid_metadata.load(Ordering::SeqCst));
        assert_eq!(
            direct
                .admin_sessions(session_limits())
                .unwrap()
                .revoke_session(raw, deadline())
                .await
                .unwrap(),
            SessionRevocation::Revoked
        );
        assert_eq!(session_rows(&fixture, raw).await, [0, 0, 0]);
    }
    direct.shutdown(deadline()).await.unwrap();
    // An explicit gap lock blocks the actual second INSERT. Its ACK is passed,
    // then opaque outbound bytes keep unchanged/COMMIT from progressing.
    let raw = "create-precommit-expiry";
    let root = lock_session(&fixture, raw, true).await;
    let input = admin_input(Duration::from_secs(15), false);
    let expiry = i64::try_from(
        input
            .expires_at()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let owner = store.clone();
    let phases = FlowPhases::new();
    let subscriber = Registry::default().with(SessionPhaseLayer(phases.clone()));
    let creating = tokio::spawn(
        (async move {
            owner
                .admin_sessions(session_limits())
                .unwrap()
                .create_session(raw, &input, Instant::now() + Duration::from_secs(30))
                .await
        })
        .with_subscriber(subscriber),
    );
    wait_statement(&fixture, StatementPhase::SessionPrincipalInsert).await;
    relay.request.block();
    release_session_lock(root).await;
    relay.request.held().await;
    phases.wait(SESSION_CREATE_STAGED).await;
    wait_native(&fixture, SESSION_NATIVE_X, 1).await;
    assert!(expiry - current_micros() > 2_000_000);
    assert_eq!(
        session_rows(&fixture, raw).await,
        [0, 0, 0],
        "uncommitted inserts remain unpublished"
    );
    cross_expiry(expiry).await;
    relay.request.unblock();
    assert_eq!(
        creating.await.unwrap(),
        Err(MySqlControlError::SessionExpired)
    );
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(session_rows(&fixture, raw).await, [0, 0, 0]);
    assert!(!phases.invalid_metadata.load(Ordering::SeqCst));
    store.shutdown(deadline()).await.unwrap();
    relay.stop().await;
}

async fn session_create_barrier(
    fixture: &Fixture,
    creating: JoinHandle<Result<(), MySqlControlError>>,
    end: Instant,
    stage: &'static str,
) -> JoinHandle<Result<(), MySqlControlError>> {
    let observer_end = end.min(Instant::now() + Duration::from_secs(5));
    if let Err(snapshot) = try_wait_statement_until(
        fixture,
        StatementPhase::SessionPrincipalInsert,
        observer_end,
    )
    .await
    {
        let before_caller_end = Instant::now() < end;
        let finished = creating.is_finished();
        if !finished {
            creating.abort();
        }
        let outcome = match creating.await {
            Ok(Ok(())) => "Success".to_owned(),
            Ok(Err(error)) => format!("Error({error:?})"),
            Err(error) if error.is_cancelled() => "Cancelled".to_owned(),
            Err(_) => "Panicked".to_owned(),
        };
        panic!(
            "session create native barrier stage={stage} snapshot={snapshot:?} before_caller_end={before_caller_end} future_finished={finished} outcome={outcome}"
        );
    }
    assert!(
        Instant::now() < end,
        "session create native barrier after original caller deadline"
    );
    creating
}

#[tokio::test]
#[ignore = "real precommit cancellation, original deadlines and shared admission shutdown"]
async fn mysql_sessions_cancellation_and_shared_lifecycle() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let store = Arc::new(fixture.open(1).await);
    for (raw, cancel) in [("cancelled-session", true), ("bounded-session", false)] {
        let root = lock_session(&fixture, raw, true).await;
        let owner = store.clone();
        let end = Instant::now() + Duration::from_secs(if cancel { 8 } else { 7 });
        let creating = tokio::spawn(async move {
            owner
                .admin_sessions(session_limits())
                .unwrap()
                .create_session(raw, &admin_input(Duration::from_secs(120), true), end)
                .await
        });
        let creating = session_create_barrier(
            &fixture,
            creating,
            end,
            if cancel { "cancel" } else { "caller-deadline" },
        )
        .await;
        if !cancel {
            let mut observer = try_observer_connection_until(&fixture, end)
                .await
                .expect("native row timeout observer original deadline");
            let row = tokio::time::timeout_at(end.into(), sqlx_core::query::query("SELECT CAST(COUNT(*) AS SIGNED),CAST(MIN(v.VARIABLE_VALUE) AS SIGNED) FROM performance_schema.variables_by_thread v JOIN performance_schema.threads t ON t.THREAD_ID=v.THREAD_ID WHERE v.VARIABLE_NAME='innodb_lock_wait_timeout' AND t.PROCESSLIST_USER=? AND t.PROCESSLIST_ID>0 AND t.THREAD_ID>0 AND t.PROCESSLIST_COMMAND='Execute' AND t.PROCESSLIST_INFO LIKE 'INSERT INTO `broker`.`admin_session_principals`%'").bind(ACCOUNT).fetch_one(&mut observer)).await.expect("native row timeout query original deadline").unwrap();
            assert!(
                Instant::now() < end,
                "native row timeout observed after original deadline"
            );
            assert_eq!(
                row.try_get::<i64, _>(0).unwrap(),
                1,
                "actual singleton blocked ordinary INSERT"
            );
            let row_timeout = row.try_get::<i64, _>(1).unwrap();
            assert!(
                row_timeout > 7,
                "actual native row timeout must exceed original caller7s"
            );
        }
        if cancel {
            creating.abort();
            assert!(creating.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(creating.await.unwrap(), Err(MySqlControlError::Deadline));
        }
        // A transport drop does not assert instantaneous server cancellation.
        release_session_lock(root).await;
        wait_native(&fixture, NO_ORDINARY, 0).await;
        assert_eq!(session_rows(&fixture, raw).await, [0, 0, 0]);
        store
            .admin_sessions(session_limits())
            .unwrap()
            .create_session(
                "permit-reused",
                &admin_input(Duration::from_secs(120), false),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .admin_sessions(session_limits())
                .unwrap()
                .revoke_session("permit-reused", deadline())
                .await
                .unwrap(),
            SessionRevocation::Revoked
        );
    }
    let root = lock_session(&fixture, "admitted-before-shutdown", true).await;
    let owner = store.clone();
    let end = deadline();
    let creating = tokio::spawn(async move {
        owner
            .admin_sessions(session_limits())
            .unwrap()
            .create_session(
                "admitted-before-shutdown",
                &admin_input(Duration::from_secs(120), true),
                end,
            )
            .await
    });
    let creating = session_create_barrier(&fixture, creating, end, "admitted-shutdown").await;
    let owner = store.clone();
    let waiting = tokio::spawn(async move {
        owner
            .admin_sessions(session_limits())
            .unwrap()
            .session("absent", deadline())
            .await
    });
    assert_eq!(
        store
            .shutdown(Instant::now() + Duration::from_millis(100))
            .await,
        Err(MySqlControlError::Deadline)
    );
    assert_eq!(
        waiting.await.unwrap().unwrap_err(),
        MySqlControlError::Closed
    );
    assert_eq!(
        store
            .admin_sessions(session_limits())
            .unwrap()
            .revoke_session("absent", deadline())
            .await,
        Err(MySqlControlError::Closed)
    );
    release_session_lock(root).await;
    creating.await.unwrap().unwrap();
    store.shutdown(deadline()).await.unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(
        session_rows(&fixture, "admitted-before-shutdown").await,
        [1, 1, 1]
    );
}

#[tokio::test]
#[ignore = "real COMMIT write ACK loss for create, revoke and expiry"]
async fn mysql_sessions_write_commit_uncertainty() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let baseline = fixture.open(1).await;
    baseline.shutdown(deadline()).await.unwrap();
    for case in 0..3 {
        let raw = match case {
            0 => "create-commit-ack",
            1 => "revoke-commit-ack",
            _ => "expiry-commit-ack",
        };
        let relay = Relay::new(fixture.port).await;
        let store = Arc::new(
            MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
                .await
                .unwrap(),
        );
        if case != 0 {
            store
                .admin_sessions(session_limits())
                .unwrap()
                .create_session(
                    raw,
                    &admin_input(Duration::from_secs(3600), true),
                    deadline(),
                )
                .await
                .unwrap();
        }
        if case == 2 {
            fixture.sql(&format!("UPDATE broker.admin_sessions SET created_at=1,expires_at=2 WHERE token_hash='{}'",session_hash(raw))).await;
        }
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
            .await;
        let owner = store.clone();
        let operation = tokio::spawn(async move {
            let end = Instant::now() + Duration::from_secs(5);
            let sessions = owner.admin_sessions(session_limits()).unwrap();
            match case {
                0 => {
                    sessions
                        .create_session(raw, &admin_input(Duration::from_secs(120), true), end)
                        .await
                }
                1 => sessions.revoke_session(raw, end).await.map(|_| ()),
                _ => sessions.session(raw, end).await.map(|_| ()),
            }
        });
        if let Err(snapshot) = try_wait_statement(&fixture, StatementPhase::Commit).await {
            let result = operation.await.unwrap();
            panic!(
                "native session COMMIT not observed case={case} snapshot={snapshot:?} outcome={result:?}"
            );
        }
        relay.response.block();
        assert_eq!(
            operation.await.unwrap(),
            Err(MySqlControlError::OutcomeUncertain)
        );
        assert_eq!(
            session_rows(&fixture, raw).await,
            if case == 0 { [1, 1, 1] } else { [0, 0, 0] },
            "native committed state exists despite missing ACK"
        );
        relay.stop().await;
        wait_native(&fixture, NO_ORDINARY, 0).await;
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
            .await;
        store.shutdown(deadline()).await.unwrap();
    }
}

async fn native_read_commit_count(root: &mut MySqlConnection, end: Instant) -> i64 {
    assert!(
        Instant::now() < end,
        "native COMMIT history original deadline"
    );
    let count = tokio::time::timeout_at(end.into(), sqlx_core::query_scalar::query_scalar::<_,i64>(
        "SELECT CAST(COUNT(*) AS SIGNED) FROM performance_schema.events_statements_history_long e JOIN performance_schema.threads t ON t.THREAD_ID=e.THREAD_ID WHERE t.PROCESSLIST_USER='ordinary`@_%' AND t.PROCESSLIST_ID>0 AND t.THREAD_ID>0 AND e.END_EVENT_ID IS NOT NULL AND e.SQL_TEXT='COMMIT'").fetch_one(root))
        .await.expect("native COMMIT history under original deadline")
        .unwrap_or_else(|error| sdk_failure("fixture_session_commit_history", &error));
    assert!(
        Instant::now() < end,
        "native COMMIT history returned after original deadline"
    );
    count
}
#[tokio::test]
#[ignore = "real readonly COMMIT ACK loss with completed native history and opaque chunks"]
async fn mysql_sessions_readonly_commit_uncertainty() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    fixture.sql("UPDATE performance_schema.setup_consumers SET ENABLED='YES' WHERE NAME='events_statements_history_long'").await;
    let relay = Relay::new(fixture.port).await;
    let store = Arc::new(
        MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
            .await
            .unwrap(),
    );
    store
        .admin_sessions(session_limits())
        .unwrap()
        .create_session(
            "readonly-commit-ack",
            &admin_input(Duration::from_secs(3600), true),
            deadline(),
        )
        .await
        .unwrap();
    let root = lock_session(&fixture, "readonly-commit-ack", false).await;
    let mut observer = fixture.connection().await;
    let owner = store.clone();
    let phases = FlowPhases::new();
    let subscriber = Registry::default().with(SessionPhaseLayer(phases.clone()));
    let end = Instant::now() + Duration::from_secs(8);
    let operation = tokio::spawn(
        (async move {
            owner
                .admin_sessions(session_limits())
                .unwrap()
                .session("readonly-commit-ack", end)
                .await
        })
        .with_subscriber(subscriber),
    );
    try_wait_statement_until(&fixture, StatementPhase::SessionRowLock, end)
        .await
        .expect("native SELECT original deadline");
    relay.request.block();
    let mut root = root;
    tokio::time::timeout_at(
        end.into(),
        sqlx_core::raw_sql::raw_sql("ROLLBACK").execute(&mut root),
    )
    .await
    .expect("fixture unlock original deadline")
    .unwrap();
    assert!(
        Instant::now() < end,
        "fixture unlocked after original deadline"
    );
    relay.request.held_after(0, end).await;
    tokio::time::timeout_at(end.into(), phases.wait(SESSION_LOCKED_LIVE))
        .await
        .expect("fetched phase original deadline");
    assert!(
        Instant::now() < end,
        "fetched phase observed after original deadline"
    );
    try_wait_native_until(&fixture, NO_ORDINARY, 1, end)
        .await
        .expect("native singleton original deadline");
    assert_eq!(native_read_commit_count(&mut observer, end).await, 0);
    // The observer only records trace bits; the parent forwards opaque chunks.
    // A bit never proves COMMIT. The native completed statement below does.
    let mut steps = 0;
    while phases.observed.load(Ordering::SeqCst) & SESSION_COMMIT_STARTING == 0 {
        steps += 1;
        assert!(steps <= 32, "finite opaque precommit chunk budget");
        let held = relay.request.held_chunks.load(Ordering::SeqCst);
        relay.request.step(end).await;
        relay.request.held_after(held, end).await;
    }
    relay.response.block();
    assert_eq!(native_read_commit_count(&mut observer, end).await, 0);
    loop {
        steps += 1;
        assert!(steps <= 32, "finite opaque COMMIT chunk budget");
        let held = relay.request.held_chunks.load(Ordering::SeqCst);
        relay.request.step(end).await;
        loop {
            let commits = native_read_commit_count(&mut observer, end).await;
            if commits > 0 {
                assert_eq!(commits, 1);
                break;
            }
            if relay.request.held_chunks.load(Ordering::SeqCst) > held {
                assert!(
                    Instant::now() < end,
                    "next chunk observed after original deadline"
                );
                break;
            }
            tokio::time::timeout_at(end.into(), tokio::time::sleep(Duration::from_millis(10)))
                .await
                .expect("COMMIT history observation deadline");
        }
        if native_read_commit_count(&mut observer, end).await == 1 {
            break;
        }
    }
    relay.response.held_after(0, end).await;
    assert!(!phases.invalid_metadata.load(Ordering::SeqCst));
    assert_eq!(
        operation.await.unwrap().unwrap_err(),
        MySqlControlError::OutcomeUncertain
    );
    assert_eq!(
        session_rows(&fixture, "readonly-commit-ack").await,
        [1, 1, 1]
    );
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
    store.shutdown(deadline()).await.unwrap();
    eprintln!("native readonly COMMIT opaque_chunks={steps} domain=fixture_transport_counts");
}

fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(vec![0x73; 32].into_boxed_slice()),
        DigestLimits::new(n(64), n(256), n(256), n(256), n(256)).unwrap(),
    )
    .unwrap()
}
fn limits() -> FlowLimits {
    FlowLimits {
        provider_bytes: n(100_000),
        request_bytes: n(100_000),
        continuation_bytes: n(100_000),
    }
}
fn flow(ttl: Duration) -> OidcFlow {
    OidcFlow::new(
        "synthetic-native-nonce".into(),
        "a".repeat(43),
        FlowContinuation::OAuth {
            provider_id: "provider".into(),
            request_id: "request".into(),
        },
        SystemTime::now() + ttl,
        limits(),
    )
    .unwrap()
}
fn docker(args: &[&str]) -> String {
    docker_phase(args, "fixture_docker_control")
}
fn docker_phase(args: &[&str], phase: &'static str) -> String {
    String::from_utf8(docker_output(args, phase, false).stdout).unwrap()
}
fn docker_output(args: &[&str], phase: &'static str, capture_stderr: bool) -> Output {
    let output = Command::new("docker")
        .args(args)
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .output()
        .expect("Docker executable");
    assert!(
        output.status.success(),
        "Docker control failed phase={phase} operation={}",
        args.first().copied().unwrap_or("missing")
    );
    output
}
fn private_file(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
}
fn startup_failure(
    kind: &'static str,
    number: Option<u16>,
    io_kind: Option<&'static str>,
    attempts: u32,
) {
    setup_failure("fixture_startup", kind, number, io_kind, attempts);
}
fn sdk_failure(phase: &'static str, error: &sqlx_core::error::Error) -> ! {
    use sqlx_core::error::Error;
    let number = error
        .as_database_error()
        .and_then(|error| error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>())
        .map(sqlx_mysql::MySqlDatabaseError::number);
    let (kind, io_kind) = match error {
        Error::Configuration(_) => ("CONFIGURATION", None),
        Error::Protocol(_) => ("PROTOCOL", None),
        Error::Database(_) => ("DATABASE", None),
        Error::Tls(_) => ("TLS", None),
        Error::Io(error) => (
            "IO",
            Some(match error.kind() {
                std::io::ErrorKind::ConnectionRefused => "CONNECTION_REFUSED",
                std::io::ErrorKind::ConnectionReset => "CONNECTION_RESET",
                std::io::ErrorKind::TimedOut => "TIMED_OUT",
                _ => "OTHER_IO",
            }),
        ),
        _ => ("OTHER", None),
    };
    setup_failure(phase, kind, number, io_kind, 1);
    panic!("private native SDK setup failure");
}
fn deadline_failure(phase: &'static str) -> ! {
    setup_failure(phase, "DEADLINE", None, None, 1);
    panic!("private native SDK setup deadline");
}
async fn tls_control(root: &mut MySqlConnection, sql: &'static str, phase: &'static str) {
    match tokio::time::timeout(
        Duration::from_secs(10),
        sqlx_core::query::query(AssertSqlSafe(sql)).execute(root),
    )
    .await
    {
        Ok(Ok(_)) => (),
        Ok(Err(error)) => sdk_failure(phase, &error),
        Err(_) => deadline_failure(phase),
    }
}
fn setup_failure(
    phase: &'static str,
    kind: &'static str,
    number: Option<u16>,
    io_kind: Option<&'static str>,
    attempts: u32,
) {
    eprintln!(
        "native fixture failure phase={phase} kind={kind} number={number:?} io={io_kind:?} attempts={attempts}"
    );
}

enum AdminDdl {
    InertProcedure,
    AutonomousEvent,
    DropEvent,
    CounterTrigger,
    DropTrigger,
    ActiveRole,
}
impl AdminDdl {
    fn statement(self) -> (&'static str, &'static str) {
        match self {
            Self::InertProcedure => (
                "CREATE PROCEDURE broker.inert() SELECT 1",
                "fixture_admin_inertprocedure",
            ),
            Self::AutonomousEvent => (
                "CREATE EVENT broker.autonomous ON SCHEDULE EVERY 1 DAY DO SELECT 1",
                "fixture_admin_autonomousevent",
            ),
            Self::DropEvent => ("DROP EVENT broker.autonomous", "fixture_admin_dropevent"),
            Self::CounterTrigger => (
                "CREATE TRIGGER broker.count_insert AFTER INSERT ON broker.oidc_flows FOR EACH ROW UPDATE broker.counter SET value=value+1",
                "fixture_admin_countertrigger",
            ),
            Self::DropTrigger => (
                "DROP TRIGGER broker.count_insert",
                "fixture_admin_droptrigger",
            ),
            Self::ActiveRole => (
                "CREATE ROLE 'active_broker'@'%'",
                "fixture_admin_activerole",
            ),
        }
    }
}

struct Fixture {
    id: String,
    files: TempDir,
    port: u16,
    ca: Vec<u8>,
    keyring_path: Option<PathBuf>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let result = Command::new("docker")
            .args(["rm", "--force", "--volumes", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !result.is_ok_and(|status| status.success()) {
            eprintln!("could not remove owned MySQL test fixture");
        }
    }
}
impl Fixture {
    async fn new() -> Self {
        let mut builder = tempfile::Builder::new();
        builder.prefix("broker-mysql-control-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let files = builder.tempdir().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Graphit private MySQL fixture CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.use_authority_key_identifier_extension = true;
        let cert = server_params.signed_by(&key, &issuer).unwrap();
        private_file(&files.path().join("ca.pem"), ca.pem().as_bytes());
        private_file(&files.path().join("server.pem"), cert.pem().as_bytes());
        private_file(
            &files.path().join("server.key"),
            key.serialize_pem().as_bytes(),
        );
        let mut fixture = Self {
            id: files
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            files,
            port: 1,
            ca: ca.pem().into_bytes(),
            keyring_path: None,
        };
        docker(&[
            "create",
            "--name",
            &fixture.id,
            "--publish",
            "127.0.0.1::3306",
            "--env",
            &format!("MYSQL_ROOT_PASSWORD={PASSWORD}"),
            "--env",
            "MYSQL_ROOT_HOST=%",
            IMAGE,
            "--log-bin=mysql-bin",
            "--server-id=1",
            "--sync-binlog=1",
        ]);
        // Keep the owned ID under cleanup before startup can fail or time out.
        docker(&["start", &fixture.id]);
        fixture.port = fixture.published_port();
        fixture.wait().await;
        for name in ["ca.pem", "server.pem", "server.key"] {
            docker(&[
                "cp",
                fixture.files.path().join(name).to_str().unwrap(),
                &format!("{}:/var/lib/mysql/fixture-{name}", fixture.id),
            ]);
            docker(&[
                "exec",
                "--user",
                "root",
                &fixture.id,
                "chown",
                "mysql:mysql",
                &format!("/var/lib/mysql/fixture-{name}"),
            ]);
            docker(&[
                "exec",
                "--user",
                "root",
                &fixture.id,
                "chmod",
                "600",
                &format!("/var/lib/mysql/fixture-{name}"),
            ]);
        }
        fixture.tls().await;
        fixture.sql("CREATE USER 'ordinary`@_%'@'%' IDENTIFIED BY 'ephemeral-mysql-control-fixture' REQUIRE SSL").await;
        fixture.sql("GRANT SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON broker.* TO 'ordinary`@_%'@'%'").await;
        fixture
            .sql("GRANT PROCESS ON *.* TO 'ordinary`@_%'@'%'")
            .await;
        fixture.reset().await;
        fixture
    }
    fn published_port(&self) -> u16 {
        let output = docker_output(
            &["port", &self.id, "3306/tcp"],
            "fixture_published_port",
            false,
        );
        assert!(
            output.stdout.len() <= 4096,
            "fixture published port output limit"
        );
        let published = std::str::from_utf8(&output.stdout)
            .unwrap_or_else(|_| panic!("fixture published port UTF8"));
        let port = published
            .trim()
            .strip_prefix("127.0.0.1:")
            .expect("fixture published port IPv4 mapping")
            .parse::<u16>()
            .expect("fixture published port numeric type");
        assert!(port != 0, "fixture published port zero");
        port
    }
    fn options(&self) -> MySqlConnectOptions {
        MySqlConnectOptions::new()
            .host("localhost")
            .port(self.port)
            .username("root")
            .password(PASSWORD)
            .charset("utf8mb4")
            .collation("utf8mb4_bin")
            .pipes_as_concat(false)
            .disable_statement_logging()
    }
    async fn wait(&self) {
        let end = Instant::now() + Duration::from_secs(60);
        let mut attempts = 0_u32;
        let mut last = ("STARTUP_DEADLINE", None, None);
        loop {
            if Instant::now() >= end {
                startup_failure(last.0, last.1, last.2, attempts);
                self.startup_diagnostics();
                panic!("native MySQL fixture startup deadline");
            }
            attempts = attempts.checked_add(1).expect("startup attempt counter");
            let result = tokio::time::timeout_at(
                (Instant::now() + Duration::from_secs(2)).min(end).into(),
                MySqlConnection::connect_with(
                    &self
                        .options()
                        .host("127.0.0.1")
                        .ssl_mode(MySqlSslMode::Required),
                ),
            )
            .await;
            let (kind, number, io_kind, permanent) = match result {
                Ok(Ok(connection)) => {
                    drop(connection);
                    if Instant::now() >= end {
                        startup_failure("LATE_CONNECTION", None, None, attempts);
                        self.startup_diagnostics();
                        panic!("native MySQL fixture startup deadline");
                    }
                    return;
                }
                Ok(Err(error)) => {
                    use sqlx_core::error::Error;
                    let number = error
                        .as_database_error()
                        .and_then(|error| {
                            error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>()
                        })
                        .map(sqlx_mysql::MySqlDatabaseError::number);
                    match &error {
                        Error::Configuration(_) => ("CONFIGURATION", number, None, true),
                        Error::Protocol(_) => ("PROTOCOL", number, None, true),
                        Error::Database(_) => ("DATABASE", number, None, false),
                        Error::Tls(_) => ("TLS", number, None, false),
                        Error::Io(error) => {
                            let io_kind = match error.kind() {
                                std::io::ErrorKind::ConnectionRefused => "CONNECTION_REFUSED",
                                std::io::ErrorKind::ConnectionReset => "CONNECTION_RESET",
                                std::io::ErrorKind::TimedOut => "TIMED_OUT",
                                _ => "OTHER_IO",
                            };
                            ("IO", number, Some(io_kind), false)
                        }
                        _ => ("OTHER", number, None, false),
                    }
                }
                Err(_) => ("ATTEMPT_DEADLINE", None, None, false),
            };
            last = (kind, number, io_kind);
            if permanent || Instant::now() >= end {
                startup_failure(kind, number, io_kind, attempts);
                if Instant::now() >= end {
                    self.startup_diagnostics();
                }
                panic!("native MySQL fixture startup failure");
            }
            tokio::time::sleep_until((Instant::now() + Duration::from_millis(50)).min(end).into())
                .await;
        }
    }
    fn startup_diagnostics(&self) {
        let state = docker_output(
            &["inspect", "--format", "{{json .State}}", &self.id],
            "fixture_startup_state",
            false,
        );
        assert!(
            state.stdout.len() <= 65_536,
            "fixture startup state output limit"
        );
        let state: serde_json::Value = serde_json::from_slice(&state.stdout)
            .unwrap_or_else(|_| panic!("fixture startup state JSON"));
        let running = state["Running"]
            .as_bool()
            .expect("fixture startup Running type");
        let status = match state["Status"].as_str() {
            Some("created") => "CREATED",
            Some("running") => "RUNNING",
            Some("paused") => "PAUSED",
            Some("restarting") => "RESTARTING",
            Some("removing") => "REMOVING",
            Some("exited") => "EXITED",
            Some("dead") => "DEAD",
            _ => panic!("fixture startup Status type or value"),
        };
        let exit_code = state["ExitCode"]
            .as_i64()
            .expect("fixture startup ExitCode type");
        let oom = state["OOMKilled"]
            .as_bool()
            .expect("fixture startup OOMKilled type");
        let has_error = !state["Error"]
            .as_str()
            .expect("fixture startup Error type")
            .is_empty();
        eprintln!(
            "native fixture state running={running} status={status} exit_code={exit_code} oom={oom} has_error={has_error}"
        );
        let logs = docker_output(
            &["logs", "--tail", "40", &self.id],
            "fixture_startup_logs",
            true,
        );
        let bytes = logs
            .stdout
            .len()
            .checked_add(logs.stderr.len())
            .expect("fixture startup log size overflow");
        assert!(bytes <= 65_536, "fixture startup logs output limit");
        let mut count = 0_u32;
        let mut permission_denied = false;
        let mut no_such_file = false;
        let mut keyring = false;
        let mut component = false;
        let mut manifest = false;
        let mut configuration = false;
        for output in [&logs.stdout, &logs.stderr] {
            let text =
                std::str::from_utf8(output).unwrap_or_else(|_| panic!("fixture startup logs UTF8"));
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                permission_denied |= lower.contains("permission denied");
                no_such_file |= lower.contains("no such file");
                keyring |= lower.contains("keyring");
                component |= lower.contains("component");
                manifest |= lower.contains("manifest");
                configuration |= lower.contains("configuration");
                let severity = if line.contains("[ERROR]") {
                    "ERROR"
                } else if line.contains("[Warning]") || line.contains("[WARNING]") {
                    "WARNING"
                } else if line.contains("[Note]") || line.contains("[NOTE]") {
                    "NOTE"
                } else {
                    "OTHER"
                };
                for (offset, _) in line.match_indices("[MY-") {
                    let suffix = &line.as_bytes()[offset + 4..];
                    if suffix.len() >= 7
                        && suffix[..6].iter().all(u8::is_ascii_digit)
                        && suffix[6] == b']'
                    {
                        count = count.checked_add(1).expect("fixture startup log counter");
                        assert!(count <= 80, "fixture startup log record limit");
                        let code = std::str::from_utf8(&suffix[..6]).expect("native code ASCII");
                        eprintln!("native fixture log code=MY-{code} severity={severity}");
                        if code == "013714" {
                            let reason = [
                                ("Failed to set path to component", "COMPONENT_PATH"),
                                (
                                    "Failed to allocate memory for configuration details",
                                    "CONFIG_ALLOCATION",
                                ),
                                (
                                    "Failed to set path to configuration file",
                                    "CONFIG_FILE_PATH",
                                ),
                                (
                                    "Could not find 'path' value in configuration file",
                                    "CONFIG_PATH_UNAVAILABLE_OR_INVALID_OR_MISSING_FIELD",
                                ),
                                (
                                    "Could not find 'read_only' value in configuration file",
                                    "CONFIG_READ_ONLY_UNAVAILABLE_OR_INVALID_OR_MISSING_FIELD",
                                ),
                                (
                                    "Failed to initialize keyring backend",
                                    "BACKEND_INITIALIZATION",
                                ),
                                (
                                    "Failed to allocate memory for keyring operations",
                                    "OPERATIONS_ALLOCATION",
                                ),
                                (
                                    "Failed to initialize keyring operations",
                                    "OPERATIONS_INITIALIZATION",
                                ),
                                ("Got an exception while loading component", "EXCEPTION"),
                            ]
                            .into_iter()
                            .find_map(|(text, reason)| line.contains(text).then_some(reason))
                            .unwrap_or("UNKNOWN");
                            eprintln!("native fixture keyring reason={reason}");
                        }
                    }
                }
            }
        }
        eprintln!(
            "native fixture logs count={count} permission_denied={permission_denied} no_such_file={no_such_file} keyring={keyring} component={component} manifest={manifest} configuration={configuration}"
        );
        if running {
            let same_before_after = self.published_port() == self.port;
            eprintln!("native fixture port same_before_after={same_before_after}");
        } else {
            eprintln!("native fixture port observation=UNOBSERVED");
        }
        let Some(path) = &self.keyring_path else {
            eprintln!("native fixture keyring observation=NOT_CONFIGURED");
            return;
        };
        let output = docker_output(
            &["exec", "--user", "mysql", &self.id, "id", "-u"],
            "fixture_keyring_probe_user",
            false,
        );
        assert!(
            output.stdout.len() <= 4096,
            "fixture keyring probe user output limit"
        );
        let mysql_uid = std::str::from_utf8(&output.stdout)
            .unwrap_or_else(|_| panic!("fixture keyring probe user UTF8"))
            .trim()
            .parse::<u32>()
            .expect("fixture keyring probe user numeric type");
        assert!(
            mysql_uid != 0,
            "fixture keyring probe requires nonroot mysql"
        );
        let backup = path.with_file_name("keyring.backup");
        for (object, path) in [("PRIMARY", path.as_path()), ("BACKUP", backup.as_path())] {
            self.keyring_file_diagnostics(object, path, mysql_uid);
        }
    }
    fn keyring_file_diagnostics(&self, object: &'static str, path: &Path, mysql_uid: u32) {
        const PROBE: &str = r#"set -eu
probe_parent_directory=false
probe_parent_searchable=false
probe_kind=UNOBSERVED
probe_uid=-
probe_mode=-
probe_readable=false
probe_writable=false
if [ -d "$2" ]; then probe_parent_directory=true; fi
if [ -x "$2" ]; then probe_parent_searchable=true; fi
if [ -e "$1" ]; then
  if [ -f "$1" ]; then probe_kind=REGULAR; elif [ -d "$1" ]; then probe_kind=DIRECTORY; else probe_kind=OTHER; fi
  probe_uid=$(stat -L -c %u "$1")
  probe_mode=$(stat -L -c %a "$1")
fi
if [ -r "$1" ]; then probe_readable=true; fi
if [ -w "$1" ]; then probe_writable=true; fi
printf '%s %s %s %s %s %s %s\n' "$probe_parent_directory" "$probe_parent_searchable" "$probe_kind" "$probe_uid" "$probe_mode" "$probe_readable" "$probe_writable"
"#;
        let output = docker_output(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "sh",
                "-c",
                PROBE,
                "fixture_keyring_metadata",
                path.to_str().expect("fixture keyring probe path UTF8"),
                path.parent()
                    .expect("fixture keyring probe parent")
                    .to_str()
                    .expect("fixture keyring probe parent UTF8"),
            ],
            "fixture_keyring_metadata",
            false,
        );
        assert!(
            output.stdout.len() <= 4096,
            "fixture keyring probe output limit"
        );
        let text = std::str::from_utf8(&output.stdout)
            .unwrap_or_else(|_| panic!("fixture keyring probe UTF8"));
        let fields: Vec<_> = text.split_whitespace().collect();
        assert!(fields.len() == 7, "fixture keyring probe field count");
        let boolean = |value: &str| match value {
            "true" => true,
            "false" => false,
            _ => panic!("fixture keyring probe boolean type"),
        };
        let parent_directory = boolean(fields[0]);
        let parent_searchable = boolean(fields[1]);
        let kind = match fields[2] {
            "REGULAR" => "REGULAR",
            "DIRECTORY" => "DIRECTORY",
            "OTHER" => "OTHER",
            "UNOBSERVED" => "UNOBSERVED",
            _ => panic!("fixture keyring probe kind type"),
        };
        let (owner_mysql, owner_root, mode) = if kind == "UNOBSERVED" {
            assert!(
                fields[3] == "-" && fields[4] == "-",
                "fixture keyring unobserved metadata"
            );
            (None, None, "UNOBSERVED".to_owned())
        } else {
            let uid = fields[3]
                .parse::<u32>()
                .expect("fixture keyring probe owner type");
            let mode = u16::from_str_radix(fields[4], 8).expect("fixture keyring probe mode type");
            assert!(mode <= 0o7777, "fixture keyring probe mode range");
            (
                Some(uid == mysql_uid),
                Some(uid == 0),
                format!("{mode:04o}"),
            )
        };
        let readable = boolean(fields[5]);
        let writable = boolean(fields[6]);
        eprintln!(
            "native fixture keyring object={object} parent_directory={parent_directory} parent_searchable={parent_searchable} kind={kind} owner_mysql={owner_mysql:?} owner_root={owner_root:?} mode={mode} readable={readable} writable={writable}"
        );
    }
    async fn connection(&self) -> MySqlConnection {
        match tokio::time::timeout(
            Duration::from_secs(5),
            MySqlConnection::connect_with(
                &self
                    .options()
                    .ssl_mode(MySqlSslMode::VerifyIdentity)
                    .ssl_ca_from_pem(self.ca.clone()),
            ),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => sdk_failure("fixture_tls_verify", &error),
            Err(_) => deadline_failure("fixture_tls_verify"),
        }
    }
    async fn tls(&self) {
        let result = tokio::time::timeout(Duration::from_secs(15), async {
            let mut c = match MySqlConnection::connect_with(
                &self
                    .options()
                    .host("127.0.0.1")
                    .ssl_mode(MySqlSslMode::Required),
            )
            .await
            {
                Ok(connection) => connection,
                Err(error) => sdk_failure("fixture_tls_bootstrap", &error),
            };
            for sql in [
                "SET GLOBAL ssl_ca='/var/lib/mysql/fixture-ca.pem'",
                "SET GLOBAL ssl_cert='/var/lib/mysql/fixture-server.pem'",
                "SET GLOBAL ssl_key='/var/lib/mysql/fixture-server.key'",
                "ALTER INSTANCE RELOAD TLS",
            ] {
                if let Err(error) = sqlx_core::query::query(sql).execute(&mut c).await {
                    sdk_failure("fixture_tls_reload", &error);
                }
            }
            drop(c);
            drop(self.connection().await);
        })
        .await;
        if result.is_err() {
            deadline_failure("fixture_tls_setup");
        }
    }
    async fn sql(&self, sql: &str) {
        let mut c = self.connection().await;
        match tokio::time::timeout(
            Duration::from_secs(10),
            sqlx_core::query::query(AssertSqlSafe(sql)).execute(&mut c),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(error)) => sdk_failure("fixture_setup_sql", &error),
            Err(_) => deadline_failure("fixture_setup_sql"),
        }
    }
    async fn scalar(&self, sql: &str) -> i64 {
        let mut c = self.connection().await;
        match tokio::time::timeout(
            Duration::from_secs(5),
            sqlx_core::query_scalar::query_scalar(AssertSqlSafe(sql)).fetch_one(&mut c),
        )
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => sdk_failure("fixture_setup_scalar", &error),
            Err(_) => deadline_failure("fixture_setup_scalar"),
        }
    }
    async fn admin_ddl(&self, control: AdminDdl) {
        let (sql, phase) = control.statement();
        let mut root = self.connection().await;
        match tokio::time::timeout(
            Duration::from_secs(10),
            sqlx_core::raw_sql::raw_sql(sql).execute(&mut root),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(error)) => sdk_failure(phase, &error),
            Err(_) => deadline_failure(phase),
        }
    }
    async fn reset(&self) {
        self.sql("DROP DATABASE IF EXISTS broker").await;
        self.sql("CREATE DATABASE broker CHARACTER SET latin1 COLLATE latin1_swedish_ci")
            .await;
    }
    async fn reference(&self) {
        self.reset().await;
        let mut c = self.connection().await;
        sqlx_core::raw_sql::raw_sql("USE broker")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx_core::query::query("SET SESSION sql_quote_show_create=1")
            .execute(&mut c)
            .await
            .unwrap();
        for table in TABLES {
            sqlx_core::query::query(AssertSqlSafe(table.create_statement(Dialect::Mysql)))
                .execute(&mut c)
                .await
                .unwrap();
        }
        sqlx_core::query::query(
            "INSERT INTO broker.schema_meta(id,format,epoch) VALUES(1,'rust-broker-v1',2)",
        )
        .execute(&mut c)
        .await
        .unwrap();
    }
    async fn constraint(&self, table: &str, kind: &str) -> String {
        let mut c = self.connection().await;
        let name: String=sqlx_core::query_scalar::query_scalar("SELECT CONSTRAINT_NAME FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA='broker' AND TABLE_NAME=? AND CONSTRAINT_TYPE=? ORDER BY CONSTRAINT_NAME LIMIT 1").bind(table).bind(kind).fetch_one(&mut c).await.unwrap();
        format!("`{}`", name.replace('`', "``"))
    }
    fn config(&self, max: usize) -> MySqlControlConfig {
        let connection = MysqlConnectionLimits {
            text_bytes: n(1024),
            ca_bytes: n(16_384),
        };
        MySqlControlConfig {
            endpoint: MysqlEndpoint::new(
                "localhost".into(),
                NonZeroU16::new(self.port).unwrap(),
                "broker".into(),
                connection,
            )
            .unwrap(),
            credentials: MysqlCredentials::new(
                ACCOUNT.into(),
                Zeroizing::new(PASSWORD.into()),
                connection,
            )
            .unwrap(),
            ca_pem: Some(self.ca.clone()),
            connection,
            admission: MysqlAdmissionLimits {
                max_inflight: n(max),
                budgets: MysqlBudgets {
                    acquire: Duration::from_secs(5),
                    connect: Duration::from_secs(5),
                    operation: Duration::from_secs(8),
                    startup: Duration::from_secs(15),
                    shutdown: Duration::from_secs(3),
                    lock: Duration::from_secs(5),
                },
            },
            catalog: MysqlCatalogLimits {
                rows_per_category: n(256),
                cell_bytes: n(16_384),
                total_bytes: n(2_000_000),
                grant_rows: n(64),
                grant_bytes: n(32_768),
                grant_tokens: n(2048),
                roles: n(32),
                statement_bytes: n(16_384),
                probes: n(256),
            },
            flows: limits(),
        }
    }
    async fn open(&self, max: usize) -> MySqlControlStore {
        MySqlControlStore::open(self.config(max), digester(), deadline())
            .await
            .unwrap()
    }
    async fn rejects(&self, expected: MySqlControlError) {
        self.rejects_phase(expected, "fixture_service_reject").await;
    }
    async fn rejects_phase(&self, expected: MySqlControlError, phase: &'static str) {
        assert_eq!(
            MySqlControlStore::open(self.config(1), digester(), deadline())
                .await
                .unwrap_err(),
            expected,
            "{phase}"
        );
    }
    async fn keyring(&mut self) {
        let executable = docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "readlink",
                "/proc/1/exe",
            ],
            "fixture_keyring_executable",
        );
        let (directory, name) = executable.trim().rsplit_once('/').unwrap();
        assert_eq!(name, "mysqld");
        let mut c = self.connection().await;
        let locations = match tokio::time::timeout(
            Duration::from_secs(10),
            sqlx_core::query::query("SELECT @@plugin_dir,@@datadir").fetch_one(&mut c),
        )
        .await
        {
            Ok(Ok(row)) => row,
            Ok(Err(error)) => sdk_failure("fixture_keyring_locations", &error),
            Err(_) => deadline_failure("fixture_keyring_locations"),
        };
        let plugin = locations
            .try_get::<String, _>(0)
            .unwrap_or_else(|error| sdk_failure("fixture_keyring_plugin_location", &error));
        let datadir = locations
            .try_get::<String, _>(1)
            .unwrap_or_else(|error| sdk_failure("fixture_keyring_data_location", &error));
        drop(c);
        assert!(Path::new(&datadir).is_absolute(), "fixture_keyring_datadir");
        docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "test",
                "-r",
                &format!("{}/component_keyring_file.so", plugin.trim_end_matches('/')),
            ],
            "fixture_keyring_component_library",
        );
        let keyring_directory = docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "mktemp",
                "-d",
                "/tmp/broker-keyring-XXXXXXXX",
            ],
            "fixture_keyring_directory",
        );
        let keyring_directory = docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "readlink",
                "-f",
                keyring_directory.trim(),
            ],
            "fixture_keyring_directory_canonical",
        );
        let datadir = docker_phase(
            &[
                "exec", "--user", "mysql", &self.id, "readlink", "-f", &datadir,
            ],
            "fixture_keyring_datadir_canonical",
        );
        let keyring_directory = Path::new(keyring_directory.trim());
        let datadir = Path::new(datadir.trim());
        for path in [keyring_directory, datadir] {
            assert!(
                path.is_absolute() && path != Path::new("/"),
                "fixture_keyring_canonical_locations"
            );
        }
        assert!(
            !keyring_directory.starts_with(datadir),
            "fixture_keyring_target_in_datadir"
        );
        let mode = docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "stat",
                "-c",
                "%a",
                keyring_directory.to_str().unwrap(),
            ],
            "fixture_keyring_directory_mode",
        );
        assert_eq!(mode.trim(), "700", "fixture_keyring_directory_mode");
        docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "test",
                "-w",
                keyring_directory.to_str().unwrap(),
            ],
            "fixture_keyring_directory_writable",
        );
        self.keyring_path = Some(keyring_directory.join("keyring"));
        const CREATE_KEYRING: &str = r#"set -eu
[ "$(id -u)" -ne 0 ]
[ ! -e "$1" ]
[ ! -L "$1" ]
umask 077
set -C
: > "$1"
[ -f "$1" ]
[ "$(stat -L -c %s "$1")" = 0 ]
[ "$(stat -L -c %u "$1")" = "$(id -u)" ]
[ "$(stat -L -c %a "$1")" = 600 ]
[ -r "$1" ]
[ -w "$1" ]
"#;
        docker_phase(
            &[
                "exec",
                "--user",
                "mysql",
                &self.id,
                "sh",
                "-c",
                CREATE_KEYRING,
                "fixture_keyring_file_create",
                self.keyring_path
                    .as_deref()
                    .expect("fixture keyring path")
                    .to_str()
                    .expect("fixture keyring path UTF8"),
            ],
            "fixture_keyring_file_create",
        );
        private_file(
            &self.files.path().join("mysqld.my"),
            br#"{"components":"file://component_keyring_file"}"#,
        );
        private_file(
            &self.files.path().join("component_keyring_file.cnf"),
            &serde_json::to_vec(&serde_json::json!({
                "path": keyring_directory.join("keyring"),
                "read_only": false,
            }))
            .expect("private keyring configuration"),
        );
        for (name, target, phase) in [
            (
                "mysqld.my",
                format!("{directory}/mysqld.my"),
                "fixture_keyring_manifest_mode",
            ),
            (
                "component_keyring_file.cnf",
                format!(
                    "{}/component_keyring_file.cnf",
                    plugin.trim_end_matches('/')
                ),
                "fixture_keyring_config_mode",
            ),
        ] {
            docker(&[
                "cp",
                self.files.path().join(name).to_str().unwrap(),
                &format!("{}:{target}", self.id),
            ]);
            docker_phase(
                &["exec", "--user", "root", &self.id, "chmod", "644", &target],
                phase,
            );
        }
        docker(&["restart", "--time", "5", &self.id]);
        self.port = self.published_port();
        self.wait().await;
        self.tls().await;
        assert_eq!(self.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM performance_schema.keyring_component_status WHERE STATUS_KEY='Component_status' AND STATUS_VALUE='Active'").await,1);
    }
}

async fn lease_snapshot(root: &mut MySqlConnection, expected_accounts: u64) -> [u64; 4] {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let rows = tokio::time::timeout_at(end.into(), sqlx_core::query::query("SELECT VARIABLE_NAME,VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME IN ('Connections','Ssl_accepts','Ssl_finished_accepts','Performance_schema_accounts_lost','Performance_schema_thread_instances_lost')").fetch_all(&mut *root)).await.expect("native cost status deadline")
            .unwrap_or_else(|error| sdk_failure("fixture_cost_status", &error));
        assert_eq!(rows.len(), 5, "native cost requires all status counters");
        let mut values = [None; 5];
        for row in rows {
            let name: String = row
                .try_get(0)
                .unwrap_or_else(|error| sdk_failure("fixture_cost_status", &error));
            let index = match name.as_str() {
                "Connections" => 0,
                "Ssl_accepts" => 1,
                "Ssl_finished_accepts" => 2,
                "Performance_schema_accounts_lost" => 3,
                "Performance_schema_thread_instances_lost" => 4,
                _ => panic!("unexpected native cost status counter"),
            };
            let value: String = row
                .try_get(1)
                .unwrap_or_else(|error| sdk_failure("fixture_cost_status", &error));
            assert!(
                values[index]
                    .replace(value.parse::<u64>().expect("native unsigned cost status"))
                    .is_none(),
                "duplicate native cost status counter"
            );
        }
        let values = values.map(|value| value.expect("missing native cost status counter"));
        assert_eq!(
            [values[3], values[4]],
            [0, 0],
            "native cost instrument loss"
        );
        let row = tokio::time::timeout_at(end.into(), sqlx_core::query::query("SELECT CAST(COUNT(*) AS UNSIGNED),CAST(COALESCE(SUM(TOTAL_CONNECTIONS),0) AS UNSIGNED),CAST(COALESCE(SUM(CURRENT_CONNECTIONS),0) AS UNSIGNED) FROM performance_schema.accounts WHERE USER=?").bind(ACCOUNT).fetch_one(&mut *root)).await.expect("native cost account deadline")
            .unwrap_or_else(|error| sdk_failure("fixture_cost_account", &error));
        let accounts: u64 = row
            .try_get(0)
            .unwrap_or_else(|error| sdk_failure("fixture_cost_account", &error));
        let total: u64 = row
            .try_get(1)
            .unwrap_or_else(|error| sdk_failure("fixture_cost_account", &error));
        let current: u64 = row
            .try_get(2)
            .unwrap_or_else(|error| sdk_failure("fixture_cost_account", &error));
        let tracked: u64 = tokio::time::timeout_at(end.into(), sqlx_core::query_scalar::query_scalar("SELECT CAST(COUNT(*) AS UNSIGNED) FROM performance_schema.accounts WHERE USER='root' AND CURRENT_CONNECTIONS>0").fetch_one(&mut *root)).await.expect("native cost root instrumentation deadline")
            .unwrap_or_else(|error| sdk_failure("fixture_cost_root", &error));
        assert!(tracked > 0, "native cost observer must be instrumented");
        assert!(Instant::now() < end, "native cost snapshot deadline");
        assert_eq!(
            accounts, expected_accounts,
            "native cost account row visibility"
        );
        if current == 0 {
            return [values[0], values[1], values[2], total];
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn lease_delta(root: &mut MySqlConnection, before: [u64; 4], expected: u64) {
    let after = lease_snapshot(root, 1).await;
    let delta = std::array::from_fn::<_, 4, _>(|index| {
        after[index]
            .checked_sub(before[index])
            .expect("native cost counters must not reset")
    });
    assert_eq!(delta, [expected; 4], "native connection/TLS/account cost");
    eprintln!("native connection cost attempts/TLS-started/TLS-finished/account={delta:?}");
}

#[tokio::test]
#[ignore = "real pinned MySQL TLS/startup/flows"]
async fn mysql_control_runtime_contract() {
    let started = Instant::now();
    let fixture = Fixture::new().await;
    let mut costs = fixture.connection().await;
    let accounts_size: i64 = tokio::time::timeout(
        Duration::from_secs(5),
        sqlx_core::query_scalar::query_scalar(
            "SELECT CAST(@@performance_schema_accounts_size AS SIGNED)",
        )
        .fetch_one(&mut costs),
    )
    .await
    .expect("native cost accounts size deadline")
    .unwrap_or_else(|error| sdk_failure("fixture_cost_size", &error));
    assert_ne!(accounts_size, 0, "native account counters must be enabled");
    let before_startup = lease_snapshot(&mut costs, 0).await;
    let store = fixture.open(4).await;
    lease_delta(&mut costs, before_startup, 1).await;
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await,MYSQL_CONTROL_ORACLE,"MYSQL_CONTROL_ORACLE");
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='broker'").await,138);
    assert_eq!(
        fixture
            .scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_permissions WHERE role='admin'"
            )
            .await,
        9
    );
    assert_eq!(
        fixture
            .scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_permissions WHERE role='user'"
            )
            .await,
        2
    );
    assert_eq!(fixture.scalar("SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NULL AS SIGNED)").await,1);
    let before_save = lease_snapshot(&mut costs, 1).await;
    store
        .save_flow(
            b"state",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    lease_delta(&mut costs, before_save, 1).await;
    assert_eq!(
        store
            .save_flow(
                b"state",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline()
            )
            .await,
        Err(MySqlControlError::FlowExists)
    );
    assert_eq!(
        store
            .consume_flow(b"state", b"wrong", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unavailable
    );
    let before_consume = lease_snapshot(&mut costs, 1).await;
    let result = store
        .consume_flow(b"state", b"binding", deadline())
        .await
        .unwrap();
    lease_delta(&mut costs, before_consume, 1).await;
    assert_eq!(result.nonce(), "synthetic-native-nonce");
    assert_eq!(result.continuation().request_id(), Some("request"));
    assert_eq!(
        store
            .consume_flow(b"state", b"binding", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unavailable
    );
    assert_eq!(
        store
            .save_flow(b"", b"binding", flow(Duration::from_secs(120)), deadline())
            .await,
        Err(MySqlControlError::InvalidFlow)
    );
    assert_eq!(
        store
            .save_flow(
                b"long-ttl",
                b"binding",
                flow(Duration::from_secs(601)),
                deadline()
            )
            .await,
        Err(MySqlControlError::InvalidFlow)
    );
    store
        .save_flow(
            b"race",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    let (one, two) = tokio::join!(
        store.consume_flow(b"race", b"binding", deadline()),
        store.consume_flow(b"race", b"binding", deadline())
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert_eq!(
        one.err().or_else(|| two.err()).unwrap(),
        MySqlControlError::Unavailable
    );
    let before = fixture
        .scalar("SELECT created_at FROM broker.roles WHERE name='admin'")
        .await;
    fixture
        .sql("INSERT INTO broker.roles(name,created_at) VALUES('custom',7)")
        .await;
    fixture
        .sql("INSERT INTO broker.role_permissions(role,action) VALUES('custom','custom.action')")
        .await;
    fixture
        .sql("UPDATE broker.resource_acl_state SET revision=17 WHERE id=1")
        .await;
    let reopened = fixture.open(1).await;
    assert_eq!(
        fixture
            .scalar("SELECT created_at FROM broker.roles WHERE name='admin'")
            .await,
        before
    );
    assert_eq!(
        fixture
            .scalar("SELECT revision FROM broker.resource_acl_state WHERE id=1")
            .await,
        17
    );
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_permissions WHERE role='custom' AND action='custom.action'").await,1);
    reopened.shutdown(deadline()).await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    let before_closed = lease_snapshot(&mut costs, 1).await;
    assert_eq!(
        store
            .save_flow(
                b"closed",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline()
            )
            .await,
        Err(MySqlControlError::Closed)
    );
    lease_delta(&mut costs, before_closed, 0).await;
    drop(costs);
    eprintln!(
        "MySQL startup/new-lease/flow contract wall {:?}; includes one owned server; process RSS collected separately, no hard driver-allocation bound",
        started.elapsed()
    );
}

#[tokio::test]
#[ignore = "real MySQL TEXT/TTL/corruption cases"]
async fn mysql_flow_payload_and_stored_corruption() {
    let fixture = Fixture::new().await;
    let store = fixture.open(2).await;
    // JSON output, not input character count, owns the physical TEXT boundary.
    for (size, valid) in [(65_535usize, true), (65_536, false)] {
        let overhead = FlowContinuation::Admin {
            provider_id: "x".into(),
        }
        .to_json(limits())
        .unwrap()
        .len()
            - 1;
        let provider = format!("é{}", "x".repeat(size - overhead - 2));
        let continuation = FlowContinuation::Admin {
            provider_id: provider,
        };
        assert_eq!(continuation.to_json(limits()).unwrap().len(), size);
        let input = OidcFlow::new(
            "n".into(),
            "a".repeat(43),
            continuation,
            SystemTime::now() + Duration::from_secs(120),
            limits(),
        )
        .unwrap();
        let result = store
            .save_flow(
                format!("payload-{size}").as_bytes(),
                b"binding",
                input,
                deadline(),
            )
            .await;
        assert_eq!(
            result,
            if valid {
                Ok(())
            } else {
                Err(MySqlControlError::InvalidFlow)
            }
        );
        if valid {
            store
                .consume_flow(format!("payload-{size}").as_bytes(), b"binding", deadline())
                .await
                .unwrap();
        }
    }
    let escaped = FlowContinuation::Admin {
        provider_id: "\"".repeat(40_000),
    };
    let input = OidcFlow::new(
        "n".into(),
        "a".repeat(43),
        escaped,
        SystemTime::now() + Duration::from_secs(120),
        limits(),
    )
    .unwrap();
    assert_eq!(
        store
            .save_flow(b"escaped", b"binding", input, deadline())
            .await,
        Err(MySqlControlError::InvalidFlow)
    );
    for (state, mutation) in [
        (
            "json",
            "continuation_json='{\"provider_id\":\"provider\",\"request_id\":\"request\",\"unknown\":true}'",
        ),
        ("nonce", "nonce=REPEAT('é',100)"),
        ("verifier", "pkce_verifier='short'"),
        ("purpose", "purpose='ADMIN'"),
        ("future", "created_at=expires_at-1,expires_at=expires_at+1"),
        ("ttl", "expires_at=created_at+600000001"),
    ] {
        store
            .save_flow(
                state.as_bytes(),
                b"binding",
                flow(Duration::from_secs(120)),
                deadline(),
            )
            .await
            .unwrap();
        let hash = digester()
            .token(TokenKind::OidcFlowState, state.as_bytes())
            .unwrap()
            .to_sql_hex();
        fixture
            .sql(&format!(
                "UPDATE broker.oidc_flows SET {mutation} WHERE state_hash='{hash}'"
            ))
            .await;
        assert_eq!(
            store
                .consume_flow(state.as_bytes(), b"binding", deadline())
                .await
                .unwrap_err(),
            MySqlControlError::CorruptFlow,
            "{state}"
        );
        assert_eq!(fixture.scalar(&format!("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows WHERE state_hash='{hash}'")).await,1);
        fixture
            .sql(&format!(
                "DELETE FROM broker.oidc_flows WHERE state_hash='{hash}'"
            ))
            .await;
    }
    store
        .save_flow(
            b"expired",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    let hash = digester()
        .token(TokenKind::OidcFlowState, b"expired")
        .unwrap()
        .to_sql_hex();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    fixture
        .sql(&format!(
            "UPDATE broker.oidc_flows SET created_at={},expires_at={} WHERE state_hash='{hash}'",
            now - 2_000_000,
            now - 1_000_000
        ))
        .await;
    assert_eq!(
        store
            .consume_flow(b"expired", b"binding", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Expired
    );
    assert_eq!(
        store
            .consume_flow(b"expired", b"binding", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unavailable
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real TLS and native least-authority visibility"]
async fn mysql_tls_session_capability_and_visibility() {
    let fixture = Fixture::new().await;
    let connection = MysqlConnectionLimits {
        text_bytes: n(1024),
        ca_bytes: n(16_384),
    };
    for host in [
        "mysql://localhost",
        "/tmp/mysql.sock",
        "localhost?ssl=false",
        "a@localhost",
        "localhost:3306",
        "localhost\n",
    ] {
        assert_eq!(
            MysqlEndpoint::new(
                host.into(),
                NonZeroU16::new(3306).unwrap(),
                "broker".into(),
                connection
            )
            .unwrap_err(),
            MySqlControlError::Configuration
        );
    }
    let mut config = fixture.config(1);
    let independent_key = KeyPair::generate().unwrap();
    let mut independent_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    independent_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let independent_ca = independent_params.self_signed(&independent_key).unwrap();
    assert_ne!(independent_ca.pem().as_bytes(), fixture.ca.as_slice());
    config.ca_pem = Some(independent_ca.pem().into_bytes());
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Connection
    );
    let mut config = fixture.config(1);
    config.ca_pem = Some(b"invalid CA".to_vec());
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Connection
    );
    let mut config = fixture.config(1);
    config.endpoint = MysqlEndpoint::new(
        "127.0.0.1".into(),
        NonZeroU16::new(fixture.port).unwrap(),
        "broker".into(),
        connection,
    )
    .unwrap();
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Connection
    );
    let mut config = fixture.config(1);
    config.admission.budgets.operation = Duration::ZERO;
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Configuration
    );
    let mut config = fixture.config(1);
    config.catalog.rows_per_category = n(128);
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Configuration
    );
    let config = fixture.config(1);
    let debug = format!("{config:?} {:?} {:?}", config.endpoint, config.credentials);
    for private in [ACCOUNT, PASSWORD, "localhost", "broker"] {
        assert!(!debug.contains(private));
    }
    let mut ordinary = MySqlConnection::connect_with(
        &fixture
            .options()
            .username(ACCOUNT)
            .password(PASSWORD)
            .ssl_mode(MySqlSslMode::VerifyIdentity)
            .ssl_ca_from_pem(fixture.ca.clone()),
    )
    .await
    .unwrap();
    let restricted = sqlx_core::query::query("SET SESSION innodb_strict_mode=ON")
        .execute(&mut ordinary)
        .await
        .unwrap_err();
    assert_eq!(
        restricted
            .as_database_error()
            .unwrap()
            .try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>()
            .unwrap()
            .number(),
        1227
    );
    drop(ordinary);
    fixture.sql("SET GLOBAL innodb_strict_mode=OFF").await;
    fixture
        .rejects(MySqlControlError::Unproven(UnprovenReason::SessionSettings))
        .await;
    fixture.sql("SET GLOBAL innodb_strict_mode=ON").await;
    // Native column grants survive DROP DATABASE, as documented by MySQL.
    // They cannot qualify whole-parent REFERENCES for a later fresh startup.
    fixture.reference().await;
    fixture
        .sql("GRANT REFERENCES(name) ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE REFERENCES ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture.reset().await;
    fixture
        .rejects(MySqlControlError::Unproven(UnprovenReason::Visibility))
        .await;
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await, 0);
    fixture
        .sql("REVOKE REFERENCES(name) ON broker.roles FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("GRANT REFERENCES ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    for privilege in ["CREATE", "REFERENCES", "SELECT", "TRIGGER"] {
        fixture
            .sql(&format!(
                "REVOKE {privilege} ON broker.* FROM 'ordinary`@_%'@'%'"
            ))
            .await;
        fixture
            .rejects(MySqlControlError::Unproven(UnprovenReason::Visibility))
            .await;
        assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await,0,"fresh proof must precede DDL");
        fixture
            .sql(&format!(
                "GRANT {privilege} ON broker.* TO 'ordinary`@_%'@'%'"
            ))
            .await;
    }
    fixture
        .sql("REVOKE EVENT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects(MySqlControlError::Denied(RequiredCapability::Event))
        .await;
    fixture
        .sql("GRANT EVENT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture.admin_ddl(AdminDdl::InertProcedure).await;
    let store = fixture.open(1).await;
    store.shutdown(deadline()).await.unwrap();
    fixture.admin_ddl(AdminDdl::AutonomousEvent).await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Event))
        .await;
    fixture.admin_ddl(AdminDdl::DropEvent).await;
    fixture
        .sql("REVOKE EVENT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects(MySqlControlError::Denied(RequiredCapability::Event))
        .await;
    fixture
        .sql("GRANT EVENT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE INSERT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects(MySqlControlError::Denied(RequiredCapability::Insert))
        .await;
    fixture
        .sql("GRANT INSERT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    // No row is written by native EXPLAIN, even with an actual trigger present.
    fixture
        .sql("CREATE TABLE broker.counter(value BIGINT NOT NULL)")
        .await;
    fixture.sql("INSERT INTO broker.counter VALUES(0)").await;
    fixture.admin_ddl(AdminDdl::CounterTrigger).await;
    fixture.sql("EXPLAIN FORMAT=TRADITIONAL INSERT INTO broker.oidc_flows(state_hash,browser_binding_hash,nonce,pkce_verifier,purpose,continuation_json,expires_at,created_at) VALUES('capability-only','capability-only','n','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','admin','{}',1,0)").await;
    assert_eq!(fixture.scalar("SELECT value FROM broker.counter").await, 0);
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Trigger))
        .await;
    fixture
        .sql("REVOKE TRIGGER ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects(MySqlControlError::Unproven(UnprovenReason::Visibility))
        .await;
    fixture.admin_ddl(AdminDdl::DropTrigger).await;
    fixture
        .sql("GRANT TRIGGER ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    for table in TABLES {
        if table.name() != "roles" {
            fixture
                .sql(&format!(
                    "GRANT SELECT ON broker.`{}` TO 'ordinary`@_%'@'%'",
                    table.name()
                ))
                .await;
        }
    }
    fixture
        .sql("GRANT SELECT(name) ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects(MySqlControlError::Denied(RequiredCapability::Select))
        .await;
    fixture
        .sql("REVOKE SELECT(name) ON broker.roles FROM 'ordinary`@_%'@'%'")
        .await;
    for table in TABLES {
        if table.name() != "roles" {
            fixture
                .sql(&format!(
                    "REVOKE SELECT ON broker.`{}` FROM 'ordinary`@_%'@'%'",
                    table.name()
                ))
                .await;
        }
    }
    fixture
        .sql("GRANT SELECT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture.admin_ddl(AdminDdl::ActiveRole).await;
    fixture.sql("GRANT SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON broker.* TO 'active_broker'@'%'").await;
    fixture
        .sql("GRANT 'active_broker'@'%' TO 'ordinary`@_%'@'%'")
        .await;
    fixture.sql("REVOKE SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON broker.* FROM 'ordinary`@_%'@'%'").await;
    fixture
        .sql("GRANT SELECT(name) ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects_phase(
            MySqlControlError::Unproven(UnprovenReason::Visibility),
            "tls_inactive_role",
        )
        .await;
    fixture
        .sql("REVOKE SELECT(name) ON broker.roles FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("SET DEFAULT ROLE 'active_broker'@'%' TO 'ordinary`@_%'@'%'")
        .await;
    let active = fixture.open(1).await;
    active.shutdown(deadline()).await.unwrap();
    fixture
        .sql("SET DEFAULT ROLE NONE TO 'ordinary`@_%'@'%'")
        .await;
    fixture.sql("GRANT SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON broker.* TO 'ordinary`@_%'@'%'").await;
    fixture.sql("SET GLOBAL partial_revokes=ON").await;
    fixture
        .sql("GRANT SELECT ON *.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    // A native global grant/revoke never supplies lower SELECT absence proof.
    fixture.reset().await;
    fixture
        .rejects_phase(
            MySqlControlError::Unproven(UnprovenReason::Visibility),
            "tls_partial_revoke",
        )
        .await;
    fixture.reference().await;
    for table in TABLES {
        fixture
            .sql(&format!(
                "GRANT SELECT ON broker.`{}` TO 'ordinary`@_%'@'%'",
                table.name()
            ))
            .await;
    }
    let lower = fixture.open(1).await;
    lower.shutdown(deadline()).await.unwrap();
    for table in TABLES {
        fixture
            .sql(&format!(
                "REVOKE SELECT ON broker.`{}` FROM 'ordinary`@_%'@'%'",
                table.name()
            ))
            .await;
    }
    fixture
        .sql("REVOKE SELECT ON *.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture.sql("SET GLOBAL partial_revokes=OFF").await;
    fixture
        .sql("GRANT SELECT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    tls_control(
        &mut root,
        "SET GLOBAL tls_version=''",
        "fixture_tls_disable_version",
    )
    .await;
    tls_control(
        &mut root,
        "ALTER INSTANCE RELOAD TLS NO ROLLBACK ON ERROR",
        "fixture_tls_disable_reload",
    )
    .await;
    let warning = match tokio::time::timeout(Duration::from_secs(10), async {
        let mut rows = sqlx_core::raw_sql::raw_sql("SHOW WARNINGS LIMIT 1").fetch(&mut root);
        let row = rows.try_next().await?;
        assert!(
            rows.try_next().await?.is_none(),
            "fixture_tls_disable_warning_cardinality"
        );
        Ok::<_, sqlx_core::error::Error>(row)
    })
    .await
    {
        Ok(Ok(Some(row))) => row,
        Ok(Ok(None)) => panic!("fixture_tls_disable_warning missing"),
        Ok(Err(error)) => sdk_failure("fixture_tls_disable_warning", &error),
        Err(_) => deadline_failure("fixture_tls_disable_warning"),
    };
    let level = warning
        .try_get::<String, _>(0)
        .unwrap_or_else(|error| sdk_failure("fixture_tls_disable_warning_level", &error));
    let code = warning
        .try_get::<u16, _>(1)
        .unwrap_or_else(|error| sdk_failure("fixture_tls_disable_warning_code", &error));
    assert_eq!(level, "Warning", "fixture_tls_disable_warning_level");
    assert_eq!(code, 3888, "fixture_tls_disable_warning_code");
    fixture.rejects(MySqlControlError::Connection).await;
    tls_control(
        &mut root,
        "SET GLOBAL tls_version='TLSv1.2,TLSv1.3'",
        "fixture_tls_restore_version",
    )
    .await;
    tls_control(
        &mut root,
        "ALTER INSTANCE RELOAD TLS",
        "fixture_tls_restore_reload",
    )
    .await;
    let restored = fixture.open(1).await;
    restored.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real strict metadata/schema mutants and native storage options"]
async fn mysql_schema_marker_metadata_and_storage_options() {
    let mut fixture = Fixture::new().await;
    fixture.keyring().await;
    let mut bounded = fixture.config(1);
    bounded.catalog.probes = n(16);
    assert_eq!(
        MySqlControlStore::open(bounded, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unproven(UnprovenReason::Truncated)
    );
    let partial=fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await;
    assert!(
        partial > 0 && partial < TABLES.len() as i64,
        "genuine producer DDL must remain partial after work exhaustion"
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.schema_meta")
            .await,
        0
    );
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Relations))
        .await;
    fixture.reset().await;
    fixture.sql("CREATE TABLE broker.partial(id BIGINT)").await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Relations))
        .await;
    fixture.reference().await;
    // oidc_flows has no dependent FK; substitute a real view of the same name.
    fixture.sql("DROP TABLE broker.oidc_flows").await;
    fixture
        .sql("CREATE VIEW broker.oidc_flows AS SELECT 1 AS id")
        .await;
    fixture
        .sql("GRANT SHOW VIEW ON broker.oidc_flows TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Table))
        .await;
    fixture.reference().await;
    fixture
        .sql("REVOKE SHOW VIEW ON broker.oidc_flows FROM 'ordinary`@_%'@'%'")
        .await;
    // Derive the primary-key-free fixture from the immutable producer DDL.
    let table = TABLES
        .iter()
        .find(|table| table.name() == "oidc_flows")
        .unwrap();
    let declared = table.create_statement(Dialect::Mysql);
    assert_eq!(declared.matches(" PRIMARY KEY").count(), 1);
    let without_primary = declared.replacen(" PRIMARY KEY", "", 1);
    fixture.sql("DROP TABLE broker.oidc_flows").await;
    let mut root = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("USE broker")
        .execute(&mut root)
        .await
        .unwrap();
    sqlx_core::query::query("SET SESSION sql_generate_invisible_primary_key=ON")
        .execute(&mut root)
        .await
        .unwrap();
    sqlx_core::query::query(AssertSqlSafe(without_primary))
        .execute(&mut root)
        .await
        .unwrap();
    drop(root);
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='broker' AND TABLE_NAME='oidc_flows' AND COLUMN_NAME='my_row_id'").await, 1);
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Columns))
        .await;
    fixture.reference().await;
    fixture.sql("DELETE FROM broker.schema_meta").await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Marker))
        .await;
    fixture
        .sql("INSERT INTO broker.schema_meta VALUES(1,'foreign',1)")
        .await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Marker))
        .await;
    let mutations = [
        (
            "ALTER TABLE broker.oidc_flows MODIFY purpose VARCHAR(33) NOT NULL",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles MODIFY created_at BIGINT UNSIGNED NOT NULL",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles MODIFY created_at SMALLINT NOT NULL",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles MODIFY created_at BIGINT NULL",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.local_tokens ALTER resource SET DEFAULT 'changed'",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles MODIFY created_at BIGINT NOT NULL FIRST",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles ADD extra_column BIGINT NOT NULL",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles DROP COLUMN created_at",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles DROP COLUMN created_at, ADD COLUMN created_at BIGINT GENERATED ALWAYS AS (1) STORED",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.roles MODIFY created_at BIGINT NOT NULL INVISIBLE",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.embedding_cache MODIFY provider TEXT CHARACTER SET latin1 COLLATE latin1_bin NOT NULL",
            SchemaReason::Columns,
        ),
        (
            "ALTER TABLE broker.local_tokens DROP INDEX token_id",
            SchemaReason::Indexes,
        ),
        (
            "ALTER TABLE broker.roles ADD INDEX extra_index(created_at)",
            SchemaReason::Indexes,
        ),
        (
            "ALTER TABLE broker.local_tokens DROP INDEX token_id, ADD UNIQUE INDEX replacement(token_id(10))",
            SchemaReason::Indexes,
        ),
        (
            "ALTER TABLE broker.local_tokens DROP INDEX token_id, ADD UNIQUE INDEX replacement(token_id DESC)",
            SchemaReason::Indexes,
        ),
        (
            "ALTER TABLE broker.local_tokens ALTER INDEX token_id INVISIBLE",
            SchemaReason::Indexes,
        ),
        (
            "ALTER TABLE broker.schema_meta ADD CHECK(epoch<999)",
            SchemaReason::Checks,
        ),
        (
            "ALTER TABLE broker.embedding_cache ENGINE=MyISAM",
            SchemaReason::Table,
        ),
        (
            "ALTER TABLE broker.roles ROW_FORMAT=COMPACT",
            SchemaReason::Table,
        ),
        (
            "ALTER TABLE broker.roles DEFAULT CHARACTER SET latin1 COLLATE latin1_bin",
            SchemaReason::Table,
        ),
        (
            "ALTER TABLE broker.embedding_cache PARTITION BY KEY(input_hash,compatibility_hash) PARTITIONS 2",
            SchemaReason::Partition,
        ),
    ];
    for (sql, reason) in mutations {
        fixture.reference().await;
        fixture.sql(sql).await;
        fixture
            .rejects(MySqlControlError::SchemaRejected(reason))
            .await;
        assert_eq!(
            fixture
                .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.roles")
                .await,
            0,
            "capture must reject before seeds"
        );
    }
    for replacement in [
        "",
        ", ADD FOREIGN KEY(role) REFERENCES broker.roles(name) ON DELETE RESTRICT",
        ", ADD FOREIGN KEY(role) REFERENCES broker.roles(name) ON DELETE CASCADE ON UPDATE CASCADE",
    ] {
        fixture.reference().await;
        let name = fixture.constraint("role_assignments", "FOREIGN KEY").await;
        fixture
            .sql(&format!(
                "ALTER TABLE broker.role_assignments DROP FOREIGN KEY {name}{replacement}"
            ))
            .await;
        fixture
            .rejects(MySqlControlError::SchemaRejected(SchemaReason::ForeignKeys))
            .await;
    }
    for action in ["drop", "weaken", "disabled"] {
        fixture.reference().await;
        let name = fixture.constraint("schema_meta", "CHECK").await;
        let alteration = match action {
            "drop" => format!("DROP CHECK {name}"),
            "weaken" => format!("DROP CHECK {name}, ADD CHECK(id>=0)"),
            _ => format!("ALTER CHECK {name} NOT ENFORCED"),
        };
        fixture
            .sql(&format!("ALTER TABLE broker.schema_meta {alteration}"))
            .await;
        fixture
            .rejects(MySqlControlError::SchemaRejected(SchemaReason::Checks))
            .await;
    }
    fixture.reference().await;
    let ready = fixture.open(1).await;
    ready
        .save_flow(
            b"new-session-temp",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    fixture
        .sql("GRANT CREATE TEMPORARY TABLES ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("SET GLOBAL init_connect='CREATE TEMPORARY TABLE broker.oidc_flows(id BIGINT)'")
        .await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Temporary))
        .await;
    assert_eq!(
        ready
            .save_flow(
                b"temp-write",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline()
            )
            .await,
        Err(MySqlControlError::SchemaRejected(SchemaReason::Temporary))
    );
    assert_eq!(
        ready
            .consume_flow(b"new-session-temp", b"binding", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::SchemaRejected(SchemaReason::Temporary)
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows")
            .await,
        1
    );
    fixture.sql("SET GLOBAL init_connect=''").await;
    fixture
        .sql("REVOKE CREATE TEMPORARY TABLES ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    ready
        .consume_flow(b"new-session-temp", b"binding", deadline())
        .await
        .unwrap();
    ready.shutdown(deadline()).await.unwrap();
    for (sql, phase) in [
        (
            "ALTER TABLE broker.roles ENGINE_ATTRIBUTE='{\"unknown\":1}'",
            "fixture_engine_attribute_unknown",
        ),
        (
            "ALTER TABLE broker.roles ENGINE_ATTRIBUTE='{}'",
            "fixture_engine_attribute_empty",
        ),
    ] {
        let mut root = fixture.connection().await;
        match tokio::time::timeout(
            Duration::from_secs(10),
            sqlx_core::query::query(AssertSqlSafe(sql)).execute(&mut root),
        )
        .await
        {
            Ok(Err(error)) => {
                let number = error
                    .as_database_error()
                    .and_then(|error| error.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>())
                    .map(sqlx_mysql::MySqlDatabaseError::number);
                if number != Some(3981) {
                    sdk_failure(phase, &error);
                }
            }
            Ok(Ok(_)) => panic!("InnoDB accepted an unsupported engine attribute"),
            Err(_) => deadline_failure(phase),
        }
    }
    let unchanged = fixture.open(1).await;
    unchanged
        .save_flow(
            b"unsupported-attribute",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    unchanged
        .consume_flow(b"unsupported-attribute", b"binding", deadline())
        .await
        .unwrap();
    unchanged.shutdown(deadline()).await.unwrap();
    for options in [
        "ROW_FORMAT=DEFAULT",
        "COMPRESSION='none'",
        "COMPRESSION='zlib'",
        "COMPRESSION='lz4'",
        "MAX_ROWS=4294967295 MIN_ROWS=1 AVG_ROW_LENGTH=9 STATS_SAMPLE_PAGES=4 STATS_AUTO_RECALC=0 STATS_PERSISTENT=1 PACK_KEYS=0 CHECKSUM=1 DELAY_KEY_WRITE=1",
    ] {
        fixture
            .sql(&format!("ALTER TABLE broker.oidc_flows {options}"))
            .await;
        let store = fixture.open(1).await;
        store
            .save_flow(
                b"storage",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline(),
            )
            .await
            .unwrap();
        store
            .consume_flow(b"storage", b"binding", deadline())
            .await
            .unwrap();
        store.shutdown(deadline()).await.unwrap();
    }
    for encryption in ["Y", "N"] {
        fixture
            .sql(&format!(
                "ALTER TABLE broker.oidc_flows ENCRYPTION='{encryption}'"
            ))
            .await;
        let store = fixture.open(1).await;
        store
            .save_flow(
                b"encrypted",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline(),
            )
            .await
            .unwrap();
        store
            .consume_flow(b"encrypted", b"binding", deadline())
            .await
            .unwrap();
        store.shutdown(deadline()).await.unwrap();
        let mut root = fixture.connection().await;
        let options:String=sqlx_core::query_scalar::query_scalar("SELECT CREATE_OPTIONS FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker' AND TABLE_NAME='oidc_flows'").fetch_one(&mut root).await.unwrap();
        eprintln!("native storage options observed: {options}");
    }
    let mut config = fixture.config(1);
    config.catalog.cell_bytes = n(8);
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unproven(UnprovenReason::Truncated)
    );
    let mut config = fixture.config(1);
    config.catalog.probes = n(2);
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unproven(UnprovenReason::Truncated)
    );
}

#[tokio::test]
#[ignore = "real quoted database grants and partial-revoke native contexts"]
async fn mysql_literal_grant_scopes_and_active_roles() {
    let fixture = Fixture::new().await;
    fixture
        .sql("CREATE DATABASE `case_%` CHARACTER SET latin1")
        .await;
    fixture.sql("GRANT SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON `case_%`.* TO 'ordinary`@_%'@'%'").await;
    let make = || {
        let mut config = fixture.config(1);
        config.endpoint = MysqlEndpoint::new(
            "localhost".into(),
            NonZeroU16::new(fixture.port).unwrap(),
            "case_%".into(),
            config.connection,
        )
        .unwrap();
        config
    };
    assert_eq!(
        MySqlControlStore::open(make(), digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unproven(UnprovenReason::Visibility)
    );
    fixture.sql(r"GRANT SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON `case\_\%`.* TO 'ordinary`@_%'@'%'").await;
    let store = MySqlControlStore::open(make(), digester(), deadline())
        .await
        .unwrap();
    store
        .save_flow(
            b"scope",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    store
        .consume_flow(b"scope", b"binding", deadline())
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
    fixture.sql("SET GLOBAL partial_revokes=ON").await;
    let store = MySqlControlStore::open(make(), digester(), deadline())
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
    fixture.sql("SET GLOBAL partial_revokes=OFF").await;
    fixture
        .sql("CREATE DATABASE `case``@name` CHARACTER SET latin1")
        .await;
    fixture.sql("GRANT SELECT,INSERT,DELETE,CREATE,REFERENCES,TRIGGER,EVENT ON `case``@name`.* TO 'ordinary`@_%'@'%'").await;
    let mut config = fixture.config(1);
    config.endpoint = MysqlEndpoint::new(
        "localhost".into(),
        NonZeroU16::new(fixture.port).unwrap(),
        "case`@name".into(),
        config.connection,
    )
    .unwrap();
    let store = MySqlControlStore::open(config, digester(), deadline())
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
}

struct RelayGate {
    blocked: AtomicBool,
    held_chunks: AtomicUsize,
    allowed_chunks: AtomicUsize,
    forwarded_chunks: AtomicUsize,
    changed: Notify,
}
impl RelayGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            blocked: AtomicBool::new(false),
            held_chunks: AtomicUsize::new(0),
            allowed_chunks: AtomicUsize::new(0),
            forwarded_chunks: AtomicUsize::new(0),
            changed: Notify::new(),
        })
    }
    fn block(&self) {
        self.held_chunks.store(0, Ordering::SeqCst);
        self.allowed_chunks.store(0, Ordering::SeqCst);
        self.blocked.store(true, Ordering::SeqCst);
    }
    fn unblock(&self) {
        self.blocked.store(false, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
    async fn held(&self) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.held_chunks.load(Ordering::SeqCst) > 0 {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("opaque outbound bytes held after native row SELECT");
    }
    async fn wait(&self) {
        if self.blocked.load(Ordering::SeqCst) {
            self.held_chunks.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
        }
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.blocked.load(Ordering::SeqCst)
                || self
                    .allowed_chunks
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1))
                    .is_ok()
            {
                return;
            }
            changed.await;
        }
    }
    async fn step(&self, end: Instant) {
        assert!(Instant::now() < end, "opaque chunk original deadline");
        assert!(self.blocked.load(Ordering::SeqCst));
        let before = self.forwarded_chunks.load(Ordering::SeqCst);
        self.allowed_chunks.fetch_add(1, Ordering::SeqCst);
        self.changed.notify_waiters();
        tokio::time::timeout_at(end.into(), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.forwarded_chunks.load(Ordering::SeqCst) > before {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("opaque chunk must forward under original operation deadline");
        assert!(
            Instant::now() < end,
            "opaque chunk forwarded after original deadline"
        );
    }
    async fn held_after(&self, count: usize, end: Instant) {
        assert!(Instant::now() < end, "opaque hold original deadline");
        tokio::time::timeout_at(end.into(), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.held_chunks.load(Ordering::SeqCst) > count {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("next opaque chunk must be held under original operation deadline");
        assert!(
            Instant::now() < end,
            "opaque hold observed after original deadline"
        );
    }
}
/// Opaque byte forwarding only: no TLS, SQL or MySQL packet decoding. Native
/// Performance Schema independently identifies the actual COMMIT under test.
struct Relay {
    port: u16,
    request: Arc<RelayGate>,
    response: Arc<RelayGate>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Relay {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Relay {
    async fn new(target: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let request = RelayGate::new();
        let response = RelayGate::new();
        let out = request.clone();
        let incoming = response.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{
                        let (client,_)=accepted.unwrap(); let request=out.clone(); let response=incoming.clone();
                        connections.spawn(async move {
                            let server=TcpStream::connect(("127.0.0.1",target)).await.unwrap();
                            let (mut cr,mut cw)=client.into_split(); let (mut sr,mut sw)=server.into_split();
                            tokio::select! { _=forward(&mut cr,&mut sw,request)=>{}, _=forward(&mut sr,&mut cw,response)=>{} }
                        });
                    },
                    _=connections.join_next(),if !connections.is_empty()=>{},
                }
            }
        });
        Self {
            port,
            request,
            response,
            task: Some(task),
        }
    }
    async fn stop(mut self) {
        let task = self.task.take().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    fn config(&self, fixture: &Fixture, max: usize) -> MySqlControlConfig {
        let mut config = fixture.config(max);
        config.endpoint = MysqlEndpoint::new(
            "localhost".into(),
            NonZeroU16::new(self.port).unwrap(),
            "broker".into(),
            config.connection,
        )
        .unwrap();
        config
    }
}
async fn forward<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    gate: Arc<RelayGate>,
) -> std::io::Result<()> {
    let mut bytes = [0u8; 8192];
    loop {
        let size = read.read(&mut bytes).await?;
        if size == 0 {
            return Ok(());
        }
        gate.wait().await;
        write.write_all(&bytes[..size]).await?;
        gate.forwarded_chunks.fetch_add(1, Ordering::SeqCst);
        gate.changed.notify_waiters();
    }
}
async fn wait_native(fixture: &Fixture, predicate: &str, count: i64) {
    try_wait_native_until(
        fixture,
        predicate,
        count,
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .expect("native observation deadline");
}
async fn try_observer_connection_until(fixture: &Fixture, end: Instant) -> Option<MySqlConnection> {
    match tokio::time::timeout_at(
        end.into(),
        MySqlConnection::connect_with(
            &fixture
                .options()
                .ssl_mode(MySqlSslMode::VerifyIdentity)
                .ssl_ca_from_pem(fixture.ca.clone()),
        ),
    )
    .await
    {
        Ok(Ok(connection)) => Some(connection),
        Ok(Err(error)) => sdk_failure("fixture_tls_verify", &error),
        Err(_) => None,
    }
}
async fn try_wait_native_until(
    fixture: &Fixture,
    predicate: &str,
    count: i64,
    end: Instant,
) -> Result<(), Option<i64>> {
    let mut root = match try_observer_connection_until(fixture, end).await {
        Some(root) => root,
        None => return Err(None),
    };
    let mut last_count = None;
    loop {
        let query =
            sqlx_core::query_scalar::query_scalar(AssertSqlSafe(predicate)).fetch_one(&mut root);
        let observed = match tokio::time::timeout_at(end.into(), query).await {
            Ok(Ok(observed)) => observed,
            Ok(Err(error)) => sdk_failure("fixture_setup_scalar", &error),
            Err(_) => return Err(last_count),
        };
        last_count = Some(observed);
        if Instant::now() >= end {
            return Err(last_count);
        }
        if observed == count {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
enum StatementPhase {
    Commit,
    CreateTable,
    CreateMarker,
    ConsumeRowLock,
    StartupRowLock,
    SessionRowLock,
    SessionPrincipalInsert,
}
impl StatementPhase {
    fn prefix(self) -> &'static str {
        match self {
            Self::SessionRowLock => "SELECT CASE WHEN OCTET_LENGTH(s.subject)",
            Self::SessionPrincipalInsert => "INSERT INTO `broker`.`admin_session_principals`",
            Self::Commit => "COMMIT",
            Self::CreateTable => "CREATE TABLE ",
            Self::CreateMarker => "CREATE TABLE schema_meta (",
            Self::ConsumeRowLock => "SELECT CASE WHEN OCTET_LENGTH(nonce)",
            Self::StartupRowLock => {
                "SELECT id,revision,updated_at FROM `broker`.`resource_acl_state` WHERE id=1 FOR UPDATE"
            }
        }
    }
}
async fn wait_statement(fixture: &Fixture, phase: StatementPhase) {
    try_wait_statement(fixture, phase)
        .await
        .expect("actual native statement not observed");
}
async fn try_wait_statement(
    fixture: &Fixture,
    phase: StatementPhase,
) -> Result<(), Option<[i64; 4]>> {
    try_wait_statement_until(fixture, phase, Instant::now() + Duration::from_secs(5)).await
}
async fn try_wait_statement_until(
    fixture: &Fixture,
    phase: StatementPhase,
    end: Instant,
) -> Result<(), Option<[i64; 4]>> {
    let execute_only = matches!(
        phase,
        StatementPhase::CreateMarker
            | StatementPhase::SessionRowLock
            | StatementPhase::SessionPrincipalInsert
    );
    let prefix = phase.prefix();
    let mut root = match try_observer_connection_until(fixture, end).await {
        Some(root) => root,
        None => return Err(None),
    };
    let mut last_snapshot: Option<[i64; 4]> = None;
    loop {
        let query = sqlx_core::query::query("SELECT CAST(COALESCE(SUM(e.END_EVENT_ID IS NULL AND e.SQL_TEXT LIKE ?),0) AS SIGNED),CAST(COALESCE(SUM(t.PROCESSLIST_COMMAND<>'Sleep' AND t.PROCESSLIST_INFO LIKE ? AND (?=0 OR t.PROCESSLIST_COMMAND='Execute')),0) AS SIGNED),CAST(COALESCE(SUM(t.PROCESSLIST_COMMAND<>'Sleep' AND e.SQL_TEXT IS NULL),0) AS SIGNED),CAST(COALESCE(SUM(t.PROCESSLIST_COMMAND<>'Sleep'),0) AS SIGNED),CAST(COUNT(*) AS SIGNED),CAST(COALESCE(MIN(t.PROCESSLIST_ID>0 AND t.THREAD_ID>0),0) AS SIGNED) FROM performance_schema.threads t LEFT JOIN performance_schema.events_statements_current e ON e.THREAD_ID=t.THREAD_ID WHERE t.PROCESSLIST_USER=?")
            .bind(format!("{prefix}%"))
            .bind(format!("{prefix}%"))
            .bind(execute_only)
            .bind(ACCOUNT)
            .fetch_one(&mut root);
        let row = match tokio::time::timeout_at(end.into(), query).await {
            Ok(row) => {
                row.unwrap_or_else(|error| sdk_failure("fixture_statement_observer", &error))
            }
            Err(_) => return Err(last_snapshot),
        };
        let observed = [
            row.try_get::<i64, _>(0).unwrap(),
            row.try_get::<i64, _>(1).unwrap(),
            row.try_get::<i64, _>(2).unwrap(),
            row.try_get::<i64, _>(3).unwrap(),
        ];
        last_snapshot = Some(observed);
        let singleton = row.try_get::<i64, _>(4).unwrap() == 1;
        let native_session = row.try_get::<i64, _>(5).unwrap() == 1;
        if Instant::now() >= end {
            return Err(last_snapshot);
        }
        if observed[1] == 1 && observed[3] == 1 && singleton && native_session {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn instrumentation(fixture: &Fixture) {
    fixture.sql("UPDATE performance_schema.setup_consumers SET ENABLED='YES' WHERE NAME='events_statements_current'").await;
    fixture.sql("UPDATE performance_schema.setup_instruments SET ENABLED='YES',TIMED='YES' WHERE NAME LIKE 'statement/%'").await;
}
const NO_ORDINARY: &str = "SELECT CAST(COUNT(*) AS SIGNED) FROM performance_schema.threads WHERE PROCESSLIST_USER='ordinary`@_%'";
type FreshBarrierFault = (&'static str, Option<[i64; 4]>, Option<i64>);
async fn arm_fresh_commit(
    fixture: &Fixture,
    relay: &Relay,
    startup_end: Instant,
) -> Result<(), FreshBarrierFault> {
    let first_end = startup_end.min(Instant::now() + Duration::from_secs(5));
    try_wait_statement_until(fixture, StatementPhase::CreateMarker, first_end)
        .await
        .map_err(|snapshot| ("first_create", snapshot, None))?;
    // The first genuine CREATE is still active; withhold its opaque ACK.
    relay.response.block();
    let mut root = try_observer_connection_until(fixture, startup_end)
        .await
        .ok_or(("root_connect", None, None))?;
    for (sql, phase) in [
        (
            "SET GLOBAL binlog_group_commit_sync_delay=0",
            "disable_ddl_delay",
        ),
        ("LOCK TABLES `broker`.`schema_meta` WRITE", "lock_marker"),
    ] {
        match tokio::time::timeout_at(
            startup_end.into(),
            sqlx_core::raw_sql::raw_sql(sql).execute(&mut root),
        )
        .await
        {
            Ok(Ok(_)) if Instant::now() < startup_end => (),
            Ok(Err(error)) => sdk_failure(phase, &error),
            _ => return Err((phase, None, None)),
        }
    }
    let held_end = startup_end.min(Instant::now() + Duration::from_secs(5));
    tokio::time::timeout_at(held_end.into(), async {
        loop {
            let changed = relay.response.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if relay.response.held_chunks.load(Ordering::SeqCst) > 0 {
                break;
            }
            changed.await;
        }
    })
    .await
    .map_err(|_| ("first_create_ack", None, None))?;
    if Instant::now() >= held_end {
        return Err(("first_create_ack", None, None));
    }
    relay.response.unblock();
    // Remaining DDL runs without delay. The retained root WRITE lock blocks
    // catalog opening of schema_meta, without inserting or changing any row.
    const PENDING_MARKER: &str = "SELECT CAST(COUNT(*) AS SIGNED) FROM performance_schema.metadata_locks m JOIN performance_schema.threads t ON t.THREAD_ID=m.OWNER_THREAD_ID WHERE t.PROCESSLIST_USER='ordinary`@_%' AND t.PROCESSLIST_COMMAND<>'Sleep' AND t.PROCESSLIST_ID>0 AND t.THREAD_ID>0 AND m.OBJECT_TYPE='TABLE' AND m.OBJECT_SCHEMA='broker' AND m.OBJECT_NAME='schema_meta' AND m.LOCK_STATUS='PENDING'";
    try_wait_native_until(fixture, PENDING_MARKER, 1, startup_end)
        .await
        .map_err(|count| ("pending_marker", None, count))?;
    for (sql, phase) in [
        (
            "SET GLOBAL binlog_group_commit_sync_delay=1000000",
            "arm_commit_delay",
        ),
        ("UNLOCK TABLES", "unlock_marker"),
    ] {
        match tokio::time::timeout_at(
            startup_end.into(),
            sqlx_core::raw_sql::raw_sql(sql).execute(&mut root),
        )
        .await
        {
            Ok(Ok(_)) if Instant::now() < startup_end => (),
            Ok(Err(error)) => sdk_failure(phase, &error),
            _ => return Err((phase, None, None)),
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "real COMMIT/lost release ACK over opaque TLS relay"]
async fn mysql_commit_uncertainty_and_known_startup_cleanup() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let baseline = fixture.open(1).await;
    baseline.shutdown(deadline()).await.unwrap();
    for consume in [false, true] {
        let state = if consume {
            b"consume-commit-fault".as_slice()
        } else {
            b"save-commit-fault".as_slice()
        };
        let relay = Relay::new(fixture.port).await;
        let store = Arc::new(
            MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
                .await
                .unwrap(),
        );
        if consume {
            store
                .save_flow(
                    state,
                    b"binding",
                    flow(Duration::from_secs(120)),
                    deadline(),
                )
                .await
                .unwrap();
        }
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
            .await;
        let owner = store.clone();
        let operation = tokio::spawn(async move {
            let end = Instant::now() + Duration::from_secs(5);
            if consume {
                owner.consume_flow(state, b"binding", end).await.map(|_| ())
            } else {
                owner
                    .save_flow(state, b"binding", flow(Duration::from_secs(120)), end)
                    .await
            }
        });
        if let Err(snapshot) = try_wait_statement(&fixture, StatementPhase::Commit).await {
            let outcome = operation.await.unwrap();
            panic!(
                "native COMMIT not observed phase={} snapshot={snapshot:?} outcome={outcome:?}",
                if consume { "consume" } else { "save" }
            );
        }
        relay.response.block();
        assert_eq!(
            operation.await.unwrap(),
            Err(MySqlControlError::OutcomeUncertain)
        );
        // The real server has committed despite the caller lacking an ACK.
        let hash = digester()
            .token(TokenKind::OidcFlowState, state)
            .unwrap()
            .to_sql_hex();
        assert_eq!(fixture.scalar(&format!("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows WHERE state_hash='{hash}'")).await,if consume {0} else {1});
        relay.stop().await;
        wait_native(&fixture, NO_ORDINARY, 0).await;
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
            .await;
        store.shutdown(deadline()).await.unwrap();
    }
    fixture.reset().await;
    let relay = Relay::new(fixture.port).await;
    let config = relay.config(&fixture, 1);
    fixture
        .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
        .await;
    let startup_end = Instant::now() + config.admission.budgets.startup;
    let opening =
        tokio::spawn(async move { MySqlControlStore::open(config, digester(), deadline()).await });
    if let Err(fault) = arm_fresh_commit(&fixture, &relay, startup_end).await {
        let outcome = opening.await.unwrap().map(|_| ());
        panic!(
            "native Fresh barrier not observed phase=startup_release fault={fault:?} outcome={outcome:?}"
        );
    }
    let commit_end = startup_end.min(Instant::now() + Duration::from_secs(5));
    if let Err(snapshot) =
        try_wait_statement_until(&fixture, StatementPhase::Commit, commit_end).await
    {
        let outcome = opening.await.unwrap().map(|_| ());
        panic!(
            "native COMMIT not observed phase=startup_release snapshot={snapshot:?} outcome={outcome:?}"
        );
    }
    // Request forwarding is held only after the server receives COMMIT. Its ACK
    // returns unchanged; subsequent RELEASE_LOCK cannot reach the server.
    relay.request.block();
    assert_eq!(
        opening.await.unwrap().unwrap_err(),
        MySqlControlError::StartupCommittedCleanupFailed(CleanupReason::Deadline)
    );
    assert_eq!(
        fixture
            .scalar("SELECT epoch FROM broker.schema_meta WHERE id=1")
            .await,
        2
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_permissions")
            .await,
        11
    );
    assert_eq!(fixture.scalar("SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NOT NULL AS SIGNED)").await,1);
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
    wait_native(
        &fixture,
        "SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NULL AS SIGNED)",
        1,
    )
    .await;
    fixture
        .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
        .await;
    let recovered = fixture.open(1).await;
    recovered.shutdown(deadline()).await.unwrap();
    // An unacknowledged startup COMMIT is independently uncertain, even when a
    // later operator read observes the committed marker.
    fixture.reset().await;
    let relay = Relay::new(fixture.port).await;
    let config = relay.config(&fixture, 1);
    fixture
        .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
        .await;
    let startup_end = Instant::now() + config.admission.budgets.startup;
    let opening =
        tokio::spawn(async move { MySqlControlStore::open(config, digester(), deadline()).await });
    if let Err(fault) = arm_fresh_commit(&fixture, &relay, startup_end).await {
        let outcome = opening.await.unwrap().map(|_| ());
        panic!(
            "native Fresh barrier not observed phase=startup_ack fault={fault:?} outcome={outcome:?}"
        );
    }
    let commit_end = startup_end.min(Instant::now() + Duration::from_secs(5));
    if let Err(snapshot) =
        try_wait_statement_until(&fixture, StatementPhase::Commit, commit_end).await
    {
        let outcome = opening.await.unwrap().map(|_| ());
        panic!(
            "native COMMIT not observed phase=startup_ack snapshot={snapshot:?} outcome={outcome:?}"
        );
    }
    relay.response.block();
    assert_eq!(
        opening.await.unwrap().unwrap_err(),
        MySqlControlError::OutcomeUncertain
    );
    assert_eq!(
        fixture
            .scalar("SELECT epoch FROM broker.schema_meta WHERE id=1")
            .await,
        2
    );
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
    fixture
        .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
        .await;
}

const FLOW_LOCKED_LIVE: usize = 1;
const FLOW_DELETE_STAGED: usize = 2;
const FLOW_CONSUME_COMMITTED: usize = 4;

struct FlowPhases {
    observed: AtomicUsize,
    invalid_metadata: AtomicBool,
    changed: Notify,
}
impl FlowPhases {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            observed: AtomicUsize::new(0),
            invalid_metadata: AtomicBool::new(false),
            changed: Notify::new(),
        })
    }
    async fn wait(&self, phases: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.observed.load(Ordering::SeqCst) & phases == phases {
                    return;
                }
                changed.await;
            }
        })
        .await
        .expect("actual production flow phase observed");
    }
}
struct FlowPhaseLayer(Arc<FlowPhases>);
impl Layer<Registry> for FlowPhaseLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, Registry>) {
        let metadata = event.metadata();
        let phase = match metadata.target() {
            "broker_control::mysql::flow_locked_live" => FLOW_LOCKED_LIVE,
            "broker_control::mysql::flow_delete_staged" => FLOW_DELETE_STAGED,
            "broker_control::mysql::flow_consume_committed" => FLOW_CONSUME_COMMITTED,
            _ => return,
        };
        // This observer has no clock, SQL, store or relay reference. It records
        // metadata only; the test parent controls transport independently.
        if *metadata.level() != tracing::Level::TRACE
            || metadata.fields().len() != 1
            || metadata
                .fields()
                .iter()
                .any(|field| field.name() != "message")
        {
            self.0.invalid_metadata.store(true, Ordering::SeqCst);
        }
        self.0.observed.fetch_or(phase, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

#[tokio::test]
#[ignore = "real expiry after locked SELECT and before COMMIT"]
async fn mysql_expiry_after_row_lock_before_commit() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let relay = Relay::new(fixture.port).await;
    let mut config = relay.config(&fixture, 1);
    config.admission.budgets.operation = Duration::from_secs(30);
    let store = Arc::new(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap(),
    );
    let saved = flow(Duration::from_secs(15));
    store
        .save_flow(b"precommit-expiry", b"binding", saved, deadline())
        .await
        .unwrap();
    let hash = digester()
        .token(TokenKind::OidcFlowState, b"precommit-expiry")
        .unwrap()
        .to_sql_hex();
    let expiry = fixture
        .scalar(&format!(
            "SELECT expires_at FROM broker.oidc_flows WHERE state_hash='{hash}'"
        ))
        .await;
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query(
        "SELECT state_hash FROM broker.oidc_flows WHERE state_hash=? FOR UPDATE",
    )
    .bind(&hash)
    .fetch_one(&mut blocker)
    .await
    .unwrap();
    let owner = store.clone();
    let phases = FlowPhases::new();
    let subscriber = Registry::default().with(FlowPhaseLayer(phases.clone()));
    let consuming = tokio::spawn(
        (async move {
            owner
                .consume_flow(
                    b"precommit-expiry",
                    b"binding",
                    Instant::now() + Duration::from_secs(30),
                )
                .await
        })
        .with_subscriber(subscriber),
    );
    wait_statement(&fixture, StatementPhase::ConsumeRowLock).await;
    // SELECT is already at the real server. Its ACK returns unchanged after
    // releasing the blocker; subsequent opaque outbound bytes are held.
    // This makes the DELETE exchange unable to finish before expiry, without
    // interpreting driver preparation/close packets as SQL authority.
    relay.request.block();
    sqlx_core::raw_sql::raw_sql("ROLLBACK")
        .execute(&mut blocker)
        .await
        .unwrap();
    drop(blocker);
    relay.request.held().await;
    phases.wait(FLOW_LOCKED_LIVE).await;
    wait_native(&fixture, "SELECT CAST(COUNT(*)>=1 AS SIGNED) FROM performance_schema.data_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE t.PROCESSLIST_USER='ordinary`@_%' AND l.OBJECT_SCHEMA='broker' AND l.OBJECT_NAME='oidc_flows' AND l.LOCK_TYPE='RECORD' AND l.LOCK_STATUS='GRANTED' AND l.LOCK_MODE LIKE 'X%'", 1).await;
    let before_hold = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    assert!(
        expiry - before_hold > 2_000_000,
        "flow must still be live while its native row lock is held"
    );
    assert_eq!(
        fixture
            .scalar(&format!(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows WHERE state_hash='{hash}'"
            ))
            .await,
        1
    );
    let until_expiry = u64::try_from(expiry - before_hold).unwrap();
    tokio::time::sleep(Duration::from_micros(until_expiry) + Duration::from_millis(100)).await;
    relay.request.unblock();
    assert_eq!(
        consuming.await.unwrap().unwrap_err(),
        MySqlControlError::Expired
    );
    phases
        .wait(FLOW_DELETE_STAGED | FLOW_CONSUME_COMMITTED)
        .await;
    assert_eq!(
        phases.observed.load(Ordering::SeqCst),
        FLOW_LOCKED_LIVE | FLOW_DELETE_STAGED | FLOW_CONSUME_COMMITTED
    );
    assert!(!phases.invalid_metadata.load(Ordering::SeqCst));
    assert_eq!(
        fixture
            .scalar(&format!(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows WHERE state_hash='{hash}'"
            ))
            .await,
        0
    );
    assert_eq!(
        store
            .consume_flow(b"precommit-expiry", b"binding", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unavailable
    );
    store.shutdown(deadline()).await.unwrap();
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
}

#[tokio::test]
#[ignore = "real CREATE ACK loss and two competing startups"]
async fn mysql_create_ack_loss_and_competing_startups() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let mut root = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("LOCK INSTANCE FOR BACKUP")
        .execute(&mut root)
        .await
        .unwrap();
    let relay = Relay::new(fixture.port).await;
    let config = relay.config(&fixture, 1);
    let opening = tokio::spawn(async move {
        MySqlControlStore::open(config, digester(), Instant::now() + Duration::from_secs(8)).await
    });
    wait_statement(&fixture, StatementPhase::CreateTable).await;
    // The native backup lock holds genuine producer DDL before its ACK. The
    // opaque relay then withholds the response after the server executes it.
    relay.response.block();
    sqlx_core::raw_sql::raw_sql("UNLOCK INSTANCE")
        .execute(&mut root)
        .await
        .unwrap();
    drop(root);
    wait_native(&fixture, "SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'", 1).await;
    assert_eq!(
        opening.await.unwrap().unwrap_err(),
        MySqlControlError::Deadline
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.schema_meta")
            .await,
        0
    );
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
    wait_native(
        &fixture,
        "SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NULL AS SIGNED)",
        1,
    )
    .await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Relations))
        .await;

    fixture.reference().await;
    fixture
        .sql("INSERT INTO broker.resource_acl_state VALUES(1,17,19)")
        .await;
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT id FROM broker.resource_acl_state WHERE id=1 FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let first = fixture.config(1);
    let opening =
        tokio::spawn(async move { MySqlControlStore::open(first, digester(), deadline()).await });
    wait_statement(&fixture, StatementPhase::StartupRowLock).await;
    assert_eq!(fixture.scalar("SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NOT NULL AS SIGNED)").await, 1);
    let mut second = fixture.config(1);
    second.admission.budgets.lock = Duration::from_secs(1);
    assert_eq!(
        MySqlControlStore::open(second, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::StartupBusy
    );
    sqlx_core::raw_sql::raw_sql("ROLLBACK")
        .execute(&mut blocker)
        .await
        .unwrap();
    drop(blocker);
    let first = opening.await.unwrap().unwrap();
    first.shutdown(deadline()).await.unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(
        fixture
            .scalar("SELECT revision FROM broker.resource_acl_state WHERE id=1")
            .await,
        17
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_permissions")
            .await,
        11
    );
    wait_native(
        &fixture,
        "SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NULL AS SIGNED)",
        1,
    )
    .await;
    let second = fixture.open(1).await;
    second.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real admission/row locks/MDL/cancellation/shutdown"]
async fn mysql_lifecycle_locking_and_cancelled_seed_rollback() {
    let fixture = Fixture::new().await;
    instrumentation(&fixture).await;
    let store = Arc::new(fixture.open(1).await);
    store
        .save_flow(
            b"blocked",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    let hash = digester()
        .token(TokenKind::OidcFlowState, b"blocked")
        .unwrap()
        .to_sql_hex();
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query(
        "SELECT state_hash FROM broker.oidc_flows WHERE state_hash=? FOR UPDATE",
    )
    .bind(&hash)
    .fetch_one(&mut blocker)
    .await
    .unwrap();
    let owner = store.clone();
    let operation =
        tokio::spawn(async move { owner.consume_flow(b"blocked", b"binding", deadline()).await });
    wait_statement(&fixture, StatementPhase::ConsumeRowLock).await;
    assert_eq!(fixture.scalar(NO_ORDINARY).await, 1);
    let short = Instant::now() + Duration::from_millis(200);
    assert_eq!(
        store
            .save_flow(
                b"waiting",
                b"binding",
                flow(Duration::from_secs(120)),
                short
            )
            .await,
        Err(MySqlControlError::Deadline)
    );
    assert_eq!(
        fixture.scalar(NO_ORDINARY).await,
        1,
        "queued caller must not open a second handle"
    );
    let mut ddl = fixture.connection().await;
    let id: u64 = sqlx_core::query_scalar::query_scalar("SELECT CAST(CONNECTION_ID() AS UNSIGNED)")
        .fetch_one(&mut ddl)
        .await
        .unwrap();
    let mut changing = tokio::spawn(async move {
        sqlx_core::query::query("ALTER TABLE broker.roles ADD mdl_probe BIGINT")
            .execute(&mut ddl)
            .await
    });
    wait_native(&fixture,"SELECT CAST(COUNT(*) AS SIGNED) FROM performance_schema.threads WHERE PROCESSLIST_STATE='Waiting for table metadata lock' AND PROCESSLIST_INFO LIKE 'ALTER TABLE broker.roles ADD mdl_probe%'",1).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut changing)
            .await
            .is_err(),
        "all25 MDL must remain held during row locking"
    );
    fixture.sql(&format!("KILL QUERY {id}")).await;
    assert!(changing.await.unwrap().is_err());
    let owner = store.clone();
    let waiter = tokio::spawn(async move {
        owner
            .save_flow(
                b"shutdown-waiter",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline(),
            )
            .await
    });
    tokio::task::yield_now().await;
    let owner = store.clone();
    let shutting = tokio::spawn(async move {
        owner
            .shutdown(Instant::now() + Duration::from_millis(100))
            .await
    });
    assert_eq!(waiter.await.unwrap(), Err(MySqlControlError::Closed));
    assert_eq!(shutting.await.unwrap(), Err(MySqlControlError::Deadline));
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    store.shutdown(deadline()).await.unwrap();
    sqlx_core::raw_sql::raw_sql("ROLLBACK")
        .execute(&mut blocker)
        .await
        .unwrap();
    drop(blocker);
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(
        fixture
            .scalar(&format!(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows WHERE state_hash='{hash}'"
            ))
            .await,
        1
    );
    assert_eq!(
        store
            .save_flow(
                b"closed",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline()
            )
            .await,
        Err(MySqlControlError::Closed)
    );
    let store = fixture.open(1).await;
    assert_eq!(
        store
            .shutdown(Instant::now() - Duration::from_secs(1))
            .await,
        Err(MySqlControlError::Deadline)
    );
    assert_eq!(
        store
            .save_flow(
                b"expired-shutdown",
                b"binding",
                flow(Duration::from_secs(120)),
                deadline()
            )
            .await,
        Err(MySqlControlError::Closed)
    );
    let store = Arc::new(fixture.open(1).await);
    store
        .save_flow(
            b"lock-expiry",
            b"binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    let hash = digester()
        .token(TokenKind::OidcFlowState, b"lock-expiry")
        .unwrap()
        .to_sql_hex();
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query(
        "SELECT state_hash FROM broker.oidc_flows WHERE state_hash=? FOR UPDATE",
    )
    .bind(&hash)
    .fetch_one(&mut blocker)
    .await
    .unwrap();
    let expiry = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
    .checked_add(2_000_000)
    .unwrap();
    sqlx_core::query::query("UPDATE broker.oidc_flows SET expires_at=? WHERE state_hash=?")
        .bind(expiry)
        .bind(&hash)
        .execute(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let expiring = tokio::spawn(async move {
        owner
            .consume_flow(b"lock-expiry", b"binding", deadline())
            .await
    });
    wait_statement(&fixture, StatementPhase::ConsumeRowLock).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    drop(blocker);
    assert_eq!(
        expiring.await.unwrap().unwrap_err(),
        MySqlControlError::Expired
    );
    assert_eq!(
        fixture
            .scalar(&format!(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows WHERE state_hash='{hash}'"
            ))
            .await,
        0
    );
    // Same service recaptures permissions on its next new connection.
    fixture
        .sql("REVOKE DELETE ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store
            .consume_flow(b"blocked", b"binding", deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Denied(RequiredCapability::Delete)
    );
    fixture
        .sql("GRANT DELETE ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    store.shutdown(deadline()).await.unwrap();
    let mut root = fixture.connection().await;
    let held: Option<i64> = sqlx_core::query_scalar::query_scalar(
        "SELECT CAST(GET_LOCK('graphit-broker-rust-control-startup-v1',0) AS SIGNED)",
    )
    .fetch_one(&mut root)
    .await
    .unwrap();
    assert_eq!(held, Some(1));
    let mut config = fixture.config(1);
    config.admission.budgets.lock = Duration::from_secs(1);
    assert_eq!(
        MySqlControlStore::open(config, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::StartupBusy
    );
    sqlx_core::query::query("SELECT RELEASE_LOCK('graphit-broker-rust-control-startup-v1')")
        .execute(&mut root)
        .await
        .unwrap();
    drop(root);
    fixture.reference().await;
    fixture
        .sql("INSERT INTO broker.resource_acl_state(id,revision,updated_at) VALUES(1,1,1)")
        .await;
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT id FROM broker.resource_acl_state WHERE id=1 FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let config = fixture.config(1);
    let opening =
        tokio::spawn(async move { MySqlControlStore::open(config, digester(), deadline()).await });
    wait_statement(&fixture, StatementPhase::StartupRowLock).await;
    opening.abort();
    assert!(opening.await.unwrap_err().is_cancelled());
    sqlx_core::raw_sql::raw_sql("ROLLBACK")
        .execute(&mut blocker)
        .await
        .unwrap();
    drop(blocker);
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.roles")
            .await,
        0
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_permissions")
            .await,
        0
    );
    wait_native(
        &fixture,
        "SELECT CAST(IS_USED_LOCK('graphit-broker-rust-control-startup-v1') IS NULL AS SIGNED)",
        1,
    )
    .await;
}

#[tokio::test]
#[ignore = "real MySQL PROCESS authority, external FK/orphan and complete capture"]
async fn mysql_inbound_authority_service_contract() {
    let fixture = Fixture::new().await;
    let unproven = MySqlControlError::Unproven(UnprovenReason::Visibility);
    let foreign = MySqlControlError::SchemaRejected(SchemaReason::ForeignKeys);
    fixture
        .sql("REVOKE PROCESS ON *.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture.rejects(unproven).await;
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await, 0);
    fixture
        .sql("GRANT PROCESS ON *.* TO 'ordinary`@_%'@'%'")
        .await;
    let store = fixture.open(1).await;
    store
        .save_flow(
            b"authority-state",
            b"authority-binding",
            flow(Duration::from_secs(120)),
            deadline(),
        )
        .await
        .unwrap();
    fixture
        .sql("REVOKE PROCESS ON *.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture.rejects(unproven).await;
    assert_eq!(
        store
            .save_flow(
                b"denied-state",
                b"authority-binding",
                flow(Duration::from_secs(120)),
                deadline()
            )
            .await,
        Err(unproven)
    );
    assert_eq!(
        store
            .consume_flow(b"authority-state", b"authority-binding", deadline())
            .await
            .unwrap_err(),
        unproven
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows")
            .await,
        1
    );
    fixture
        .sql("GRANT PROCESS ON *.* TO 'ordinary`@_%'@'%'")
        .await;
    store
        .consume_flow(b"authority-state", b"authority-binding", deadline())
        .await
        .unwrap();

    fixture
        .sql("CREATE DATABASE inbound_fixture CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")
        .await;
    for action in ["CASCADE", "RESTRICT"] {
        fixture.sql(&format!("CREATE TABLE inbound_fixture.child(state_hash VARCHAR(64), CONSTRAINT incoming_fk FOREIGN KEY(state_hash) REFERENCES broker.oidc_flows(state_hash) ON DELETE {action}) ENGINE=InnoDB ROW_FORMAT=DYNAMIC")).await;
        let mut ordinary = match tokio::time::timeout(
            Duration::from_secs(5),
            MySqlConnection::connect_with(
                &fixture
                    .options()
                    .database("broker")
                    .username(ACCOUNT)
                    .password(PASSWORD)
                    .ssl_mode(MySqlSslMode::VerifyIdentity)
                    .ssl_ca_from_pem(fixture.ca.clone()),
            ),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => sdk_failure("fixture_tls_verify", &error),
            Err(_) => deadline_failure("fixture_tls_verify"),
        };
        let denied = tokio::time::timeout(
            Duration::from_secs(5),
            sqlx_core::query::query("SELECT state_hash FROM inbound_fixture.child LIMIT 0")
                .execute(&mut ordinary),
        )
        .await
        .expect("native child SELECT deadline")
        .err();
        assert!(matches!(
            denied
                .as_ref()
                .and_then(|e| e.as_database_error())
                .and_then(|e| e.try_downcast_ref::<sqlx_mysql::MySqlDatabaseError>())
                .map(sqlx_mysql::MySqlDatabaseError::number),
            Some(1142 | 1143)
        ));
        drop(ordinary);
        fixture.rejects(foreign).await;
        assert_eq!(
            store
                .save_flow(
                    b"foreign-state",
                    b"authority-binding",
                    flow(Duration::from_secs(120)),
                    deadline()
                )
                .await,
            Err(foreign)
        );
        assert_eq!(
            store
                .consume_flow(b"absent-state", b"authority-binding", deadline())
                .await
                .unwrap_err(),
            foreign
        );
        assert_eq!(
            fixture
                .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows")
                .await,
            0
        );
        fixture.sql("DROP TABLE inbound_fixture.child").await;
    }
    fixture.sql("CREATE TABLE broker.external_child(state_hash VARCHAR(64), CONSTRAINT same_schema_fk FOREIGN KEY(state_hash) REFERENCES broker.oidc_flows(state_hash) ON DELETE RESTRICT) ENGINE=InnoDB ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin").await;
    fixture.rejects(foreign).await;
    fixture.sql("DROP TABLE broker.external_child").await;
    store.shutdown(deadline()).await.unwrap();

    fixture.reset().await;
    let mut root = fixture.connection().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        for sql in [
            "SET SESSION foreign_key_checks=0",
            "CREATE TABLE inbound_fixture.orphan(state_hash VARCHAR(64), CONSTRAINT orphan_fk FOREIGN KEY(state_hash) REFERENCES broker.oidc_flows(state_hash) ON DELETE CASCADE) ENGINE=InnoDB ROW_FORMAT=DYNAMIC",
            "SET SESSION foreign_key_checks=1",
        ] {
            if let Err(error) = sqlx_core::query::query(sql).execute(&mut root).await { sdk_failure("fixture_orphan_setup", &error); }
        }
    }).await.expect("orphan DDL setup deadline");
    drop(root);
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await, 0);
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.INNODB_FOREIGN WHERE CAST(REF_NAME AS BINARY)=CAST('broker/oidc_flows' AS BINARY)").await, 1);
    fixture.rejects(foreign).await;
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await, 0);
    fixture.sql("DROP TABLE inbound_fixture.orphan").await;
    let recovered = fixture.open(1).await;
    recovered.shutdown(deadline()).await.unwrap();

    // The public category minimum is 138 columns; cap64 belongs only to the
    // independent private probe. Every one of these 139 FKs is real native DDL.
    for index in 0..139 {
        fixture.sql(&format!("CREATE TABLE inbound_fixture.overflow_child_{index:03}(state_hash VARCHAR(64), CONSTRAINT overflow_fk_{index:03} FOREIGN KEY(state_hash) REFERENCES broker.oidc_flows(state_hash) ON DELETE RESTRICT) ENGINE=InnoDB ROW_FORMAT=DYNAMIC")).await;
    }
    let child_names = (0..139)
        .map(|i| format!("'overflow_child_{i:03}'"))
        .collect::<Vec<_>>()
        .join(",");
    let key_names = (0..139)
        .map(|i| format!("'overflow_fk_{i:03}'"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(fixture.scalar(&format!("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA='inbound_fixture' AND REFERENCED_TABLE_SCHEMA='broker' AND REFERENCED_TABLE_NAME='oidc_flows' AND TABLE_NAME IN ({child_names}) AND CONSTRAINT_NAME IN ({key_names})")).await, 139);
    let mut bounded = fixture.config(1);
    bounded.catalog.rows_per_category = n(138);
    assert_eq!(
        MySqlControlStore::open(bounded, digester(), deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Unproven(UnprovenReason::Truncated)
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.schema_meta")
            .await,
        1
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.oidc_flows")
            .await,
        0
    );
    fixture.sql("DROP DATABASE inbound_fixture").await;
    let recovered = fixture.open(1).await;
    recovered.shutdown(deadline()).await.unwrap();
}

fn identity_limits() -> IdentityReadLimits {
    IdentityReadLimits {
        username_bytes: n(128),
        subject_bytes: n(512),
        role_bytes: n(128),
        roles: n(64),
        rows: n(1024),
    }
}
fn current_identity(value: LocalIdentityRead) -> LocalIdentitySnapshot {
    match value {
        LocalIdentityRead::Current(value) => value,
        LocalIdentityRead::Unavailable(_) => panic!("expected current native local identity"),
    }
}
async fn identity_read(
    store: &MySqlControlStore,
    username: &str,
    subject: &str,
    revision: i64,
) -> LocalIdentityRead {
    let reference =
        LocalIdentityReference::new(username, subject, revision, &identity_limits()).unwrap();
    store
        .local_identities(identity_limits())
        .unwrap()
        .read(&reference, deadline())
        .await
        .unwrap()
}
fn assert_identity_unavailable(value: LocalIdentityRead, expected: LocalIdentityUnavailable) {
    match value {
        LocalIdentityRead::Unavailable(reason) => assert_eq!(reason, expected),
        LocalIdentityRead::Current(_) => panic!("expected unavailable local identity"),
    }
}
async fn seed_identity(fixture: &Fixture, username: &str, subject: &str, kind: &str) {
    let mut root = fixture.connection().await;
    let now = current_micros();
    sqlx_core::query::query("INSERT INTO broker.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES(?,?,?,'deliberately-unselected-not-a-PHC','','','','deliberately-unselected-not-JSON',1,0,1,?,?)")
        .bind(username).bind(subject).bind(kind).bind(now).bind(now).execute(&mut root).await.unwrap_or_else(|error|sdk_failure("fixture_identity_seed",&error));
}
async fn identity_assignment(fixture: &Fixture, subject: &str, role: &str) {
    let mut root = fixture.connection().await;
    sqlx_core::query::query(
        "INSERT INTO broker.role_assignments(subject,role,created_at) VALUES(?,?,?)",
    )
    .bind(format!("local|{subject}"))
    .bind(role)
    .bind(current_micros())
    .execute(&mut root)
    .await
    .unwrap_or_else(|error| sdk_failure("fixture_identity_assignment", &error));
}
type IdentityRows = (
    Vec<(String, String, String, i64, i64)>,
    Vec<(String, String)>,
    Vec<(String, String)>,
);
async fn identity_state(fixture: &Fixture) -> IdentityRows {
    let mut root = fixture.connection().await;
    let users=sqlx_core::query_as::query_as("SELECT username,subject,identity_kind,CAST(enabled AS SIGNED),CAST(revision AS SIGNED) FROM broker.local_users ORDER BY username").fetch_all(&mut root).await.unwrap_or_else(|error| sdk_failure("fixture_identity_state_users", &error));
    let assignments = sqlx_core::query_as::query_as(
        "SELECT subject,role FROM broker.role_assignments ORDER BY subject,role",
    )
    .fetch_all(&mut root)
    .await
    .unwrap_or_else(|error| sdk_failure("fixture_identity_state_assignments", &error));
    let permissions = sqlx_core::query_as::query_as(
        "SELECT role,action FROM broker.role_permissions ORDER BY role,action",
    )
    .fetch_all(&mut root)
    .await
    .unwrap_or_else(|error| sdk_failure("fixture_identity_state_permissions", &error));
    (users, assignments, permissions)
}
#[tokio::test]
#[ignore = "requires pinned MySQL Docker fixture"]
async fn mysql_identity_roundtrip_and_current_rbac() {
    let fixture = Fixture::new().await;
    let store = fixture.open(2).await;
    seed_identity(&fixture, "identity-human", "identity-subject", "human").await;
    seed_identity(
        &fixture,
        "identity-service",
        "identity-service-subject",
        "service",
    )
    .await;
    let view = store.local_identities(identity_limits()).unwrap();
    assert_eq!(format!("{view:?}"), "MySqlLocalIdentities([REDACTED])");
    let before = fixture.scalar(SESSION_CONNECTIONS).await;
    let mut tight = identity_limits();
    tight.username_bytes = n(2);
    let reference =
        LocalIdentityReference::new("identity-human", "identity-subject", 1, &identity_limits())
            .unwrap();
    assert_eq!(
        store
            .local_identities(tight)
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        MySqlControlError::InvalidIdentity
    );
    let mut invalid = identity_limits();
    invalid.subject_bytes = n(usize::MAX);
    assert_eq!(
        store.local_identities(invalid).unwrap_err(),
        MySqlControlError::Configuration
    );
    assert_eq!(fixture.scalar(SESSION_CONNECTIONS).await, before);
    let snapshot =
        current_identity(identity_read(&store, "identity-human", "identity-subject", 1).await);
    assert_eq!(snapshot.username(), "identity-human");
    assert_eq!(snapshot.subject(), "identity-subject");
    assert_eq!(snapshot.kind(), LocalIdentityKind::Human);
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(snapshot.roles(), ["user"]);
    assert_eq!(snapshot.permissions().len(), 2);
    assert!(snapshot.allows(SystemAction::SessionRead));
    assert!(snapshot.allows(SystemAction::ProjectsRead));
    assert!(!snapshot.allows(SystemAction::UsersWrite));
    assert_eq!(
        current_identity(
            identity_read(&store, "identity-service", "identity-service-subject", 1).await
        )
        .kind(),
        LocalIdentityKind::Service
    );
    fixture
        .sql("INSERT INTO broker.roles(name,created_at) VALUES('empty-role',0),('custom-role',0)")
        .await;
    fixture
        .sql("INSERT INTO broker.role_permissions(role,action) VALUES('custom-role','users.read')")
        .await;
    identity_assignment(&fixture, "identity-subject", "empty-role").await;
    identity_assignment(&fixture, "identity-subject", "custom-role").await;
    identity_assignment(&fixture, "identity-subject", "user").await;
    let snapshot =
        current_identity(identity_read(&store, "identity-human", "identity-subject", 1).await);
    assert_eq!(snapshot.roles(), ["custom-role", "empty-role", "user"]);
    assert!(snapshot.allows(SystemAction::UsersRead));
    assert!(!snapshot.allows(SystemAction::UsersWrite));
    fixture
        .sql("DELETE FROM broker.role_permissions WHERE role='custom-role'")
        .await;
    fixture
        .sql("INSERT INTO broker.role_permissions(role,action) VALUES('custom-role','*')")
        .await;
    let snapshot =
        current_identity(identity_read(&store, "identity-human", "identity-subject", 1).await);
    assert!(snapshot.permissions().contains(&SystemPermission::All));
    assert!(snapshot.allows(SystemAction::UsersWrite));
    fixture
        .sql("DELETE FROM broker.role_assignments WHERE role='custom-role'")
        .await;
    assert!(
        !current_identity(identity_read(&store, "identity-human", "identity-subject", 1).await)
            .allows(SystemAction::UsersWrite)
    );
    identity_assignment(&fixture, "identity-service-subject", "admin").await;
    assert!(
        current_identity(
            identity_read(&store, "identity-service", "identity-service-subject", 1).await
        )
        .allows(SystemAction::UsersWrite)
    );
    assert!(
        !current_identity(identity_read(&store, "identity-human", "identity-subject", 1).await)
            .allows(SystemAction::UsersWrite)
    );
    // SELECT binds may exceed assignment storage width; this creates no grant.
    let ascii = "s".repeat(512);
    seed_identity(&fixture, "identity-long-ascii", &ascii, "human").await;
    assert_eq!(
        current_identity(identity_read(&store, "identity-long-ascii", &ascii, 1).await).roles(),
        ["user"]
    );
    let unicode = "é".repeat(256);
    assert_eq!(unicode.len(), 512);
    seed_identity(&fixture, "identity-long-unicode", &unicode, "human").await;
    identity_assignment(&fixture, &unicode, "admin").await;
    assert!(
        current_identity(identity_read(&store, "identity-long-unicode", &unicode, 1).await)
            .allows(SystemAction::UsersWrite)
    );
    assert_identity_unavailable(
        identity_read(&store, "identity-missing", "identity-subject", 1).await,
        LocalIdentityUnavailable::Missing,
    );
    assert_identity_unavailable(
        identity_read(&store, "Identity-human", "identity-subject", 1).await,
        LocalIdentityUnavailable::Missing,
    );
    assert_identity_unavailable(
        identity_read(&store, "identity-human", "other-subject", 1).await,
        LocalIdentityUnavailable::SubjectChanged,
    );
    assert_identity_unavailable(
        identity_read(&store, "identity-human", "identity-subject", 2).await,
        LocalIdentityUnavailable::RevisionChanged,
    );
    fixture
        .sql("UPDATE broker.local_users SET enabled=0 WHERE username='identity-human'")
        .await;
    assert_identity_unavailable(
        identity_read(&store, "identity-human", "identity-subject", 1).await,
        LocalIdentityUnavailable::Disabled,
    );
    fixture.sql("UPDATE broker.local_users SET enabled=1,username='identity-renamed',revision=2 WHERE username='identity-human'").await;
    assert_identity_unavailable(
        identity_read(&store, "identity-human", "identity-subject", 1).await,
        LocalIdentityUnavailable::Missing,
    );
    assert_identity_unavailable(
        identity_read(&store, "identity-renamed", "identity-subject", 1).await,
        LocalIdentityUnavailable::RevisionChanged,
    );
    assert_eq!(
        current_identity(identity_read(&store, "identity-renamed", "identity-subject", 2).await)
            .revision(),
        2
    );
    fixture
        .sql("DELETE FROM broker.local_users WHERE username='identity-renamed'")
        .await;
    assert_identity_unavailable(
        identity_read(&store, "identity-renamed", "identity-subject", 2).await,
        LocalIdentityUnavailable::Missing,
    );
    assert!(
        current_identity(
            identity_read(&store, "identity-service", "identity-service-subject", 1).await
        )
        .allows(SystemAction::UsersWrite)
    );
    store.shutdown(deadline()).await.unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
}
#[tokio::test]
#[ignore = "requires pinned MySQL Docker fixture"]
async fn mysql_identity_bounds_and_corruption() {
    let fixture = Fixture::new().await;
    let store = fixture.open(1).await;
    seed_identity(
        &fixture,
        "identity-bounds",
        "identity-bounds-subject",
        "human",
    )
    .await;
    seed_identity(
        &fixture,
        "identity-other",
        "identity-other-subject",
        "service",
    )
    .await;
    let reference = LocalIdentityReference::new(
        "identity-bounds",
        "identity-bounds-subject",
        1,
        &identity_limits(),
    )
    .unwrap();
    for sql in [
        "enabled=2",
        "enabled=-1",
        "revision=0",
        "revision=-1",
        "identity_kind='unknown'",
        "subject=' noncanonical '",
        "subject=CONCAT('identity',CHAR(0),'subject')",
        "subject=REPEAT('é',257)",
        "identity_kind=REPEAT('é',9)",
    ] {
        fixture
            .sql(&format!(
                "UPDATE broker.local_users SET {sql} WHERE username='identity-bounds'"
            ))
            .await;
        let before = identity_state(&fixture).await;
        assert_eq!(
            store
                .local_identities(identity_limits())
                .unwrap()
                .read(&reference, deadline())
                .await
                .unwrap_err(),
            MySqlControlError::CorruptIdentity
        );
        assert_eq!(
            identity_state(&fixture).await,
            before,
            "corrupt identity read must not mutate rows"
        );
        fixture.sql("UPDATE broker.local_users SET enabled=1,revision=1,identity_kind='human',subject='identity-bounds-subject' WHERE username='identity-bounds'").await;
    }
    // Invalid credential/JSON columns are deliberately outside this operation.
    assert_eq!(
        current_identity(
            identity_read(&store, "identity-bounds", "identity-bounds-subject", 1).await
        )
        .roles(),
        ["user"]
    );
    fixture
        .sql("INSERT INTO broker.roles(name,created_at) VALUES('limit-role',0)")
        .await;
    fixture
        .sql("INSERT INTO broker.role_permissions(role,action) VALUES('limit-role','users.read')")
        .await;
    identity_assignment(&fixture, "identity-bounds-subject", "limit-role").await;
    for (field, value, expected) in [
        ("roles", 1, MySqlControlError::IdentityLimitExceeded),
        ("rows", 2, MySqlControlError::IdentityLimitExceeded),
        ("role_bytes", 4, MySqlControlError::CorruptRbac),
        ("role_bytes", 9, MySqlControlError::CorruptRbac),
        ("subject_bytes", 2, MySqlControlError::InvalidIdentity),
    ] {
        let mut limits = identity_limits();
        match field {
            "roles" => limits.roles = n(value),
            "rows" => limits.rows = n(value),
            "role_bytes" => limits.role_bytes = n(value),
            "subject_bytes" => limits.subject_bytes = n(value),
            _ => unreachable!(),
        };
        assert_eq!(
            store
                .local_identities(limits)
                .unwrap()
                .read(&reference, deadline())
                .await
                .unwrap_err(),
            expected
        );
    }
    let mut exact = identity_limits();
    exact.roles = n(2);
    exact.rows = n(3);
    exact.role_bytes = n(10);
    let before = identity_state(&fixture).await;
    assert_eq!(
        current_identity(
            store
                .local_identities(exact)
                .unwrap()
                .read(&reference, deadline())
                .await
                .unwrap()
        )
        .roles(),
        ["limit-role", "user"]
    );
    assert_eq!(identity_state(&fixture).await, before);
    fixture
        .sql("INSERT INTO broker.role_permissions(role,action) VALUES('limit-role','unknown.read')")
        .await;
    let before = identity_state(&fixture).await;
    assert_eq!(
        store
            .local_identities(identity_limits())
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        MySqlControlError::CorruptRbac
    );
    assert_eq!(identity_state(&fixture).await, before);
    fixture
        .sql("DELETE FROM broker.role_permissions WHERE action='unknown.read'")
        .await;
    fixture
        .sql("INSERT INTO broker.role_permissions(role,action) VALUES('limit-role',REPEAT('é',65))")
        .await;
    let before = identity_state(&fixture).await;
    assert_eq!(
        store
            .local_identities(identity_limits())
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        MySqlControlError::CorruptRbac
    );
    assert_eq!(
        identity_state(&fixture).await,
        before,
        "oversize stored action read preserves native rows"
    );
    fixture
        .sql("DELETE FROM broker.role_permissions WHERE action=REPEAT('é',65)")
        .await;
    // The producer's utf8mb4_bin is PAD SPACE: native equality can match a padded key.
    seed_identity(&fixture, "padded ", "padded-key-subject", "human").await;
    let before = identity_state(&fixture).await;
    for cap in [128, 6] {
        let mut limits = identity_limits();
        limits.username_bytes = n(cap);
        let valid =
            LocalIdentityReference::new("padded", "padded-key-subject", 1, &limits).unwrap();
        assert_eq!(
            store
                .local_identities(limits)
                .unwrap()
                .read(&valid, deadline())
                .await
                .unwrap_err(),
            MySqlControlError::CorruptIdentity
        );
        assert_eq!(
            identity_state(&fixture).await,
            before,
            "invalid and CASE-oversize stored usernames preserve native rows"
        );
    }
    // Distinct invalid keys never become an identity snapshot.
    seed_identity(&fixture, "é", "invalid-key-subject", "human").await;
    seed_identity(&fixture, "long-key", "long-key-subject", "human").await;
    let before = identity_state(&fixture).await;
    assert_identity_unavailable(
        identity_read(&store, "e", "invalid-key-subject", 1).await,
        LocalIdentityUnavailable::Missing,
    );
    let mut bounded = identity_limits();
    bounded.username_bytes = n(4);
    let valid = LocalIdentityReference::new("long", "long-key-subject", 1, &bounded).unwrap();
    assert_identity_unavailable(
        store
            .local_identities(bounded)
            .unwrap()
            .read(&valid, deadline())
            .await
            .unwrap(),
        LocalIdentityUnavailable::Missing,
    );
    assert_eq!(
        identity_state(&fixture).await,
        before,
        "unreachable corrupt or overcap keys preserved"
    );
    // Orphan data is fixture-only and foreign_key_checks is restored on this SDK handle.
    let mut root = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("SET SESSION FOREIGN_KEY_CHECKS=0; INSERT INTO broker.role_assignments(subject,role,created_at) VALUES('local|identity-bounds-subject','unknown-role',0); SET SESSION FOREIGN_KEY_CHECKS=1").execute(&mut root).await.unwrap_or_else(|error| sdk_failure("fixture_identity_orphan_assignment", &error));
    let checks: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT CAST(@@SESSION.foreign_key_checks AS SIGNED)",
    )
    .fetch_one(&mut root)
    .await
    .unwrap_or_else(|error| sdk_failure("fixture_identity_foreign_keys_restored", &error));
    assert_eq!(checks, 1);
    let snapshot = current_identity(
        identity_read(&store, "identity-bounds", "identity-bounds-subject", 1).await,
    );
    assert_eq!(snapshot.roles(), ["limit-role", "unknown-role", "user"]);
    assert_eq!(snapshot.permissions().len(), 3);
    fixture
        .sql("DELETE FROM broker.role_permissions WHERE role='user'")
        .await;
    let snapshot = current_identity(
        identity_read(&store, "identity-bounds", "identity-bounds-subject", 1).await,
    );
    assert!(!snapshot.allows(SystemAction::SessionRead));
    assert!(snapshot.allows(SystemAction::UsersRead));
    fixture
        .sql("DELETE FROM broker.roles WHERE name='user'")
        .await;
    assert_eq!(
        current_identity(
            identity_read(&store, "identity-other", "identity-other-subject", 1).await
        )
        .permissions()
        .len(),
        0
    );
    store.shutdown(deadline()).await.unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
}

const IDENTITY_FETCHED: usize = 64;
const IDENTITY_COMMIT: usize = 128;
struct IdentityPhaseLayer(Arc<FlowPhases>);
impl Layer<Registry> for IdentityPhaseLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, Registry>) {
        let metadata = event.metadata();
        let bit = match metadata.target() {
            "broker_control::mysql::identity_snapshot_fetched" => IDENTITY_FETCHED,
            "broker_control::mysql::identity_commit_starting" => IDENTITY_COMMIT,
            _ => return,
        };
        self.0.observed.fetch_or(bit, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}
async fn hold_identity_after_fetch(
    store: Arc<MySqlControlStore>,
    relay: &Relay,
    end: Instant,
) -> (
    JoinHandle<Result<LocalIdentityRead, MySqlControlError>>,
    Arc<FlowPhases>,
) {
    relay.request.block();
    let phases = FlowPhases::new();
    let subscriber = Registry::default().with(IdentityPhaseLayer(phases.clone()));
    let operation = tokio::spawn(
        (async move {
            let reference = LocalIdentityReference::new(
                "identity-live",
                "identity-live-subject",
                1,
                &identity_limits(),
            )
            .unwrap();
            store
                .local_identities(identity_limits())
                .unwrap()
                .read(&reference, end)
                .await
        })
        .with_subscriber(subscriber),
    );
    relay.request.held_after(0, end).await;
    while phases.observed.load(Ordering::SeqCst) & IDENTITY_FETCHED == 0 {
        let held = relay.request.held_chunks.load(Ordering::SeqCst);
        relay.request.step(end).await;
        relay.request.held_after(held, end).await;
    }
    assert_eq!(phases.observed.load(Ordering::SeqCst) & IDENTITY_COMMIT, 0);
    (operation, phases)
}
#[tokio::test]
#[ignore = "requires pinned MySQL Docker fixture"]
async fn mysql_identity_snapshot_and_lifecycle() {
    let fixture = Fixture::new().await;
    let relay = Relay::new(fixture.port).await;
    let store = Arc::new(
        MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
            .await
            .unwrap(),
    );
    seed_identity(&fixture, "identity-live", "identity-live-subject", "human").await;
    fixture
        .sql("INSERT INTO broker.roles(name,created_at) VALUES('snapshot-role',0)")
        .await;
    fixture
        .sql(
            "INSERT INTO broker.role_permissions(role,action) VALUES('snapshot-role','users.read')",
        )
        .await;
    identity_assignment(&fixture, "identity-live-subject", "snapshot-role").await;
    let mut observer = fixture.connection().await;
    let end = Instant::now() + Duration::from_secs(8);
    let (operation, _) = hold_identity_after_fetch(store.clone(), &relay, end).await;
    tokio::time::timeout_at(end.into(),sqlx_core::raw_sql::raw_sql("START TRANSACTION; UPDATE broker.local_users SET revision=2,identity_kind='service' WHERE username='identity-live'; DELETE FROM broker.role_permissions WHERE role='snapshot-role'; INSERT INTO broker.role_permissions(role,action) VALUES('snapshot-role','users.write'); COMMIT").execute(&mut observer)).await.expect("independent writer ACK under original read deadline").unwrap_or_else(|error| sdk_failure("fixture_identity_independent_writer", &error));
    relay.request.unblock();
    let snapshot = current_identity(operation.await.unwrap().unwrap());
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(snapshot.kind(), LocalIdentityKind::Human);
    assert!(snapshot.allows(SystemAction::UsersRead));
    assert!(!snapshot.allows(SystemAction::UsersWrite));
    assert_identity_unavailable(
        identity_read(&store, "identity-live", "identity-live-subject", 1).await,
        LocalIdentityUnavailable::RevisionChanged,
    );
    let current =
        current_identity(identity_read(&store, "identity-live", "identity-live-subject", 2).await);
    assert_eq!(current.kind(), LocalIdentityKind::Service);
    assert!(current.allows(SystemAction::UsersWrite));
    assert!(!current.allows(SystemAction::UsersRead));
    fixture
        .sql("UPDATE broker.local_users SET revision=1 WHERE username='identity-live'")
        .await;
    let before = identity_state(&fixture).await;
    let end = Instant::now() + Duration::from_secs(8);
    let (operation, _) = hold_identity_after_fetch(store.clone(), &relay, end).await;
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    relay.request.unblock();
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(identity_state(&fixture).await, before);
    assert_eq!(
        current_identity(identity_read(&store, "identity-live", "identity-live-subject", 1).await)
            .revision(),
        1
    );
    // Original admission/shutdown applies to this view too.
    let end = Instant::now() + Duration::from_secs(8);
    let (operation, _) = hold_identity_after_fetch(store.clone(), &relay, end).await;
    let owner = store.clone();
    let shutdown = tokio::spawn(async move {
        owner
            .shutdown(Instant::now() + Duration::from_secs(5))
            .await
    });
    let reference = LocalIdentityReference::new(
        "identity-live",
        "identity-live-subject",
        1,
        &identity_limits(),
    )
    .unwrap();
    assert_eq!(
        store
            .local_identities(identity_limits())
            .unwrap()
            .read(&reference, Instant::now() + Duration::from_millis(100))
            .await
            .unwrap_err(),
        MySqlControlError::Closed
    );
    assert!(!shutdown.is_finished());
    relay.request.unblock();
    assert!(matches!(
        operation.await.unwrap().unwrap(),
        LocalIdentityRead::Current(_)
    ));
    shutdown.await.unwrap().unwrap();
    let reference = LocalIdentityReference::new(
        "identity-live",
        "identity-live-subject",
        1,
        &identity_limits(),
    )
    .unwrap();
    assert_eq!(
        store
            .local_identities(identity_limits())
            .unwrap()
            .read(&reference, deadline())
            .await
            .unwrap_err(),
        MySqlControlError::Closed
    );
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
}
#[tokio::test]
#[ignore = "requires pinned MySQL Docker fixture"]
async fn mysql_identity_capabilities_and_commit_uncertainty() {
    let fixture = Fixture::new().await;
    let store = fixture.open(1).await;
    seed_identity(&fixture, "identity-live", "identity-live-subject", "human").await;
    let reference = LocalIdentityReference::new(
        "identity-live",
        "identity-live-subject",
        1,
        &identity_limits(),
    )
    .unwrap();
    // Leave catalog visibility intact via table grants, then omit selected columns.
    fixture
        .sql("REVOKE SELECT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    let selected = [
        (
            "local_users",
            vec![
                "username",
                "subject",
                "identity_kind",
                "enabled",
                "revision",
            ],
        ),
        ("role_assignments", vec!["subject", "role"]),
        ("roles", vec!["name"]),
        ("role_permissions", vec!["role", "action"]),
    ];
    for (missing_table, columns) in selected {
        for table in TABLES {
            if table.name() != missing_table {
                fixture
                    .sql(&format!(
                        "GRANT SELECT ON broker.{} TO 'ordinary`@_%'@'%'",
                        table.name()
                    ))
                    .await;
            }
        }
        for missing in &columns {
            let remaining = columns
                .iter()
                .filter(|column| *column != missing)
                .copied()
                .collect::<Vec<_>>();
            if !remaining.is_empty() {
                fixture
                    .sql(&format!(
                        "GRANT SELECT({}) ON broker.{missing_table} TO 'ordinary`@_%'@'%'",
                        remaining.join(",")
                    ))
                    .await;
            }
            let before = identity_state(&fixture).await;
            let error = store
                .local_identities(identity_limits())
                .unwrap()
                .read(&reference, deadline())
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    MySqlControlError::Denied(RequiredCapability::Select)
                        | MySqlControlError::Unproven(UnprovenReason::Visibility)
                ),
                "finite current capability rejection"
            );
            assert_eq!(identity_state(&fixture).await, before);
            if !remaining.is_empty() {
                fixture
                    .sql(&format!(
                        "REVOKE SELECT({}) ON broker.{missing_table} FROM 'ordinary`@_%'@'%'",
                        remaining.join(",")
                    ))
                    .await;
            }
        }
        for table in TABLES {
            if table.name() != missing_table {
                fixture
                    .sql(&format!(
                        "REVOKE SELECT ON broker.{} FROM 'ordinary`@_%'@'%'",
                        table.name()
                    ))
                    .await;
            }
        }
    }
    fixture
        .sql("GRANT SELECT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    store.shutdown(deadline()).await.unwrap();
    instrumentation(&fixture).await;
    fixture.sql("UPDATE performance_schema.setup_consumers SET ENABLED='YES' WHERE NAME='events_statements_history_long'").await;
    let relay = Relay::new(fixture.port).await;
    let store = Arc::new(
        MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
            .await
            .unwrap(),
    );
    let before = identity_state(&fixture).await;
    let mut observer = fixture.connection().await;
    let end = Instant::now() + Duration::from_secs(8);
    let (operation, phases) = hold_identity_after_fetch(store.clone(), &relay, end).await;
    assert_eq!(native_read_commit_count(&mut observer, end).await, 0);
    while phases.observed.load(Ordering::SeqCst) & IDENTITY_COMMIT == 0 {
        let held = relay.request.held_chunks.load(Ordering::SeqCst);
        relay.request.step(end).await;
        relay.request.held_after(held, end).await;
    }
    relay.response.block();
    assert_eq!(native_read_commit_count(&mut observer, end).await, 0);
    loop {
        let held = relay.request.held_chunks.load(Ordering::SeqCst);
        relay.request.step(end).await;
        loop {
            if native_read_commit_count(&mut observer, end).await == 1 {
                break;
            }
            if relay.request.held_chunks.load(Ordering::SeqCst) > held {
                break;
            }
            tokio::time::timeout_at(end.into(), tokio::time::sleep(Duration::from_millis(10)))
                .await
                .expect("identity COMMIT history original deadline");
        }
        if native_read_commit_count(&mut observer, end).await == 1 {
            break;
        }
    }
    relay.response.held_after(0, end).await;
    assert_eq!(
        operation.await.unwrap().unwrap_err(),
        MySqlControlError::OutcomeUncertain
    );
    relay.stop().await;
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(identity_state(&fixture).await, before);
    store.shutdown(deadline()).await.unwrap();
}

async fn mysql_role_codes(root: &mut MySqlConnection, role: &str) -> Vec<String> {
    sqlx_core::query_scalar::query_scalar::<_, String>(
        "SELECT action FROM broker.role_permissions WHERE role=? ORDER BY action",
    )
    .bind(role)
    .fetch_all(root)
    .await
    .unwrap()
}

async fn mysql_role_created(root: &mut MySqlConnection, role: &str) -> i64 {
    sqlx_core::query_scalar::query_scalar::<_, i64>(
        "SELECT created_at FROM broker.roles WHERE name=?",
    )
    .bind(role)
    .fetch_one(root)
    .await
    .unwrap()
}

const MYSQL_ROLE_LOCK_WAIT: &str = "SELECT CAST(COUNT(*)>=1 AS SIGNED) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE=w.ENGINE JOIN performance_schema.threads t ON t.THREAD_ID=l.THREAD_ID WHERE t.PROCESSLIST_USER='ordinary`@_%' AND l.OBJECT_SCHEMA='broker' AND l.OBJECT_NAME='roles'";

#[tokio::test]
#[ignore = "real MySQL role definitions and current RBAC"]
async fn mysql_role_definitions_and_current_permissions() {
    let fixture = Fixture::new().await;
    let store = fixture.open(2).await;
    fixture
        .sql("GRANT UPDATE ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    store
        .set_role(
            " auditor ",
            &[
                SystemPermission::Action(SystemAction::ConfigurationRead),
                SystemPermission::All,
                SystemPermission::All,
            ],
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        mysql_role_codes(&mut root, "auditor").await,
        ["*", "configuration.read"]
    );
    let created = mysql_role_created(&mut root, "auditor").await;
    assert!(created >= 0);
    seed_identity(&fixture, "role-human", "role-human-subject", "human").await;
    identity_assignment(&fixture, "role-human-subject", "auditor").await;
    let assignment_created: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT created_at FROM broker.role_assignments WHERE subject='local|role-human-subject' AND role='auditor'",
    ).fetch_one(&mut root).await.unwrap();
    let snapshot =
        current_identity(identity_read(&store, "role-human", "role-human-subject", 1).await);
    assert!(snapshot.permissions().contains(&SystemPermission::All));
    assert!(
        snapshot
            .permissions()
            .contains(&SystemPermission::Action(SystemAction::ConfigurationRead))
    );
    store
        .set_role(
            "auditor",
            &[
                SystemPermission::Action(SystemAction::GrantsRead),
                SystemPermission::Action(SystemAction::GrantsRead),
            ],
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        mysql_role_codes(&mut root, "auditor").await,
        ["grants.read"]
    );
    let snapshot =
        current_identity(identity_read(&store, "role-human", "role-human-subject", 1).await);
    assert_eq!(
        snapshot
            .permissions()
            .iter()
            .map(|p| p.as_str())
            .collect::<Vec<_>>(),
        ["grants.read", "projects.read", "session.read"]
    );
    assert_eq!(mysql_role_created(&mut root, "auditor").await, created);
    assert_eq!(sqlx_core::query_scalar::query_scalar::<_,i64>(
        "SELECT created_at FROM broker.role_assignments WHERE subject='local|role-human-subject' AND role='auditor'",
    ).fetch_one(&mut root).await.unwrap(), assignment_created);
    assert_eq!(
        fixture
            .scalar("SELECT revision FROM broker.local_users WHERE username='role-human'")
            .await,
        1
    );
    store
        .set_role(
            "Auditor",
            &[SystemPermission::Action(SystemAction::UsersRead)],
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(mysql_role_codes(&mut root, "Auditor").await, ["users.read"]);
    assert_eq!(
        mysql_role_codes(&mut root, "auditor").await,
        ["grants.read"]
    );
    store.set_role("admin", &[], deadline()).await.unwrap();
    let admin = vec![
        "configuration.read",
        "grants.read",
        "grants.write",
        "projects.read",
        "roles.read",
        "roles.write",
        "session.read",
        "users.read",
        "users.write",
    ];
    assert_eq!(mysql_role_codes(&mut root, "admin").await, admin);
    store
        .set_role("admin", &[SystemPermission::All], deadline())
        .await
        .unwrap();
    assert_eq!(mysql_role_codes(&mut root, "admin").await, admin);
    store
        .set_role("user", &[SystemPermission::All], deadline())
        .await
        .unwrap();
    assert_eq!(
        mysql_role_codes(&mut root, "user").await,
        ["projects.read", "session.read"]
    );
    store.set_role("user", &[], deadline()).await.unwrap();
    let too_long = "a".repeat(129);
    for invalid in ["", ".", "..", "../bad", "bad/name", "é", too_long.as_str()] {
        assert_eq!(
            store
                .set_role(invalid, &[SystemPermission::All], deadline())
                .await,
            Err(MySqlControlError::InvalidRole)
        );
    }
    assert_eq!(
        store.set_role("empty-custom", &[], deadline()).await,
        Err(MySqlControlError::InvalidRole)
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.roles WHERE name='empty-custom'")
            .await,
        0
    );
    let max_name = "a".repeat(128);
    store
        .set_role(&max_name, &[SystemPermission::All], deadline())
        .await
        .unwrap();
    assert_eq!(mysql_role_codes(&mut root, &max_name).await, ["*"]);
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store.set_role("empty-custom", &[], deadline()).await,
        Err(MySqlControlError::InvalidRole)
    );
    assert_eq!(
        store
            .set_role("auditor", &[SystemPermission::All], deadline())
            .await,
        Err(MySqlControlError::Closed)
    );
    assert_eq!(
        MySqlControlError::InvalidRole.to_string(),
        "invalid system role definition"
    );
}

#[tokio::test]
#[ignore = "real MySQL role rollback and concurrent replacement"]
async fn mysql_role_atomic_failure_and_concurrent_replacement() {
    let fixture = Fixture::new().await;
    let store = Arc::new(fixture.open(2).await);
    fixture
        .sql("GRANT UPDATE ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    store
        .set_role(
            "atomic-role",
            &[SystemPermission::Action(SystemAction::ConfigurationRead)],
            deadline(),
        )
        .await
        .unwrap();
    let created = mysql_role_created(&mut root, "atomic-role").await;
    sqlx_core::raw_sql::raw_sql("CREATE TRIGGER broker.role_insert_failure BEFORE INSERT ON broker.role_permissions FOR EACH ROW BEGIN IF NEW.role IN ('atomic-role','new-role-failure') AND NEW.action='grants.write' THEN SIGNAL SQLSTATE '45000'; END IF; END")
        .execute(&mut root).await.unwrap();
    for role in ["atomic-role", "new-role-failure"] {
        assert_eq!(
            store
                .set_role(
                    role,
                    &[
                        SystemPermission::Action(SystemAction::GrantsRead),
                        SystemPermission::Action(SystemAction::GrantsWrite),
                    ],
                    deadline()
                )
                .await,
            Err(MySqlControlError::Storage)
        );
    }
    assert_eq!(
        mysql_role_codes(&mut root, "atomic-role").await,
        ["configuration.read"]
    );
    assert_eq!(mysql_role_created(&mut root, "atomic-role").await, created);
    assert_eq!(
        fixture
            .scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.roles WHERE name='new-role-failure'"
            )
            .await,
        0
    );
    sqlx_core::raw_sql::raw_sql("DROP TRIGGER broker.role_insert_failure")
        .execute(&mut root)
        .await
        .unwrap();
    for role in ["new-raced-role", "atomic-role"] {
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let left_store = store.clone();
        let left_barrier = barrier.clone();
        let left = tokio::spawn(async move {
            left_barrier.wait().await;
            left_store
                .set_role(
                    role,
                    &[
                        SystemPermission::Action(SystemAction::GrantsRead),
                        SystemPermission::Action(SystemAction::GrantsWrite),
                    ],
                    deadline(),
                )
                .await
        });
        let right_store = store.clone();
        let right_barrier = barrier.clone();
        let right = tokio::spawn(async move {
            right_barrier.wait().await;
            right_store
                .set_role(
                    role,
                    &[
                        SystemPermission::Action(SystemAction::UsersRead),
                        SystemPermission::Action(SystemAction::UsersWrite),
                    ],
                    deadline(),
                )
                .await
        });
        barrier.wait().await;
        left.await.unwrap().unwrap();
        right.await.unwrap().unwrap();
        let actual = mysql_role_codes(&mut root, role).await;
        assert!(
            actual == ["grants.read", "grants.write"] || actual == ["users.read", "users.write"]
        );
    }
    assert_eq!(mysql_role_created(&mut root, "atomic-role").await, created);
    let before = mysql_role_codes(&mut root, "atomic-role").await;
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='atomic-role' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let writer = tokio::spawn(async move {
        owner
            .set_role(
                "atomic-role",
                &[SystemPermission::Action(SystemAction::RolesRead)],
                deadline(),
            )
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    assert_eq!(mysql_role_codes(&mut root, "atomic-role").await, before);
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    writer.await.unwrap().unwrap();
    assert_eq!(
        mysql_role_codes(&mut root, "atomic-role").await,
        ["roles.read"]
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real MySQL role permissions, cancellation and COMMIT uncertainty"]
async fn mysql_role_permissions_deadline_cancel_and_commit() {
    let fixture = Fixture::new().await;
    let store = Arc::new(fixture.open(2).await);
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM mysql.user WHERE User='ordinary`@_%' AND Host='%' AND Super_priv='N'").await, 1);
    fixture
        .sql("GRANT UPDATE ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    store
        .set_role(
            "healthy-role",
            &[SystemPermission::Action(SystemAction::ConfigurationRead)],
            deadline(),
        )
        .await
        .unwrap();
    let mut root = fixture.connection().await;
    fixture
        .sql("REVOKE UPDATE ON broker.roles FROM 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store
            .set_role("healthy-role", &[SystemPermission::All], deadline())
            .await,
        Err(MySqlControlError::Denied(RequiredCapability::Insert))
    );
    assert_eq!(
        mysql_role_codes(&mut root, "healthy-role").await,
        ["configuration.read"]
    );
    fixture
        .sql("GRANT UPDATE ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE INSERT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("GRANT INSERT ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store
            .set_role("healthy-role", &[SystemPermission::All], deadline())
            .await,
        Err(MySqlControlError::Denied(RequiredCapability::Insert))
    );
    assert_eq!(
        mysql_role_codes(&mut root, "healthy-role").await,
        ["configuration.read"]
    );
    fixture
        .sql("GRANT INSERT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE INSERT ON broker.roles FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("GRANT SELECT(name) ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store
            .set_role("healthy-role", &[SystemPermission::All], deadline())
            .await,
        Err(MySqlControlError::Denied(RequiredCapability::Delete))
    );
    assert_eq!(
        mysql_role_codes(&mut root, "healthy-role").await,
        ["configuration.read"]
    );
    fixture
        .sql("GRANT SELECT(role) ON broker.role_permissions TO 'ordinary`@_%'@'%'")
        .await;
    store
        .set_role("healthy-role", &[SystemPermission::All], deadline())
        .await
        .unwrap();
    fixture
        .sql("GRANT SELECT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT(name) ON broker.roles FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT(role) ON broker.role_permissions FROM 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(mysql_role_codes(&mut root, "healthy-role").await, ["*"]);
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='healthy-role' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let timed = tokio::spawn(async move {
        owner
            .set_role(
                "healthy-role",
                &[SystemPermission::Action(SystemAction::RolesRead)],
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    assert_eq!(timed.await.unwrap(), Err(MySqlControlError::Deadline));
    assert_eq!(mysql_role_codes(&mut root, "healthy-role").await, ["*"]);
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='healthy-role' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let cancelled = tokio::spawn(async move {
        owner
            .set_role(
                "healthy-role",
                &[SystemPermission::Action(SystemAction::UsersWrite)],
                deadline(),
            )
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    assert_eq!(mysql_role_codes(&mut root, "healthy-role").await, ["*"]);
    store
        .set_role(
            "healthy-role",
            &[SystemPermission::Action(SystemAction::RolesRead)],
            deadline(),
        )
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store
            .set_role("healthy-role", &[SystemPermission::All], deadline())
            .await,
        Err(MySqlControlError::Closed)
    );
    instrumentation(&fixture).await;
    for disconnect in [true, false] {
        let relay = Relay::new(fixture.port).await;
        let owner = Arc::new(
            MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
                .await
                .unwrap(),
        );
        owner
            .set_role(
                "commit-role",
                &[SystemPermission::Action(SystemAction::ConfigurationRead)],
                deadline(),
            )
            .await
            .unwrap();
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
            .await;
        let writer_owner = owner.clone();
        let writer = tokio::spawn(async move {
            writer_owner
                .set_role(
                    "commit-role",
                    &[SystemPermission::Action(SystemAction::GrantsRead)],
                    Instant::now() + Duration::from_secs(5),
                )
                .await
        });
        if let Err(snapshot) = try_wait_statement(&fixture, StatementPhase::Commit).await {
            let outcome = writer.await.unwrap();
            panic!("role COMMIT not observed snapshot={snapshot:?} outcome={outcome:?}");
        }
        let outcome = if disconnect {
            relay.stop().await;
            writer.await.unwrap()
        } else {
            relay.response.block();
            let result = writer.await.unwrap();
            relay.stop().await;
            result
        };
        assert_eq!(outcome, Err(MySqlControlError::OutcomeUncertain));
        wait_native(&fixture, NO_ORDINARY, 0).await;
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
            .await;
        let actual = mysql_role_codes(&mut root, "commit-role").await;
        if disconnect {
            assert!(actual == ["configuration.read"] || actual == ["grants.read"]);
        } else {
            assert_eq!(actual, ["grants.read"]);
        }
        owner.shutdown(deadline()).await.unwrap();
        let recovered = fixture.open(1).await;
        recovered
            .set_role("healthy-role", &[SystemPermission::All], deadline())
            .await
            .unwrap();
        recovered.shutdown(deadline()).await.unwrap();
    }
}

async fn mysql_assignment_created(
    root: &mut MySqlConnection,
    subject: &str,
    role: &str,
) -> Option<i64> {
    sqlx_core::query_scalar::query_scalar::<_, i64>(
        "SELECT created_at FROM broker.role_assignments WHERE subject=? AND role=?",
    )
    .bind(subject)
    .bind(role)
    .fetch_optional(root)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "real MySQL assignment inputs, idempotency and current RBAC"]
async fn mysql_assignment_creation_and_current_permissions() {
    let fixture = Fixture::new().await;
    let store = fixture.open(2).await;
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    fixture.sql("INSERT INTO broker.roles(name,created_at) VALUES('assignment-role',1),('Assignment-Role',2)").await;
    fixture.sql("INSERT INTO broker.role_permissions(role,action) VALUES('assignment-role','configuration.read'),('Assignment-Role','users.read')").await;
    seed_identity(
        &fixture,
        "assignment-human",
        "assignment-human-subject",
        "human",
    )
    .await;
    store
        .assign_role(
            " local|assignment-human-subject ",
            " assignment-role ",
            deadline(),
        )
        .await
        .unwrap();
    let created = mysql_assignment_created(
        &mut root,
        "local|assignment-human-subject",
        "assignment-role",
    )
    .await
    .unwrap();
    assert!(created >= 0);
    let snapshot = current_identity(
        identity_read(&store, "assignment-human", "assignment-human-subject", 1).await,
    );
    assert!(
        snapshot
            .permissions()
            .contains(&SystemPermission::Action(SystemAction::ConfigurationRead))
    );
    sqlx_core::query::query(
        "UPDATE broker.role_assignments SET created_at=7 WHERE subject=? AND role=?",
    )
    .bind("local|assignment-human-subject")
    .bind("assignment-role")
    .execute(&mut root)
    .await
    .unwrap();
    store
        .assign_role(
            "local|assignment-human-subject",
            "assignment-role",
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        mysql_assignment_created(
            &mut root,
            "local|assignment-human-subject",
            "assignment-role"
        )
        .await,
        Some(7)
    );
    assert_eq!(
        fixture
            .scalar("SELECT revision FROM broker.local_users WHERE username='assignment-human'")
            .await,
        1
    );
    store
        .assign_role("issuer|external-subject", "Assignment-Role", deadline())
        .await
        .unwrap();
    store
        .assign_role("Issuer|external-subject", "assignment-role", deadline())
        .await
        .unwrap();
    assert!(
        mysql_assignment_created(&mut root, "issuer|external-subject", "Assignment-Role")
            .await
            .is_some()
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|external-subject", "assignment-role").await,
        None
    );
    assert!(
        mysql_assignment_created(&mut root, "Issuer|external-subject", "assignment-role")
            .await
            .is_some()
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.local_users")
            .await,
        1
    );
    let unicode = "界".repeat(512);
    assert!(unicode.len() > 512);
    store
        .assign_role(&unicode, "assignment-role", deadline())
        .await
        .unwrap();
    assert!(
        mysql_assignment_created(&mut root, &unicode, "assignment-role")
            .await
            .is_some()
    );
    let max_role = "a".repeat(128);
    sqlx_core::query::query("INSERT INTO broker.roles(name,created_at) VALUES(?,1)")
        .bind(&max_role)
        .execute(&mut root)
        .await
        .unwrap();
    store
        .assign_role("unstructured-subject", &max_role, deadline())
        .await
        .unwrap();
    let long_subject = "界".repeat(513);
    let long_role = "a".repeat(129);
    let before = fixture
        .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments")
        .await;
    for (subject, role) in [
        ("", "assignment-role"),
        (" \t\n ", "assignment-role"),
        (long_subject.as_str(), "assignment-role"),
        ("rejected", ""),
        ("rejected", "../bad"),
        ("rejected", "é"),
        ("rejected", long_role.as_str()),
    ] {
        assert_eq!(
            store.assign_role(subject, role, deadline()).await,
            Err(MySqlControlError::InvalidAssignment)
        );
    }
    assert_eq!(
        store
            .assign_role("rejected", "missing-role", deadline())
            .await,
        Err(MySqlControlError::RoleNotFound)
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments")
            .await,
        before
    );
    assert_eq!(
        MySqlControlError::InvalidAssignment.to_string(),
        "invalid system role assignment"
    );
    assert_eq!(
        MySqlControlError::RoleNotFound.to_string(),
        "system role does not exist"
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store.assign_role("", "assignment-role", deadline()).await,
        Err(MySqlControlError::InvalidAssignment)
    );
    assert_eq!(
        store
            .assign_role("valid", "assignment-role", deadline())
            .await,
        Err(MySqlControlError::Closed)
    );
}

#[tokio::test]
#[ignore = "real MySQL assignment rollback, denied capabilities and concurrency"]
async fn mysql_assignment_atomic_permissions_and_concurrency() {
    let fixture = Fixture::new().await;
    let store = Arc::new(fixture.open(2).await);
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    store
        .assign_role("preserved", "admin", deadline())
        .await
        .unwrap();
    let preserved = mysql_assignment_created(&mut root, "preserved", "admin").await;
    sqlx_core::raw_sql::raw_sql("CREATE TRIGGER broker.assignment_insert_failure BEFORE INSERT ON broker.role_assignments FOR EACH ROW BEGIN IF NEW.subject='trigger-rejected' THEN SIGNAL SQLSTATE '45000'; END IF; END").execute(&mut root).await.unwrap();
    assert_eq!(
        store
            .assign_role("trigger-rejected", "admin", deadline())
            .await,
        Err(MySqlControlError::Storage)
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "trigger-rejected", "admin").await,
        None
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "preserved", "admin").await,
        preserved
    );
    sqlx_core::raw_sql::raw_sql("DROP TRIGGER broker.assignment_insert_failure")
        .execute(&mut root)
        .await
        .unwrap();
    for subject in ["raced-pair", "raced-pair", "raced-new-pair"] {
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let left_store = store.clone();
        let left_barrier = barrier.clone();
        let left = tokio::spawn(async move {
            left_barrier.wait().await;
            left_store.assign_role(subject, "admin", deadline()).await
        });
        let right_store = store.clone();
        let right_barrier = barrier.clone();
        let right = tokio::spawn(async move {
            right_barrier.wait().await;
            right_store.assign_role(subject, "admin", deadline()).await
        });
        barrier.wait().await;
        left.await.unwrap().unwrap();
        right.await.unwrap().unwrap();
        assert!(
            mysql_assignment_created(&mut root, subject, "admin")
                .await
                .is_some()
        );
        let count:i64=sqlx_core::query_scalar::query_scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments WHERE subject=? AND role='admin'").bind(subject).fetch_one(&mut root).await.unwrap();
        assert_eq!(count, 1);
    }
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='admin' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let writer =
        tokio::spawn(async move { owner.assign_role("blocked-pair", "admin", deadline()).await });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    assert_eq!(
        mysql_assignment_created(&mut root, "blocked-pair", "admin").await,
        None
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "preserved", "admin").await,
        preserved
    );
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    writer.await.unwrap().unwrap();
    assert!(
        mysql_assignment_created(&mut root, "blocked-pair", "admin")
            .await
            .is_some()
    );
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM mysql.user WHERE User='ordinary`@_%' AND Host='%' AND Super_priv='N'").await,1);
    fixture
        .sql("REVOKE UPDATE(subject) ON broker.role_assignments FROM 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store.assign_role("preserved", "admin", deadline()).await,
        Err(MySqlControlError::Denied(RequiredCapability::Insert))
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "preserved", "admin").await,
        preserved
    );
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE INSERT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store
            .assign_role("denied-insert", "admin", deadline())
            .await,
        Err(MySqlControlError::Denied(RequiredCapability::Insert))
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "denied-insert", "admin").await,
        None
    );
    fixture
        .sql("GRANT INSERT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    store
        .assign_role("restored", "admin", deadline())
        .await
        .unwrap();
    assert!(
        mysql_assignment_created(&mut root, "restored", "admin")
            .await
            .is_some()
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real MySQL assignment cancellation, deadline and observed COMMIT uncertainty"]
async fn mysql_assignment_deadline_cancel_and_commit() {
    let fixture = Fixture::new().await;
    let store = Arc::new(fixture.open(2).await);
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='admin' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let timed = tokio::spawn(async move {
        owner
            .assign_role(
                "deadline-pair",
                "admin",
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    assert_eq!(timed.await.unwrap(), Err(MySqlControlError::Deadline));
    assert_eq!(
        mysql_assignment_created(&mut root, "deadline-pair", "admin").await,
        None
    );
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='admin' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let cancelled = tokio::spawn(async move {
        owner
            .assign_role("cancelled-pair", "admin", deadline())
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert_eq!(
        mysql_assignment_created(&mut root, "cancelled-pair", "admin").await,
        None
    );
    store
        .assign_role("healthy-pair", "admin", deadline())
        .await
        .unwrap();
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store.assign_role("closed-pair", "admin", deadline()).await,
        Err(MySqlControlError::Closed)
    );
    instrumentation(&fixture).await;
    for (disconnect, subject) in [(true, "disconnect-pair"), (false, "ack-timeout-pair")] {
        let relay = Relay::new(fixture.port).await;
        let owner = Arc::new(
            MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
                .await
                .unwrap(),
        );
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
            .await;
        let writer_owner = owner.clone();
        let writer = tokio::spawn(async move {
            writer_owner
                .assign_role(subject, "admin", Instant::now() + Duration::from_secs(5))
                .await
        });
        if let Err(snapshot) = try_wait_statement(&fixture, StatementPhase::Commit).await {
            let outcome = writer.await.unwrap();
            panic!("assignment COMMIT not observed snapshot={snapshot:?} outcome={outcome:?}");
        }
        let outcome = if disconnect {
            relay.stop().await;
            writer.await.unwrap()
        } else {
            relay.response.block();
            let result = writer.await.unwrap();
            relay.stop().await;
            result
        };
        assert_eq!(outcome, Err(MySqlControlError::OutcomeUncertain));
        wait_native(&fixture, NO_ORDINARY, 0).await;
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
            .await;
        let actual = mysql_assignment_created(&mut root, subject, "admin").await;
        if disconnect {
            assert!(actual.is_none() || actual.is_some_and(|created| created >= 0));
        } else {
            assert!(actual.is_some_and(|created| created >= 0));
        }
        owner.shutdown(deadline()).await.unwrap();
        let recovered = fixture.open(1).await;
        recovered
            .assign_role("recovered-pair", "admin", deadline())
            .await
            .unwrap();
        assert!(
            mysql_assignment_created(&mut root, "recovered-pair", "admin")
                .await
                .is_some()
        );
        recovered.shutdown(deadline()).await.unwrap();
    }
}

async fn mysql_revocation_reset(fixture: &Fixture) {
    fixture.sql("DELETE FROM broker.role_assignments").await;
    fixture.sql("DELETE FROM broker.local_users").await;
}

#[tokio::test]
#[ignore = "real MySQL revocation, current RBAC, canonical identities and last admin"]
async fn mysql_revocation_current_permissions_and_last_admin() {
    let fixture = Fixture::new().await;
    let store = fixture.open(2).await;
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    fixture.sql("INSERT INTO broker.roles(name,created_at) VALUES('revocation-role',1),('custom-admin-like',2)").await;
    fixture.sql("INSERT INTO broker.role_permissions(role,action) VALUES('revocation-role','configuration.read'),('custom-admin-like','*')").await;
    seed_identity(
        &fixture,
        "revocation-human",
        "revocation-human-subject",
        "human",
    )
    .await;
    store
        .assign_role(
            "local|revocation-human-subject",
            "revocation-role",
            deadline(),
        )
        .await
        .unwrap();
    store
        .assign_role("issuer|preserved", "user", deadline())
        .await
        .unwrap();
    let preserved = mysql_assignment_created(&mut root, "issuer|preserved", "user").await;
    assert!(
        current_identity(
            identity_read(&store, "revocation-human", "revocation-human-subject", 1).await
        )
        .permissions()
        .contains(&SystemPermission::Action(SystemAction::ConfigurationRead))
    );
    store
        .revoke_role(
            " local|revocation-human-subject ",
            " revocation-role ",
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        !current_identity(
            identity_read(&store, "revocation-human", "revocation-human-subject", 1).await
        )
        .permissions()
        .contains(&SystemPermission::Action(SystemAction::ConfigurationRead))
    );
    assert_eq!(
        fixture
            .scalar("SELECT revision FROM broker.local_users WHERE username='revocation-human'")
            .await,
        1
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|preserved", "user").await,
        preserved
    );
    for (subject, role) in [
        ("local|revocation-human-subject", "revocation-role"),
        ("absent", "admin"),
        ("absent", "unknown-role"),
        ("", ""),
        ("", "../unvalidated-delete"),
    ] {
        store.revoke_role(subject, role, deadline()).await.unwrap();
    }
    for (other, local, eligible) in [
        ("issuer|other", None, true),
        ("local|missing", None, false),
        ("local|guard-subject", Some(("human", 1)), true),
        ("local|guard-subject", Some(("human", 0)), false),
        ("local|guard-subject", Some(("service", 1)), true),
        ("Local|unconfigured", None, true),
        ("local||missing", None, false),
        ("local|", None, false),
    ] {
        mysql_revocation_reset(&fixture).await;
        if let Some((kind, enabled)) = local {
            seed_identity(&fixture, "guard-user", "guard-subject", kind).await;
            sqlx_core::query::query(
                "UPDATE broker.local_users SET enabled=? WHERE username='guard-user'",
            )
            .bind(enabled)
            .execute(&mut root)
            .await
            .unwrap();
        }
        store
            .assign_role("issuer|target", "admin", deadline())
            .await
            .unwrap();
        store.assign_role(other, "admin", deadline()).await.unwrap();
        let other_created = mysql_assignment_created(&mut root, other, "admin").await;
        let result = store
            .revoke_role("issuer|target", "admin", deadline())
            .await;
        if eligible {
            result.unwrap();
            assert_eq!(
                mysql_assignment_created(&mut root, "issuer|target", "admin").await,
                None
            );
        } else {
            assert_eq!(result, Err(MySqlControlError::LastAssignedAdmin));
            assert!(
                mysql_assignment_created(&mut root, "issuer|target", "admin")
                    .await
                    .is_some()
            );
        }
        assert_eq!(
            mysql_assignment_created(&mut root, other, "admin").await,
            other_created
        );
    }
    mysql_revocation_reset(&fixture).await;
    seed_identity(
        &fixture,
        "disabled-target",
        "disabled-target-subject",
        "human",
    )
    .await;
    fixture
        .sql("UPDATE broker.local_users SET enabled=0 WHERE username='disabled-target'")
        .await;
    store
        .assign_role("local|disabled-target-subject", "admin", deadline())
        .await
        .unwrap();
    store
        .assign_role("issuer|custom-only", "custom-admin-like", deadline())
        .await
        .unwrap();
    assert_eq!(
        store
            .revoke_role("local|disabled-target-subject", "admin", deadline())
            .await,
        Err(MySqlControlError::LastAssignedAdmin)
    );
    assert!(
        mysql_assignment_created(&mut root, "local|disabled-target-subject", "admin")
            .await
            .is_some()
    );
    store
        .revoke_role("absent", "admin", deadline())
        .await
        .unwrap();
    store
        .assign_role("issuer|rescue", "admin", deadline())
        .await
        .unwrap();
    store
        .revoke_role("local|disabled-target-subject", "admin", deadline())
        .await
        .unwrap();
    assert_eq!(
        mysql_assignment_created(&mut root, "local|disabled-target-subject", "admin").await,
        None
    );
    let long_subject = "界".repeat(172);
    for (username, subject, kind, revision, padded_assignment) in [
        ("bad ", "guard-subject", "human", 1, false),
        ("guard-user", " guard-subject", "human", 1, false),
        ("guard-user", "guard-subject ", "human", 1, false),
        ("guard-user", "guard-subject\u{2003}", "human", 1, false),
        ("guard-user", "guard\0subject", "human", 1, false),
        ("guard-user", long_subject.as_str(), "human", 1, false),
        ("guard-user", "guard-subject", "unknown", 1, false),
        ("guard-user", "guard-subject", "human", 0, false),
        ("guard-user", "guard-subject", "human", 1, true),
    ] {
        mysql_revocation_reset(&fixture).await;
        seed_identity(&fixture, username, subject, kind).await;
        sqlx_core::query::query("UPDATE broker.local_users SET revision=? WHERE username=?")
            .bind(revision)
            .bind(username)
            .execute(&mut root)
            .await
            .unwrap();
        let assignment = if padded_assignment {
            format!("local|{subject} ")
        } else {
            format!("local|{subject}")
        };
        sqlx_core::query::query(
            "INSERT INTO broker.role_assignments(subject,role,created_at) VALUES(?,'admin',7)",
        )
        .bind(&assignment)
        .execute(&mut root)
        .await
        .unwrap();
        store
            .assign_role("issuer|target", "admin", deadline())
            .await
            .unwrap();
        assert_eq!(
            store
                .revoke_role("issuer|target", "admin", deadline())
                .await,
            Err(MySqlControlError::CorruptIdentity)
        );
        assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments WHERE role='admin'").await,2);
        assert_eq!(
            mysql_assignment_created(&mut root, &assignment, "admin").await,
            Some(7)
        );
        store
            .assign_role("issuer|valid-other", "admin", deadline())
            .await
            .unwrap();
        store
            .revoke_role("issuer|target", "admin", deadline())
            .await
            .unwrap();
        assert_eq!(
            mysql_assignment_created(&mut root, "issuer|target", "admin").await,
            None
        );
    }
    mysql_revocation_reset(&fixture).await;
    fixture.sql("INSERT INTO broker.role_assignments(subject,role,created_at) VALUES('issuer|self ','admin',7)").await;
    store
        .revoke_role(" issuer|self ", "admin", deadline())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments")
            .await,
        1,
        "PAD SPACE must not let the raw self row become its own rescue and then be deleted"
    );
    fixture.sql("DELETE FROM broker.role_assignments").await;
    fixture.sql("INSERT INTO broker.role_assignments(subject,role,created_at) VALUES('issuer|self','admin ',7)").await;
    store
        .revoke_role("issuer|self", " admin ", deadline())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments")
            .await,
        1,
        "role comparison must use the same exact equivalence"
    );
    assert_eq!(
        MySqlControlError::LastAssignedAdmin.to_string(),
        "cannot revoke the last assigned administrator"
    );
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real MySQL concurrent last-admin guard, DELETE rollback and denied capabilities"]
async fn mysql_revocation_atomic_guard_permissions_and_concurrency() {
    let fixture = Fixture::new().await;
    let store = Arc::new(fixture.open(2).await);
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("GRANT UPDATE(name) ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    let mut root = fixture.connection().await;
    store
        .assign_role("issuer|first", "admin", deadline())
        .await
        .unwrap();
    store
        .assign_role("issuer|second", "admin", deadline())
        .await
        .unwrap();
    let first = mysql_assignment_created(&mut root, "issuer|first", "admin").await;
    let second = mysql_assignment_created(&mut root, "issuer|second", "admin").await;
    sqlx_core::raw_sql::raw_sql("CREATE TRIGGER broker.assignment_delete_failure BEFORE DELETE ON broker.role_assignments FOR EACH ROW BEGIN IF OLD.subject='issuer|first' THEN SIGNAL SQLSTATE '45000'; END IF; END").execute(&mut root).await.unwrap();
    assert_eq!(
        store.revoke_role("issuer|first", "admin", deadline()).await,
        Err(MySqlControlError::Storage)
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|first", "admin").await,
        first
    );
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|second", "admin").await,
        second
    );
    sqlx_core::raw_sql::raw_sql("DROP TRIGGER broker.assignment_delete_failure")
        .execute(&mut root)
        .await
        .unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let left_store = store.clone();
    let left_barrier = barrier.clone();
    let left = tokio::spawn(async move {
        left_barrier.wait().await;
        left_store
            .revoke_role("issuer|first", "admin", deadline())
            .await
    });
    let right_store = store.clone();
    let right_barrier = barrier.clone();
    let right = tokio::spawn(async move {
        right_barrier.wait().await;
        right_store
            .revoke_role("issuer|second", "admin", deadline())
            .await
    });
    barrier.wait().await;
    let results = (left.await.unwrap(), right.await.unwrap());
    assert!(matches!(
        results,
        (Ok(()), Err(MySqlControlError::LastAssignedAdmin))
            | (Err(MySqlControlError::LastAssignedAdmin), Ok(()))
    ));
    assert_eq!(
        fixture
            .scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments WHERE role='admin'"
            )
            .await,
        1
    );
    store
        .assign_role("issuer|first", "admin", deadline())
        .await
        .unwrap();
    store
        .assign_role("issuer|second", "admin", deadline())
        .await
        .unwrap();
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='admin' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let writer =
        tokio::spawn(async move { owner.revoke_role("issuer|first", "admin", deadline()).await });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    assert!(
        mysql_assignment_created(&mut root, "issuer|first", "admin")
            .await
            .is_some()
    );
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    writer.await.unwrap().unwrap();
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|first", "admin").await,
        None
    );
    store
        .assign_role("issuer|first", "admin", deadline())
        .await
        .unwrap();
    fixture
        .sql("REVOKE DELETE ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    store
        .assign_role("locking-read-health", "user", deadline())
        .await
        .unwrap();
    assert_eq!(
        store.revoke_role("issuer|first", "admin", deadline()).await,
        Err(MySqlControlError::Denied(RequiredCapability::Delete))
    );
    assert!(
        mysql_assignment_created(&mut root, "issuer|first", "admin")
            .await
            .is_some()
    );
    fixture
        .sql("GRANT DELETE ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("REVOKE SELECT ON broker.* FROM 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("GRANT SELECT(name) ON broker.roles TO 'ordinary`@_%'@'%'")
        .await;
    assert_eq!(
        store.revoke_role("issuer|first", "admin", deadline()).await,
        Err(MySqlControlError::Denied(RequiredCapability::Select))
    );
    assert!(
        mysql_assignment_created(&mut root, "issuer|first", "admin")
            .await
            .is_some()
    );
    fixture
        .sql("GRANT SELECT(subject,role) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    fixture
        .sql("DELETE FROM broker.role_assignments WHERE subject='issuer|second'")
        .await;
    seed_identity(&fixture, "guard-user", "guard-subject", "human").await;
    store
        .assign_role("local|guard-subject", "admin", deadline())
        .await
        .unwrap();
    assert_eq!(
        store.revoke_role("issuer|first", "admin", deadline()).await,
        Err(MySqlControlError::Denied(RequiredCapability::Select))
    );
    assert!(
        mysql_assignment_created(&mut root, "issuer|first", "admin")
            .await
            .is_some()
    );
    fixture
        .sql("GRANT SELECT ON broker.* TO 'ordinary`@_%'@'%'")
        .await;
    store
        .revoke_role("issuer|first", "admin", deadline())
        .await
        .unwrap();
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|first", "admin").await,
        None
    );
    assert_eq!(
        fixture
            .scalar(
                "SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments WHERE role='admin'"
            )
            .await,
        1
    );
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM mysql.user WHERE User='ordinary`@_%' AND Host='%' AND Super_priv='N'").await,1);
    store.shutdown(deadline()).await.unwrap();
}

#[tokio::test]
#[ignore = "real MySQL revocation deadline, cancellation and observed COMMIT uncertainty"]
async fn mysql_revocation_deadline_cancel_and_commit() {
    let fixture = Fixture::new().await;
    let store = Arc::new(fixture.open(2).await);
    fixture
        .sql("GRANT UPDATE(subject) ON broker.role_assignments TO 'ordinary`@_%'@'%'")
        .await;
    store
        .assign_role("issuer|target", "admin", deadline())
        .await
        .unwrap();
    store
        .assign_role("issuer|last-admin", "admin", deadline())
        .await
        .unwrap();
    let mut root = fixture.connection().await;
    let last_created = mysql_assignment_created(&mut root, "issuer|last-admin", "admin").await;
    let mut blocker = fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='admin' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let timed = tokio::spawn(async move {
        owner
            .revoke_role(
                "issuer|target",
                "admin",
                Instant::now() + Duration::from_secs(3),
            )
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    assert_eq!(timed.await.unwrap(), Err(MySqlControlError::Deadline));
    assert!(
        mysql_assignment_created(&mut root, "issuer|target", "admin")
            .await
            .is_some()
    );
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::raw_sql::raw_sql("START TRANSACTION")
        .execute(&mut blocker)
        .await
        .unwrap();
    sqlx_core::query::query("SELECT name FROM broker.roles WHERE name='admin' FOR UPDATE")
        .fetch_one(&mut blocker)
        .await
        .unwrap();
    let owner = store.clone();
    let cancelled = tokio::spawn(async move {
        owner
            .revoke_role("issuer|target", "admin", deadline())
            .await
    });
    wait_native(&fixture, MYSQL_ROLE_LOCK_WAIT, 1).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    sqlx_core::raw_sql::raw_sql("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    wait_native(&fixture, NO_ORDINARY, 0).await;
    assert!(
        mysql_assignment_created(&mut root, "issuer|target", "admin")
            .await
            .is_some()
    );
    store
        .revoke_role("issuer|target", "admin", deadline())
        .await
        .unwrap();
    assert_eq!(
        mysql_assignment_created(&mut root, "issuer|last-admin", "admin").await,
        last_created
    );
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        store
            .revoke_role("issuer|target", "admin", deadline())
            .await,
        Err(MySqlControlError::Closed)
    );
    instrumentation(&fixture).await;
    for (disconnect, subject) in [
        (true, "issuer|disconnect-target"),
        (false, "issuer|ack-timeout-target"),
    ] {
        let relay = Relay::new(fixture.port).await;
        let owner = Arc::new(
            MySqlControlStore::open(relay.config(&fixture, 1), digester(), deadline())
                .await
                .unwrap(),
        );
        owner
            .assign_role(subject, "admin", deadline())
            .await
            .unwrap();
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=1000000")
            .await;
        let writer_owner = owner.clone();
        let writer = tokio::spawn(async move {
            writer_owner
                .revoke_role(subject, "admin", Instant::now() + Duration::from_secs(5))
                .await
        });
        if let Err(snapshot) = try_wait_statement(&fixture, StatementPhase::Commit).await {
            let outcome = writer.await.unwrap();
            panic!("revocation COMMIT not observed snapshot={snapshot:?} outcome={outcome:?}");
        }
        let outcome = if disconnect {
            relay.stop().await;
            writer.await.unwrap()
        } else {
            relay.response.block();
            let result = writer.await.unwrap();
            relay.stop().await;
            result
        };
        assert_eq!(outcome, Err(MySqlControlError::OutcomeUncertain));
        wait_native(&fixture, NO_ORDINARY, 0).await;
        fixture
            .sql("SET GLOBAL binlog_group_commit_sync_delay=0")
            .await;
        let actual = mysql_assignment_created(&mut root, subject, "admin").await;
        if disconnect {
            assert!(actual.is_none() || actual.is_some_and(|created| created >= 0));
        } else {
            assert_eq!(actual, None);
        }
        assert_eq!(
            mysql_assignment_created(&mut root, "issuer|last-admin", "admin").await,
            last_created
        );
        assert!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.role_assignments WHERE role='admin'").await>=1);
        owner.shutdown(deadline()).await.unwrap();
        let recovered = fixture.open(1).await;
        recovered
            .assign_role(subject, "admin", deadline())
            .await
            .unwrap();
        recovered
            .revoke_role(subject, "admin", deadline())
            .await
            .unwrap();
        assert_eq!(
            mysql_assignment_created(&mut root, subject, "admin").await,
            None
        );
        recovered.shutdown(deadline()).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "real MySQL fresh/restart and incompatible instance-schema rejection"]
async fn mysql_instance_schema_epoch_contract() {
    let fixture = Fixture::new().await;
    let store = fixture.open(1).await;
    assert_eq!(
        fixture
            .scalar("SELECT epoch FROM broker.schema_meta WHERE id=1")
            .await,
        2
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.broker_instances")
            .await,
        0
    );
    assert_eq!(
        fixture
            .scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM broker.broker_instance_project_versions")
            .await,
        0
    );
    store.shutdown(deadline()).await.unwrap();
    let restarted = fixture.open(1).await;
    restarted.shutdown(deadline()).await.unwrap();
    for epoch in [1, 3] {
        fixture
            .sql(&format!("UPDATE broker.schema_meta SET epoch={epoch}"))
            .await;
        fixture
            .rejects(MySqlControlError::SchemaRejected(SchemaReason::Marker))
            .await;
    }
    fixture
        .sql("DROP TABLE broker.broker_instance_project_versions")
        .await;
    fixture.sql("DROP TABLE broker.broker_instances").await;
    fixture.sql("UPDATE broker.schema_meta SET epoch=1").await;
    fixture
        .rejects(MySqlControlError::SchemaRejected(SchemaReason::Relations))
        .await;
    assert_eq!(fixture.scalar("SELECT CAST(COUNT(*) AS SIGNED) FROM information_schema.TABLES WHERE TABLE_SCHEMA='broker'").await, 23);
    assert_eq!(
        fixture
            .scalar("SELECT epoch FROM broker.schema_meta WHERE id=1")
            .await,
        1
    );
    fixture.reference().await;
    let fresh = fixture.open(1).await;
    fresh.shutdown(deadline()).await.unwrap();
}
