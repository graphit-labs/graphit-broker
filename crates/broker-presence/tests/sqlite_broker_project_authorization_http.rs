use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessError, BrokerAccessVerifier, BrokerProjectAuthorizationError, FlowLimits,
    ProjectResourceAction as Action, ProjectResourceModule as Module, SqliteControlConfig,
    SqliteControlStore,
};
use broker_presence::{
    BrokerProjectAuthorizationHttpConfig, sqlite_broker_project_authorization_router,
};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rusqlite::{Connection, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const PATH: &str = "/v1/project/access/authorize";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const SUBJECT: &str = "broker-subject";
const JTI: &str = "jwt-native-token";
fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(
            b"project-http-fixture-pepper-32-bytes"
                .to_vec()
                .into_boxed_slice(),
        ),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self { key:EncodingKey::from_ed_der(&pair.serialize_der()),
            keys:serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"project-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap() }
    }
    fn verifier(&self) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "project-api", Some(RESOURCE), &self.keys, n(8192))
            .unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":SUBJECT,"aud":["project-api",RESOURCE],"iat":now-1,"exp":now+600,
            "token_use":"access","client_id":"approved-client","jti":JTI,"scope":"project-sdk",
            "preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
    }
    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("project-key".into());
        encode(&header, claims, &self.key).unwrap()
    }
}
fn config() -> BrokerProjectAuthorizationHttpConfig {
    BrokerProjectAuthorizationHttpConfig {
        required_scopes: vec!["project-sdk".into()],
        grants_json_bytes: n(65536),
        body_bytes: n(1024),
        request_timeout: Duration::from_secs(4),
    }
}
struct Fixture {
    store: Arc<SqliteControlStore>,
    path: PathBuf,
    _temp: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("private").join("broker.db");
        let store = Arc::new(open(&path).await);
        Self {
            store,
            path,
            _temp: temp,
        }
    }
    fn db(&self) -> Connection {
        let db = Connection::open(&self.path).unwrap();
        db.pragma_update(None, "foreign_keys", true).unwrap();
        db.busy_timeout(Duration::from_secs(5)).unwrap();
        db
    }
}
async fn open(path: &Path) -> SqliteControlStore {
    let config = SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(256),
            continuation_bytes: n(1024),
        },
    )
    .unwrap();
    SqliteControlStore::open(config, digester(), end())
        .await
        .unwrap()
}
fn clear(db: &Connection) {
    db.execute_batch("DELETE FROM resource_grants; UPDATE resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1").unwrap();
}
fn grant(db: &Connection, id: &str, kind: &str, principal: &str, caps: &[&str], projects: &[&str]) {
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES(?1,'fixture',?2,?3,'',0,0)",params![id,kind,principal]).unwrap();
    for cap in caps {
        db.execute(
            "INSERT INTO grant_capabilities(grant_id,value) VALUES(?1,?2)",
            params![id, cap],
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
fn revision(db: &Connection) -> i64 {
    db.query_row(
        "SELECT revision FROM resource_acl_state WHERE id=1",
        [],
        |row| row.get(0),
    )
    .unwrap()
}
fn input(project: &str, module: &str, action: &str) -> String {
    json!({"project_id":project,"module":module,"action":action}).to_string()
}
struct Server {
    address: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            stop,
            task,
        }
    }
    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(6), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    content_type: Option<&str>,
    body: Body,
) -> (StatusCode, Value, bool) {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let mut request = Request::builder().method(method).uri(path);
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    for value in auth {
        request = request.header(header::AUTHORIZATION, *value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(request.body(body).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let status = response.status();
    let challenge = response.headers().get(header::WWW_AUTHENTICATE).cloned();
    let bearer = challenge.as_ref().is_some_and(|value| value == "Bearer");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if method == "HEAD" {
        assert!(bytes.is_empty());
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    if value["error"]["code"] == "insufficient_scope" {
        assert_eq!(challenge.unwrap(), "Bearer error=\"insufficient_scope\"");
    }
    drop(sender);
    if let Err(error) = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap()
    {
        assert!(
            streaming && status == StatusCode::GATEWAY_TIMEOUT && error.is_incomplete_message()
        );
    }
    (status, value, bearer)
}
async fn post(server: &Server, auth: &[&str], raw: String) -> (StatusCode, Value, bool) {
    exchange(
        server.address,
        "POST",
        PATH,
        auth,
        Some("application/json"),
        Body::from(raw),
    )
    .await
}
fn error(reply: (StatusCode, Value, bool), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, json!({"error":{"code":code}}));
    assert_eq!(reply.2, status == StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nine_pairs_use_signed_subject_and_fresh_whole_sqlite_policy_over_tcp() {
    let f = Fixture::new().await;
    let db = f.db();
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    let auth = format!("Bearer {raw}");
    let server = Server::start(
        sqlite_broker_project_authorization_router(f.store.clone(), verifier.clone(), config())
            .unwrap(),
    )
    .await;
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for (module, action, capability) in [
        ("task", "read", "task:read"),
        ("task", "write", "task:write"),
        ("memory", "read", "memory:read"),
        ("memory", "write", "memory:write"),
        ("knowledge", "read", "knowledge:read"),
        ("knowledge", "write", "knowledge:write"),
        ("ast", "read", "ast:read"),
        ("ast", "write", "ast:write"),
        ("hub", "read", "hub"),
    ] {
        clear(&db);
        grant(
            &db,
            "logical",
            "subject",
            &format!("{ISSUER}|{SUBJECT}"),
            &[capability],
            &[A],
        );
        let reply = post(&server, &[&auth], input(A, module, action)).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert!(!reply.2);
        assert_eq!(
            reply.1,
            json!({"subject":{"issuer":ISSUER,"subject":SUBJECT},"authorization_revision":revision(&db),"project_id":A,"module":module,"action":action})
        );
        error(
            post(&server, &[&auth], input(B, module, action)).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
        if module != "hub" {
            error(
                post(
                    &server,
                    &[&auth],
                    input(A, module, if action == "read" { "write" } else { "read" }),
                )
                .await,
                StatusCode::FORBIDDEN,
                "forbidden",
            );
        }
    }
    error(
        post(&server, &["Bearer opaque-local"], input(A, "hub", "write")).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    clear(&db);
    grant(&db, "project-b", "subject", SUBJECT, &["task:read"], &[B]);
    grant(&db, "wrong-cap", "subject", SUBJECT, &["task:write"], &[A]);
    grant(
        &db,
        "wrong-subject",
        "subject",
        "other",
        &["task:read"],
        &[A],
    );
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for substitute in [
        "knowledge:read",
        "presence",
        "s3",
        "s3:read",
        "hub:read",
        "hub:write",
    ] {
        clear(&db);
        grant(&db, "substitute", "subject", SUBJECT, &[substitute], &[A]);
        error(
            post(&server, &[&auth], input(A, "hub", "read")).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
    }
    clear(&db);
    grant(&db, "logical", "subject", SUBJECT, &["task:read"], &[A]);
    let first = post(&server, &[&auth], input(A, "task", "read")).await;
    assert_eq!(first.0, StatusCode::OK);
    let tx = db.unchecked_transaction().unwrap();
    tx.execute("DELETE FROM resource_grants WHERE id='logical'", [])
        .unwrap();
    tx.execute(
        "UPDATE resource_acl_state SET revision=revision+1 WHERE id=1",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(&db, "logical", "subject", SUBJECT, &["task:read"], &[A]);
    let next = post(&server, &[&auth], input(A, "task", "read")).await;
    assert_eq!(next.0, StatusCode::OK);
    assert_eq!(
        next.1["authorization_revision"],
        first.1["authorization_revision"].as_i64().unwrap() + 1
    );
    grant(&db, "unrelated-invalid", "user", "[", &["task:write"], &[B]);
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    let mut claims = signer.claims();
    for field in ["preferred_username", "organization", "groups", "roles"] {
        claims.as_object_mut().unwrap().remove(field);
    }
    let no_attributes = format!("Bearer {}", signer.sign(&claims));
    for kind in ["user", "organization", "team"] {
        clear(&db);
        grant(&db, "missing", kind, "*", &["task:read"], &[A]);
        error(
            post(&server, &[&no_attributes], input(A, "task", "read")).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
    }
    clear(&db);
    grant(&db, "logical", "subject", SUBJECT, &["task:read"], &[A]);
    assert_eq!(
        post(&server, &[&no_attributes], input(A, "task", "read"))
            .await
            .0,
        StatusCode::OK
    );
    let mut tiny = config();
    tiny.grants_json_bytes = n(1);
    let capped = Server::start(
        sqlite_broker_project_authorization_router(f.store.clone(), verifier, tiny).unwrap(),
    )
    .await;
    error(
        post(&capped, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    capped.stop().await;
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_validation_precedes_sql_and_sql_auth_metadata_does_not_revoke_signed_identity() {
    let f = Fixture::new().await;
    let mut db = f.db();
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    let auth = format!("Bearer {raw}");
    grant(&db, "logical", "user", "alice", &["task:read"], &[A]);
    let server = Server::start(
        sqlite_broker_project_authorization_router(f.store.clone(), verifier, config()).unwrap(),
    )
    .await;
    let empty:(i64,i64,i64)=db.query_row("SELECT (SELECT count(*) FROM local_users),(SELECT count(*) FROM local_tokens),(SELECT count(*) FROM oauth_dynamic_clients)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(empty, (0, 0, 0));
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    db.execute_batch("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','original-subject','human','','Old','','old','[\"old\"]',1,0,1,0,0); INSERT INTO oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('approved-client','Fixture','[\"https://client.example.test/callback\"]','[\"project-sdk\"]','web',0)").unwrap();
    let digest = digester()
        .token(TokenKind::OidcStoredAccess, JTI.as_bytes())
        .unwrap()
        .to_sql_hex();
    db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES(?1,?2,'oidc_access','original-subject',?3,'{}','approved-client','project-api',?4,'[\"project-sdk\"]',1,'',0,9223372036854775807,0)",params![digest,JTI,SUBJECT,RESOURCE]).unwrap();
    db.execute_batch("UPDATE local_users SET enabled=0,revision=2,organization='changed',teams_json='[]' WHERE username='alice'; UPDATE local_tokens SET revoked_at=1,expires_at=0,principal_json='{}'; DELETE FROM oauth_dynamic_clients WHERE client_id='approved-client'").unwrap();
    let reply = post(&server, &[&auth], input(A, "task", "read")).await;
    assert_eq!(reply.0, StatusCode::OK);
    assert_eq!(
        reply.1["subject"],
        json!({"issuer":ISSUER,"subject":SUBJECT})
    );
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let rogue = Signer::new();
    error(
        post(
            &server,
            &[&format!("Bearer {}", rogue.sign(&rogue.claims()))],
            input(A, "task", "read"),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    let mut expired = signer.claims();
    expired["exp"] = json!(seconds() - 1);
    error(
        post(
            &server,
            &[&format!("Bearer {}", signer.sign(&expired))],
            input(A, "task", "read"),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    let mut scope = signer.claims();
    scope["scope"] = json!("other");
    error(
        post(
            &server,
            &[&format!("Bearer {}", signer.sign(&scope))],
            input(A, "task", "read"),
        )
        .await,
        StatusCode::FORBIDDEN,
        "insufficient_scope",
    );
    error(
        post(&server, &["Bearer opaque-local"], input(A, "hub", "write")).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    writer.rollback().unwrap();
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    server.stop().await;
    f.store.shutdown(end()).await.unwrap();
}

async fn poll_pending(future: std::pin::Pin<&mut impl std::future::Future>) {
    let mut future = future;
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jwt_expiry_during_sql_wait_rechecks_both_allow_and_deny() {
    let f = Fixture::new().await;
    let mut db = f.db();
    let signer = Signer::new();
    let verifier = signer.verifier();
    let authorizer = f
        .store
        .broker_project_authorizer(&verifier, n(65536))
        .unwrap();
    assert_eq!(
        format!("{authorizer:?}"),
        "SqliteBrokerProjectAuthorizer([REDACTED])"
    );
    let scopes = vec!["project-sdk".to_owned()];
    for allowed in [true, false] {
        clear(&db);
        grant(
            &db,
            "logical",
            "subject",
            if allowed { SUBJECT } else { "other" },
            &["task:read"],
            &[A],
        );
        let writer = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        // WAL readers do not wait for this writer. Occupy the store's physical
        // owner with an actual write operation before submitting the read.
        let mut blocked = std::pin::pin!(f.store.consume_flow(&[b'x'; 32], &[b'y'; 32], end()));
        poll_pending(blocked.as_mut()).await;
        let mut claims = signer.claims();
        let expiry = seconds() + 2;
        claims["exp"] = json!(expiry);
        let raw = signer.sign(&claims);
        verifier
            .verify(&raw, &scopes, end())
            .unwrap()
            .check()
            .unwrap();
        let mut pending = std::pin::pin!(authorizer.authorize(
            &raw,
            &scopes,
            Module::Task,
            Action::Read,
            A,
            end()
        ));
        poll_pending(pending.as_mut()).await;
        let expiry = UNIX_EPOCH + Duration::from_secs(expiry);
        tokio::time::sleep(
            expiry.duration_since(SystemTime::now()).unwrap_or_default() + Duration::from_millis(2),
        )
        .await;
        writer.rollback().unwrap();
        assert!(matches!(
            blocked.await,
            Err(broker_control::SqliteControlError::Unavailable)
        ));
        assert!(
            matches!(
                pending.await,
                Err(BrokerProjectAuthorizationError::Authentication(
                    BrokerAccessError::Expired
                ))
            ),
            "allow={allowed}"
        );
    }
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_wire_body_sql_deadline_cancel_close_and_reopen_keep_owned_lifecycle() {
    let f = Fixture::new().await;
    let mut db = f.db();
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let raw = signer.sign(&signer.claims());
    let auth = format!("Bearer {raw}");
    grant(&db, "logical", "subject", SUBJECT, &["task:read"], &[A]);
    for bad in ["", " ", "two scopes"] {
        let mut invalid = config();
        invalid.required_scopes = vec![bad.into()];
        assert!(
            sqlite_broker_project_authorization_router(f.store.clone(), verifier.clone(), invalid)
                .is_err()
        );
    }
    let mut invalid = config();
    invalid.request_timeout = Duration::ZERO;
    assert!(
        sqlite_broker_project_authorization_router(f.store.clone(), verifier.clone(), invalid)
            .is_err()
    );
    let server = Server::start(
        sqlite_broker_project_authorization_router(f.store.clone(), verifier.clone(), config())
            .unwrap(),
    )
    .await;
    for headers in [
        vec![],
        vec!["Basic opaque"],
        vec![auth.as_str(), auth.as_str()],
    ] {
        error(
            post(&server, &headers, "not-json".into()).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    for body in [
        r#"{"project_id":"p","module":"task","action":"read","extra":true}"#.to_owned(),
        format!(r#"{{"project_id":"{A}","module":"task","module":"ast","action":"read"}}"#),
        input("*", "task", "read"),
        input(&A.to_ascii_lowercase(), "task", "read"),
    ] {
        error(
            post(&server, &[&auth], body).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }
    error(
        exchange(
            server.address,
            "POST",
            &format!("{PATH}?q=x"),
            &[&auth],
            Some("application/json"),
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[&auth],
            Some("text/plain"),
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    error(
        post(&server, &[&auth], " ".repeat(1025)).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    let chunks = futures_util::stream::iter([
        Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b' '; 700]))),
        Ok(Frame::data(Bytes::from(vec![b' '; 700]))),
    ]);
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[&auth],
            Some("application/json"),
            Body::new(http_body_util::StreamBody::new(chunks)),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    error(
        exchange(server.address, "GET", PATH, &[], None, Body::empty()).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    let head = exchange(server.address, "HEAD", PATH, &[], None, Body::empty()).await;
    assert_eq!(head.0, StatusCode::METHOD_NOT_ALLOWED);
    assert!(head.1.is_null());
    error(
        exchange(
            server.address,
            "POST",
            &format!("{PATH}/"),
            &[],
            None,
            Body::empty(),
        )
        .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let mut short = config();
    short.request_timeout = Duration::from_millis(40);
    let limited = Server::start(
        sqlite_broker_project_authorization_router(f.store.clone(), verifier.clone(), short)
            .unwrap(),
    )
    .await;
    let body = Body::new(http_body_util::StreamBody::new(
        futures_util::stream::pending::<Result<Frame<Bytes>, Infallible>>(),
    ));
    error(
        exchange(
            limited.address,
            "POST",
            PATH,
            &[&auth],
            Some("application/json"),
            body,
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    // A read-only WAL transaction is not blocked by an unrelated writer. Make
    // the deadline exercise waiting for the shared store owner instead.
    let mut blocked = std::pin::pin!(f.store.consume_flow(&[b'x'; 32], &[b'y'; 32], end()));
    poll_pending(blocked.as_mut()).await;
    error(
        post(&limited, &[&auth], input(A, "task", "read")).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    writer.rollback().unwrap();
    assert!(matches!(
        blocked.await,
        Err(broker_control::SqliteControlError::Unavailable)
    ));
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    limited.stop().await;
    let writer = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let mut blocked = std::pin::pin!(f.store.consume_flow(&[b'x'; 32], &[b'y'; 32], end()));
    poll_pending(blocked.as_mut()).await;
    {
        let authorizer = f
            .store
            .broker_project_authorizer(&verifier, n(65536))
            .unwrap();
        let scopes = vec!["project-sdk".to_owned()];
        let mut pending = std::pin::pin!(authorizer.authorize(
            &raw,
            &scopes,
            Module::Task,
            Action::Read,
            A,
            end()
        ));
        poll_pending(pending.as_mut()).await;
    }
    writer.rollback().unwrap();
    assert!(matches!(
        blocked.await,
        Err(broker_control::SqliteControlError::Unavailable)
    ));
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    f.store.shutdown(end()).await.unwrap();
    error(
        post(&server, &[&auth], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    server.stop().await;
    let reopened = Arc::new(open(&f.path).await);
    let server = Server::start(
        sqlite_broker_project_authorization_router(reopened.clone(), verifier, config()).unwrap(),
    )
    .await;
    assert_eq!(
        post(&server, &[&auth], input(A, "task", "read")).await.0,
        StatusCode::OK
    );
    server.stop().await;
    reopened.shutdown(end()).await.unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM resource_grants", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
