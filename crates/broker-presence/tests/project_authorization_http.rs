#[allow(
    dead_code,
    reason = "shared PostgreSQL fixture also serves other control suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
};
use broker_control::{
    ConnectionLimits, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{ProjectAuthorizationHttpConfig, project_authorization_router};
use broker_security::TokenKind;
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::net::{TcpListener, TcpStream};

const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const PATH: &str = "/v1/project/access/authorize";
const RAW: &str = "gb_at_project-http";
const AUTH: &str = "Bearer gb_at_project-http";
const SERVICE: &str = "Bearer gb_sc_project-http";
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn config() -> ProjectAuthorizationHttpConfig {
    ProjectAuthorizationHttpConfig {
        audience: "explicit-audience".into(),
        required_scopes: vec!["project-api".into()],
        identity_json_bytes: n(4096),
        grants_json_bytes: n(65536),
        body_bytes: n(1024),
        request_timeout: Duration::from_secs(4),
    }
}
fn store_config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "project_http_owner".into(),
            zeroize::Zeroizing::new("ephemeral-owner".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}
fn input(project: &str, module: &str, action: &str) -> String {
    serde_json::json!({"project_id":project,"module":module,"action":action}).to_string()
}
async fn clear(c: &mut PgConnection) {
    c.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
}
async fn grant(c: &mut PgConnection, id: &str, who: &str, cap: &str, project: &str) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture','user',$2,'',0,0)").bind(id).bind(who).execute(&mut *c).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(cap)
        .execute(&mut *c)
        .await
        .unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(project)
        .execute(&mut *c)
        .await
        .unwrap();
}
async fn oracle(c: &mut PgConnection) -> String {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('acl',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.resource_acl_state ORDER BY id) t),'rules',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.resource_grants ORDER BY id) t),'caps',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_capabilities ORDER BY grant_id,value) t),'projects',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.grant_projects ORDER BY grant_id,value) t),'users',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.local_users ORDER BY subject) t),'tokens',(SELECT jsonb_agg(to_jsonb(t)) FROM (SELECT * FROM public.local_tokens ORDER BY token_id) t))::text").fetch_one(c).await.unwrap()
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
) -> (StatusCode, serde_json::Value, bool) {
    let streaming = body.size_hint().exact().is_none();
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let mut request = Request::builder().method(method).uri(path);
    if let Some(ct) = content_type {
        request = request.header(header::CONTENT_TYPE, ct);
    }
    for a in auth {
        request = request.header(header::AUTHORIZATION, *a);
    }
    let reply = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(request.body(body).unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let status = reply.status();
    let challenge = reply
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .is_some_and(|v| v == "Bearer");
    assert_eq!(
        reply.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = reply.into_body().collect().await.unwrap().to_bytes();
    let json = if method == "HEAD" {
        assert!(bytes.is_empty());
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    drop(sender);
    let outcome = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = outcome {
        assert!(
            streaming && status == StatusCode::GATEWAY_TIMEOUT && error.is_incomplete_message(),
            "HTTP connection failed after response: status={status}, streaming={streaming}, error={error}"
        );
    }
    (status, json, challenge)
}
async fn post(
    address: std::net::SocketAddr,
    auth: &[&str],
    raw: String,
) -> (StatusCode, serde_json::Value, bool) {
    exchange(
        address,
        "POST",
        PATH,
        auth,
        Some("application/json"),
        Body::from(raw),
    )
    .await
}
fn error(reply: (StatusCode, serde_json::Value, bool), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, serde_json::json!({"error":{"code":code}}));
    assert_eq!(reply.2, status == StatusCode::UNAUTHORIZED);
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='project_http_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(
            Instant::now() < end,
            "HTTP request reaches real ACL SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real TCP Axum/Hyper and PostgreSQL TLS current local PROJECT authorization"]
async fn project_authorization_http_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE project_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION project_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO project_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='project_http_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    for i in 0..6 {
        let mut cfg = config();
        match i {
            0 => cfg.audience = " ".into(),
            1 => cfg.required_scopes = vec![" ".into()],
            2 => cfg.request_timeout = Duration::ZERO,
            3 => cfg.request_timeout = Duration::MAX,
            4 => cfg.identity_json_bytes = n(usize::MAX),
            _ => cfg.grants_json_bytes = n(usize::MAX),
        }
        assert!(project_authorization_router(store.clone(), cfg).is_err());
    }
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    let principal=serde_json::json!({"issuer":"local","subject":"alice-subject","username":"stale","auth_method":"old","local_user_revision":1}).to_string();
    for (raw, kind, id, label, subject) in [
        (
            RAW,
            TokenKind::LocalAccess,
            "http-access",
            "access",
            "alice-subject",
        ),
        (
            "gb_sc_project-http",
            TokenKind::ServiceCredential,
            "http-service",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = support::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=serde_json::json!({"issuer":"local","subject":subject,"username":"stale","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope',$5,'client','explicit-audience','','[\"project-api\"]',1,'',0,$6,0)").bind(digest.to_sql_hex()).bind(id).bind(label).bind(subject).bind(principal).bind(now()+3_600_000_000).execute(&mut c).await.unwrap();
    }
    let server =
        Server::start(project_authorization_router(store.clone(), config()).unwrap()).await;

    // Logical Hub PROJECT read does not inherit Knowledge or S3 permissions.
    clear(&mut c).await;
    grant(&mut c, "hub", "alice", "hub", A).await;
    let hub = post(server.address, &[AUTH], input(A, "hub", "read")).await;
    let revision: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.resource_acl_state WHERE id=1",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(hub.0, StatusCode::OK);
    assert_eq!(
        hub.1,
        serde_json::json!({"subject":{"issuer":"local","subject":"alice-subject"},"authorization_revision":revision,"project_id":A,"module":"hub","action":"read"})
    );
    error(
        post(server.address, &[AUTH], input(A, "hub", "write")).await,
        StatusCode::BAD_REQUEST,
        "invalid_request",
    );
    error(
        post(server.address, &[AUTH], input(B, "hub", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    error(
        post(server.address, &["Bearer invalid"], input(A, "hub", "read")).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    let next = post(server.address, &[AUTH], input(A, "hub", "read")).await;
    assert_eq!(next.0, StatusCode::OK);
    assert_eq!(
        next.1["authorization_revision"].as_i64().unwrap(),
        revision + 1
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='hub'")
        .await
        .unwrap();
    error(
        post(server.address, &[AUTH], input(A, "hub", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for cap in ["knowledge:read", "s3", "s3:read", "hub:read", "hub:write"] {
        clear(&mut c).await;
        grant(&mut c, "substitute", "alice", cap, A).await;
        error(
            post(server.address, &[AUTH], input(A, "hub", "read")).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        );
    }
    clear(&mut c).await;
    grant(&mut c, "hub-b", "alice", "hub", B).await;
    grant(&mut c, "project-a", "alice", "knowledge:read", A).await;
    grant(&mut c, "other", "other", "hub", A).await;
    error(
        post(server.address, &[AUTH], input(A, "hub", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    for module in ["task", "memory", "knowledge", "ast"] {
        for action in ["read", "write"] {
            clear(&mut c).await;
            grant(&mut c, "logical", "alice", &format!("{module}:{action}"), A).await;
            let revision: i64 = sqlx_core::query_scalar::query_scalar(
                "SELECT revision FROM public.resource_acl_state WHERE id=1",
            )
            .fetch_one(&mut c)
            .await
            .unwrap();
            let before = oracle(&mut c).await;
            let reply = post(server.address, &[AUTH], input(A, module, action)).await;
            assert_eq!(reply.0, StatusCode::OK);
            assert_eq!(
                reply.1,
                serde_json::json!({"subject":{"issuer":"local","subject":"alice-subject"},"authorization_revision":revision,"project_id":A,"module":module,"action":action})
            );
            assert!(!reply.2);
            for (project, modul, act, credential) in [
                (B, module, action, AUTH),
                (
                    A,
                    if module == "task" { "memory" } else { "task" },
                    action,
                    AUTH,
                ),
                (
                    A,
                    module,
                    if action == "read" { "write" } else { "read" },
                    AUTH,
                ),
                (A, module, action, SERVICE),
            ] {
                error(
                    post(server.address, &[credential], input(project, modul, act)).await,
                    StatusCode::FORBIDDEN,
                    "forbidden",
                );
            }
            assert_eq!(oracle(&mut c).await, before);
        }
    }
    clear(&mut c).await;
    grant(&mut c, "cap-b", "alice", "task:read", B).await;
    grant(&mut c, "project-a", "alice", "task:write", A).await;
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    clear(&mut c).await;
    for cap in ["hub", "presence:read", "s3", "s3:read"] {
        grant(&mut c, cap, "alice", cap, A).await;
    }
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(&mut c, "logical", "alice", "task:read", A).await;
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    let first = post(server.address, &[AUTH], input(A, "task", "read")).await;
    assert_eq!(first.0, StatusCode::OK);
    c.execute("UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1")
        .await
        .unwrap();
    let second = post(server.address, &[AUTH], input(A, "task", "read")).await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(
        second.1["authorization_revision"].as_i64().unwrap(),
        first.1["authorization_revision"].as_i64().unwrap() + 1
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='logical'")
        .await
        .unwrap();
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    clear(&mut c).await;
    grant(&mut c, "logical", "alice", "task:read", A).await;
    grant(&mut c, "service", "bot", "task:read", A).await;
    let service = post(server.address, &[SERVICE], input(A, "task", "read")).await;
    assert_eq!(service.0, StatusCode::OK);
    assert_eq!(
        service.1["subject"],
        serde_json::json!({"issuer":"local","subject":"bot-subject"})
    );
    let before = oracle(&mut c).await;
    for raw in [
        "{}".into(),
        serde_json::json!([A, "task", "read"]).to_string(),
        serde_json::json!({"project_id":A,"module":{"task":null},"action":"read"}).to_string(),
        serde_json::json!({"project_id":A,"module":"task","action":{"read":null}}).to_string(),
        serde_json::json!({"project_id":A,"module":[],"action":"read"}).to_string(),
        serde_json::json!({"project_id":A,"module":"task","action":[]}).to_string(),
        input(A, "Task", "read"),
        input(A, "task", "Read"),
        input(A, "hub", "write"),
        input(A, "task", "delete"),
        format!(r#"{{"project_id":"{A}","module":"task","action":"read","subject":"forged"}}"#),
        format!(r#"{{"project_id":"{A}","module":"task","action":"read","version":"main"}}"#),
        format!(r#"{{"project_id":"{A}","project_id":"{B}","module":"task","action":"read"}}"#),
        format!(r#"{{"project_id":"{A}","module":"task","module":"ast","action":"read"}}"#),
        format!(r#"{{"project_id":"{A}","module":"task","action":"read","action":"write"}}"#),
        r#"{"project_id":null,"module":"task","action":"read"}"#.to_string(),
        format!(r#"{{"project_id":"{A}","module":1,"action":"read"}}"#),
        format!("{} {{}}", input(A, "task", "read")),
        input("00000000000000000000000000", "task", "read"),
        input(&A.to_lowercase(), "task", "read"),
        input("project", "task", "read"),
    ] {
        error(
            post(server.address, &[AUTH], raw).await,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        );
    }
    error(
        exchange(
            server.address,
            "POST",
            &format!("{PATH}?subject=forged"),
            &[AUTH],
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
            &[AUTH],
            Some("application/json"),
            Body::from(vec![0xff]),
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
            &[AUTH],
            None,
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[AUTH],
            Some("text/plain"),
            Body::from(input(A, "task", "read")),
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported_media_type",
    );
    error(
        post(server.address, &[AUTH], " ".repeat(2048)).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    let chunks =
        futures_util::stream::iter([Ok::<Bytes, std::io::Error>(Bytes::from(vec![b' '; 2048]))]);
    error(
        exchange(
            server.address,
            "POST",
            PATH,
            &[AUTH],
            Some("application/json"),
            Body::from_stream(chunks),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
    );
    for headers in [
        vec![],
        vec![AUTH, AUTH],
        vec!["Basic fake"],
        vec!["Bearer invalid"],
        vec!["Bearer gb_rt_refresh"],
        vec!["Bearer a.b.c"],
        vec!["Bearer gb_at_not-issued"],
    ] {
        error(
            post(server.address, &headers, input(A, "task", "read")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    for method in ["GET", "PUT", "PATCH", "DELETE"] {
        error(
            exchange(server.address, method, PATH, &[], None, Body::empty()).await,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        );
    }
    let head = exchange(server.address, "HEAD", PATH, &[], None, Body::empty()).await;
    assert_eq!(head.0, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(head.1, serde_json::Value::Null);
    assert!(!head.2);
    for path in [
        "/v1/project/access/authorize/",
        "/v1/project/access",
        "/v1/hub/access/resolve",
    ] {
        error(
            exchange(server.address, "POST", path, &[], None, Body::empty()).await,
            StatusCode::NOT_FOUND,
            "not_found",
        );
    }
    assert_eq!(oracle(&mut c).await, before);
    // Every call observes SQL authentication changes, independently of logical grants.
    for (change, restore) in [
        (
            "UPDATE public.local_tokens SET revoked_at=1 WHERE token_id='http-access'",
            "UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='http-access'",
        ),
        (
            "UPDATE public.local_users SET enabled=0 WHERE subject='alice-subject'",
            "UPDATE public.local_users SET enabled=1 WHERE subject='alice-subject'",
        ),
        (
            "UPDATE public.local_users SET revision=2 WHERE subject='alice-subject'",
            "UPDATE public.local_users SET revision=1 WHERE subject='alice-subject'",
        ),
        (
            "UPDATE public.local_tokens SET audience='other' WHERE token_id='http-access'",
            "UPDATE public.local_tokens SET audience='explicit-audience' WHERE token_id='http-access'",
        ),
        (
            "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='http-access'",
            "UPDATE public.local_tokens SET scopes_json='[\"project-api\"]' WHERE token_id='http-access'",
        ),
        (
            "UPDATE public.local_tokens SET expires_at=1 WHERE token_id='http-access'",
            "UPDATE public.local_tokens SET expires_at=9999999999999999 WHERE token_id='http-access'",
        ),
    ] {
        c.execute(change).await.unwrap();
        error(
            post(server.address, &[AUTH], input(A, "task", "read")).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        c.execute(restore).await.unwrap();
        assert_eq!(
            post(server.address, &[AUTH], input(A, "task", "read"))
                .await
                .0,
            StatusCode::OK
        );
    }
    c.execute("UPDATE public.local_tokens SET principal_json='{' WHERE token_id='http-access'")
        .await
        .unwrap();
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id='http-access'",
    )
    .bind(principal)
    .execute(&mut c)
    .await
    .unwrap();
    grant(&mut c, "unrelated", "nobody", "task:read", "[").await;
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='unrelated'")
        .await
        .unwrap();
    c.execute("REVOKE SELECT ON public.resource_grants FROM project_http_owner")
        .await
        .unwrap();
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.resource_grants TO project_http_owner")
        .await
        .unwrap();
    c.execute("REVOKE SELECT ON public.local_users FROM project_http_owner")
        .await
        .unwrap();
    // The producer folds Control errors without inventing an authentication phase.
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.local_users TO project_http_owner")
        .await
        .unwrap();
    for identity in [true, false] {
        let mut cfg = config();
        if identity {
            cfg.identity_json_bytes = n(1);
        } else {
            cfg.grants_json_bytes = n(1);
        }
        let capped = Server::start(project_authorization_router(store.clone(), cfg).unwrap()).await;
        error(
            post(capped.address, &[AUTH], input(A, "task", "read")).await,
            StatusCode::SERVICE_UNAVAILABLE,
            if identity {
                "authentication_unavailable"
            } else {
                "authorization_unavailable"
            },
        );
        capped.stop().await;
    }
    // A credential is live after SQL lock admission, then expires before permission can return.
    let expires = now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='http-access'",
    )
    .bind(expires)
    .execute(&mut c)
    .await
    .unwrap();
    let mut held = c.begin().await.unwrap();
    held.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let address = server.address;
    let pending =
        tokio::spawn(async move { post(address, &[AUTH], input(A, "task", "read")).await });
    let mut observer = f.connection().await;
    observe_lock(&mut observer).await;
    assert!(!pending.is_finished());
    assert!(now() < expires, "token live at observed HTTP SQL lock");
    while now() <= expires {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    held.rollback().await.unwrap();
    error(
        pending.await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    c.execute(
        "UPDATE public.local_tokens SET expires_at=9999999999999999 WHERE token_id='http-access'",
    )
    .await
    .unwrap();
    // Body and SQL share the first admitted deadline; neither can reset it.
    let mut cfg = config();
    cfg.request_timeout = Duration::from_millis(1500);
    let bounded = Server::start(project_authorization_router(store.clone(), cfg).unwrap()).await;
    let address = bounded.address;
    let mut held = c.begin().await.unwrap();
    held.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let start = Instant::now();
    let pending = tokio::spawn(async move {
        let body = futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            Ok::<Bytes, std::io::Error>(Bytes::from(input(A, "task", "read")))
        });
        exchange(
            address,
            "POST",
            PATH,
            &[AUTH],
            Some("application/json"),
            Body::from_stream(body),
        )
        .await
    });
    observe_lock(&mut observer).await;
    assert!(!pending.is_finished());
    error(
        pending.await.unwrap(),
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    assert!(
        start.elapsed() < Duration::from_millis(2300),
        "SQL did not reset the deadline after body"
    );
    held.rollback().await.unwrap();
    assert_eq!(
        post(bounded.address, &[AUTH], input(A, "task", "read"))
            .await
            .0,
        StatusCode::OK
    );
    let body = futures_util::stream::pending::<Result<Bytes, std::io::Error>>();
    error(
        exchange(
            bounded.address,
            "POST",
            PATH,
            &[AUTH],
            Some("application/json"),
            Body::from_stream(body),
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    // Close the actual TCP client while SQL is pending, then recover the pool.
    let mut held = c.begin().await.unwrap();
    held.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let stream = TcpStream::connect(bounded.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let connection_worker = tokio::spawn(connection);
    let pending = tokio::spawn(async move {
        sender
            .send_request(
                Request::builder()
                    .method("POST")
                    .uri(PATH)
                    .header(header::AUTHORIZATION, AUTH)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(input(A, "task", "read")))
                    .unwrap(),
            )
            .await
    });
    observe_lock(&mut observer).await;
    assert!(!pending.is_finished());
    connection_worker.abort();
    assert!(connection_worker.await.unwrap_err().is_cancelled());
    pending.abort();
    let _ = pending.await;
    held.rollback().await.unwrap();
    assert_eq!(
        post(bounded.address, &[AUTH], input(A, "task", "read"))
            .await
            .0,
        StatusCode::OK
    );
    bounded.stop().await;
    assert_eq!(
        post(server.address, &[AUTH], input(A, "task", "read"))
            .await
            .0,
        StatusCode::OK
    );
    let before = oracle(&mut c).await;
    store.shutdown(deadline()).await.unwrap();
    error(
        post(server.address, &[AUTH], input(A, "task", "read")).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    assert_eq!(oracle(&mut c).await, before);
    server.stop().await;
}
