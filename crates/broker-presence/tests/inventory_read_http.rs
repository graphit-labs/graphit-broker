#[allow(
    dead_code,
    reason = "Shared PostgreSQL helpers also serve other active control suites."
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use broker_control::{
    ConnectionLimits, InstanceInventory, InstanceOwner, InstanceProjectVersions, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{
    InstanceInventoryListHttpConfig, InstanceInventoryReadHttpConfig, InstanceRegistryHttpConfig,
    instance_inventory_read_router, instance_inventory_router,
};
use broker_security::TokenKind;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::net::{TcpListener, TcpStream};
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const AUTH: &str = "Bearer gb_at_read-http";
const SERVICE: &str = "Bearer gb_sc_read-http";
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn store_config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "read_owner".into(),
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
fn read_config() -> InstanceInventoryReadHttpConfig {
    InstanceInventoryReadHttpConfig {
        audience: "explicit-audience".into(),
        required_scopes: vec!["presence:read".into()],
        identity_json_bytes: n(4096),
        grants_json_bytes: n(16384),
        inventory_json_bytes: n(16384),
        request_timeout: Duration::from_secs(4),
    }
}
fn list_config() -> InstanceInventoryListHttpConfig {
    InstanceInventoryListHttpConfig {
        audience: "explicit-audience".into(),
        required_scopes: vec!["presence:read".into()],
        identity_json_bytes: n(4096),
        grants_json_bytes: n(16384),
        inventory_json_bytes: n(16384),
        request_timeout: Duration::from_secs(4),
        query_bytes: n(1024),
    }
}
fn publish_config() -> InstanceRegistryHttpConfig {
    InstanceRegistryHttpConfig {
        audience: "explicit-audience".into(),
        required_scopes: vec!["presence:publish".into()],
        identity_json_bytes: n(4096),
        grants_json_bytes: n(16384),
        body_bytes: n(4096),
        request_timeout: Duration::from_secs(4),
    }
}
fn inventory(id: &str, projects: &[(&str, &[&str])]) -> InstanceInventory {
    InstanceInventory::new(
        id.into(),
        projects
            .iter()
            .map(|(p, v)| {
                InstanceProjectVersions::new((*p).into(), v.iter().map(|v| (*v).into()).collect())
                    .unwrap()
            })
            .collect(),
    )
    .unwrap()
}
async fn grant(
    c: &mut sqlx_postgres::PgConnection,
    id: &str,
    who: &str,
    cap: &str,
    project: Option<&str>,
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture','user',$2,'',0,0)").bind(id).bind(who).execute(&mut *c).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(cap)
        .execute(&mut *c)
        .await
        .unwrap();
    if let Some(p) = project {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(p)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
async fn snapshot(c: &mut sqlx_postgres::PgConnection) -> serde_json::Value {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('instances',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY instance_id),'[]'::jsonb) FROM public.broker_instances i),'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY instance_id,project_id,position),'[]'::jsonb) FROM public.broker_instance_project_versions v))").fetch_one(c).await.unwrap()
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
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
fn request(method: &str, path: &str, auth: &[&str], body: Body) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for auth in auth {
        r = r.header(header::AUTHORIZATION, *auth);
    }
    r.body(body).unwrap()
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    body: Body,
) -> (StatusCode, serde_json::Value, bool) {
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let reply = tokio::time::timeout(
        Duration::from_secs(6),
        sender.send_request(request(method, path, auth, body)),
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
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    (status, json, challenge)
}
async fn get(
    address: std::net::SocketAddr,
    id: &str,
    auth: &[&str],
) -> (StatusCode, serde_json::Value, bool) {
    exchange(
        address,
        "GET",
        &format!("/v1/instances/{id}/inventory"),
        auth,
        Body::empty(),
    )
    .await
}
fn error(reply: (StatusCode, serde_json::Value, bool), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, serde_json::json!({"error":{"code":code}}));
    assert_eq!(reply.2, status == StatusCode::UNAUTHORIZED);
}
async fn observe_grant_lock(c: &mut sqlx_postgres::PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let found:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='read_owner' AND wait_event_type='Lock' AND query LIKE '%WITH policy AS MATERIALIZED%')").fetch_one(&mut *c).await.unwrap();
        if found {
            return;
        }
        assert!(Instant::now() < end, "GET reaches real grant SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real TCP Axum/Hyper, PostgreSQL TLS and authenticated own-inventory read"]
async fn inventory_read_http_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE read_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION read_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO read_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='read_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    for i in 0..7 {
        let mut cfg = read_config();
        match i {
            0 => cfg.audience = " ".into(),
            1 => cfg.required_scopes = vec![" ".into()],
            2 => cfg.request_timeout = Duration::ZERO,
            3 => cfg.request_timeout = Duration::MAX,
            4 => cfg.identity_json_bytes = n(usize::MAX),
            5 => cfg.grants_json_bytes = n(usize::MAX),
            _ => cfg.inventory_json_bytes = n(usize::MAX),
        }
        assert!(instance_inventory_read_router(store.clone(), cfg).is_err());
    }
    let mut cfg = publish_config();
    cfg.request_timeout = Duration::ZERO;
    assert!(instance_inventory_router(store.clone(), cfg, read_config(), list_config()).is_err());
    let mut cfg = read_config();
    cfg.audience = " ".into();
    assert!(
        instance_inventory_router(store.clone(), publish_config(), cfg, list_config()).is_err()
    );
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    for (raw, kind, id, name, subject) in [
        (
            "gb_at_read-http",
            TokenKind::LocalAccess,
            "access-http-read",
            "access",
            "alice-subject",
        ),
        (
            "gb_sc_read-http",
            TokenKind::ServiceCredential,
            "service-http-read",
            "service",
            "bot-subject",
        ),
    ] {
        let hash = support::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=serde_json::json!({"issuer":"local","subject":subject,"username":"stale-name","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope',$5,'client','explicit-audience','','[\"presence:read\",\"presence:publish\"]',1,'',0,$6,0)").bind(hash.to_sql_hex()).bind(id).bind(name).bind(subject).bind(principal).bind(now()+120_000_000).execute(&mut c).await.unwrap();
    }
    let own = InstanceOwner::new("local", "alice-subject").unwrap();
    let stored = store
        .replace_instance_inventory(
            &own,
            &inventory("station", &[(B, &["main"]), (A, &["release", "main"])]),
            deadline(),
        )
        .await
        .unwrap();
    store
        .replace_instance_inventory(&own, &inventory("empty", &[]), deadline())
        .await
        .unwrap();
    store
        .replace_instance_inventory(
            &InstanceOwner::new("local", "bot-subject").unwrap(),
            &inventory("service", &[(A, &["main"])]),
            deadline(),
        )
        .await
        .unwrap();
    store
        .replace_instance_inventory(
            &InstanceOwner::new("local", "alice-subject ").unwrap(),
            &inventory("literal", &[(A, &["main"])]),
            deadline(),
        )
        .await
        .unwrap();
    grant(&mut c, "read-a", "alice", "presence:read", Some(A)).await;
    grant(&mut c, "publish-b", "alice", "presence:publish", Some(B)).await;
    grant(&mut c, "other-b", "bot", "presence:read", Some(B)).await;
    let server = Server::start(
        instance_inventory_router(
            store.clone(),
            publish_config(),
            read_config(),
            list_config(),
        )
        .unwrap(),
    )
    .await;
    let before = snapshot(&mut c).await;
    error(
        get(server.address, "station", &[AUTH]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    error(
        get(server.address, "empty", &[AUTH]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    error(
        get(server.address, "service", &[AUTH]).await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    error(
        get(server.address, "literal", &[AUTH]).await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    error(
        get(server.address, "absent", &[AUTH]).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    for headers in [
        &[][..],
        &[AUTH, AUTH][..],
        &["Basic dTpw"][..],
        &["Bearer gb_at_unknown"][..],
        &["Bearer gb_rt_read-http"][..],
        &["Bearer eyJhbGci.fake.jwt"][..],
    ] {
        error(
            get(server.address, "absent", headers).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    error(
        get(server.address, "bad%20id", &[AUTH]).await,
        StatusCode::BAD_REQUEST,
        "invalid_inventory",
    );
    error(
        get(server.address, "%FF", &[AUTH]).await,
        StatusCode::BAD_REQUEST,
        "invalid_inventory",
    );
    error(
        exchange(server.address, "GET", "/missing", &[AUTH], Body::empty()).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    error(
        exchange(
            server.address,
            "POST",
            "/v1/instances/station/inventory",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    grant(&mut c, "read-b", "alice", "presence:read", Some(B)).await;
    let expected = serde_json::json!({"instance_id":"station","projects":[{"project_id":A,"versions":["main","release"]},{"project_id":B,"versions":["main"]}],"created_at":stored.created_at_micros(),"updated_at":stored.updated_at_micros()});
    assert_eq!(
        get(server.address, "station", &[AUTH]).await,
        (StatusCode::OK, expected.clone(), false)
    );
    grant(&mut c, "any-publish", "alice", "presence:publish", None).await;
    error(
        get(server.address, "empty", &[AUTH]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    grant(&mut c, "any-read", "alice", "presence:read", None).await;
    let empty = get(server.address, "empty", &[AUTH]).await;
    assert_eq!(empty.0, StatusCode::OK);
    assert_eq!(empty.1["projects"], serde_json::json!([]));
    assert_eq!(empty.1.as_object().unwrap().len(), 4);
    grant(&mut c, "bot-read", "bot", "presence:read", Some(A)).await;
    assert_eq!(
        get(server.address, "service", &[SERVICE]).await.0,
        StatusCode::OK
    );
    let head = exchange(
        server.address,
        "HEAD",
        "/v1/instances/station/inventory",
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(head, (StatusCode::OK, serde_json::Value::Null, false));
    assert_eq!(
        exchange(
            server.address,
            "HEAD",
            "/v1/instances/station/inventory",
            &[],
            Body::empty()
        )
        .await,
        (StatusCode::UNAUTHORIZED, serde_json::Value::Null, true)
    );
    for (change, restore) in [
        (
            "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
            "UPDATE public.local_users SET enabled=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_users SET revision=2 WHERE username='alice'",
            "UPDATE public.local_users SET revision=1 WHERE username='alice'",
        ),
        (
            "UPDATE public.local_tokens SET audience='other' WHERE token_id='access-http-read'",
            "UPDATE public.local_tokens SET audience='explicit-audience' WHERE token_id='access-http-read'",
        ),
        (
            "UPDATE public.local_tokens SET scopes_json='[\"presence:publish\"]' WHERE token_id='access-http-read'",
            "UPDATE public.local_tokens SET scopes_json='[\"presence:read\",\"presence:publish\"]' WHERE token_id='access-http-read'",
        ),
        (
            "UPDATE public.local_tokens SET revoked_at=1 WHERE token_id='access-http-read'",
            "UPDATE public.local_tokens SET revoked_at=NULL WHERE token_id='access-http-read'",
        ),
    ] {
        c.execute(change).await.unwrap();
        error(
            get(server.address, "station", &[AUTH]).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        c.execute(restore).await.unwrap();
        assert_eq!(
            get(server.address, "station", &[AUTH]).await.0,
            StatusCode::OK
        );
    }
    c.execute("UPDATE public.grant_capabilities SET value='presence:publish' WHERE grant_id IN ('read-b','any-read')").await.unwrap();
    error(
        get(server.address, "station", &[AUTH]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    c.execute("UPDATE public.grant_capabilities SET value='presence:read' WHERE grant_id IN ('read-b','any-read')").await.unwrap();
    for (index, code) in [
        (0, "authentication_unavailable"),
        (1, "authorization_unavailable"),
        (2, "inventory_unavailable"),
    ] {
        let mut cfg = read_config();
        match index {
            0 => cfg.identity_json_bytes = n(8),
            1 => cfg.grants_json_bytes = n(8),
            _ => cfg.inventory_json_bytes = n(8),
        };
        let limited =
            Server::start(instance_inventory_read_router(store.clone(), cfg).unwrap()).await;
        error(
            get(limited.address, "station", &[AUTH]).await,
            StatusCode::SERVICE_UNAVAILABLE,
            code,
        );
        limited.stop().await;
    }
    c.execute("UPDATE public.resource_grants SET principal='[' WHERE id='other-b'")
        .await
        .unwrap();
    error(
        get(server.address, "station", &[AUTH]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    c.execute("UPDATE public.resource_grants SET principal='bot' WHERE id='other-b'")
        .await
        .unwrap();
    c.execute("UPDATE public.broker_instance_project_versions SET position=4 WHERE instance_id='service' AND position=1").await.unwrap();
    error(
        get(server.address, "service", &[SERVICE]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "inventory_unavailable",
    );
    c.execute("UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='service' AND position=4").await.unwrap();
    c.execute("REVOKE SELECT ON public.broker_instance_project_versions FROM read_owner")
        .await
        .unwrap();
    error(
        get(server.address, "station", &[AUTH]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "inventory_unavailable",
    );
    c.execute("GRANT SELECT ON public.broker_instance_project_versions TO read_owner")
        .await
        .unwrap();
    let expiry = now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-http-read'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    c.execute("BEGIN; LOCK TABLE public.resource_grants IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let address = server.address;
    let waiting = tokio::spawn(async move { get(address, "station", &[AUTH]).await });
    observe_grant_lock(&mut c).await;
    assert!(!waiting.is_finished());
    assert!(
        now() < expiry,
        "Auth remains future when real grant wait starts"
    );
    while now() < expiry {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    c.execute("COMMIT").await.unwrap();
    error(
        waiting.await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-http-read'",
    )
    .bind(now() + 120_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    let mut cfg = read_config();
    cfg.request_timeout = Duration::from_millis(300);
    let short = Server::start(instance_inventory_read_router(store.clone(), cfg).unwrap()).await;
    c.execute("BEGIN; LOCK TABLE public.resource_grants IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    error(
        get(short.address, "station", &[AUTH]).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    c.execute("ROLLBACK").await.unwrap();
    short.stop().await;
    assert_eq!(
        get(server.address, "station", &[AUTH]).await,
        (StatusCode::OK, expected, false)
    );
    assert_eq!(snapshot(&mut c).await, before);
    let body = serde_json::json!({"projects":[{"project_id":A,"versions":["main"]}]}).to_string();
    let path = "/v1/instances/combined/inventory";
    let put = exchange(
        server.address,
        "PUT",
        path,
        &[AUTH],
        Body::from(body.clone()),
    )
    .await;
    assert_eq!(put.0, StatusCode::CREATED);
    assert_eq!(put.1["change"], "created");
    assert_eq!(put.1.as_object().unwrap().len(), 4);
    let again = exchange(server.address, "PUT", path, &[AUTH], Body::from(body)).await;
    assert_eq!(again.0, StatusCode::OK);
    assert_eq!(again.1["change"], "unchanged");
    let read = get(server.address, "combined", &[AUTH]).await;
    assert_eq!(read.0, StatusCode::OK);
    assert_eq!(
        read.1["projects"],
        serde_json::json!([{"project_id":A,"versions":["main"]}])
    );
    assert_eq!(read.1["created_at"], put.1["created_at"]);
    assert_eq!(read.1["updated_at"], put.1["updated_at"]);
    assert_eq!(read.1.as_object().unwrap().len(), 4);
    store.shutdown(deadline()).await.unwrap();
    error(
        get(server.address, "combined", &[AUTH]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    server.stop().await;
    let reopened = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let reopened_server =
        Server::start(instance_inventory_read_router(reopened.clone(), read_config()).unwrap())
            .await;
    assert_eq!(
        get(reopened_server.address, "combined", &[AUTH]).await.1,
        read.1
    );
    reopened_server.stop().await;
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
