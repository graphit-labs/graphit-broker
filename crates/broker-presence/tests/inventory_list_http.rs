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
    instance_inventory_router,
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
const AUTH: &str = "Bearer gb_at_list-http";
const SERVICE: &str = "Bearer gb_sc_list-http";
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
            "list_http_owner".into(),
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
async fn observe_inventory_lock(c: &mut sqlx_postgres::PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let found:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='list_http_owner' AND wait_event_type='Lock' AND query LIKE '%WITH candidate AS MATERIALIZED%')").fetch_one(&mut *c).await.unwrap();
        if found {
            return;
        }
        assert!(Instant::now() < end, "LIST reaches real inventory SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "real TCP Axum/Hyper, PostgreSQL TLS and authorized partial inventory LIST"]
async fn inventory_list_http_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE list_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION list_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO list_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='list_http_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    for case in 0..8 {
        let mut cfg = list_config();
        match case {
            0 => cfg.audience = " ".into(),
            1 => cfg.required_scopes = vec![" ".into()],
            2 => cfg.request_timeout = Duration::ZERO,
            3 => cfg.request_timeout = Duration::MAX,
            4 => cfg.identity_json_bytes = n(usize::MAX),
            5 => cfg.grants_json_bytes = n(usize::MAX),
            6 => cfg.inventory_json_bytes = n(usize::MAX),
            _ => cfg.query_bytes = n(usize::MAX),
        }
        assert!(
            instance_inventory_router(store.clone(), publish_config(), read_config(), cfg).is_err()
        );
    }
    assert_eq!(
        format!("{:?}", list_config()),
        "InstanceInventoryListHttpConfig([REDACTED])"
    );
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    for (raw, kind, id, name, subject) in [
        (
            "gb_at_list-http",
            TokenKind::LocalAccess,
            "access-list-http",
            "access",
            "alice-subject",
        ),
        (
            "gb_sc_list-http",
            TokenKind::ServiceCredential,
            "service-list-http",
            "service",
            "bot-subject",
        ),
    ] {
        let digest = support::digester().token(kind, raw.as_bytes()).unwrap();
        let principal=serde_json::json!({"issuer":"local","subject":subject,"username":"obsolete","auth_method":"old","local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'envelope-subject',$5,'client','explicit-audience','','[\"presence:read\",\"presence:publish\"]',1,'',0,$6,0)")
            .bind(digest.to_sql_hex()).bind(id).bind(name).bind(subject).bind(principal).bind(now()+120_000_000).execute(&mut c).await.unwrap();
    }
    let own = InstanceOwner::new("local", "alice-subject").unwrap();
    let foreign = InstanceOwner::new("local", "bot-subject").unwrap();
    let first = store
        .replace_instance_inventory(
            &foreign,
            &inventory("A-foreign", &[(A, &["release", "main"]), (B, &["private"])]),
            deadline(),
        )
        .await
        .unwrap();
    store
        .replace_instance_inventory(
            &own,
            &inventory("C-owned", &[(A, &["main"]), (B, &["private"])]),
            deadline(),
        )
        .await
        .unwrap();
    store
        .replace_instance_inventory(&own, &inventory("E-empty", &[]), deadline())
        .await
        .unwrap();
    store
        .replace_instance_inventory(&foreign, &inventory("F-empty", &[]), deadline())
        .await
        .unwrap();
    store
        .replace_instance_inventory(
            &InstanceOwner::new("local", "alice-subject ").unwrap(),
            &inventory("G-literal", &[]),
            deadline(),
        )
        .await
        .unwrap();
    for i in 0..55 {
        store
            .replace_instance_inventory(
                &foreign,
                &inventory(
                    &format!("I{i:03}"),
                    &[(A, &["release", "main", "feature branch"])],
                ),
                deadline(),
            )
            .await
            .unwrap();
        store
            .replace_instance_inventory(
                &foreign,
                &inventory(&format!("I{i:03}-hidden"), &[(B, &["private"])]),
                deadline(),
            )
            .await
            .unwrap();
    }
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
    let first_page = exchange(
        server.address,
        "GET",
        "/v1/instances",
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(first_page.0, StatusCode::OK);
    assert_eq!(
        first_page
            .1
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["items", "next_after"]
    );
    let items = first_page.1["items"].as_array().unwrap();
    assert_eq!(items.len(), 50);
    assert_eq!(first_page.1["next_after"], "I047");
    assert_eq!(
        items[0],
        serde_json::json!({"instance_id":"A-foreign","projects":[{"project_id":A,"versions":["main","release"]}],"created_at":first.created_at_micros(),"updated_at":first.updated_at_micros()})
    );
    for item in items {
        assert_eq!(item.as_object().unwrap().len(), 4);
        assert!(!item["instance_id"].as_str().unwrap().contains("hidden"));
        assert_eq!(item["projects"].as_array().unwrap().len(), 1);
        assert_eq!(item["projects"][0].as_object().unwrap().len(), 2);
        assert_eq!(item["projects"][0]["project_id"], A);
    }
    let tail = exchange(
        server.address,
        "GET",
        "/v1/instances?after=I047",
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(tail.0, StatusCode::OK);
    assert_eq!(tail.1["items"].as_array().unwrap().len(), 7);
    assert_eq!(tail.1["items"][0]["instance_id"], "I048");
    assert!(tail.1["next_after"].is_null());
    for path in ["/v1/instances?limit=01", "/v1/instances?%6cimit=1"] {
        let reply = exchange(server.address, "GET", path, &[AUTH], Body::empty()).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(reply.1["next_after"], "A-foreign");
    }
    let whole = exchange(
        server.address,
        "GET",
        "/v1/instances?limit=100",
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(whole.0, StatusCode::OK);
    assert_eq!(whole.1["items"].as_array().unwrap().len(), 57);
    assert!(whole.1["next_after"].is_null());
    for (suffix, id, version) in [
        (
            "instance_id=I000&version=feature+branch",
            "I000",
            "feature branch",
        ),
        (
            "instance_id=I000&version=feature%20branch",
            "I000",
            "feature branch",
        ),
        (
            "instance_id=A-foreign&version=release",
            "A-foreign",
            "release",
        ),
    ] {
        let reply = exchange(
            server.address,
            "GET",
            &format!("/v1/instances?{suffix}"),
            &[AUTH],
            Body::empty(),
        )
        .await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1["items"].as_array().unwrap().len(), 1);
        assert_eq!(reply.1["items"][0]["instance_id"], id);
        assert_eq!(
            reply.1["items"][0]["projects"],
            serde_json::json!([{"project_id":A,"versions":[version]}])
        );
    }
    let cumulative = exchange(
        server.address,
        "GET",
        &format!("/v1/instances?instance_id=I000&project_id={A}&version=release"),
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(cumulative.0, StatusCode::OK);
    assert_eq!(
        cumulative.1["items"][0]["projects"],
        serde_json::json!([{"project_id":A,"versions":["release"]}])
    );
    for suffix in [
        "version=private".to_string(),
        format!("project_id={B}"),
        format!("project_id={B}&version=main"),
        "version=absent".into(),
        "instance_id=absent".into(),
        "instance_id=A-foreign&after=A-foreign".into(),
        "after=zz".into(),
        "instance_id=E-empty".into(),
    ] {
        let reply = exchange(
            server.address,
            "GET",
            &format!("/v1/instances?{suffix}"),
            &[AUTH],
            Body::empty(),
        )
        .await;
        assert_eq!(
            (reply.0, reply.1),
            (
                StatusCode::OK,
                serde_json::json!({"items":[],"next_after":null})
            )
        );
    }
    // The unchanged own GET requires Read ALL and does not disclose a partial inventory.
    error(
        get(server.address, "C-owned", &[AUTH]).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let bot = exchange(
        server.address,
        "GET",
        "/v1/instances?instance_id=I000-hidden",
        &[SERVICE],
        Body::empty(),
    )
    .await;
    assert_eq!(bot.0, StatusCode::OK);
    assert_eq!(bot.1["items"][0]["projects"][0]["project_id"], B);
    grant(&mut c, "any", "alice", "presence:read", None).await;
    let empty = exchange(
        server.address,
        "GET",
        "/v1/instances?instance_id=E-empty",
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(empty.0, StatusCode::OK);
    assert_eq!(empty.1["items"][0]["projects"], serde_json::json!([]));
    for suffix in [
        "instance_id=F-empty",
        "instance_id=G-literal",
        "instance_id=E-empty&version=main",
    ] {
        let reply = exchange(
            server.address,
            "GET",
            &format!("/v1/instances?{suffix}"),
            &[AUTH],
            Body::empty(),
        )
        .await;
        assert_eq!(reply.1, serde_json::json!({"items":[],"next_after":null}));
    }
    assert_eq!(
        get(server.address, "C-owned", &[AUTH]).await.0,
        StatusCode::OK
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='any'")
        .await
        .unwrap();

    for suffix in [
        "limit=",
        "limit=0",
        "limit=101",
        "limit=+1",
        "limit=%2B1",
        "limit=-1",
        "limit=1%20",
        "limit=%EF%BC%91",
        "limit=99999999999999999999999999999",
        "limit=1&limit=2",
        "limit=1&%6cimit=2",
        "unknown=x",
        "%FF=x",
        "version=%FF",
        "version=%",
        "version=%0",
        "version=%GG",
        "version=%C0%AF",
        "after=",
        "instance_id=x%27",
        "after=x%2F1",
        "project_id=friendly",
        "version=+main",
        "version=main%00",
    ] {
        error(
            exchange(
                server.address,
                "GET",
                &format!("/v1/instances?{suffix}"),
                &[AUTH],
                Body::empty(),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "INVALID_QUERY",
        );
    }
    let exact = format!("/v1/instances?version={}", "x".repeat(1016));
    let reply = exchange(server.address, "GET", &exact, &[AUTH], Body::empty()).await;
    assert_eq!(
        (reply.0, reply.1),
        (
            StatusCode::OK,
            serde_json::json!({"items":[],"next_after":null})
        )
    );
    error(
        exchange(
            server.address,
            "GET",
            &format!("{exact}x"),
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "QUERY_TOO_LARGE",
    );
    let mut tiny = list_config();
    tiny.query_bytes = n(7);
    let capped = Server::start(
        instance_inventory_router(store.clone(), publish_config(), read_config(), tiny).unwrap(),
    )
    .await;
    assert_eq!(
        exchange(
            capped.address,
            "GET",
            "/v1/instances?limit=1",
            &[AUTH],
            Body::empty()
        )
        .await
        .0,
        StatusCode::OK
    );
    error(
        exchange(
            capped.address,
            "GET",
            "/v1/instances?limit=01",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "QUERY_TOO_LARGE",
    );
    capped.stop().await;
    for auth in [
        vec![],
        vec!["invalid"],
        vec!["Bearer gb_rt_list-http"],
        vec!["Bearer eyJ.fake.jwt"],
        vec![AUTH, AUTH],
    ] {
        error(
            exchange(server.address, "GET", "/v1/instances", &auth, Body::empty()).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    // Header decoding precedes query parsing; current SQL authentication follows query validation.
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances?limit=bad",
            &[],
            Body::empty(),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    for sql in [
        "UPDATE public.local_tokens SET audience='other' WHERE token_id='access-list-http'",
        "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='access-list-http'",
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-list-http'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET revision=2 WHERE username='alice'",
    ] {
        c.execute(sql).await.unwrap();
        error(
            exchange(
                server.address,
                "GET",
                "/v1/instances?after=zz",
                &[AUTH],
                Body::empty(),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        c.execute("UPDATE public.local_tokens SET audience='explicit-audience',scopes_json='[\"presence:read\",\"presence:publish\"]',revoked_at=NULL WHERE token_id='access-list-http'; UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'").await.unwrap();
    }
    c.execute("UPDATE public.grant_capabilities SET value='hub:admin' WHERE grant_id='read-a'")
        .await
        .unwrap();
    let revoked = exchange(
        server.address,
        "GET",
        "/v1/instances?after=I047",
        &[AUTH],
        Body::empty(),
    )
    .await;
    assert_eq!(revoked.1, serde_json::json!({"items":[],"next_after":null}));
    c.execute("UPDATE public.grant_capabilities SET value='presence:read' WHERE grant_id='read-a'")
        .await
        .unwrap();
    grant(&mut c, "malformed", "[", "presence:read", None).await;
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances?after=zz&instance_id=A-foreign",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='malformed'")
        .await
        .unwrap();
    for (case, code) in [
        (0, "authentication_unavailable"),
        (1, "authorization_unavailable"),
        (2, "inventory_unavailable"),
    ] {
        let mut cfg = list_config();
        match case {
            0 => cfg.identity_json_bytes = n(8),
            1 => cfg.grants_json_bytes = n(8),
            _ => cfg.inventory_json_bytes = n(8),
        }
        let restricted = Server::start(
            instance_inventory_router(store.clone(), publish_config(), read_config(), cfg).unwrap(),
        )
        .await;
        error(
            exchange(
                restricted.address,
                "GET",
                "/v1/instances?instance_id=A-foreign",
                &[AUTH],
                Body::empty(),
            )
            .await,
            StatusCode::SERVICE_UNAVAILABLE,
            code,
        );
        restricted.stop().await;
    }
    c.execute("UPDATE public.broker_instance_project_versions SET position=3 WHERE instance_id='I000-hidden'").await.unwrap();
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances?after=I000",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "inventory_unavailable",
    );
    c.execute("UPDATE public.broker_instance_project_versions SET position=1 WHERE instance_id='I000-hidden'; REVOKE SELECT ON public.resource_grants FROM list_http_owner").await.unwrap();
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.resource_grants TO list_http_owner; REVOKE SELECT ON public.broker_instance_project_versions FROM list_http_owner").await.unwrap();
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "inventory_unavailable",
    );
    c.execute("GRANT SELECT ON public.broker_instance_project_versions TO list_http_owner")
        .await
        .unwrap();
    error(
        exchange(
            server.address,
            "POST",
            "/v1/instances",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    error(
        exchange(
            server.address,
            "POST",
            "/v1/instances/C-owned/inventory",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    error(
        exchange(server.address, "GET", "/unknown", &[AUTH], Body::empty()).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    assert_eq!(
        exchange(
            server.address,
            "HEAD",
            "/v1/instances?limit=1",
            &[AUTH],
            Body::empty()
        )
        .await
        .0,
        StatusCode::OK
    );
    let denied_head = exchange(server.address, "HEAD", "/v1/instances", &[], Body::empty()).await;
    assert_eq!(denied_head.0, StatusCode::UNAUTHORIZED);
    assert!(denied_head.2);

    let expiry = now() + 2_000_000;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-list-http'",
    )
    .bind(expiry)
    .execute(&mut c)
    .await
    .unwrap();
    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let address = server.address;
    let job = tokio::spawn(async move {
        exchange(
            address,
            "GET",
            "/v1/instances?limit=1",
            &[AUTH],
            Body::empty(),
        )
        .await
    });
    observe_inventory_lock(&mut c).await;
    assert!(!job.is_finished());
    assert!(now() < expiry, "current bearer reached real inventory wait");
    while now() <= expiry {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    c.execute("COMMIT").await.unwrap();
    error(
        job.await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=$1 WHERE token_id='access-list-http'",
    )
    .bind(now() + 120_000_000)
    .execute(&mut c)
    .await
    .unwrap();
    let mut cfg = list_config();
    cfg.request_timeout = Duration::from_millis(300);
    let timed = Server::start(
        instance_inventory_router(store.clone(), publish_config(), read_config(), cfg).unwrap(),
    )
    .await;
    c.execute("BEGIN; LOCK TABLE public.broker_instance_project_versions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let start = Instant::now();
    error(
        exchange(
            timed.address,
            "GET",
            "/v1/instances",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    c.execute("ROLLBACK").await.unwrap();
    timed.stop().await;
    assert_eq!(
        exchange(
            server.address,
            "GET",
            "/v1/instances?limit=1",
            &[AUTH],
            Body::empty()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(snapshot(&mut c).await, before);

    // Explicit PUT phase changes inventory; subsequent GET/LIST remain read-only.
    grant(&mut c, "publish-a", "alice", "presence:publish", Some(A)).await;
    let body = serde_json::json!({"projects":[{"project_id":A,"versions":["main"]}]}).to_string();
    assert_eq!(
        exchange(
            server.address,
            "PUT",
            "/v1/instances/Z-put/inventory",
            &[AUTH],
            Body::from(body.clone())
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        exchange(
            server.address,
            "PUT",
            "/v1/instances/Z-put/inventory",
            &[AUTH],
            Body::from(body)
        )
        .await
        .0,
        StatusCode::OK
    );
    let after_put = snapshot(&mut c).await;
    assert_eq!(
        get(server.address, "Z-put", &[AUTH]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        exchange(
            server.address,
            "GET",
            "/v1/instances?instance_id=Z-put",
            &[AUTH],
            Body::empty()
        )
        .await
        .1["items"][0]["instance_id"],
        "Z-put"
    );
    assert_eq!(snapshot(&mut c).await, after_put);
    store.shutdown(deadline()).await.unwrap();
    error(
        exchange(
            server.address,
            "GET",
            "/v1/instances",
            &[AUTH],
            Body::empty(),
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    server.stop().await;
    let reopened = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let reopened_server = Server::start(
        instance_inventory_router(
            reopened.clone(),
            publish_config(),
            read_config(),
            list_config(),
        )
        .unwrap(),
    )
    .await;
    assert_eq!(
        exchange(
            reopened_server.address,
            "GET",
            "/v1/instances?limit=1",
            &[AUTH],
            Body::empty()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(snapshot(&mut c).await, after_put);
    reopened_server.stop().await;
    reopened.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}
