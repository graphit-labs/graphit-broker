#[allow(
    dead_code,
    reason = "Reuse the existing PostgreSQL fixture; its other helpers serve control-store suites."
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use broker_control::{
    ConnectionLimits, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{InstanceRegistryHttpConfig, instance_registry_router};
use broker_security::TokenKind;
use http_body_util::BodyExt;
use hyper::body::Body as _;
use hyper_util::rt::TokioIo;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    convert::Infallible,
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::net::{TcpListener, TcpStream};

const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn ordinary_config(fixture: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "opaque_owner".into(),
            zeroize::Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}
fn config() -> InstanceRegistryHttpConfig {
    InstanceRegistryHttpConfig {
        audience: "explicit-audience".into(),
        required_scopes: vec!["presence:publish".into()],
        identity_json_bytes: n(4096),
        grants_json_bytes: n(16384),
        body_bytes: n(4096),
        request_timeout: Duration::from_secs(2),
    }
}
async fn sql_snapshot(c: &mut sqlx_postgres::PgConnection) -> serde_json::Value {
    sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_object('instances',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY instance_id),'[]'::jsonb) FROM public.broker_instances i),'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY instance_id,project_id,position),'[]'::jsonb) FROM public.broker_instance_project_versions v))")
        .fetch_one(c).await.unwrap()
}
fn request(path: &str, authorization: &[&str], body: Body) -> Request<Body> {
    let mut r = Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    for auth in authorization {
        r = r.header(header::AUTHORIZATION, *auth);
    }
    r.body(body).unwrap()
}
async fn exchange(
    addr: std::net::SocketAddr,
    r: Request<Body>,
) -> (StatusCode, serde_json::Value, bool) {
    let streaming = r.body().size_hint().exact().is_none();
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let reply = tokio::time::timeout(Duration::from_secs(5), sender.send_request(r))
        .await
        .unwrap()
        .unwrap();
    let status = reply.status();
    assert_eq!(
        reply.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let challenge = reply
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .is_some_and(|v| v == "Bearer");
    let bytes = reply.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap();
    drop(sender);
    let outcome = tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .unwrap()
        .unwrap();
    if let Err(error) = outcome {
        // A deadline response closes HTTP/1 while this deliberately unfinished body
        // is still being sent. Only this SDK classification is expected here.
        assert!(
            streaming && status == StatusCode::GATEWAY_TIMEOUT && error.is_incomplete_message(),
            "HTTP connection failed after response: status={status}, streaming={streaming}, error={error}"
        );
    }
    (status, json, challenge)
}
fn assert_error(reply: (StatusCode, serde_json::Value, bool), status: StatusCode, code: &str) {
    assert_eq!(reply.0, status);
    assert_eq!(reply.1, serde_json::json!({"error":{"code":code}}));
    assert_eq!(reply.2, status == StatusCode::UNAUTHORIZED);
}
#[tokio::test]
#[ignore = "real TCP Axum/Hyper and PostgreSQL TLS authenticated registration"]
async fn registration_http_postgres_contract() {
    let fixture = Fixture::new(true).await;
    let mut c = fixture.connection().await;
    c.execute("CREATE ROLE opaque_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION opaque_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO opaque_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(ordinary_config(&fixture), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='opaque_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    for timeout in [Duration::ZERO, Duration::MAX] {
        let mut cfg = config();
        cfg.request_timeout = timeout;
        assert!(instance_registry_router(store.clone(), cfg).is_err());
    }
    let mut cfg = config();
    cfg.audience = " ".into();
    assert!(instance_registry_router(store.clone(), cfg).is_err());
    let mut cfg = config();
    cfg.required_scopes = vec![" ".into()];
    assert!(instance_registry_router(store.clone(), cfg).is_err());
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','Alice','','org','[]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','org','[]',1,0,1,0,0)").await.unwrap();
    let raw = "gb_at_http-access";
    let service_raw = "gb_sc_http-service";
    let principal=serde_json::json!({"issuer":"local","subject":"alice-subject","username":"old-name","auth_method":"old","local_user_revision":1}).to_string();
    for(token,kind,name,id,subject,p)in [
        (raw,TokenKind::LocalAccess,"access","access-http","alice-subject",principal.clone()),
        (service_raw,TokenKind::ServiceCredential,"service","service-http","bot-subject",serde_json::json!({"issuer":"local","subject":"bot-subject","username":"old-name","auth_method":"old","local_user_revision":1}).to_string()),
    ]{
        let hash=support::digester().token(kind,token.as_bytes()).unwrap();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'other',$5,'client','explicit-audience','','[\"presence:publish\"]',1,'',0,$6,0)")
            .bind(hash.to_sql_hex()).bind(id).bind(name).bind(subject).bind(p).bind(now()+120_000_000).execute(&mut c).await.unwrap();
    }
    c.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('a','fixture','user','alice','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('a','presence:publish')").await.unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES('a',$1)")
        .bind(A)
        .execute(&mut c)
        .await
        .unwrap();
    let app = instance_registry_router(store.clone(), config()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
            .unwrap();
    });
    let path = "/v1/instances/station/inventory";
    let auth = "Bearer gb_at_http-access";
    let bot_auth = "Bearer gb_sc_http-service";
    let body=serde_json::json!({"projects":[{"project_id":A,"versions":["release","main"]},{"project_id":B,"versions":["main"]}]}).to_string();
    let empty = r#"{"projects":[]}"#;
    let before = sql_snapshot(&mut c).await;
    assert_error(
        exchange(address, request(path, &[auth], Body::from(body.clone()))).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_eq!(sql_snapshot(&mut c).await, before);
    sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES('a',$1)")
        .bind(B)
        .execute(&mut c)
        .await
        .unwrap();
    let created = exchange(address, request(path, &[auth], Body::from(body.clone()))).await;
    assert_eq!(created.0, StatusCode::CREATED);
    assert_eq!(created.1.as_object().unwrap().len(), 4);
    assert_eq!(created.1["instance_id"], "station");
    assert_eq!(created.1["change"], "created");
    let stored = sql_snapshot(&mut c).await;
    assert_eq!(stored["instances"][0]["owner_issuer"], "local");
    assert_eq!(stored["instances"][0]["owner_subject"], "alice-subject");
    assert_eq!(
        stored["instances"][0]["created_at"],
        created.1["created_at"]
    );
    assert_eq!(stored["versions"].as_array().unwrap().len(), 3);
    let repeated = exchange(address, request(path, &[auth], Body::from(body.clone()))).await;
    assert_eq!(repeated.0, StatusCode::OK);
    assert_eq!(repeated.1["change"], "unchanged");
    assert_eq!(repeated.1["updated_at"], created.1["updated_at"]);
    assert_eq!(sql_snapshot(&mut c).await, stored);
    let replacement =
        serde_json::json!({"projects":[{"project_id":A,"versions":["feature"]}]}).to_string();
    let updated = exchange(
        address,
        request(path, &[auth], Body::from(replacement.clone())),
    )
    .await;
    assert_eq!(updated.0, StatusCode::OK);
    assert_eq!(updated.1["change"], "updated");
    assert_eq!(updated.1["created_at"], created.1["created_at"]);
    assert_eq!(
        sql_snapshot(&mut c).await["versions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let populated = sql_snapshot(&mut c).await;
    assert_error(
        exchange(address, request(path, &[auth], Body::from(empty))).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_error(
        exchange(address, request(path, &[bot_auth], Body::from(empty))).await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_eq!(sql_snapshot(&mut c).await, populated);
    c.execute("DELETE FROM public.grant_projects WHERE grant_id='a'; UPDATE public.resource_grants SET access_kind='authenticated',principal=''").await.unwrap();
    let first_empty = exchange(
        address,
        request(
            "/v1/instances/empty-first/inventory",
            &[auth],
            Body::from(empty),
        ),
    )
    .await;
    assert_eq!(first_empty.0, StatusCode::CREATED);
    assert_eq!(first_empty.1["change"], "created");
    let cleared = exchange(address, request(path, &[auth], Body::from(empty))).await;
    assert_eq!(cleared.0, StatusCode::OK);
    assert_eq!(cleared.1["change"], "updated");
    let clear_again = exchange(address, request(path, &[auth], Body::from(empty))).await;
    assert_eq!(clear_again.0, StatusCode::OK);
    assert_eq!(clear_again.1["change"], "unchanged");
    assert_eq!(clear_again.1["updated_at"], cleared.1["updated_at"]);
    let empty_state = sql_snapshot(&mut c).await;
    assert_eq!(empty_state["instances"].as_array().unwrap().len(), 2);
    assert!(empty_state["versions"].as_array().unwrap().is_empty());
    assert_error(
        exchange(address, request(path, &[bot_auth], Body::from(empty))).await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    assert_error(
        exchange(
            address,
            request(path, &[bot_auth], Body::from(replacement.clone())),
        )
        .await,
        StatusCode::CONFLICT,
        "owner_conflict",
    );
    assert_eq!(sql_snapshot(&mut c).await, empty_state);
    for auths in [
        &[][..],
        &["Basic dTpw"][..],
        &["Bearer"][..],
        &[auth, bot_auth][..],
        &["Bearer gb_rt_refresh"][..],
        &["Bearer gb_at_absent"][..],
        &["Bearer eyJ.jwt"][..],
    ] {
        assert_error(
            exchange(address, request(path, auths, Body::from(empty))).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    for mutation in [
        "UPDATE public.local_tokens SET audience='wrong' WHERE token_id='access-http'",
        "UPDATE public.local_tokens SET scopes_json='[]' WHERE token_id='access-http'",
        "UPDATE public.local_tokens SET revoked_at=0 WHERE token_id='access-http'",
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
    ] {
        sqlx_core::query::query(mutation)
            .execute(&mut c)
            .await
            .unwrap();
        assert_error(
            exchange(address, request(path, &[auth], Body::from(empty))).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
        c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'; UPDATE public.local_tokens SET audience='explicit-audience',scopes_json='[\"presence:publish\"]',revoked_at=NULL WHERE token_id='access-http'").await.unwrap();
    }
    for invalid in [
        "{}",
        r#"{"projects":[],"owner":"forged"}"#,
        r#"{"projects":[],"updated_at":0}"#,
        r#"{"projects":[],"projects":[]}"#,
        r#"{"projects":[]} trailing"#,
        r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main"],"subject":"forged"}]}"#,
    ] {
        assert_error(
            exchange(address, request(path, &[auth], Body::from(invalid))).await,
            StatusCode::BAD_REQUEST,
            "invalid_json",
        );
    }
    for invalid in [
        r#"{"projects":[{"project_id":"friendly","versions":["main"]}]}"#,
        r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main","main"]}]}"#,
        r#"{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":[" main"]}]}"#,
    ] {
        assert_error(
            exchange(address, request(path, &[auth], Body::from(invalid))).await,
            StatusCode::BAD_REQUEST,
            "invalid_inventory",
        );
    }
    assert_error(
        exchange(
            address,
            request("/v1/instances/_bad/inventory", &[auth], Body::from(empty)),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid_inventory",
    );
    let oversized =
        serde_json::json!({"projects":[{"project_id":A,"versions":["v".repeat(5000)]}]})
            .to_string();
    assert_error(
        exchange(address, request(path, &[auth], Body::from(oversized))).await,
        StatusCode::BAD_REQUEST,
        "body_too_large",
    );
    let mut bad_content_type = request(path, &[auth], Body::from(empty));
    bad_content_type.headers_mut().remove(header::CONTENT_TYPE);
    assert_error(
        exchange(address, bad_content_type).await,
        StatusCode::BAD_REQUEST,
        "invalid_json",
    );
    assert_eq!(sql_snapshot(&mut c).await, empty_state);
    c.execute("UPDATE public.resource_grants SET access_kind='user',principal='['")
        .await
        .unwrap();
    assert_error(
        exchange(address, request(path, &[auth], Body::from(empty))).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "invalid_policy",
    );
    c.execute("UPDATE public.resource_grants SET access_kind='authenticated',principal=''; REVOKE SELECT ON public.grant_capabilities FROM opaque_owner").await.unwrap();
    assert_error(
        exchange(address, request(path, &[auth], Body::from(empty))).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.grant_capabilities TO opaque_owner; UPDATE public.local_tokens SET principal_json='{}' WHERE token_id='access-http'").await.unwrap();
    assert_error(
        exchange(address, request(path, &[auth], Body::from(empty))).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
    );
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET principal_json=$1 WHERE token_id='access-http'",
    )
    .bind(principal)
    .execute(&mut c)
    .await
    .unwrap();
    // Explicit identity/grant read caps must reach the real SQL-backed registrar.
    for (identity_bytes, grants_bytes, code) in [
        (8, 16384, "authentication_unavailable"),
        (4096, 8, "authorization_unavailable"),
    ] {
        let mut limited = config();
        limited.identity_json_bytes = n(identity_bytes);
        limited.grants_json_bytes = n(grants_bytes);
        let router = instance_registry_router(store.clone(), limited).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        assert_error(
            exchange(addr, request(path, &[auth], Body::from(empty))).await,
            StatusCode::SERVICE_UNAVAILABLE,
            code,
        );
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(sql_snapshot(&mut c).await, empty_state);
    }
    // SDK streaming body remains incomplete until the original request deadline.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, Infallible>>(1);
    tx.send(Ok(axum::body::Bytes::from_static(b"{\"projects\":")))
        .await
        .unwrap();
    let stream = futures_util::stream::unfold(rx, |mut receiver| async move {
        receiver.recv().await.map(|part| (part, receiver))
    });
    assert_error(
        exchange(address, request(path, &[auth], Body::from_stream(stream))).await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    drop(tx);
    assert_eq!(sql_snapshot(&mut c).await, empty_state);
    let mut locker = fixture.connection().await;
    let mut lock = locker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT instance_id FROM public.broker_instances WHERE instance_id='station' FOR UPDATE",
    )
    .fetch_one(&mut *lock)
    .await
    .unwrap();
    assert_error(
        exchange(
            address,
            request(path, &[auth], Body::from(replacement.clone())),
        )
        .await,
        StatusCode::GATEWAY_TIMEOUT,
        "deadline",
    );
    lock.rollback().await.unwrap();
    assert_eq!(sql_snapshot(&mut c).await, empty_state);
    let recovered = exchange(
        address,
        request(path, &[auth], Body::from(replacement.clone())),
    )
    .await;
    assert_eq!(recovered.0, StatusCode::OK);
    assert_eq!(recovered.1["change"], "updated");
    // Dropping an incomplete-body client's real TCP connection cannot publish its inventory.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, Infallible>>(1);
    tx.send(Ok(axum::body::Bytes::from_static(b"{\"projects\":")))
        .await
        .unwrap();
    let stream = futures_util::stream::unfold(rx, |mut receiver| async move {
        receiver.recv().await.map(|part| (part, receiver))
    });
    let tcp = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .unwrap();
    let worker = tokio::spawn(connection);
    let incomplete = tokio::spawn(async move {
        sender
            .send_request(request(
                "/v1/instances/cancelled/inventory",
                &[auth],
                Body::from_stream(stream),
            ))
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    worker.abort();
    let _ = worker.await;
    incomplete.abort();
    let _ = incomplete.await;
    drop(tx);
    let ok = exchange(address, request(path, &[auth], Body::from(replacement))).await;
    assert_eq!(ok.0, StatusCode::OK);
    assert_eq!(ok.1["change"], "unchanged");
    let cancelled: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.broker_instances WHERE instance_id='cancelled'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(cancelled, 0);
    assert_error(
        exchange(
            address,
            Request::builder().uri(path).body(Body::empty()).unwrap(),
        )
        .await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    );
    assert_error(
        exchange(address, request("/missing", &[auth], Body::empty())).await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    store.shutdown(deadline()).await.unwrap();
    assert_error(
        exchange(address, request(path, &[auth], Body::from(empty))).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    locker.close().await.unwrap();
    c.close().await.unwrap();
}
