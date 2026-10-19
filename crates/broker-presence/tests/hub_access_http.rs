#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other control suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint,
};
use broker_presence::{
    HubAccessHttpConfig, LocalHubAccessHttpConfig, broker_hub_access_router,
    local_hub_access_router,
};
use broker_security::TokenKind;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
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
const PATH: &str = "/v1/hub/access/resolve";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const RAW: &str = "gb_at_ephemeral-http-hub";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self{key:EncodingKey::from_ed_der(&pair.serialize_der()),keys:serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"hub-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap()}
    }
    fn verifier(&self) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "hub-api", Some(RESOURCE), &self.keys, n(8192)).unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":"http-subject","aud":["hub-api",RESOURCE],"iat":now-1,"exp":now+600,"token_use":"access","client_id":"explicit-client","jti":"hub-http-token","scope":"","preferred_username":"alice","organization":"engineering","groups":["dev"]})
    }
    fn sign(&self, v: &Value) -> String {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some("hub-key".into());
        encode(&h, v, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn config() -> HubAccessHttpConfig {
    HubAccessHttpConfig {
        grants_json_bytes: n(65536),
        request_timeout: Duration::from_secs(4),
    }
}
fn local_config() -> LocalHubAccessHttpConfig {
    LocalHubAccessHttpConfig {
        audience: "explicit-audience".into(),
        identity_json_bytes: n(8192),
        grants_json_bytes: n(65536),
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
            "hub_http_owner".into(),
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
async fn clear(c: &mut PgConnection) {
    c.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
}
async fn grant(
    c: &mut PgConnection,
    id: &str,
    kind: &str,
    principal: &str,
    cap: &str,
    projects: &[&str],
) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,'',0,0)").bind(id).bind(kind).bind(principal).execute(&mut *c).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)")
        .bind(id)
        .bind(cap)
        .execute(&mut *c)
        .await
        .unwrap();
    for p in projects {
        sqlx_core::query::query("INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)")
            .bind(id)
            .bind(*p)
            .execute(&mut *c)
            .await
            .unwrap();
    }
}
async fn seed(c: &mut PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','local-subject','human','','current-name','','current-org','[]',1,0,1,0,0)").await.unwrap();
    let digest = support::digester()
        .token(TokenKind::LocalAccess, RAW.as_bytes())
        .unwrap();
    let principal=json!({"issuer":"local","subject":"local-subject","username":"stale-user","auth_method":"local-token","local_user_revision":1}).to_string();
    sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,'http-hub-token','access','local-subject','pseudonym-other',$2,'explicit-client','explicit-audience','','[]',1,'',0,$3,0)").bind(digest.to_sql_hex()).bind(principal).bind(i64::try_from(seconds()).unwrap()*1_000_000+600_000_000).execute(&mut *c).await.unwrap();
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
// A canceled exchange must not detach its client-side connection driver.
struct Driver(Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>);
impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
#[derive(Debug)]
struct Reply {
    status: StatusCode,
    json: Value,
    challenge: bool,
    no_store: bool,
}
async fn exchange(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    auth: &[&str],
    body: Option<&str>,
) -> Reply {
    let stream = TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    let mut worker = Driver(Some(tokio::spawn(connection)));
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("x-subject", "untrusted|admin");
    for a in auth {
        request = request.header(header::AUTHORIZATION, *a);
    }
    let reply = tokio::time::timeout(
        Duration::from_secs(8),
        sender.send_request(
            request
                .body(
                    body.map(|b| Body::from(b.to_owned()))
                        .unwrap_or_else(Body::empty),
                )
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let status = reply.status();
    let challenge = reply
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .is_some_and(|v| v == "Bearer");
    let no_store = reply
        .headers()
        .get(header::CACHE_CONTROL)
        .is_some_and(|v| v == "no-store");
    assert_eq!(
        reply.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    let bytes = reply.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap();
    drop(sender);
    tokio::time::timeout(Duration::from_secs(3), worker.0.take().unwrap())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    Reply {
        status,
        json,
        challenge,
        no_store,
    }
}
async fn post(address: std::net::SocketAddr, auth: &[&str]) -> Reply {
    exchange(address, "POST", PATH, auth, None).await
}
fn error(r: Reply, status: StatusCode, code: &str) {
    assert_eq!(r.status, status);
    assert_eq!(r.json, json!({"error":{"code":code}}));
    assert_eq!(r.challenge, status == StatusCode::UNAUTHORIZED);
}
fn success(r: Reply, subject: &str, selectors: Value) -> Value {
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.no_store);
    assert!(!r.challenge);
    assert_eq!(r.json.as_object().unwrap().len(), 4);
    assert_eq!(r.json["v"], 1);
    assert!(r.json["authorization_revision"].is_string());
    assert_eq!(r.json["subject"], subject);
    assert_eq!(r.json["selectors"], selectors);
    r.json
}
async fn observe_lock(c: &mut PgConnection) {
    let end = deadline();
    loop {
        c.execute("SELECT pg_stat_clear_snapshot()").await.unwrap();
        let waiting:bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='hub_http_owner' AND wait_event_type='Lock' AND query LIKE '%resource_acl_state%')").fetch_one(&mut *c).await.unwrap();
        if waiting {
            return;
        }
        assert!(Instant::now() < end, "HTTP reaches real ACL SQL lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
#[ignore = "real TCP Hyper/axum, PostgreSQL TLS and signed/opaque identity"]
async fn hub_access_http_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION hub_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO hub_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='hub_http_owner'",
    )
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert!(!superuser);
    let signer = Signer::new();
    let verifier = Arc::new(signer.verifier());
    let token = signer.sign(&signer.claims());
    let jwt = format!("Bearer {token}");
    let opaque = format!("Bearer {RAW}");
    seed(&mut c).await;
    let mut bad = config();
    bad.request_timeout = Duration::ZERO;
    assert!(broker_hub_access_router(store.clone(), verifier.clone(), bad).is_err());
    let mut bad = local_config();
    bad.request_timeout = Duration::MAX;
    assert!(local_hub_access_router(store.clone(), bad).is_err());
    let mut bad = config();
    bad.grants_json_bytes = n(usize::MAX);
    assert!(broker_hub_access_router(store.clone(), verifier.clone(), bad).is_err());
    assert_eq!(format!("{:?}", config()), "HubAccessHttpConfig([REDACTED])");
    assert_eq!(
        format!("{:?}", local_config()),
        "LocalHubAccessHttpConfig([REDACTED])"
    );
    let native =
        Server::start(broker_hub_access_router(store.clone(), verifier, config()).unwrap()).await;
    let local =
        Server::start(local_hub_access_router(store.clone(), local_config()).unwrap()).await;

    // H1/H2: explicit anonymous/real JWT/real opaque; body and unknown header have no authority.
    grant(&mut c, "a-public", "anonymous", "", "hub", &[A]).await;
    grant(&mut c, "b-global", "global", "", "h*", &[B, "*"]).await;
    grant(&mut c, "c-user", "user", "alice", "hub", &[A]).await;
    let anon = json!([{"id":A},{"all":true},{"id":B}]);
    // B and * are ordered by SQL C: * precedes B.
    for address in [native.address, local.address] {
        for auth in [vec![], vec![""], vec![" \t "]] {
            success(
                post(address, &auth).await,
                "anonymous|anonymous",
                anon.clone(),
            );
        }
        success(
            exchange(
                address,
                "POST",
                PATH,
                &[],
                Some("not { valid json and no content-type"),
            )
            .await,
            "anonymous|anonymous",
            anon.clone(),
        );
        for auth in [
            vec!["Basic abc"],
            vec!["Bearer"],
            vec!["Bearer "],
            vec!["", ""],
            vec!["", "Bearer invalid"],
            vec!["Bearer invalid", "Bearer invalid"],
        ] {
            error(
                post(address, &auth).await,
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
            );
        }
        error(
            exchange(address, "GET", PATH, &[], None).await,
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        );
        error(
            exchange(address, "POST", "/v1/hub/access/unknown", &[], None).await,
            StatusCode::NOT_FOUND,
            "not_found",
        );
    }
    let expected = json!([{"all":true},{"id":B},{"id":A}]);
    success(
        post(native.address, &[&jwt]).await,
        &format!("{ISSUER}|http-subject"),
        expected.clone(),
    );
    success(
        post(local.address, &[&opaque]).await,
        "local|local-subject",
        expected,
    );
    error(
        post(native.address, &[&opaque]).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        post(local.address, &[&jwt]).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    error(
        post(native.address, &[&jwt, &jwt]).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    for (field, value) in [
        ("aud", json!(["hub-api", "wrong-resource"])),
        ("token_use", json!("id")),
        ("iss", json!("https://other.test")),
        ("client_id", json!("")),
    ] {
        let mut bad = signer.claims();
        bad[field] = value;
        error(
            post(native.address, &[&format!("Bearer {}", signer.sign(&bad))]).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        );
    }
    c.execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
        .await
        .unwrap();
    error(
        post(local.address, &[&opaque]).await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    c.execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();

    // H3: fresh committed policy, empty-success, and finite SQL errors.
    let before = success(
        post(native.address, &[&jwt]).await,
        &format!("{ISSUER}|http-subject"),
        json!([{"all":true},{"id":B},{"id":A}]),
    );
    clear(&mut c).await;
    let after = success(
        post(native.address, &[&jwt]).await,
        &format!("{ISSUER}|http-subject"),
        json!([]),
    );
    assert_ne!(
        before["authorization_revision"],
        after["authorization_revision"]
    );
    success(
        post(local.address, &[&opaque]).await,
        "local|local-subject",
        json!([]),
    );
    grant(&mut c, "bad", "user", "not-this-user", "[", &[]).await;
    for address in [native.address, local.address] {
        error(
            post(address, &[]).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
        );
    }
    clear(&mut c).await;
    grant(&mut c, "all", "global", "", "hub", &[]).await;
    c.execute("REVOKE SELECT ON public.resource_grants FROM hub_http_owner")
        .await
        .unwrap();
    error(
        post(native.address, &[&jwt]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.resource_grants TO hub_http_owner")
        .await
        .unwrap();
    success(
        post(native.address, &[&jwt]).await,
        &format!("{ISSUER}|http-subject"),
        json!([{"all":true}]),
    );
    c.execute("REVOKE SELECT ON public.local_tokens FROM hub_http_owner")
        .await
        .unwrap();
    error(
        post(local.address, &[&opaque]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authorization_unavailable",
    );
    c.execute("GRANT SELECT ON public.local_tokens TO hub_http_owner")
        .await
        .unwrap();
    success(
        post(local.address, &[&opaque]).await,
        "local|local-subject",
        json!([{"all":true}]),
    );
    // Malformed current local identity is unavailable, never anonymous.
    c.execute("UPDATE public.local_users SET teams_json='invalid-json' WHERE username='alice'")
        .await
        .unwrap();
    error(
        post(local.address, &[&opaque]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "authentication_unavailable",
    );
    c.execute("UPDATE public.local_users SET teams_json='[]' WHERE username='alice'")
        .await
        .unwrap();
    let mut observer = f.connection().await;
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let address = native.address;
        tokio::spawn(async move { post(address, &[]).await })
    };
    observe_lock(&mut observer).await;
    error(task.await.unwrap(), StatusCode::GATEWAY_TIMEOUT, "deadline");
    lock.rollback().await.unwrap();
    success(
        post(native.address, &[]).await,
        "anonymous|anonymous",
        json!([{"all":true}]),
    );
    let mut short = signer.claims();
    short["exp"] = json!(seconds() + 3);
    let short = format!("Bearer {}", signer.sign(&short));
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let address = native.address;
        tokio::spawn(async move { post(address, &[&short]).await })
    };
    observe_lock(&mut observer).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    lock.rollback().await.unwrap();
    error(
        task.await.unwrap(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    );
    let mut lock = c.begin().await.unwrap();
    lock.execute("LOCK TABLE public.resource_acl_state IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let task = {
        let address = native.address;
        tokio::spawn(async move { post(address, &[]).await })
    };
    observe_lock(&mut observer).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    lock.rollback().await.unwrap();
    for _ in 0..3 {
        success(
            post(local.address, &[&opaque]).await,
            "local|local-subject",
            json!([{"all":true}]),
        );
    }
    observer.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    error(
        post(native.address, &[]).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "closed",
    );
    local.stop().await;
    native.stop().await;
    c.close().await.unwrap();
    f.shutdown().unwrap();
}

#[path = "hub_access_http/catalog.rs"]
mod catalog;
