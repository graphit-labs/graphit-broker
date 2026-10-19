//! Actual native binary, genuine credential verification and owned TLS PostgreSQL.
#[allow(
    dead_code,
    reason = "shared real HTTPS browser issuer also serves H1 protocol fault contracts"
)]
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
mod browser;
#[path = "support/admin_read_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "shared genuine cookie/MFA fixture also serves other suites"
)]
#[path = "../../broker-control/tests/support/admin_cookie.rs"]
mod cookie;
#[path = "../../broker-control/tests/support/admin_federated_read.rs"]
mod federated;
#[path = "support/admin_native.rs"]
mod native;
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture also serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
#[allow(
    dead_code,
    reason = "shared HTTPS issuer supports additional rotation and fault contracts"
)]
#[path = "support/upstream.rs"]
mod upstream;
use broker_control::SystemAction;
use cookie::CookieFixture;
use native::*;
use reqwest::{Client, Method};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::time::{Duration, Instant};
use support::{deadline, n};
use zeroize::Zeroizing;
async fn head(h: &Native, route: &str, raw: &str) {
    let r = h.request(route, Method::HEAD, Some(raw), None).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(!r.headers().contains_key("set-cookie"));
    assert!(r.bytes().await.unwrap().is_empty());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native binary, genuine LOCAL P3/opaque/cookie and upstream HTTPS bearer with TLS PostgreSQL"]
async fn broker_admin_projects_http_contract() {
    let mut h = Native::new().await;
    let cookie = h.f.cookie().await;
    let jwt = access(&h.f, &h.client, h.addr).await;
    let opaque = opaque(&mut h.f).await;
    let fed_claims = h.op.claims();
    let fed = h.op.sign(&fed_claims, "upstream-key", "at+jwt");
    h.action(SystemAction::ProjectsRead).await;
    // No SessionRead: each factor must independently authorize ProjectsRead.
    h.f.admin.execute("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('native','native','subject','local|alice-subject','',0,0),('fed','fed','authenticated','','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('native','h*'),('fed','hub'); INSERT INTO public.grant_projects(grant_id,value) VALUES('native','01M1YEAE1WYMWG9KJKV1XQC4T4'),('fed','01KSH1CRFFG8Z74B5ZS78WW808')").await.unwrap();
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('fed-subject','fed-subject','subject',$1,'',0,0)")
        .bind(format!("{}|{}",h.op.issuer,fed_claims["sub"].as_str().unwrap())).execute(&mut h.f.admin).await.unwrap();
    h.f.admin.execute("INSERT INTO public.grant_capabilities(grant_id,value) VALUES('fed-subject','hub'); INSERT INTO public.grant_projects(grant_id,value) VALUES('fed-subject','01M1YEAE1WYMWG9KJKV1XQC4T6')").await.unwrap();
    let local = h.get("projects", cookie.secret()).await;
    assert_eq!(
        local["projects"],
        json!([{"id":"01KSH1CRFFG8Z74B5ZS78WW808","capabilities":["hub"]},{"id":"01M1YEAE1WYMWG9KJKV1XQC4T4","capabilities":["h*"]}])
    );
    assert_eq!(local["all_projects"], false);
    assert!(local["authorization_revision"].as_i64().unwrap() > 0);
    let expected = format!(
        "graphit --non-interactive provider add 'organization-broker' --type broker --broker-endpoint 'http://{}'\n\ngraphit login --provider 'organization-broker' --profile 'organization-broker'",
        h.addr
    );
    assert_eq!(local["provider_command"], expected);
    for (raw, is_local) in [(&*jwt, true), (&*opaque, true), (&*fed, false)] {
        let value = document(h.request("projects", Method::GET, None, Some(raw)).await).await;
        assert!(
            value["projects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "01KSH1CRFFG8Z74B5ZS78WW808")
        );
        assert_eq!(
            value["projects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "01M1YEAE1WYMWG9KJKV1XQC4T4"),
            is_local,
            "raw LOCAL/canonical issuer binding, not OIDC pseudonym"
        );
        assert_eq!(
            value["projects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "01M1YEAE1WYMWG9KJKV1XQC4T6"),
            !is_local,
            "verified federated issuer/mappedsubject remains separate"
        );
        denied(
            h.request("projects", Method::GET, Some("invalid"), Some(raw))
                .await,
            401,
            "admin_unauthorized",
        )
        .await;
    }
    let broker_issuer = format!("http://{}", h.addr);
    let key = Zeroizing::new(std::fs::read(h.root.path().join("signing.pk8")).unwrap());
    let signer =
        broker_control::BrokerAccessIssuer::new(&broker_issuer, AUDIENCE, "configured-key", &key)
            .unwrap();
    let configured = broker_control::BrokerAccessVerifier::new(
        &broker_issuer,
        AUDIENCE,
        None,
        signer.jwks(),
        n(8192),
    )
    .unwrap();
    let other = broker_control::BrokerAccessVerifier::new(
        &broker_issuer,
        AUDIENCE,
        None,
        signer.jwks(),
        n(8192),
    )
    .unwrap();
    let proof = configured.verify(&jwt, &[], deadline()).unwrap();
    let reader =
        h.f.store
            .admin_reads(broker_control::AdminReadLimits {
                authorization: cookie::limits().authorization,
                grants_json_bytes: n(65536),
                response_json_bytes: n(65536),
            })
            .unwrap();
    assert!(matches!(
        reader
            .read(
                broker_control::AdminReadAuthentication::Broker {
                    verifier: &other,
                    proof
                },
                broker_control::AdminReadRequest::Projects {
                    provider_command: "literal"
                },
                deadline()
            )
            .await,
        Err(broker_control::AdminReadError::Authorization(
            broker_control::AdminBrokerSessionError::Authentication(
                broker_control::BrokerAccessError::InvalidToken
            )
        ))
    ));
    // Current SQL attributes replace stale LOCAL JWT profile fields.
    h.f.admin.execute("UPDATE public.local_users SET organization='current' WHERE username='alice'; INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES('current','current','organization','current','',0,0); INSERT INTO public.grant_capabilities(grant_id,value) VALUES('current','hub'); INSERT INTO public.grant_projects(grant_id,value) VALUES('current','01M1YEAE1WYMWG9KJKV1XQC4T5')").await.unwrap();
    let value = document(h.request("projects", Method::GET, None, Some(&jwt)).await).await;
    assert!(
        value["projects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == "01M1YEAE1WYMWG9KJKV1XQC4T5")
    );
    // Each configured factor independently proves each operation's SQL action.
    for (action, routes) in [
        (SystemAction::RolesRead, &["roles", "role-assignments"][..]),
        (SystemAction::UsersRead, &["local-users"][..]),
        (SystemAction::GrantsRead, &["principals", "grants"][..]),
        (SystemAction::ConfigurationRead, &["config"][..]),
    ] {
        h.action(action).await;
        for route in routes {
            h.get(route, cookie.secret()).await;
            for raw in [&*jwt, &*opaque, &*fed] {
                document(h.request(route, Method::GET, None, Some(raw)).await).await;
            }
        }
    }
    h.action(SystemAction::ProjectsRead).await;
    head(&h, "projects", cookie.secret()).await;
    denied(
        h.request("projects", Method::GET, None, None).await,
        401,
        "admin_unauthorized",
    )
    .await;
    denied(
        h.request("session", Method::GET, Some(cookie.secret()), None)
            .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.action(SystemAction::SessionRead).await;
    denied(
        h.request("projects", Method::GET, Some(cookie.secret()), None)
            .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.close().await;
}
#[tokio::test]
#[ignore = "actual native binary, genuine LOCAL cookie and TLS PostgreSQL"]
async fn broker_admin_rbac_read_http_contract() {
    let mut h = Native::new().await;
    let cookie = h.f.cookie().await;
    h.action(SystemAction::RolesRead).await;
    assert_eq!(
        h.get("role-assignments", cookie.secret()).await,
        json!({"assignments":[],"bootstrap_only":true})
    );
    h.f.admin.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('external-literal','user',0)").await.unwrap();
    let a = h.get("role-assignments", cookie.secret()).await;
    assert_eq!(a["bootstrap_only"], false);
    assert_eq!(a["assignments"][0]["subject"], "external-literal");
    let roles = h.get("roles", cookie.secret()).await;
    assert_eq!(roles["actions"].as_array().unwrap().len(), 9);
    assert!(!roles["actions"].as_array().unwrap().contains(&json!("*")));
    head(&h, "roles", cookie.secret()).await;
    head(&h, "role-assignments", cookie.secret()).await;
    h.action(SystemAction::RolesWrite).await;
    for route in ["roles", "role-assignments"] {
        denied(
            h.request(route, Method::GET, Some(cookie.secret()), None)
                .await,
            403,
            "admin_forbidden",
        )
        .await;
    }
    h.close().await;
}
#[tokio::test]
#[ignore = "actual native binary, genuine LOCAL cookie and TLS PostgreSQL"]
async fn broker_admin_user_read_http_contract() {
    let mut h = Native::new().await;
    let cookie = h.f.cookie().await;
    h.action(SystemAction::UsersRead).await;
    let users = h.get("local-users", cookie.secret()).await;
    assert_eq!(users["users"][0]["subject"], "alice-subject");
    assert_eq!(users["users"][0]["roles"], json!(["user"]));
    for key in [
        "password_hash",
        "secret_ciphertext",
        "code_hash",
        "$argon2id$",
    ] {
        assert!(!users.to_string().contains(key));
    }
    head(&h, "local-users", cookie.secret()).await;
    denied(
        h.request("principals", Method::GET, Some(cookie.secret()), None)
            .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.action(SystemAction::GrantsRead).await;
    let principals = h.get("principals", cookie.secret()).await;
    assert_eq!(
        principals["principals"][0],
        json!({"type":"anonymous","id":"anonymous"})
    );
    assert_eq!(
        principals["principals"][1],
        json!({"type":"authenticated","id":"authenticated"})
    );
    assert_eq!(principals["principals"][2]["id"], "alice-subject");
    head(&h, "principals", cookie.secret()).await;
    denied(
        h.request("local-users", Method::GET, Some(cookie.secret()), None)
            .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.close().await;
}
#[tokio::test]
#[ignore = "actual native binary, genuine LOCAL cookie and TLS PostgreSQL"]
async fn broker_admin_grant_read_http_contract() {
    let mut h = Native::new().await;
    let cookie = h.f.cookie().await;
    h.action(SystemAction::GrantsRead).await;
    let response = h
        .request("grants", Method::GET, Some(cookie.secret()), None)
        .await;
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    let value = document(response).await;
    assert_eq!(etag, format!("\"{}\"", value["revision"].as_i64().unwrap()));
    assert_eq!(value["rules"], json!([]));
    h.f.admin
        .execute("UPDATE public.resource_acl_state SET revision=9223372036854775807 WHERE id=1")
        .await
        .unwrap();
    let response = h
        .request("grants", Method::GET, Some(cookie.secret()), None)
        .await;
    assert_eq!(response.headers()["etag"], "\"9223372036854775807\"");
    assert_eq!(
        document(response).await["revision"].as_i64(),
        Some(i64::MAX)
    );
    head(&h, "grants", cookie.secret()).await;
    h.action(SystemAction::GrantsWrite).await;
    denied(
        h.request("grants", Method::GET, Some(cookie.secret()), None)
            .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.close().await;
}
#[tokio::test]
#[ignore = "actual native binary, genuine LOCAL cookie and TLS PostgreSQL"]
async fn broker_admin_config_http_contract() {
    let mut h = Native::new().await;
    let cookie = h.f.cookie().await;
    h.action(SystemAction::ConfigurationRead).await;
    let value = h.get("config", cookie.secret()).await;
    assert_eq!(value["source"], "deployment");
    assert_eq!(value["restart_required"], true);
    let yaml = value["yaml"].as_str().unwrap();
    let safe: Value = serde_saphyr::from_str(yaml).unwrap();
    assert_eq!(safe["database"]["password"], "[configured-secret]");
    assert_eq!(safe["auth"]["pepper"], "[configured-secret]");
    assert_eq!(safe["server"]["public_url"], format!("http://{}", h.addr));
    assert_eq!(
        safe["auth"]["oidc"][0]["allowed_algorithms"],
        json!(["EdDSA"])
    );
    assert_eq!(
        safe["administration"]["cli"]["provider_name"],
        "organization-broker"
    );
    for secret in [cookie::PEPPER, "ephemeral-owner", "PRIVATE KEY"] {
        assert!(!yaml.contains(secret));
    }
    assert!(!yaml.contains("browser_clients"));
    head(&h, "config", cookie.secret()).await;
    h.action(SystemAction::UsersRead).await;
    denied(
        h.request("config", Method::GET, Some(cookie.secret()), None)
            .await,
        403,
        "admin_forbidden",
    )
    .await;
    // Keep the actual deployment alive until its paths/configuration are checked.
    assert!(h.root.path().join("config.yaml").exists());
    assert!(h.config.contains("administration:"));
    h.close().await;
}

#[tokio::test]
#[ignore = "actual binary SafeProjection with configured CAPTCHA/S3 secrets, LOCAL owner and TLS PostgreSQL"]
async fn broker_admin_config_configuration_contract() {
    const CAPTCHA: &str = "fixture-captcha-secret-canary";
    const ACCESS: &str = "fixture-access-key-canary";
    const SECRET: &str = "fixture-storage-secret-canary";
    let mut h=Native::with_config(|config, _| {
        let local=block(include_str!("../../../docs/rust-admin-local-login.md"))
            .strip_prefix("auth:\n").unwrap()
            .replace("      enabled: false",&format!("      enabled: true\n      provider: turnstile\n      site_key: public-site-key\n      secret_key: {CAPTCHA}"));
        config.replace("storage:\n",&format!("{local}storage:\n  default_route: native-fs\n"))
            .replace("      directory: volumes/native-storage",&format!("      directory: volumes/native-storage\n    remote:\n      driver: s3\n      bucket: native-remote\n      base_prefix: graphit\n      role_arn: arn:aws:iam::123456789012:role/native-test\n      access_key_id: {ACCESS}\n      secret_access_key: {SECRET}\n    remote-conditional:\n      driver: s3\n      bucket: native-conditional\n      base_prefix: graphit\n      role_arn: arn:aws:iam::123456789012:role/native-test\n      conditional_delete: true"))
    }).await;
    let cookie = h.f.cookie().await;
    h.action(SystemAction::ConfigurationRead).await;
    let body = h.get("config", cookie.secret()).await;
    let yaml = body["yaml"].as_str().unwrap();
    for secret in [CAPTCHA, ACCESS, SECRET, cookie::PEPPER, "ephemeral-owner"] {
        assert!(!yaml.contains(secret));
    }
    let view: Value = serde_saphyr::from_str(yaml).unwrap();
    assert_eq!(
        view["auth"]["local"]["captcha"]["secret_key"],
        "[configured-secret]"
    );
    assert_eq!(
        view["auth"]["local"]["captcha"]["site_key"],
        "public-site-key"
    );
    assert_eq!(
        view["storage"]["routes"]["remote"]["access_key_id"],
        "[configured-secret]"
    );
    assert_eq!(
        view["storage"]["routes"]["remote"]["secret_access_key"],
        "[configured-secret]"
    );
    assert_eq!(view["storage"]["routes"]["remote"]["region"], "us-east-1");
    assert_eq!(
        view["storage"]["routes"]["remote"]["conditional_delete"],
        false
    );
    assert_eq!(
        view["storage"]["routes"]["remote-conditional"]["conditional_delete"],
        true
    );
    assert_eq!(
        view["storage"]["routes"]["remote"]["session_name"],
        "graphit-broker"
    );
    assert_eq!(
        view["storage"]["routes"]["remote"]["allow_loopback_http"],
        false
    );
    assert_eq!(
        view["storage"]["routes"]["native-fs"]["max_object_bytes"],
        5368709120u64
    );
    assert_eq!(view["server"]["read_timeout"], "15s");
    assert_eq!(view["server"]["body_bytes"], 4194304);
    assert_eq!(
        view["auth"]["local"]["mfa"]["issuer_label"],
        "Graphit Broker"
    );
    assert_eq!(
        h.op.hits(),
        0,
        "configuration read never fetches provider metadata"
    );
    h.close().await;
}

#[tokio::test]
#[ignore = "actual --check-config before sockets, volumes, SQL and issuer requests"]
async fn broker_admin_projects_configuration_contract() {
    let mut f = CookieFixture::new().await;
    let mut op = upstream::UpstreamFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca);
    private_file(&root.path().join("issuer-ca.pem"), &op.ca);
    let config = yaml(addr, f.fixture.port, &op);
    let path = write(root.path(), &config);
    assert!(
        command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap()
            .status
            .success()
    );
    let initial: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.admin_sessions")
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
    for bad in [
        config.replace("  grants_json_bytes: 65536\n", ""),
        config.replace("  response_json_bytes: 65536\n", ""),
        config.replace("  response_json_bytes: 65536", "  response_json_bytes: 0"),
        config.replace("  response_json_bytes: 65536", "  response_json_bytes: 1"),
        config.replace(
            "  response_json_bytes: 65536",
            &format!("  response_json_bytes: {}", usize::MAX),
        ),
        config.replace(
            "  response_json_bytes: 65536",
            "  response_json_bytes: 65536\n  response_json_bytes: 65536",
        ),
        config.replace(
            "administration:\n",
            "administration:\n  unknown_read_setting: true\n",
        ),
    ] {
        write(root.path(), &bad);
        let out = command()
            .args(["--config", path.to_str().unwrap(), "--check-config"])
            .output()
            .await
            .unwrap();
        assert!(!out.status.success());
        for secret in [cookie::PEPPER, "ephemeral-owner"] {
            assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
        }
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
        assert!(!root.path().join("volumes").exists());
        assert_eq!(op.hits(), 0);
    }
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.admin_sessions"
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap(),
        initial
    );
    // Literal command DATA, including apostrophes and shell metacharacters.
    let custom=config.replace("administration:\n", "administration:\n  cli:\n    provider_name: \"provider'quoted;$(literal)\"\n    profile_name: \"profile'quote\"\n");
    write(root.path(), &custom);
    let child = start(&path, addr).await;
    let cookie = f.cookie().await;
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','projects.read')").await.unwrap();
    let response = Client::new()
        .get(format!("http://{addr}/admin/api/v1/projects"))
        .header(
            "cookie",
            format!("graphit_admin_session={}", cookie.secret()),
        )
        .header("x-request-id", "admin-read-proof")
        .send()
        .await
        .unwrap();
    let body = document(response).await;
    assert_eq!(
        body["provider_command"],
        format!(
            "graphit --non-interactive provider add 'provider'\\''quoted;$(literal)' --type broker --broker-endpoint 'http://{addr}'\n\ngraphit login --provider 'provider'\\''quoted;$(literal)' --profile 'profile'\\''quote'"
        )
    );
    stop(child).await;
    let disabled = config.replace(
        "administration:\n  enabled: true",
        "administration:\n  enabled: false",
    );
    write(root.path(), &disabled);
    let child = start(&path, addr).await;
    for route in [
        "projects",
        "roles",
        "role-assignments",
        "local-users",
        "principals",
        "grants",
        "config",
    ] {
        assert_eq!(
            reqwest::get(format!("http://{addr}/admin/api/v1/{route}"))
                .await
                .unwrap()
                .status(),
            404
        );
    }
    stop(child).await;
    op.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "genuine HTTPS H1 PKCE/code exchange to H2 cookie, actual binary seven administrative reads"]
async fn broker_admin_federated_read_http_contract() {
    let mut issuer = browser::BrowserIssuer::new().await;
    let mut h = Native::with_config(|config, root| {
        private_file(&root.join("browser-ca.pem"), &issuer.ca);
        config.replace(
            "  oidc:\n",
            &format!("  oidc:\n{}", federated::native_yaml(&issuer)),
        )
    })
    .await;
    let verifier = broker_control::UpstreamBearerVerifier::new(
        &format!("http://{}", h.addr),
        n(16384),
        vec![federated::provider(&issuer)],
    )
    .unwrap();
    let cookie = federated::issue(&h.f.store, &verifier, &issuer).await;
    // Existing SessionRead still uses its own action through the same current
    // cookie observer; this is consumer coverage, not an H1/H2 producer replay.
    let session = document(
        h.request("session", Method::GET, Some(cookie.secret()), None)
            .await,
    )
    .await;
    assert_eq!(session["role_source"], "database");
    assert!(!session["csrf_token"].as_str().unwrap().is_empty());
    let before = (
        issuer.token_hits(),
        issuer.userinfo_hits(),
        issuer.jwks_hits(),
    );
    assert_eq!(before.0, 1, "actual H1 code exchange issued this cookie");
    for (action, routes) in [
        (SystemAction::ProjectsRead, &["projects"][..]),
        (SystemAction::RolesRead, &["roles", "role-assignments"][..]),
        (SystemAction::UsersRead, &["local-users"][..]),
        (SystemAction::GrantsRead, &["principals", "grants"][..]),
        (SystemAction::ConfigurationRead, &["config"][..]),
    ] {
        h.action(action).await;
        for route in routes {
            document(
                h.request(
                    route,
                    Method::GET,
                    Some(cookie.secret()),
                    Some("invalid-unused-bearer"),
                )
                .await,
            )
            .await;
            head(&h, route, cookie.secret()).await;
        }
        denied(
            h.request("session", Method::GET, Some(cookie.secret()), None)
                .await,
            403,
            "admin_forbidden",
        )
        .await;
    }
    assert_eq!(
        (
            issuer.token_hits(),
            issuer.userinfo_hits(),
            issuer.jwks_hits()
        ),
        before,
        "H2 cookie reads perform no token/JWK/UserInfo request"
    );
    assert_eq!(
        h.op.hits(),
        0,
        "the original F1 issuer remains configured and untouched by cookie reads"
    );
    h.close().await;
    issuer.close().await;
}

async fn http_locked_pid(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock'")
            .fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual bearer read must reach SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn http_closed_pid(admin: &mut sqlx_postgres::PgConnection, pid: i32) {
    let end = deadline();
    loop {
        let exists: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        if !exists {
            return;
        }
        assert!(
            Instant::now() < end,
            "uncertain bearer read must close its exact SQL connection"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native JWT/opaque/F1 read transactions, COMMIT ACK withheld after exact PID is idle"]
async fn broker_admin_bearer_read_uncertainty_contract() {
    let mut f = CookieFixture::new().await;
    let mut op = upstream::UpstreamFixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let addr = address();
    files(root.path(), &f.fixture.ca);
    private_file(&root.path().join("issuer-ca.pem"), &op.ca);
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let config = yaml(addr, relay.port, &op);
    // This fault scenario owns exactly one TLS SQL channel; other consumers use two.
    assert_eq!(config.matches("max_connections: 2").count(), 1);
    let config = config.replace("max_connections: 2", "max_connections: 1");
    let path = write(root.path(), &config);
    let child = start(&path, addr).await;
    let client = Client::new();
    let jwt = access(&f, &client, addr).await;
    let opaque = opaque(&mut f).await;
    let fed = op.sign(&op.claims(), "upstream-key", "at+jwt");
    let url = format!("http://{addr}/admin/api/v1/projects");
    for raw in [&*jwt, &*opaque, &*fed] {
        // Warm actual verification and the F1 metadata/JWK cache before the lock.
        let warm = client.get(&url).bearer_auth(raw).send().await.unwrap();
        assert_eq!(warm.status(), 200);
        warm.bytes().await.unwrap();
        let mut locker = f.fixture.connection().await;
        locker
            .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let before: i64 =
            sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_tokens")
                .fetch_one(&mut f.admin)
                .await
                .unwrap();
        let pid;
        {
            let pending = client.get(&url).bearer_auth(raw).send();
            tokio::pin!(pending);
            pid = tokio::select! {pid=http_locked_pid(&mut f.admin)=>pid,result=&mut pending=>panic!("protected bearer read must reach real lock: {:?}",result.unwrap().status())};
            relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            locker.execute("ROLLBACK").await.unwrap();
            loop {
                let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("HTTP success cannot precede real COMMIT ACK: {:?}",result.unwrap().status())};
                let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                    "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
                )
                .bind(pid)
                .fetch_one(&mut f.admin)
                .await
                .unwrap();
                if query == "COMMIT" && idle {
                    decision.send(false).unwrap();
                    break;
                }
                decision.send(true).unwrap();
            }
            denied(pending.await.unwrap(), 503, "administration_unavailable").await;
        }
        relay
            .armed
            .store(false, std::sync::atomic::Ordering::SeqCst);
        while let Ok(decision) = relay.replies.try_recv() {
            let _ = decision.send(true);
        }
        http_closed_pid(&mut f.admin, pid).await;
        assert_eq!(
            sqlx_core::query_scalar::query_scalar::<_, i64>(
                "SELECT count(*) FROM public.local_tokens"
            )
            .fetch_one(&mut f.admin)
            .await
            .unwrap(),
            before,
            "uncertain read never replays a credential exchange"
        );
        sqlx_core::connection::Connection::close(locker)
            .await
            .unwrap();
        let recovery = client.get(&url).bearer_auth(raw).send().await.unwrap();
        assert_eq!(recovery.status(), 200);
        recovery.bytes().await.unwrap();
    }
    drop(client);
    stop(child).await;
    relay.close().await;
    op.close().await;
    f.close().await;
}
