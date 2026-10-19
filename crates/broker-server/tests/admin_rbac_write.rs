//! Actual Broker binary, PostgreSQL TLS and genuine native/federated factors.
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
#[allow(
    dead_code,
    reason = "shared HTTPS issuer also exercises H1 protocol faults"
)]
mod browser;
#[path = "../../broker-control/tests/support/admin_cookie.rs"]
#[allow(dead_code, reason = "shared genuine LOCAL fixture includes MFA cases")]
mod cookie;
#[path = "../../broker-control/tests/support/admin_federated_read.rs"]
mod federated;
#[path = "support/admin_native.rs"]
#[allow(
    dead_code,
    reason = "read and write contracts share the actual binary and credential producers"
)]
mod native;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared PostgreSQL fixture includes additional native cases"
)]
mod support;
#[path = "support/upstream.rs"]
#[allow(
    dead_code,
    reason = "shared genuine HTTPS issuer includes rotation and faults"
)]
mod upstream;
use broker_control::{SystemAction, UpstreamBearerVerifier};
use native::{Native, access, denied, document, opaque, private_file};
use reqwest::{Method, Response};
use serde_json::{Value, json};
use support::n;

async fn request(
    h: &Native,
    method: Method,
    route: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    csrf: &[&str],
    body: Option<&Value>,
) -> Response {
    let mut request = h
        .client
        .request(method, format!("http://{}/admin/api/v1/{route}", h.addr))
        .header("x-request-id", "  rbac-write-proof  ");
    if let Some(raw) = cookie {
        request = request.header("cookie", format!("graphit_admin_session={raw}"));
    }
    if let Some(raw) = bearer {
        request = request.bearer_auth(raw);
    }
    for value in csrf {
        request = request.header("x-csrf-token", *value);
    }
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap());
    }
    request.send().await.unwrap()
}
async fn success(response: Response) {
    assert_eq!(response.status(), 204);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["x-request-id"], "rbac-write-proof");
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(response.bytes().await.unwrap().is_empty());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL TLS, genuine Rust HTTPS issuer and actual native binary"]
async fn broker_admin_rbac_write_http_contract() {
    let mut issuer = browser::BrowserIssuer::new().await;
    let mut h = Native::with_config(|config, root| {
        private_file(&root.join("browser-ca.pem"), &issuer.ca);
        config.replace(
            "  oidc:\n",
            &format!("  oidc:\n{}", federated::native_yaml(&issuer)),
        )
    })
    .await;
    let local = h.f.cookie().await;
    let local_session = h.get("session", local.secret()).await;
    let local_csrf = local_session["csrf_token"].as_str().unwrap().to_owned();
    let jwt = access(&h.f, &h.client, h.addr).await;
    let opaque = opaque(&mut h.f).await;
    let fed = h.op.sign(&h.op.claims(), "upstream-key", "at+jwt");
    let verifier = UpstreamBearerVerifier::new(
        &format!("http://{}", h.addr),
        n(16384),
        vec![federated::provider(&issuer)],
    )
    .unwrap();
    let external = federated::issue(&h.f.store, &verifier, &issuer).await;
    let external_session = h.get("session", external.secret()).await;
    let external_csrf = external_session["csrf_token"].as_str().unwrap().to_owned();
    h.action(SystemAction::RolesWrite).await;
    let factors = [
        (Some(local.secret()), None, Some(local_csrf.as_str())),
        (None, Some(jwt.as_str()), None),
        (None, Some(opaque.as_str()), None),
        (None, Some(fed.as_str()), None),
        (Some(external.secret()), None, Some(external_csrf.as_str())),
    ];
    for (index, (cookie, bearer, csrf)) in factors.into_iter().enumerate() {
        let csrf = csrf.into_iter().collect::<Vec<_>>();
        let role = format!("factor-{index}");
        let route = format!("roles/{role}");
        success(
            request(
                &h,
                Method::PUT,
                &route,
                cookie,
                bearer,
                &csrf,
                Some(&json!({"permissions":["roles.read","roles.read"]})),
            )
            .await,
        )
        .await;
        let body = json!({"subject":format!("https://external.invalid|{index}"),"role":role});
        success(
            request(
                &h,
                Method::POST,
                "role-assignments",
                cookie,
                bearer,
                &csrf,
                Some(&body),
            )
            .await,
        )
        .await;
        success(
            request(
                &h,
                Method::POST,
                "role-assignments",
                cookie,
                bearer,
                &csrf,
                Some(&body),
            )
            .await,
        )
        .await;
        success(
            request(
                &h,
                Method::DELETE,
                "role-assignments",
                cookie,
                bearer,
                &csrf,
                Some(&body),
            )
            .await,
        )
        .await;
        success(
            request(
                &h,
                Method::DELETE,
                "role-assignments",
                cookie,
                bearer,
                &csrf,
                Some(&body),
            )
            .await,
        )
        .await;
        success(request(&h, Method::DELETE, &route, cookie, bearer, &csrf, None).await).await;
        denied(
            h.request("session", Method::GET, cookie, bearer).await,
            403,
            "admin_forbidden",
        )
        .await;
    }
    let body = json!({"permissions":["configuration.read","configuration.read"]});
    for csrf in [
        vec![],
        vec!["bad-csrf"],
        vec![local_csrf.as_str(), local_csrf.as_str()],
    ] {
        denied(
            request(
                &h,
                Method::PUT,
                "roles/csrf-denied",
                Some(local.secret()),
                None,
                &csrf,
                Some(&body),
            )
            .await,
            403,
            "csrf_failed",
        )
        .await;
    }
    denied(
        request(
            &h,
            Method::PUT,
            "roles/precedence",
            Some("invalid"),
            Some(&jwt),
            &[&local_csrf],
            Some(&body),
        )
        .await,
        401,
        "admin_unauthorized",
    )
    .await;
    for raw in [
        r#"{"permissions":[],"foreign":true}"#,
        r#"{"permissions":["roles.read"],"permissions":["*"]}"#,
        r#"{"permissions":["roles.read"]} trailing"#,
        "null",
        "[]",
    ] {
        let response = h
            .client
            .put(format!("http://{}/admin/api/v1/roles/bad-json", h.addr))
            .header(
                "cookie",
                format!("graphit_admin_session={}", local.secret()),
            )
            .header("x-csrf-token", &local_csrf)
            .header("content-type", "application/json")
            .body(raw)
            .send()
            .await
            .unwrap();
        denied(response, 400, "invalid_role").await;
    }
    for (role, input) in [
        ("admin", json!({"permissions":["*"]})),
        ("user", json!({"permissions":["roles.write"]})),
        ("empty", json!({"permissions":[]})),
        ("unknown", json!({"permissions":["unknown.action"]})),
    ] {
        denied(
            request(
                &h,
                Method::PUT,
                &format!("roles/{role}"),
                Some(local.secret()),
                None,
                &[&local_csrf],
                Some(&input),
            )
            .await,
            400,
            "invalid_role",
        )
        .await;
    }
    success(
        request(
            &h,
            Method::PUT,
            "roles/canonical",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&body),
        )
        .await,
    )
    .await;
    h.action(SystemAction::RolesRead).await;
    let roles = h.get("roles", local.secret()).await;
    let canonical = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == "canonical")
        .unwrap();
    assert_eq!(canonical["permissions"], json!(["configuration.read"]));
    denied(
        request(
            &h,
            Method::DELETE,
            "roles/canonical",
            Some(local.secret()),
            None,
            &[&local_csrf],
            None,
        )
        .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.action(SystemAction::RolesWrite).await;
    let unicode = "😀".repeat(512);
    success(
        request(
            &h,
            Method::POST,
            "role-assignments",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&json!({"subject":unicode,"role":"canonical"})),
        )
        .await,
    )
    .await;
    success(
        request(
            &h,
            Method::DELETE,
            "roles/canonical",
            Some(local.secret()),
            None,
            &[&local_csrf],
            None,
        )
        .await,
    )
    .await;
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.role_assignments WHERE role='canonical'"
        )
        .fetch_one(&mut h.f.admin)
        .await
        .unwrap(),
        0
    );
    for role in ["admin", "user", "absent"] {
        denied(
            request(
                &h,
                Method::DELETE,
                &format!("roles/{role}"),
                Some(local.secret()),
                None,
                &[&local_csrf],
                None,
            )
            .await,
            400,
            "role_delete_failed",
        )
        .await;
    }
    denied(
        request(
            &h,
            Method::POST,
            "role-assignments",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&json!({"subject":"external","role":"absent"})),
        )
        .await,
        400,
        "assignment_failed",
    )
    .await;
    success(
        request(
            &h,
            Method::PUT,
            "roles/self-writer",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&json!({"permissions":["roles.write"]})),
        )
        .await,
    )
    .await;
    success(
        request(
            &h,
            Method::POST,
            "role-assignments",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&json!({"subject":"local|alice-subject","role":"self-writer"})),
        )
        .await,
    )
    .await;
    h.action(SystemAction::SessionRead).await;
    success(
        request(
            &h,
            Method::DELETE,
            "role-assignments",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&json!({"subject":"local|alice-subject","role":"self-writer"})),
        )
        .await,
    )
    .await;
    denied(
        request(
            &h,
            Method::PUT,
            "roles/after-demotion",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&body),
        )
        .await,
        403,
        "admin_forbidden",
    )
    .await;
    // Neither native nor federated cookies refresh credentials or contact UserInfo.
    assert_eq!(issuer.userinfo_hits(), 0);
    document(
        h.request("session", Method::GET, Some(local.secret()), None)
            .await,
    )
    .await;
    h.close().await;
    issuer.close().await;
}
