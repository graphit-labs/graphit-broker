//! Actual native Broker, owned PostgreSQL TLS and genuine administrative factors.
#[path = "../../broker-control/tests/support/browser_upstream.rs"]
#[allow(
    dead_code,
    reason = "shared genuine HTTPS issuer also supports protocol fault contracts"
)]
mod browser;
#[path = "../../broker-control/tests/support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "shared genuine LOCAL fixture also supports MFA contracts"
)]
mod cookie;
#[path = "../../broker-control/tests/support/admin_federated_read.rs"]
mod federated;
#[path = "support/admin_native.rs"]
#[allow(
    dead_code,
    reason = "reads and writes share the actual native process and factor producers"
)]
mod native;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture supports other native contracts"
)]
mod support;
#[path = "support/upstream.rs"]
#[allow(
    dead_code,
    reason = "shared genuine HTTPS issuer also supports rotation contracts"
)]
mod upstream;
use broker_control::{SystemAction, UpstreamBearerVerifier};
use native::{Native, access, denied, private_file};
use reqwest::{Method, Response};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use support::{deadline, n};
use zeroize::Zeroizing;
const PASSWORD: &str = "native administrative fixture password";
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
        .header("x-request-id", "  user-lifecycle-proof  ");
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
async fn body(response: Response, status: u16) -> Zeroizing<Vec<u8>> {
    assert_eq!(response.status(), status, "{}", response.url().path());
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["x-request-id"], "user-lifecycle-proof");
    assert!(!response.headers().contains_key("set-cookie"));
    Zeroizing::new(response.bytes().await.unwrap().to_vec())
}
async fn empty(response: Response, status: u16) {
    assert!(body(response, status).await.is_empty());
}
async fn document(response: Response, status: u16) -> Value {
    let bytes = body(response, status).await;
    serde_json::from_slice(&bytes).unwrap()
}
async fn credential(response: Response) -> (String, Zeroizing<String>) {
    let value = document(response, 201).await;
    assert_eq!(value["token_type"], "Bearer");
    let id = value["id"].as_str().unwrap().to_owned();
    let raw = Zeroizing::new(value["token"].as_str().unwrap().to_owned());
    assert!(raw.starts_with("gb_sc_"));
    assert!(!value.as_object().unwrap().contains_key("token_hash"));
    (id, raw)
}
async fn actions(h: &mut Native, actions: &[SystemAction]) {
    h.f.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user'")
        .await
        .unwrap();
    for action in actions {
        sqlx_core::query::query(
            "INSERT INTO public.role_permissions(role,action) VALUES('user',$1)",
        )
        .bind(action.as_str())
        .execute(&mut h.f.admin)
        .await
        .unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned PostgreSQL TLS, genuine Rust HTTPS issuer and actual native binary"]
async fn broker_admin_user_lifecycle_http_contract() {
    let mut issuer = browser::BrowserIssuer::new().await;
    let mut h = Native::with_config(|config, root| {
        private_file(&root.join("browser-ca.pem"), &issuer.ca);
        assert!(config.contains("  oidc:\n"));
        assert!(config.contains("    audience: explicit-admin-api\n"));
        let public_url = config.lines().find_map(|line| line.strip_prefix("  public_url: ")).unwrap().to_owned();
        let browser = format!("{}      browser_clients:\n        - display_name: User lifecycle\n          client_id: public\n          redirect_url: {public_url}/oauth/oidc/callback\n          scopes: [profile, email]\n          require_nonce: true\n", federated::native_yaml(&issuer));
        let config = config.replace("  oidc:\n", &format!("  service_credential_max_ttl: 2h\n  local:\n    login:\n      enabled: false\n    rate_limit:\n      max_concurrent: 1\n  oidc:\n{browser}"));
        config.replace("    audience: explicit-admin-api\n", "    audience: storage-api\n")
    }).await;
    let local = h.f.cookie().await;
    let local_session = h.get("session", local.secret()).await;
    let local_csrf = local_session["csrf_token"].as_str().unwrap().to_owned();
    let jwt = access(&h.f, &h.client, h.addr).await;
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

    // Administrative password writes use the configured physical engine without enabling login.
    let options: Value = h
        .client
        .get(format!("http://{}/admin/api/v1/login-options", h.addr))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap();
    assert_eq!(options["local"], false);
    assert!(
        options["oidc_providers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|provider| provider["name"] == "User lifecycle")
    );
    for route in ["local", "local/continue"] {
        let response = h
            .client
            .post(format!("http://{}/admin/auth/{route}", h.addr))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        denied(response, 503, "administration_unavailable").await;
    }
    h.action(SystemAction::UsersWrite).await;
    let human = json!({"username":"bob","subject":"bob-subject","password":PASSWORD,"enabled":null,"name":" Bob ","teams":["engineering"," engineering "]});
    empty(
        request(
            &h,
            Method::POST,
            "local-users",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&human),
        )
        .await,
        201,
    )
    .await;
    assert!(
        h.f.store
            .local_password_verifier(&h.f.engine)
            .verify("bob", PASSWORD, deadline())
            .await
            .is_ok()
    );
    denied(
        request(
            &h,
            Method::GET,
            "session",
            Some(local.secret()),
            None,
            &[],
            None,
        )
        .await,
        403,
        "admin_forbidden",
    )
    .await;
    let operator = json!({"username":"operator","subject":"operator-subject","kind":"service"});
    empty(
        request(
            &h,
            Method::POST,
            "local-users",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&operator),
        )
        .await,
        201,
    )
    .await;
    let (operator_id, opaque) = credential(
        request(
            &h,
            Method::POST,
            "local-users/operator/credentials",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&json!({"scopes":["admin:session"]})),
        )
        .await,
    )
    .await;
    let ttl: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT (expires_at-created_at)/1000000 FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(&operator_id)
    .fetch_one(&mut h.f.admin)
    .await
    .unwrap();
    assert_eq!(ttl, 7200);
    let audience: String = sqlx_core::query_scalar::query_scalar(
        "SELECT audience FROM public.local_tokens WHERE token_id=$1",
    )
    .bind(&operator_id)
    .fetch_one(&mut h.f.admin)
    .await
    .unwrap();
    assert_eq!(audience, "storage-api");
    denied(
        request(
            &h,
            Method::GET,
            "local-users/operator/credentials",
            None,
            Some(&opaque),
            &[],
            None,
        )
        .await,
        403,
        "admin_forbidden",
    )
    .await;
    actions(&mut h, &[SystemAction::UsersWrite, SystemAction::UsersRead]).await;

    // Every supported genuine factor reaches the same mounted lifecycle handlers.
    let factors = [
        (Some(local.secret()), None, Some(local_csrf.as_str())),
        (None, Some(jwt.as_str()), None),
        (None, Some(opaque.as_str()), None),
        (None, Some(fed.as_str()), None),
        (Some(external.secret()), None, Some(external_csrf.as_str())),
    ];
    for (index, (cookie, bearer, csrf)) in factors.into_iter().enumerate() {
        let csrf = csrf.into_iter().collect::<Vec<_>>();
        let name = format!("factor-{index}");
        let route = format!("local-users/{name}");
        empty(request(&h,Method::POST,"local-users",cookie,bearer,&csrf,Some(&json!({"username":name,"subject":format!("factor-subject-{index}"),"kind":"service"}))).await,201).await;
        let (id,raw)=credential(request(&h,Method::POST,&format!("{route}/credentials"),cookie,bearer,&csrf,Some(&json!({"client_id":" caller ","scopes":["admin:session","admin:session"],"expires_in":3600}))).await).await;
        let inventory = document(
            request(
                &h,
                Method::GET,
                &format!("{route}/credentials"),
                cookie,
                bearer,
                &[],
                None,
            )
            .await,
            200,
        )
        .await;
        let rows = inventory["credentials"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], id);
        assert_eq!(rows[0]["client_id"], "caller");
        assert_eq!(rows[0]["scopes"], json!(["admin:session"]));
        let serialized = serde_json::to_string(&inventory).unwrap();
        assert!(!serialized.contains(raw.as_str()));
        for forbidden in ["token_hash", "principal_json", "password_hash", "gb_sc_"] {
            assert!(!serialized.contains(forbidden));
        }
        empty(
            request(
                &h,
                Method::DELETE,
                &format!("{route}/credentials/{id}"),
                cookie,
                bearer,
                &csrf,
                None,
            )
            .await,
            204,
        )
        .await;
        denied(
            request(
                &h,
                Method::DELETE,
                &format!("{route}/credentials/{id}"),
                cookie,
                bearer,
                &csrf,
                None,
            )
            .await,
            400,
            "credential_revoke_failed",
        )
        .await;
        let revoked = document(
            request(
                &h,
                Method::GET,
                &format!("{route}/credentials"),
                cookie,
                bearer,
                &[],
                None,
            )
            .await,
            200,
        )
        .await;
        assert!(!revoked["credentials"][0]["revoked_at"].is_null());
        empty(
            request(&h, Method::DELETE, &route, cookie, bearer, &csrf, None).await,
            204,
        )
        .await;
        denied(
            request(
                &h,
                Method::GET,
                &format!("{route}/credentials"),
                cookie,
                bearer,
                &[],
                None,
            )
            .await,
            404,
            "service_identity_not_found",
        )
        .await;
    }
    let service =
        json!({"username":"csrf-denied","subject":"csrf-denied-subject","kind":"service"});
    for csrf in [
        vec![],
        vec!["wrong"],
        vec![local_csrf.as_str(), local_csrf.as_str()],
    ] {
        denied(
            request(
                &h,
                Method::POST,
                "local-users",
                Some(local.secret()),
                None,
                &csrf,
                Some(&service),
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
            Method::POST,
            "local-users",
            Some("invalid"),
            Some(&jwt),
            &[&local_csrf],
            Some(&service),
        )
        .await,
        401,
        "admin_unauthorized",
    )
    .await;
    for raw in [
        r#"{"username":"invalid","subject":"invalid","kind":"service","foreign":true}"#,
        r#"{"username":"invalid","username":"duplicate","subject":"invalid","kind":"service"}"#,
        r#"{"username":"invalid","subject":"invalid","kind":"service"} trailing"#,
        "null",
        "[]",
    ] {
        let response = h
            .client
            .post(format!("http://{}/admin/api/v1/local-users", h.addr))
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
        denied(response, 400, "user_create_failed").await;
    }
    for expires_in in [3599, 7201, -1] {
        denied(
            request(
                &h,
                Method::POST,
                "local-users/operator/credentials",
                Some(local.secret()),
                None,
                &[&local_csrf],
                Some(&json!({"expires_in":expires_in})),
            )
            .await,
            400,
            "invalid_credential",
        )
        .await;
    }
    denied(
        request(
            &h,
            Method::GET,
            "local-users/bob/credentials",
            Some(local.secret()),
            None,
            &[],
            None,
        )
        .await,
        404,
        "service_identity_not_found",
    )
    .await;
    denied(
        request(
            &h,
            Method::POST,
            "local-users/operator/mfa/reset",
            Some(local.secret()),
            None,
            &[&local_csrf],
            None,
        )
        .await,
        400,
        "mfa_reset_failed",
    )
    .await;
    let update = json!({"username":"robert","subject":"bob-subject","kind":"human","enabled":false,"password_change_required":false});
    empty(
        request(
            &h,
            Method::PUT,
            "local-users/bob",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&update),
        )
        .await,
        204,
    )
    .await;
    empty(
        request(
            &h,
            Method::POST,
            "local-users/robert/mfa/reset",
            Some(local.secret()),
            None,
            &[&local_csrf],
            None,
        )
        .await,
        204,
    )
    .await;
    let mut update = update;
    update["enabled"] = Value::Null;
    empty(
        request(
            &h,
            Method::PUT,
            "local-users/robert",
            Some(local.secret()),
            None,
            &[&local_csrf],
            Some(&update),
        )
        .await,
        204,
    )
    .await;
    assert!(
        h.f.store
            .local_password_verifier(&h.f.engine)
            .verify("robert", PASSWORD, deadline())
            .await
            .is_ok()
    );
    for (field, value) in [("subject", "changed-subject"), ("kind", "service")] {
        let mut invalid = update.clone();
        invalid[field] = json!(value);
        denied(
            request(
                &h,
                Method::PUT,
                "local-users/robert",
                Some(local.secret()),
                None,
                &[&local_csrf],
                Some(&invalid),
            )
            .await,
            400,
            "user_update_failed",
        )
        .await;
    }
    let users = document(
        request(
            &h,
            Method::GET,
            "local-users",
            Some(local.secret()),
            None,
            &[],
            None,
        )
        .await,
        200,
    )
    .await;
    let robert = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["username"] == "robert")
        .unwrap();
    assert_eq!(robert["roles"], json!(["user"]));
    assert_eq!(robert["enabled"], true);
    assert_eq!(robert["password_change_required"], true);
    assert_eq!(robert["mfa_enabled"], false);
    for forbidden in ["password_hash", PASSWORD, "secret", "recovery_code"] {
        assert!(!serde_json::to_string(&users).unwrap().contains(forbidden));
    }
    empty(
        request(
            &h,
            Method::DELETE,
            "local-users/robert",
            Some(local.secret()),
            None,
            &[&local_csrf],
            None,
        )
        .await,
        204,
    )
    .await;
    denied(
        request(
            &h,
            Method::DELETE,
            "local-users/robert",
            Some(local.secret()),
            None,
            &[&local_csrf],
            None,
        )
        .await,
        400,
        "user_delete_failed",
    )
    .await;

    // Self-edit invalidates cookies; a signed JWT still needs current identity and action.
    empty(request(&h,Method::PUT,"local-users/alice",Some(local.secret()),None,&[&local_csrf],Some(&json!({"username":"alice","subject":"alice-subject","kind":"human","name":"Alice updated"}))).await,204).await;
    denied(
        request(
            &h,
            Method::GET,
            "local-users",
            Some(local.secret()),
            None,
            &[],
            None,
        )
        .await,
        401,
        "admin_unauthorized",
    )
    .await;
    let current = document(
        request(&h, Method::GET, "local-users", None, Some(&jwt), &[], None).await,
        200,
    )
    .await;
    assert!(
        current["users"]
            .as_array()
            .unwrap()
            .iter()
            .any(|user| user["username"] == "alice" && user["name"] == "Alice updated")
    );
    h.action(SystemAction::SessionRead).await;
    denied(
        request(&h, Method::GET, "local-users", None, Some(&jwt), &[], None).await,
        403,
        "admin_forbidden",
    )
    .await;
    actions(&mut h, &[SystemAction::UsersRead, SystemAction::UsersWrite]).await;
    empty(
        request(
            &h,
            Method::DELETE,
            "local-users/alice",
            None,
            Some(&opaque),
            &[],
            None,
        )
        .await,
        204,
    )
    .await;
    denied(
        request(&h, Method::GET, "local-users", None, Some(&jwt), &[], None).await,
        403,
        "admin_forbidden",
    )
    .await;
    assert_eq!(issuer.userinfo_hits(), 0);
    h.close().await;
    issuer.close().await;
}
