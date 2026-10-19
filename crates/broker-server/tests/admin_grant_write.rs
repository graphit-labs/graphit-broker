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

struct Factor<'a> {
    cookie: Option<&'a str>,
    bearer: Option<&'a str>,
    csrf: Vec<&'a str>,
}
async fn request(
    h: &Native,
    factor: &Factor<'_>,
    method: Method,
    route: &str,
    versions: &[&str],
    body: Option<&Value>,
) -> Response {
    let mut request = h
        .client
        .request(method, format!("http://{}/admin/api/v1/{route}", h.addr))
        .header("x-request-id", "  grant-write-proof  ");
    if let Some(raw) = factor.cookie {
        request = request.header("cookie", format!("graphit_admin_session={raw}"));
    }
    if let Some(raw) = factor.bearer {
        request = request.bearer_auth(raw);
    }
    for csrf in &factor.csrf {
        request = request.header("x-csrf-token", *csrf);
    }
    for version in versions {
        request = request.header("if-match", *version);
    }
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap());
    }
    request.send().await.unwrap()
}
async fn success(response: Response, status: u16) -> (Value, i64) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["pragma"], "no-cache");
    assert_eq!(response.headers()["x-request-id"], "grant-write-proof");
    assert!(!response.headers().contains_key("set-cookie"));
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    let revision = body["revision"].as_i64().unwrap();
    assert!(revision > 0);
    assert_eq!(etag, format!("\"{revision}\""));
    assert_eq!(body["v"], 1);
    assert!(body["rules"].is_array());
    assert!(body["updated_at"].as_str().unwrap().ends_with('Z'));
    (body, revision)
}
async fn revision(h: &mut Native) -> i64 {
    sqlx_core::query_scalar::query_scalar(
        "SELECT revision FROM public.resource_acl_state WHERE id=1",
    )
    .fetch_one(&mut h.f.admin)
    .await
    .unwrap()
}
fn grant(id: &str) -> Value {
    json!({"id":id,"name":" Grant name ","access":" Organization ","principal":" acme ",
        "capabilities":[" task:* ","task:*"],"projects":["01ARZ3NDEKTSV4RRFFQ69G5FAV","01ARZ3NDEKTSV4RRFFQ69G5FAV"],
        "s3_operations":[" read ","read"],"s3_prefixes":[" data/{project} ","data/{project}"]})
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native Broker, owned PostgreSQL TLS and genuine local/upstream factors"]
async fn broker_admin_grant_write_http_contract() {
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
    let csrf = local_session["csrf_token"].as_str().unwrap().to_owned();
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
    let mut current = revision(&mut h).await;
    h.action(SystemAction::GrantsWrite).await;
    let factors = [
        Factor {
            cookie: Some(local.secret()),
            bearer: None,
            csrf: vec![&csrf],
        },
        Factor {
            cookie: None,
            bearer: Some(&jwt),
            csrf: vec![],
        },
        Factor {
            cookie: None,
            bearer: Some(&opaque),
            csrf: vec![],
        },
        Factor {
            cookie: None,
            bearer: Some(&fed),
            csrf: vec![],
        },
        Factor {
            cookie: Some(external.secret()),
            bearer: None,
            csrf: vec![&external_csrf],
        },
    ];
    for (index, factor) in factors.iter().enumerate() {
        let id = format!("factor-{index}");
        let version = current.to_string();
        let (body, next) = success(
            request(
                &h,
                factor,
                Method::POST,
                "grants",
                &[&version],
                Some(&grant(&format!(" {id} "))),
            )
            .await,
            201,
        )
        .await;
        assert_eq!(next, current + 1);
        current = next;
        let row = body["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap();
        assert_eq!(row["name"], "Grant name");
        assert_eq!(row["access"], "organization");
        assert_eq!(row["principal"], "acme");
        assert_eq!(row["capabilities"], json!(["task:*"]));
        assert_eq!(row["projects"], json!(["01ARZ3NDEKTSV4RRFFQ69G5FAV"]));
        assert_eq!(row["s3_operations"], json!(["read"]));
        assert_eq!(row["s3_prefixes"], json!(["data/{project}"]));
        let mut replacement = grant("ignored/body/id");
        replacement["name"] = json!("Replacement");
        replacement["projects"] = json!([]);
        let version = format!("W/\"{current}\"");
        let (body, next) = success(
            request(
                &h,
                factor,
                Method::PUT,
                &format!("grants/{id}"),
                &[&version],
                Some(&replacement),
            )
            .await,
            200,
        )
        .await;
        assert_eq!(next, current + 1);
        current = next;
        let row = body["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap();
        assert_eq!(row["name"], "Replacement");
        assert!(row.get("projects").is_none());
        let version = format!("\"{current}\"");
        let (body, next) = success(
            request(
                &h,
                factor,
                Method::DELETE,
                &format!("grants/{id}"),
                &[&version],
                None,
            )
            .await,
            200,
        )
        .await;
        assert_eq!(next, current + 1);
        current = next;
        assert!(
            !body["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == id)
        );
        denied(
            h.request("session", Method::GET, factor.cookie, factor.bearer)
                .await,
            403,
            "admin_forbidden",
        )
        .await;
    }
    let bearer = &factors[1];
    for version in [
        None,
        Some("0"),
        Some("bad"),
        Some("\"1"),
        Some("18446744073709551616"),
    ] {
        let versions = version.into_iter().collect::<Vec<_>>();
        denied(
            request(
                &h,
                bearer,
                Method::POST,
                "grants",
                &versions,
                Some(&grant("precondition")),
            )
            .await,
            428,
            "precondition_required",
        )
        .await;
    }
    denied(
        request(
            &h,
            bearer,
            Method::POST,
            "grants",
            &["1", "1"],
            Some(&grant("duplicate-header")),
        )
        .await,
        428,
        "precondition_required",
    )
    .await;
    denied(
        request(
            &h,
            bearer,
            Method::POST,
            "grants",
            &["18446744073709551615"],
            Some(&grant("stale-max")),
        )
        .await,
        409,
        "revision_conflict",
    )
    .await;
    assert_eq!(revision(&mut h).await, current);
    for csrf_values in [vec![], vec!["bad"], vec![csrf.as_str(), csrf.as_str()]] {
        let factor = Factor {
            cookie: Some(local.secret()),
            bearer: None,
            csrf: csrf_values,
        };
        denied(
            request(
                &h,
                &factor,
                Method::POST,
                "grants",
                &[&current.to_string()],
                Some(&grant("csrf")),
            )
            .await,
            403,
            "csrf_failed",
        )
        .await;
    }
    let invalid_cookie = Factor {
        cookie: Some("invalid"),
        bearer: Some(&jwt),
        csrf: vec![&csrf],
    };
    denied(
        request(
            &h,
            &invalid_cookie,
            Method::POST,
            "grants",
            &[&current.to_string()],
            Some(&grant("cookie-precedence")),
        )
        .await,
        401,
        "admin_unauthorized",
    )
    .await;
    for mut invalid in [
        json!({"id":"bad","name":"Bad","access":"org","principal":"acme","capabilities":["hub"]}),
        json!({"id":"bad","name":"Bad","access":"global","principal":"unexpected","capabilities":["hub"]}),
        json!({"id":"bad","name":"Bad","access":"user","capabilities":["hub"]}),
        json!({"id":"bad","name":"Bad","access":"authenticated","capabilities":["["]}),
        json!({"id":"bad","name":"Bad","access":"authenticated","capabilities":["hub"],"projects":["invalid-project"]}),
        json!({"id":"bad","name":"Bad","access":"authenticated","capabilities":["s3"],"s3_route":"missing"}),
        json!({"id":"bad","name":"Bad","access":"authenticated","capabilities":["hub"],"unknown":true}),
    ] {
        invalid["id"] = json!("bad");
        denied(
            request(
                &h,
                bearer,
                Method::POST,
                "grants",
                &[&current.to_string()],
                Some(&invalid),
            )
            .await,
            400,
            "invalid_grant",
        )
        .await;
        assert_eq!(revision(&mut h).await, current);
    }
    let version = current.to_string();
    let versions = [version.as_str()];
    let body_a = grant("concurrent-a");
    let body_b = grant("concurrent-b");
    let (a, b) = tokio::join!(
        request(&h, bearer, Method::POST, "grants", &versions, Some(&body_a)),
        request(&h, bearer, Method::POST, "grants", &versions, Some(&body_b))
    );
    if a.status() == 201 {
        let (_, next) = success(a, 201).await;
        current = next;
        denied(b, 409, "revision_conflict").await;
    } else {
        denied(a, 409, "revision_conflict").await;
        let (_, next) = success(b, 201).await;
        current = next;
    }
    assert_eq!(revision(&mut h).await, current);
    denied(
        request(
            &h,
            bearer,
            Method::PUT,
            "grants/absent",
            &[&current.to_string()],
            Some(&grant("ignored")),
        )
        .await,
        400,
        "grant_write_failed",
    )
    .await;
    denied(
        request(
            &h,
            bearer,
            Method::DELETE,
            "grants/absent",
            &[&current.to_string()],
            None,
        )
        .await,
        400,
        "grant_write_failed",
    )
    .await;
    let failed = h
        .client
        .post(format!("http://{}/admin/api/v1/grants", h.addr))
        .bearer_auth(jwt.as_str())
        .header("if-match", current.to_string())
        .header("content-type", "application/json")
        .body(r#"{"id":"a","id":"b"}"#)
        .send()
        .await
        .unwrap();
    denied(failed, 400, "invalid_grant").await;
    h.action(SystemAction::GrantsRead).await;
    let response = h.request("grants", Method::GET, None, Some(&jwt)).await;
    let etag = response.headers()["etag"].to_str().unwrap().to_owned();
    let read = document(response).await;
    assert_eq!(read["revision"], current);
    assert_eq!(etag, format!("\"{current}\""));
    let head = h.request("grants", Method::HEAD, None, Some(&jwt)).await;
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["etag"], etag);
    assert!(head.bytes().await.unwrap().is_empty());
    denied(
        request(
            &h,
            bearer,
            Method::POST,
            "grants",
            &[&current.to_string()],
            Some(&grant("now-denied")),
        )
        .await,
        403,
        "admin_forbidden",
    )
    .await;
    h.close().await;
    issuer.close().await;
}
