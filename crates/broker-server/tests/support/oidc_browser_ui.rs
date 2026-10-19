//! Optional real-browser RP, using native responses and disposable SQL actors.
//! Stage representations are taken once for read-only visual/keyboard inspection.
//! Production responses, credentials and challenge owners are never replaced.
use super::*;
use axum::{body::Body, extract::State, http::HeaderMap, response::Response};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

#[tokio::test]
async fn browser_fixture_form_return_origin_is_explicit() {
    let mut issuer = browser::BrowserIssuer::new_loopback_browser().await;
    issuer.register(browser::ClientRegistration {
        id: "public".into(),
        secret: None,
        redirect: REDIRECT.into(),
        auth: browser::ClientAuth::Public,
    });
    let uri = format!(
        "{}/authorize?{}",
        issuer.issuer,
        form(&[("client_id", "public"), ("redirect_uri", REDIRECT)])
    );
    let initial = client().get(&uri).send().await.unwrap();
    assert_eq!(initial.status(), 200);
    let initial = initial.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    let rp = url::Url::parse("http://127.0.0.1:49159").unwrap().origin();
    assert!(!initial.contains(&rp.ascii_serialization()));
    issuer.fault(browser::Fault {
        browser_return_origin: Some(rp.clone()),
        ..browser::Fault::default()
    });
    let configured = client().get(&uri).send().await.unwrap();
    let configured = configured.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert_eq!(
        configured,
        initial.replace(
            "; base-uri",
            &format!(" {}; base-uri", rp.ascii_serialization())
        )
    );
    assert!(!configured.contains('*'));
    issuer.fault(browser::Fault::default());
    let restored = client().get(&uri).send().await.unwrap();
    assert_eq!(restored.headers()["content-security-policy"], initial);
    issuer.close().await;
}

struct Rp {
    broker: SocketAddr,
    client: String,
    redirect: String,
    signer: BrokerAccessIssuer,
    previews: Mutex<HashMap<String, Response>>,
    verified: Mutex<HashSet<String>>,
}

fn html_response(body: &str) -> Response {
    Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn representation(response: reqwest::Response) -> Response {
    let mut headers = HeaderMap::new();
    for name in [
        "content-type",
        "content-security-policy",
        "cache-control",
        "pragma",
        "referrer-policy",
        "x-content-type-options",
        "x-frame-options",
    ] {
        if let Some(value) = response.headers().get(name) {
            headers.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.clone(),
            );
        }
    }
    let status = response.status();
    let mut result = Response::new(Body::from(response.text().await.unwrap()));
    *result.headers_mut() = headers;
    *result.status_mut() = status;
    result
}

async fn preview(
    State(rp): State<Arc<Rp>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    rp.previews
        .lock()
        .unwrap()
        .remove(&name)
        .unwrap_or_else(|| {
            Response::builder()
                .status(410)
                .body(Body::from("Representation already inspected"))
                .unwrap()
        })
}

async fn begin(
    State(rp): State<Arc<Rp>>,
    axum::extract::Path(mode): axum::extract::Path<String>,
) -> axum::response::Redirect {
    assert!(["query", "fragment", "form_post"].contains(&mode.as_str()));
    let fields = authorize_form(&rp.client, &mode)
        .replace(
            &form(&[("state", STATE)]),
            &form(&[("state", &format!("{STATE}|{mode}"))]),
        )
        .replace(
            &form(&[("redirect_uri", REDIRECT)]),
            &form(&[("redirect_uri", &rp.redirect)]),
        );
    axum::response::Redirect::temporary(&format!("http://{}/oauth/authorize?{fields}", rp.broker))
}

async fn finish(rp: &Rp, fields: &str) -> Response {
    let pairs: HashMap<_, _> = url::form_urlencoded::parse(fields.as_bytes())
        .into_owned()
        .collect();
    if !pairs.contains_key("code") {
        // A fragment never reaches HTTP. This RP consumer transfers only its own
        // browser-visible response fields into a form POST, then discards them.
        return html_response(
            "<!doctype html><html lang=\"en\"><title>Receive fragment</title><main><h1>Receiving application response</h1><form method=\"post\" action=\"/cb\"></form><script>const f=document.querySelector('form');for(const [name,value] of new URLSearchParams(location.hash.slice(1))){const i=document.createElement('input');i.type='hidden';i.name=name;i.value=value;f.append(i)}history.replaceState(null,'','/cb');f.submit()</script></main></html>",
        );
    }
    let branch = pairs["state"].strip_prefix(STATE).unwrap();
    assert!(["", "|query", "|fragment", "|form_post"].contains(&branch));
    let token = http::post(
        rp.broker,
        form(&[
            ("grant_type", "authorization_code"),
            ("client_id", &rp.client),
            ("code", &pairs["code"]),
            ("redirect_uri", &rp.redirect),
            ("code_verifier", VERIFIER),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(token.status(), 200);
    let tokens = http::value(token).await;
    let claims = http::claims(
        &rp.signer,
        &format!("http://{}", rp.broker),
        tokens["access_token"].as_str().unwrap(),
    );
    assert_eq!(claims["client_id"], rp.client);
    assert_eq!(
        http::claims(
            &rp.signer,
            &format!("http://{}", rp.broker),
            tokens["id_token"].as_str().unwrap()
        )["nonce"],
        "browser nonce"
    );
    let refresh = http::post(
        rp.broker,
        form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &rp.client),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("resource", RESOURCE),
        ]),
        None,
    )
    .await;
    assert_eq!(refresh.status(), 200);
    let refreshed = http::value(refresh).await;
    let _ = http::claims(
        &rp.signer,
        &format!("http://{}", rp.broker),
        refreshed["access_token"].as_str().unwrap(),
    );
    // Native code is single-use. Distinct successful callbacks prove three journeys.
    rp.verified.lock().unwrap().insert(branch.to_owned());
    html_response(
        "<!doctype html><html lang=\"en\"><title>Public browser verified</title><main><h1>Application sign-in verified</h1><p>Literal state, real PKCE exchange, signed tokens and refresh passed.</p></main></html>",
    )
}

async fn get_callback(
    State(rp): State<Arc<Rp>>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    finish(&rp, query.as_deref().unwrap_or("")).await
}
async fn post_callback(State(rp): State<Arc<Rp>>, body: axum::body::Bytes) -> Response {
    finish(&rp, std::str::from_utf8(&body).unwrap()).await
}

async fn register_rp(addr: SocketAddr, redirect: &str) -> String {
    let response=client().post(format!("http://{addr}/oauth/register")).header("content-type","application/json").body(serde_json::to_vec(&json!({"redirect_uris":[redirect],"token_endpoint_auth_method":"none","client_name":"Browser application"})).unwrap()).send().await.unwrap();
    assert_eq!(response.status(), 201);
    http::value(response).await["client_id"]
        .as_str()
        .unwrap()
        .to_owned()
}
async fn pending_rp(addr: SocketAddr, id: &str, mode: &str, redirect: &str) -> String {
    let fields = authorize_form(id, mode).replace(
        &form(&[("redirect_uri", REDIRECT)]),
        &form(&[("redirect_uri", redirect)]),
    );
    let response = client()
        .get(format!("http://{addr}/oauth/authorize?{fields}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    response.headers()["location"].to_str().unwrap().to_owned()
}

pub async fn qualify(f: &mut OidcFixture, root: &Path, index: &Path) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rp_addr = listener.local_addr().unwrap();
    let redirect = format!("http://{rp_addr}/cb");
    seed(f).await;
    f.admin.execute("DELETE FROM public.local_mfa; DELETE FROM public.local_mfa_recovery_codes; UPDATE public.local_users SET password_change_required=1").await.unwrap();
    let addr = http::address();
    let signer = http::files(root, &f.fixture.ca, &format!("http://{addr}"));
    let mut cfg = config(addr, f.fixture.port, true);
    cfg["administration"] = json!({"enabled":false,"cookie_secure":false});
    let child = start(root, &cfg, addr).await;
    let id = register_rp(addr, &redirect).await;
    let mut previews = HashMap::new();
    let path = pending_rp(addr, &id, "form_post", &redirect).await;
    let change = post(
        addr,
        &path,
        &[("username", "alice"), ("password", PASSWORD)],
    )
    .await;
    let html = change.text().await.unwrap();
    let challenge = input(&html, "challenge_token");
    // Native response to a mismatched confirmation is safe to inspect read-only.
    let invalid = post(
        addr,
        &path,
        &[
            ("challenge_token", &challenge),
            ("new_password", "disposable browser password"),
            ("confirm_password", "different"),
        ],
    )
    .await;
    previews.insert("password-change".into(), representation(invalid).await);
    let enrollment = post(
        addr,
        &path,
        &[
            ("challenge_token", &challenge),
            ("new_password", "disposable browser password"),
            ("confirm_password", "disposable browser password"),
        ],
    )
    .await;
    let headers = enrollment.headers().clone();
    let html = enrollment.text().await.unwrap();
    let challenge = input(&html, "challenge_token");
    let sdk = enrollment_sdk(&html);
    let mut response = Response::new(Body::from(html));
    // Same allowlist as representation(): no cookies or transfer framing.
    for name in [
        "content-type",
        "content-security-policy",
        "cache-control",
        "pragma",
        "referrer-policy",
        "x-content-type-options",
        "x-frame-options",
    ] {
        if let Some(value) = headers.get(name) {
            response.headers_mut().insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.clone(),
            );
        }
    }
    previews.insert("enrollment".into(), response);
    let otp = Zeroizing::new(
        sdk.generate((oidc::micros() as u64) / 1_000_000)
            .to_string(),
    );
    let recovery = post(
        addr,
        &path,
        &[("challenge_token", &challenge), ("code", &otp)],
    )
    .await;
    assert_eq!(recovery.status(), 200);
    previews.insert("recovery".into(), representation(recovery).await);
    let path = pending_rp(addr, &id, "query", &redirect).await;
    let mfa = post(
        addr,
        &path,
        &[
            ("username", "alice"),
            ("password", "disposable browser password"),
        ],
    )
    .await;
    previews.insert("mfa".into(), representation(mfa).await);
    http::stop(child).await;
    seed(f).await;
    f.admin.execute("DELETE FROM public.local_mfa; DELETE FROM public.local_mfa_recovery_codes; UPDATE public.local_users SET password_change_required=0").await.unwrap();
    let mut issuer = browser::BrowserIssuer::new_loopback_browser().await;
    let callback = format!("http://{addr}/oauth/oidc/callback");
    for id in ["public", "second"] {
        issuer.register(browser::ClientRegistration {
            id: id.into(),
            secret: None,
            redirect: callback.clone(),
            auth: browser::ClientAuth::Public,
        });
    }
    issuer.fault(browser::Fault {
        browser_return_origin: Some(url::Url::parse(&redirect).unwrap().origin()),
        id_overrides: [
            ("mapped_subject".into(), json!("alice-subject")),
            ("roles".into(), json!(["admin"])),
        ]
        .into(),
        ..browser::Fault::default()
    });
    let mut cfg = config(addr, f.fixture.port, false);
    cfg["administration"] = json!({"enabled":false,"cookie_secure":false});
    let mut provider = upstream_provider(&issuer, true);
    provider["allow_loopback_http"] = json!(true);
    provider.as_object_mut().unwrap().remove("ca_file");
    provider.as_object_mut().unwrap().remove("ca_bytes");
    for item in provider["browser_clients"].as_array_mut().unwrap() {
        item["redirect_url"] = json!(callback);
    }
    cfg["auth"]["oidc"] = json!([provider]);
    let child = start(root, &cfg, addr).await;
    let client_id = id;
    let login = pending_rp(addr, &client_id, "query", &redirect).await;
    // CAPTCHA visual is a separate native profile with its real public widget.
    let cap_addr = http::address();
    let mut cap_cfg = config(cap_addr, f.fixture.port, false);
    cap_cfg["auth"]["local"]["captcha"] = json!({"enabled":true,"provider":"turnstile","site_key":"1x00000000000000000000AA","secret_key":"fixture-private","trigger_multiplier":0,"verification_timeout":"500ms"});
    let cap_root = tempfile::tempdir().unwrap();
    let _cap_signer = http::files(
        cap_root.path(),
        &f.fixture.ca,
        &format!("http://{cap_addr}"),
    );
    let cap_child = start(cap_root.path(), &cap_cfg, cap_addr).await;
    let cap_id = register(cap_addr).await;
    let cap_path = pending(cap_addr, &cap_id, "query").await;
    let state = Arc::new(Rp {
        broker: addr,
        client: client_id,
        redirect,
        signer,
        previews: Mutex::new(previews),
        verified: Mutex::new(HashSet::new()),
    });
    let router = axum::Router::new()
        .route("/preview/{name}", axum::routing::get(preview))
        .route("/start/{mode}", axum::routing::get(begin))
        .route("/cb", axum::routing::get(get_callback).post(post_callback))
        .with_state(state.clone());
    let (stop, stopping) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopping.await;
            })
            .await
            .unwrap();
    });
    let cancel = index.with_extension("stop");
    if cancel.exists() {
        std::fs::remove_file(&cancel).unwrap();
    }
    std::fs::write(index,serde_json::to_vec(&json!({"status":"ready","rp":format!("http://{rp_addr}"),"login":format!("http://{addr}{login}"),"captcha":format!("http://{cap_addr}{cap_path}")})).unwrap()).unwrap();
    let local_only = std::env::var_os("GRAPHIT_BROKER_PUBLIC_BROWSER_UI_LOCAL_ONLY").is_some();
    let complete = tokio::time::timeout(Duration::from_secs(1200), async {
        loop {
            if cancel.exists() {
                let modes = state.verified.lock().unwrap();
                break ["|query", "|fragment", "|form_post"]
                    .iter()
                    .all(|mode| modes.contains(*mode))
                    && (local_only || modes.contains(""));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or(false);
    let _ = stop.send(());
    server.await.unwrap();
    http::stop(child).await;
    http::stop(cap_child).await;
    issuer.close().await;
    assert!(
        complete,
        "inspect browser and complete all three native RP exchanges plus manual recovery, then create the index .stop sibling"
    );
    std::fs::write(index,serde_json::to_vec(&json!({"status":"passed","rp_exchanges":state.verified.lock().unwrap().len(),"signed_tokens":true,"refresh":true})).unwrap()).unwrap();
}
