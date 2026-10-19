//! Real owned TLS authorization-code issuer used by browser login contracts.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{BrokerAccessIssuer, IssuedUpstreamAuthorization};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};
use url::Url;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuth {
    Public,
    Basic,
    Post,
}
#[derive(Clone)]
pub struct ClientRegistration {
    pub id: String,
    pub secret: Option<String>,
    pub redirect: String,
    pub auth: ClientAuth,
}
#[derive(Clone, Default)]
pub struct Fault {
    pub id_overrides: BTreeMap<String, Value>,
    pub access_overrides: BTreeMap<String, Value>,
    pub missing_profile: bool,
    pub missing_username: bool,
    pub omit_id: bool,
    pub wrong_signature: bool,
    pub bad_hash: bool,
    pub valid_hash: bool,
    pub token_padding: usize,
    pub omit_kid: bool,
    pub extra_audiences: Vec<String>,
    pub token_delay: Duration,
    pub userinfo_delay: Duration,
    pub userinfo_overrides: BTreeMap<String, Value>,
    pub token_duplicate: bool,
    pub metadata_override: Option<Value>,
    /// Explicit final RP origin for the loopback browser form redirect chain.
    pub browser_return_origin: Option<url::Origin>,
    pub jwks_override: Option<Value>,
}
struct Code {
    client: String,
    redirect: String,
    challenge: String,
    nonce: Option<String>,
}
struct State {
    issuer: String,
    browser_form: bool,
    key: Mutex<Zeroizing<Vec<u8>>>,
    kid: Mutex<String>,
    jwks: Mutex<Value>,
    clients: Mutex<BTreeMap<String, ClientRegistration>>,
    codes: Mutex<BTreeMap<String, Code>>,
    access: Mutex<BTreeMap<String, String>>,
    fault: Mutex<Fault>,
    pub token_hits: AtomicUsize,
    pub userinfo_hits: AtomicUsize,
    pub jwks_hits: AtomicUsize,
}
pub struct BrowserIssuer {
    pub issuer: String,
    pub ca: Vec<u8>,
    state: Arc<State>,
    pub client: reqwest::Client,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
type Body = Full<Bytes>;
fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(body.into()))
        .unwrap()
}
fn object(value: Value) -> Response<Body> {
    response(StatusCode::OK, serde_json::to_vec(&value).unwrap())
}
fn form(raw: &str) -> Option<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(raw.as_bytes()) {
        if result.insert(k.into_owned(), v.into_owned()).is_some() {
            return None;
        }
    }
    Some(result)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn sign(state: &State, claims: &Value, fault: &Fault) -> Zeroizing<String> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some("JWT".into());
    if !fault.omit_kid {
        header.kid = Some(state.kid.lock().unwrap().clone());
    }
    if fault.wrong_signature {
        let wrong = Zeroizing::new(
            KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_der(),
        );
        return Zeroizing::new(encode(&header, claims, &EncodingKey::from_ed_der(&wrong)).unwrap());
    }
    Zeroizing::new(
        encode(
            &header,
            claims,
            &EncodingKey::from_ed_der(&state.key.lock().unwrap()),
        )
        .unwrap(),
    )
}
fn metadata(state: &State) -> Value {
    let fault = state.fault.lock().unwrap();
    if let Some(value) = &fault.metadata_override {
        return value.clone();
    }
    json!({"issuer":state.issuer,"authorization_endpoint":format!("{}/authorize",state.issuer),"token_endpoint":format!("{}/token",state.issuer),"userinfo_endpoint":format!("{}/userinfo",state.issuer),"jwks_uri":format!("{}/jwks",state.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"],"token_endpoint_auth_methods_supported":["none","client_secret_basic","client_secret_post"]})
}
async fn handle(
    state: Arc<State>,
    request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let result = match (request.method().as_str(), request.uri().path()) {
        ("GET", "/.well-known/openid-configuration") => object(metadata(&state)),
        ("GET", "/jwks") => {
            state.jwks_hits.fetch_add(1, Ordering::SeqCst);
            let fault = state.fault.lock().unwrap();
            object(
                fault
                    .jwks_override
                    .clone()
                    .unwrap_or_else(|| state.jwks.lock().unwrap().clone()),
            )
        }
        ("GET" | "POST", "/authorize") if request.method() == "GET" || state.browser_form => {
            let query = request.uri().query().unwrap_or("").to_owned();
            let posted = request.method() == "POST";
            // A genuine browser credential precedes authorization-code generation.
            let supplied = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(b"browser-fixture:fixture-password")
            );
            let authenticated = if posted {
                let body = Limited::new(request.into_body(), 8192).collect().await.ok();
                let params = body.and_then(|body| {
                    let bytes = body.to_bytes();
                    std::str::from_utf8(&bytes).ok().and_then(form)
                });
                params.is_some_and(|params| {
                    params.len() == 2
                        && params
                            .get("username")
                            .is_some_and(|s| s == "browser-fixture")
                        && params
                            .get("password")
                            .is_some_and(|s| s == "fixture-password")
                })
            } else {
                supplied.as_deref() == Some(expected.as_str())
            };
            if !authenticated {
                if state.browser_form {
                    let callback_origin = form(&query)
                        .and_then(|params| {
                            let clients = state.clients.lock().unwrap();
                            let client = clients.get(params.get("client_id")?)?;
                            (params.get("redirect_uri") == Some(&client.redirect))
                                .then(|| client.redirect.clone())
                        })
                        .and_then(|redirect| Url::parse(&redirect).ok())
                        .map(|redirect| redirect.origin().ascii_serialization());
                    let query = query
                        .replace('&', "&amp;")
                        .replace('"', "&quot;")
                        .replace('<', "&lt;")
                        .replace('>', "&gt;");
                    let mut page=response(if posted {StatusCode::UNAUTHORIZED} else {StatusCode::OK},format!(r#"<!doctype html><html lang="en"><head><title>Owned OIDC fixture</title></head><body><h1>Owned OIDC fixture</h1><form method="post" action="/authorize?{query}"><label>Username <input name="username" autocomplete="username" required></label><label>Password <input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Authenticate</button></form></body></html>"#).into_bytes());
                    page.headers_mut().insert(
                        "content-type",
                        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
                    );
                    page.headers_mut().insert(
                        "cache-control",
                        hyper::header::HeaderValue::from_static("no-store"),
                    );
                    let mut csp = "default-src 'none'; form-action 'self'".to_owned();
                    if let Some(origin) = callback_origin {
                        csp.push(' ');
                        csp.push_str(&origin);
                    }
                    if let Some(origin) = &state.fault.lock().unwrap().browser_return_origin {
                        csp.push(' ');
                        csp.push_str(&origin.ascii_serialization());
                    }
                    csp.push_str("; base-uri 'none'; frame-ancestors 'none'");
                    page.headers_mut().insert(
                        "content-security-policy",
                        hyper::header::HeaderValue::from_str(&csp).unwrap(),
                    );
                    page
                } else {
                    response(StatusCode::UNAUTHORIZED, b"{}".as_slice())
                }
            } else if let Some(params) = form(&query) {
                let client = params
                    .get("client_id")
                    .and_then(|id| state.clients.lock().unwrap().get(id).cloned());
                if let Some(client) = client {
                    let valid = params.get("response_type").is_some_and(|s| s == "code")
                        && params.get("redirect_uri") == Some(&client.redirect)
                        && params
                            .get("code_challenge_method")
                            .is_some_and(|s| s == "S256")
                        && params.get("code_challenge").is_some_and(|s| s.len() == 43)
                        && params
                            .get("scope")
                            .is_some_and(|s| s.split_ascii_whitespace().any(|s| s == "openid"))
                        && params.get("state").is_some_and(|s| {
                            broker_control::upstream_login_purpose_hint(s).is_some()
                        });
                    if !valid {
                        response(StatusCode::BAD_REQUEST, b"{}".as_slice())
                    } else {
                        let mut bytes = [0u8; 32];
                        getrandom::fill(&mut bytes).unwrap();
                        let code = URL_SAFE_NO_PAD.encode(bytes);
                        state.codes.lock().unwrap().insert(
                            code.clone(),
                            Code {
                                client: client.id,
                                redirect: client.redirect.clone(),
                                challenge: params["code_challenge"].clone(),
                                nonce: params.get("nonce").cloned(),
                            },
                        );
                        let mut location = Url::parse(&client.redirect).unwrap();
                        location
                            .query_pairs_mut()
                            .append_pair("code", &code)
                            .append_pair("state", &params["state"]);
                        Response::builder()
                            .status(StatusCode::FOUND)
                            .header("location", location.as_str())
                            .body(Full::new(Bytes::new()))
                            .unwrap()
                    }
                } else {
                    response(StatusCode::BAD_REQUEST, b"{}".as_slice())
                }
            } else {
                response(StatusCode::BAD_REQUEST, b"{}".as_slice())
            }
        }
        ("POST", "/token") => token(state, request).await,
        ("GET", "/userinfo") => {
            state.userinfo_hits.fetch_add(1, Ordering::SeqCst);
            let raw = request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "));
            let subject = raw.and_then(|raw| state.access.lock().unwrap().get(raw).cloned());
            if let Some(subject) = subject {
                let fault = state.fault.lock().unwrap().clone();
                tokio::time::sleep(fault.userinfo_delay).await;
                let mut value = json!({"sub":subject,"preferred_username":"fixture-user","name":"Supplementary Name","email":"profile@example.invalid","organization":{"id":"profile-org"},"groups":[{"name":"profile-team"}],"roles":["admin"]});
                for (k, v) in fault.userinfo_overrides {
                    value[k] = v;
                }
                object(value)
            } else {
                response(StatusCode::UNAUTHORIZED, b"{}".as_slice())
            }
        }
        _ => response(StatusCode::NOT_FOUND, b"{}".as_slice()),
    };
    Ok(result)
}
async fn token(state: Arc<State>, request: Request<Incoming>) -> Response<Body> {
    state.token_hits.fetch_add(1, Ordering::SeqCst);
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Ok(body) = Limited::new(request.into_body(), 16384).collect().await else {
        return response(StatusCode::PAYLOAD_TOO_LARGE, b"{}".as_slice());
    };
    let bytes = body.to_bytes();
    let Ok(raw) = std::str::from_utf8(&bytes) else {
        return response(StatusCode::BAD_REQUEST, b"{}".as_slice());
    };
    let Some(params) = form(raw) else {
        return response(StatusCode::BAD_REQUEST, b"{}".as_slice());
    };
    let client_id = if let Some(basic) = authorization
        .as_deref()
        .and_then(|v| v.strip_prefix("Basic "))
    {
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(basic) else {
            return response(StatusCode::UNAUTHORIZED, b"{}".as_slice());
        };
        let Ok(decoded) = std::str::from_utf8(&decoded) else {
            return response(StatusCode::UNAUTHORIZED, b"{}".as_slice());
        };
        let Some((id, secret)) = decoded.split_once(':') else {
            return response(StatusCode::UNAUTHORIZED, b"{}".as_slice());
        };
        let client = state.clients.lock().unwrap().get(id).cloned();
        if !client
            .is_some_and(|c| c.auth == ClientAuth::Basic && c.secret.as_deref() == Some(secret))
        {
            return response(StatusCode::UNAUTHORIZED, b"{}".as_slice());
        }
        id.to_owned()
    } else {
        let id = params.get("client_id").cloned().unwrap_or_default();
        let client = state.clients.lock().unwrap().get(&id).cloned();
        if !client.is_some_and(|c| match c.auth {
            ClientAuth::Public => !params.contains_key("client_secret"),
            ClientAuth::Post => params.get("client_secret") == c.secret.as_ref(),
            ClientAuth::Basic => false,
        }) {
            return response(StatusCode::UNAUTHORIZED, b"{}".as_slice());
        }
        id
    };
    let code = params
        .get("code")
        .and_then(|c| state.codes.lock().unwrap().remove(c));
    let Some(code) = code else {
        return response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant"}"#.as_slice(),
        );
    };
    let verifier = params.get("code_verifier").cloned().unwrap_or_default();
    let actual = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier));
    if params
        .get("grant_type")
        .is_none_or(|s| s != "authorization_code")
        || code.client != client_id
        || params.get("redirect_uri") != Some(&code.redirect)
        || actual.as_str() != code.challenge
    {
        return response(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant"}"#.as_slice(),
        );
    }
    let fault = state.fault.lock().unwrap().clone();
    tokio::time::sleep(fault.token_delay).await;
    let epoch = now();
    let mut access = json!({"iss":state.issuer,"sub":"fixture-subject","aud":"external-profile-service","preferred_username":"access-user","name":"Access Name","email":"access@example.invalid","organization":{"id":"access-org"},"groups":[{"name":"access-team"}],"roles":["user"],"iat":epoch,"nbf":epoch,"exp":epoch+120});
    for (k, v) in &fault.access_overrides {
        access[k] = v.clone();
    }
    let access_token = sign(&state, &access, &fault);
    state
        .access
        .lock()
        .unwrap()
        .insert(access_token.to_string(), "fixture-subject".into());
    let mut id = json!({"iss":state.issuer,"sub":"fixture-subject","aud":client_id,"preferred_username":"id-user","name":"ID Name","email":"id@example.invalid","organization":{"id":"id-org"},"groups":[{"name":"id-team"}],"roles":["user"],"iat":epoch,"nbf":epoch,"exp":epoch+120});
    if let Some(nonce) = code.nonce {
        id["nonce"] = json!(nonce);
    }
    if !fault.extra_audiences.is_empty() {
        let mut aud = vec![Value::String(client_id.clone())];
        aud.extend(fault.extra_audiences.iter().cloned().map(Value::String));
        id["aud"] = Value::Array(aud);
        id["azp"] = json!(client_id);
    }
    if fault.missing_profile {
        for field in ["name", "email", "organization", "groups"] {
            id.as_object_mut().unwrap().remove(field);
        }
    }
    if fault.missing_username {
        id.as_object_mut().unwrap().remove("preferred_username");
    }
    for (k, v) in &fault.id_overrides {
        id[k] = v.clone();
    }
    if fault.valid_hash {
        let keys: openidconnect::core::CoreJsonWebKeySet =
            serde_json::from_value(state.jwks.lock().unwrap().clone()).unwrap();
        id["at_hash"] = serde_json::to_value(
            openidconnect::AccessTokenHash::from_token(
                &openidconnect::AccessToken::new(access_token.to_string()),
                &openidconnect::core::CoreJwsSigningAlgorithm::EdDsa,
                &keys.keys()[0],
            )
            .unwrap(),
        )
        .unwrap();
    }
    if fault.bad_hash {
        id["at_hash"] = json!("deliberately-wrong");
    }
    let id_token = sign(&state, &id, &fault);
    let mut body =
        json!({"access_token":access_token.as_str(),"token_type":"Bearer","expires_in":120});
    if !fault.omit_id {
        body["id_token"] = json!(id_token.as_str());
    }
    if fault.token_duplicate {
        return response(
            StatusCode::OK,
            br#"{"access_token":"one","access_token":"two","token_type":"Bearer"}"#.as_slice(),
        );
    }
    if fault.token_padding > 0 {
        body["padding"] = json!("x".repeat(fault.token_padding));
    }
    object(body)
}
impl BrowserIssuer {
    pub async fn new() -> Self {
        Self::configured(false).await
    }
    /// Explicit loopback-only transport/form for a real browser; TLS tests keep `new`.
    #[allow(
        dead_code,
        reason = "used by broker-server's real interactive browser contract"
    )]
    pub async fn new_loopback_browser() -> Self {
        Self::configured(true).await
    }
    async fn configured(browser_form: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!(
            "{}://127.0.0.1:{}",
            if browser_form { "http" } else { "https" },
            listener.local_addr().unwrap().port()
        );
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let tls_key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .signed_by(&tls_key, &Issuer::new(ca_params, ca_key))
            .unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivatePkcs8KeyDer::from(tls_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let ca = ca.pem().into_bytes();
        let key = Zeroizing::new(
            KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_der(),
        );
        let public =
            BrokerAccessIssuer::new(&issuer, "unused-resource", "browser-key", &key).unwrap();
        let state = Arc::new(State {
            issuer: issuer.clone(),
            browser_form,
            key: Mutex::new(key),
            kid: Mutex::new("browser-key".into()),
            jwks: Mutex::new(serde_json::to_value(public.jwks()).unwrap()),
            clients: Mutex::new(BTreeMap::new()),
            codes: Mutex::new(BTreeMap::new()),
            access: Mutex::new(BTreeMap::new()),
            fault: Mutex::new(Fault::default()),
            token_hits: AtomicUsize::new(0),
            userinfo_hits: AtomicUsize::new(0),
            jwks_hits: AtomicUsize::new(0),
        });
        let owned = state.clone();
        let (stop, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {_=&mut stopping=>break,accepted=listener.accept()=>{let(stream,_)=accepted.unwrap();let acceptor=acceptor.clone();let state=owned.clone();children.spawn(async move{if state.browser_form { let _=http1::Builder::new().serve_connection(TokioIo::new(stream),service_fn(move|request|handle(state.clone(),request))).await; } else if let Ok(stream)=acceptor.accept(stream).await{let _=http1::Builder::new().serve_connection(TokioIo::new(stream),service_fn(move|request|handle(state.clone(),request))).await;}});},_=children.join_next(),if !children.is_empty()=>{}}
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
            .build()
            .unwrap();
        Self {
            issuer,
            ca,
            state,
            client,
            stop: Some(stop),
            task: Some(task),
        }
    }
    pub fn register(&self, client: ClientRegistration) {
        assert!(
            self.state
                .clients
                .lock()
                .unwrap()
                .insert(client.id.clone(), client)
                .is_none()
        );
    }
    pub fn fault(&self, fault: Fault) {
        *self.state.fault.lock().unwrap() = fault;
    }
    pub fn token_hits(&self) -> usize {
        self.state.token_hits.load(Ordering::SeqCst)
    }
    pub fn userinfo_hits(&self) -> usize {
        self.state.userinfo_hits.load(Ordering::SeqCst)
    }
    pub fn jwks_hits(&self) -> usize {
        self.state.jwks_hits.load(Ordering::SeqCst)
    }
    pub fn keys(&self) -> Value {
        self.state.jwks.lock().unwrap().clone()
    }
    pub fn unrelated_ec_key() -> Value {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let raw = key.public_key_raw();
        assert!(raw.len() == 65 && raw[0] == 4);
        json!({"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","key_ops":["verify"],"x":URL_SAFE_NO_PAD.encode(&raw[1..33]),"y":URL_SAFE_NO_PAD.encode(&raw[33..65])})
    }
    pub fn metadata(&self) -> Value {
        metadata(&self.state)
    }
    pub async fn authorize(&self, issued: &IssuedUpstreamAuthorization) -> Zeroizing<String> {
        issued.check().unwrap();
        self.authorize_at(issued, issued.location().clone()).await
    }
    pub async fn authorize_at(
        &self,
        issued: &IssuedUpstreamAuthorization,
        location: Url,
    ) -> Zeroizing<String> {
        issued.check().unwrap();
        let response = self
            .client
            .get(location)
            .basic_auth("browser-fixture", Some("fixture-password"))
            .send()
            .await
            .unwrap();
        assert!(
            response.status() == StatusCode::FOUND,
            "actual browser credential and PKCE authorization"
        );
        let location = Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        let params = form(location.query().unwrap()).unwrap();
        assert!(
            params
                .get("state")
                .is_some_and(|state| state == issued.state()),
            "actual state binding"
        );
        Zeroizing::new(params["code"].clone())
    }
    pub fn rotate(&self, kid: &str) {
        let key = Zeroizing::new(
            KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_der(),
        );
        let public = BrokerAccessIssuer::new(&self.issuer, "unused-resource", kid, &key).unwrap();
        *self.state.key.lock().unwrap() = key;
        *self.state.kid.lock().unwrap() = kid.into();
        *self.state.jwks.lock().unwrap() = serde_json::to_value(public.jwks()).unwrap();
    }
    pub async fn close(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }
}
impl Drop for BrowserIssuer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
