//! Owned discovery/JWKS issuer with real Ed25519 access signatures.
use axum::{Json, Router, extract::State, routing::get};
use broker_control::BrokerAccessIssuer;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use std::{
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
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;
struct IssuerState {
    issuer: String,
    keys: Mutex<Value>,
    hits: AtomicUsize,
    delay: Mutex<Duration>,
    metadata: Mutex<Option<Value>>,
}
async fn discovery(State(state): State<Arc<IssuerState>>) -> Json<Value> {
    state.hits.fetch_add(1, Ordering::Relaxed);
    let delay = *state.delay.lock().unwrap();
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if let Some(value) = state.metadata.lock().unwrap().clone() {
        return Json(value);
    }
    Json(
        json!({"issuer":state.issuer,"authorization_endpoint":format!("{}/authorize",state.issuer),"jwks_uri":format!("{}/jwks",state.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"]}),
    )
}
async fn jwks(State(state): State<Arc<IssuerState>>) -> Json<Value> {
    state.hits.fetch_add(1, Ordering::Relaxed);
    Json(state.keys.lock().unwrap().clone())
}
pub struct UpstreamFixture {
    pub issuer: String,
    pub ca: Vec<u8>,
    state: Arc<IssuerState>,
    key: Zeroizing<Vec<u8>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl UpstreamFixture {
    pub async fn new() -> Self {
        Self::start(Some(tls())).await
    }
    #[allow(dead_code, reason = "the embeddings contract uses loopback HTTP")]
    pub async fn loopback_http() -> Self {
        Self::start(None).await
    }
    async fn start(tls: Option<(Vec<u8>, TlsAcceptor)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let issuer = format!(
            "{scheme}://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let (ca, acceptor) = match tls {
            Some((ca, acceptor)) => (ca, Some(acceptor)),
            None => (Vec::new(), None),
        };
        let key = Zeroizing::new(
            KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_der(),
        );
        let public =
            BrokerAccessIssuer::new(&issuer, "graphit-broker-resource", "upstream-key", &key)
                .unwrap();
        let state = Arc::new(IssuerState {
            issuer: issuer.clone(),
            keys: Mutex::new(serde_json::to_value(public.jwks()).unwrap()),
            hits: AtomicUsize::new(0),
            delay: Mutex::new(Duration::ZERO),
            metadata: Mutex::new(None),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .with_state(state.clone());
        let (stop, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            let Some(acceptor) = acceptor else {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        let _ = stopping.await;
                    })
                    .await
                    .unwrap();
                return;
            };
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopping=>break,
                    stream=listener.accept()=>{let (stream,_)=stream.unwrap();let acceptor=acceptor.clone();let router=router.clone();
                        connections.spawn(async move {if let Ok(stream)=acceptor.accept(stream).await {
                            let _=http1::Builder::new().serve_connection(TokioIo::new(stream),TowerToHyperService::new(router)).await;
                        }});
                    },
                    _=connections.join_next(),if !connections.is_empty()=>{},
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            issuer,
            ca,
            state,
            key,
            stop: Some(stop),
            task: Some(task),
        }
    }
    pub fn claims(&self) -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        json!({"iss":self.issuer,"aud":"graphit-broker-resource","sub":"external|subject","preferred_username":"alice","name":"Federated","email":"federated@example.invalid","organization":{"id":"external-org"},"groups":[{"name":"z"},{"name":" a "},{"name":"z"}],"scope":"admin:session extra","client_id":"broker-resource-client","token_use":"access","iat":now,"exp":now+120})
    }
    pub fn sign(&self, claims: &Value, kid: &str, typ: &str) -> Zeroizing<String> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        header.typ = Some(typ.into());
        Zeroizing::new(encode(&header, claims, &EncodingKey::from_ed_der(&self.key)).unwrap())
    }
    pub fn hits(&self) -> usize {
        self.state.hits.load(Ordering::Relaxed)
    }
    pub fn delay(&self, delay: Duration) {
        *self.state.delay.lock().unwrap() = delay;
    }
    pub fn metadata(&self) -> Value {
        json!({"issuer":self.issuer,"authorization_endpoint":format!("{}/authorize",self.issuer),"jwks_uri":format!("{}/jwks",self.issuer),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"]})
    }
    pub fn override_metadata(&self, value: Option<Value>) {
        *self.state.metadata.lock().unwrap() = value;
    }
    pub fn keys(&self) -> Value {
        self.state.keys.lock().unwrap().clone()
    }
    pub fn replace_keys(&self, value: Value) {
        *self.state.keys.lock().unwrap() = value;
    }
    pub fn rotate(&mut self, kid: &str) {
        self.key = Zeroizing::new(
            KeyPair::generate_for(&rcgen::PKCS_ED25519)
                .unwrap()
                .serialize_der(),
        );
        let issuer =
            BrokerAccessIssuer::new(&self.issuer, "graphit-broker-resource", kid, &self.key)
                .unwrap();
        *self.state.keys.lock().unwrap() = serde_json::to_value(issuer.jwks()).unwrap();
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
fn tls() -> (Vec<u8>, TlsAcceptor) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let tls_key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    let cert = params
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
    (ca.pem().into_bytes(), TlsAcceptor::from(Arc::new(tls)))
}
impl Drop for UpstreamFixture {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
