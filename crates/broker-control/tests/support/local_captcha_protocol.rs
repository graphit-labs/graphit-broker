//! Private real HTTPS fixture: production endpoints and hostname validation remain fixed.
use super::*;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Bytes, Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    net::TcpListener,
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, rustls};

struct Reply {
    status: u16,
    body: Vec<u8>,
    length: bool,
}
struct ServerState {
    reply: Mutex<Option<Reply>>,
    calls: AtomicUsize,
    forms: Mutex<Vec<Vec<(String, String)>>>,
}
struct Siteverify {
    addr: SocketAddr,
    ca: Vec<u8>,
    state: Arc<ServerState>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
async fn serve(
    request: Request<Incoming>,
    state: Arc<ServerState>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
    assert_eq!(request.method(), "POST");
    assert!(matches!(
        request.uri().path(),
        "/turnstile/v0/siteverify" | "/recaptcha/api/siteverify"
    ));
    assert_eq!(
        request.headers()["content-type"],
        "application/x-www-form-urlencoded"
    );
    let body = request.into_body().collect().await.unwrap().to_bytes();
    let form = url::form_urlencoded::parse(&body)
        .into_owned()
        .collect::<Vec<_>>();
    state.forms.lock().unwrap().push(form);
    state.calls.fetch_add(1, Ordering::SeqCst);
    let reply = state
        .reply
        .lock()
        .unwrap()
        .as_ref()
        .map(|reply| (reply.status, reply.body.clone(), reply.length));
    let Some((status, body, length)) = reply else {
        return std::future::pending().await;
    };
    let mut response = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if status == 302 {
        response = response.header(
            "location",
            "https://www.google.com/recaptcha/api/siteverify",
        );
    }
    if length {
        response = response.header("content-length", body.len());
    }
    let body = if length {
        Full::new(Bytes::from(body)).boxed()
    } else {
        let frames = body
            .chunks(4096)
            .map(|bytes| Ok::<_, Infallible>(Frame::data(Bytes::copy_from_slice(bytes))))
            .collect::<Vec<_>>();
        StreamBody::new(futures_util::stream::iter(frames)).boxed()
    };
    Ok(response.body(body).unwrap())
}
impl Siteverify {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let tls_key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![
            "challenges.cloudflare.com".into(),
            "www.google.com".into(),
        ])
        .unwrap()
        .signed_by(&tls_key, &Issuer::new(ca_params, ca_key))
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(tls_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let state = Arc::new(ServerState {
            reply: Mutex::new(Some(Reply {
                status: 200,
                body: br#"{"success":true,"hostname":" BROKER.EXAMPLE ","action":"admin-login"}"#
                    .to_vec(),
                length: true,
            })),
            calls: AtomicUsize::new(0),
            forms: Mutex::new(Vec::new()),
        });
        let shared = Arc::clone(&state);
        let (stop, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopping=>break,
                    stream=listener.accept()=>{
                        let (stream,_)=stream.unwrap(); let acceptor=acceptor.clone(); let state=Arc::clone(&shared);
                        connections.spawn(async move { if let Ok(stream)=acceptor.accept(stream).await {
                            let _=http1::Builder::new().serve_connection(TokioIo::new(stream),service_fn(move|request|serve(request,Arc::clone(&state)))).await;
                        }});
                    },
                    _=connections.join_next(),if !connections.is_empty()=>{}
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            addr,
            ca: ca.pem().into_bytes(),
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }
    fn captcha(&self, provider: LocalCaptchaProvider, multiplier: f64) -> LocalCaptcha {
        let mut captcha = LocalCaptcha::new(
            LocalCaptchaConfiguration::Enabled {
                provider,
                site_key: "public-fixture-site".into(),
                secret_key: Zeroizing::new("protected-fixture-key".into()),
                public_url: Url::parse("https://broker.example").unwrap(),
                trigger_multiplier: multiplier,
                verification_timeout: Duration::from_secs(5),
            },
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(2).unwrap(),
        )
        .unwrap();
        // Private test-only client trust/DNS, not an endpoint input or TLS bypass.
        captcha.enabled.as_mut().unwrap().client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .tls_certs_only([reqwest::Certificate::from_pem(&self.ca).unwrap()])
            .resolve("challenges.cloudflare.com", self.addr)
            .resolve("www.google.com", self.addr)
            .build()
            .unwrap();
        captcha
    }
    fn set(&self, status: u16, body: Vec<u8>, length: bool) {
        *self.state.reply.lock().unwrap() = Some(Reply {
            status,
            body,
            length,
        });
    }
    fn calls(&self) -> usize {
        self.state.calls.load(Ordering::SeqCst)
    }
    async fn close(mut self) {
        let _ = self.stop.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }
}
impl Drop for Siteverify {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual fixed-host Rust HTTPS CAPTCHA, PostgreSQL TLS NOSUPERUSER and native Argon2 password/cookie proof"]
async fn postgres_https_local_password_admission_contract() {
    use crate::admin_cookie_fixture::{CookieFixture, PASSWORD, limits, policy};
    use crate::support::{deadline, n};
    use crate::{
        LocalAuthStep, LocalPasswordAdmission, LocalPasswordAdmissionError,
        LocalPasswordAdmissionPolicy, PreparedAdminLogin,
    };
    use broker_security::LocalAuthBinding;
    let fixture = CookieFixture::new().await;
    let site = Siteverify::new().await;
    let admission = LocalPasswordAdmission::new(
        LocalPasswordAdmissionPolicy {
            max_failures: n(1),
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            workers: n(1),
            saturation_multiplier: n(2),
            max_tracked: n(4096),
        },
        &fixture.engine,
        site.captcha(LocalCaptchaProvider::Turnstile, 0.0),
    )
    .unwrap();
    let view = fixture
        .store
        .admitted_local_passwords(&fixture.engine, &admission, LocalAuthPurpose::AdminLogin)
        .unwrap();
    assert!(matches!(
        view.authenticate("alice", PASSWORD, None, deadline()).await,
        Err(LocalPasswordAdmissionError::CaptchaRequired(_))
    ));
    assert_eq!(site.calls(), 0);
    site.set(
        200,
        br#"{"success":false,"hostname":"broker.example","action":"admin-login"}"#.to_vec(),
        true,
    );
    for _ in 0..2 {
        assert!(matches!(
            view.authenticate("alice", PASSWORD, Some("fixture-proof"), deadline())
                .await,
            Err(LocalPasswordAdmissionError::CaptchaRequired(_))
        ));
    }
    site.set(
        200,
        br#"{"success":true,"hostname":"broker.example","action":"admin-login"}"#.to_vec(),
        true,
    );
    let original = deadline();
    let password = view
        .authenticate(" alice ", PASSWORD, Some("fixture-proof"), original)
        .await
        .unwrap();
    assert_eq!(password.username(), "alice");
    assert_eq!(password.auth_method(), "local-password");
    let auth =
        fixture
            .store
            .local_auth_service(&fixture.digester, &fixture.protector, &fixture.exempt);
    let login = match auth
        .begin(password, LocalAuthBinding::AdminLogin, original)
        .await
        .unwrap()
    {
        LocalAuthStep::Complete(login) => login,
        _ => panic!("genuine fixture must complete LOCAL"),
    };
    let cookie = fixture
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .issue_local(
            PreparedAdminLogin::try_from(login).unwrap(),
            &fixture.exempt,
            original,
        )
        .await
        .unwrap();
    assert_eq!(cookie.secret().len(), 43);
    let oauth = fixture
        .store
        .admitted_local_passwords(
            &fixture.engine,
            &admission,
            LocalAuthPurpose::OauthAuthorize,
        )
        .unwrap();
    let observed = admission
        .next_password_challenge(LocalAuthPurpose::OauthAuthorize)
        .unwrap()
        .unwrap();
    assert_eq!(observed.action(), Some("oauth-login"));
    // Wrong-action replies must stop before a real wrong-password guess can charge the shared owner.
    for _ in 0..2 {
        match oauth
            .authenticate(
                "alice",
                "a wrong genuine native password",
                Some("fixture-proof"),
                deadline(),
            )
            .await
        {
            Err(LocalPasswordAdmissionError::CaptchaRequired(challenge)) => {
                assert_eq!(challenge.action(), Some("oauth-login"))
            }
            _ => panic!("Admin CAPTCHA must not admit an OAuth password guess"),
        }
    }
    site.set(
        200,
        serde_json::to_vec(
            &serde_json::json!({"success":true,"hostname":"broker.example","action":"oauth-login"}),
        )
        .unwrap(),
        true,
    );
    let original = deadline();
    let password = oauth
        .authenticate("alice", PASSWORD, Some("fixture-proof"), original)
        .await
        .unwrap();
    let request = broker_security::new_local_auth_challenge().unwrap();
    let login = match auth
        .begin(
            password,
            LocalAuthBinding::OauthAuthorize(request.as_bytes()),
            original,
        )
        .await
        .unwrap()
    {
        LocalAuthStep::Complete(login) => login,
        _ => panic!("genuine password-only OAuth fixture must complete LOCAL"),
    };
    login
        .verify_binding(
            &fixture.digester,
            LocalAuthBinding::OauthAuthorize(request.as_bytes()),
        )
        .unwrap();
    let prepared = crate::PreparedOidcLogin::try_from(login).unwrap();
    drop(prepared);

    let calls = site.calls();
    let one = admission
        .admit_password_change(&fixture.engine, deadline())
        .unwrap();
    let two = admission
        .admit_password_change(&fixture.engine, deadline())
        .unwrap();
    for saturated in [&view, &oauth] {
        assert!(
            matches!(saturated.authenticate("alice",PASSWORD,Some("fixture-proof"),deadline()).await,Err(LocalPasswordAdmissionError::RateLimited(wait)) if wait == Duration::from_secs(1))
        );
    }
    assert_eq!(site.calls(), calls);
    drop(one);
    drop(two);
    assert!(matches!(
        oauth
            .authenticate(
                "alice",
                "a wrong genuine native password",
                Some("fixture-proof"),
                deadline()
            )
            .await,
        Err(LocalPasswordAdmissionError::Unauthenticated)
    ));
    let calls = site.calls();
    assert!(matches!(
        view.authenticate("alice", PASSWORD, Some("fixture-proof"), deadline())
            .await,
        Err(LocalPasswordAdmissionError::RateLimited(_))
    ));
    assert_eq!(site.calls(), calls);
    admission.close();
    fixture.engine.close().await;
    site.close().await;
    fixture.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_fixed_host_https_siteverify_protocol() {
    let site = Siteverify::new().await;
    let mut captcha = site.captcha(LocalCaptchaProvider::Turnstile, 0.0);
    assert!(captcha.required(1));
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                None,
                Instant::now() + Duration::from_secs(10)
            )
            .await,
        Err(CaptchaFailure::Required)
    ));
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some(" "),
                Instant::now() + Duration::from_secs(10)
            )
            .await,
        Err(CaptchaFailure::Required)
    ));
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some(&"x".repeat(2049)),
                Instant::now() + Duration::from_secs(10)
            )
            .await,
        Err(CaptchaFailure::Required)
    ));
    assert_eq!(site.calls(), 0);
    assert!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some("  actual-fixture-proof  "),
                Instant::now() + Duration::from_secs(10)
            )
            .await
            .is_ok()
    );
    assert_eq!(
        *site.state.forms.lock().unwrap(),
        vec![vec![
            ("secret".into(), "protected-fixture-key".into()),
            ("response".into(), "actual-fixture-proof".into())
        ]]
    );
    let purposes = [
        (LocalAuthPurpose::AdminLogin, "admin-login"),
        (LocalAuthPurpose::OauthAuthorize, "oauth-login"),
        (LocalAuthPurpose::DeviceApprove, "device-login"),
    ];
    let calls = site.calls();
    let challenges = purposes.map(|(purpose, _)| captcha.challenge(purpose).unwrap());
    for (challenge, (_, expected)) in challenges.iter().zip(purposes) {
        assert_eq!(challenge.action(), Some(expected));
    }
    assert_eq!(
        site.calls(),
        calls,
        "public challenge observation performs no network work"
    );
    for (reply_purpose, action) in purposes {
        site.set(
            200,
            serde_json::to_vec(
                &serde_json::json!({"success":true,"hostname":"broker.example","action":action}),
            )
            .unwrap(),
            true,
        );
        for (purpose, _) in purposes {
            let result = captcha
                .verify(
                    purpose,
                    Some("fixture-proof"),
                    Instant::now() + Duration::from_secs(10),
                )
                .await;
            assert_eq!(
                result.is_ok(),
                purpose as u8 == reply_purpose as u8,
                "Turnstile action must match the trusted route purpose"
            );
        }
    }
    site.set(
        200,
        br#"{"success":true,"hostname":"broker.example","action":"admin-login"}"#.to_vec(),
        true,
    );
    let (admin, oauth) = tokio::join!(
        captcha.verify(
            LocalAuthPurpose::AdminLogin,
            Some("fixture-proof"),
            Instant::now() + Duration::from_secs(10)
        ),
        captcha.verify(
            LocalAuthPurpose::OauthAuthorize,
            Some("fixture-proof"),
            Instant::now() + Duration::from_secs(10)
        ),
    );
    assert!(admin.is_ok());
    assert!(matches!(oauth, Err(CaptchaFailure::Required)));
    for (status, body) in [
        (
            200,
            br#"{"success":false,"hostname":"broker.example","action":"admin-login"}"#.to_vec(),
        ),
        (
            200,
            br#"{"success":"true","hostname":"broker.example","action":"admin-login"}"#.to_vec(),
        ),
        (
            200,
            br#"{"success":true,"hostname":"other.example","action":"admin-login"}"#.to_vec(),
        ),
        (
            200,
            br#"{"success":true,"hostname":"broker.example","action":"other"}"#.to_vec(),
        ),
        (
            200,
            br#"{"success":true,"hostname":"broker.example"}"#.to_vec(),
        ),
        (200, b"{}{}".to_vec()),
        (200, vec![b'x'; RESPONSE_BYTES + 1]),
        (403, b"{}".to_vec()),
        (302, b"{}".to_vec()),
    ] {
        site.set(status, body, true);
        let calls = site.calls();
        assert!(matches!(
            captcha
                .verify(
                    LocalAuthPurpose::AdminLogin,
                    Some("fixture-proof"),
                    Instant::now() + Duration::from_secs(10)
                )
                .await,
            Err(CaptchaFailure::Required)
        ));
        assert_eq!(
            site.calls(),
            calls + 1,
            "redirect or denial must never retry/follow"
        );
    }
    site.set(200, vec![b'x'; RESPONSE_BYTES + 1], false);
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some("fixture-proof"),
                Instant::now() + Duration::from_secs(10)
            )
            .await,
        Err(CaptchaFailure::Required)
    ));
    site.set(
        200,
        br#"{"success":true,"hostname":"broker.example"}"#.to_vec(),
        true,
    );
    let google = site.captcha(LocalCaptchaProvider::Recaptcha, 1.5);
    assert!(!google.required(1));
    assert!(google.required(2));
    assert!(
        google
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some("fixture-proof"),
                Instant::now() + Duration::from_secs(10)
            )
            .await
            .is_ok()
    );
    for (purpose, _) in purposes {
        assert_eq!(google.challenge(purpose).unwrap().action(), None);
        assert!(
            google
                .verify(
                    purpose,
                    Some("fixture-proof"),
                    Instant::now() + Duration::from_secs(10)
                )
                .await
                .is_ok()
        );
    }
    // The peer receives requests but deliberately never provides a response.
    *site.state.reply.lock().unwrap() = None;
    captcha.enabled.as_mut().unwrap().timeout = Duration::from_millis(500);
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some("fixture-proof"),
                Instant::now() + Duration::from_secs(10)
            )
            .await,
        Err(CaptchaFailure::Required)
    ));
    captcha.enabled.as_mut().unwrap().timeout = Duration::from_secs(5);
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some("fixture-proof"),
                Instant::now() + Duration::from_millis(50)
            )
            .await,
        Err(CaptchaFailure::Control(ControlError::Deadline))
    ));
    let calls = site.calls();
    assert!(matches!(
        captcha
            .verify(
                LocalAuthPurpose::AdminLogin,
                Some("fixture-proof"),
                Instant::now()
            )
            .await,
        Err(CaptchaFailure::Control(ControlError::Deadline))
    ));
    assert_eq!(site.calls(), calls);
    assert!(!format!("{captcha:?}").contains("protected-fixture-key"));
    site.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual fixed-host Rust HTTPS CAPTCHA, private SQLite and native Argon2 proof"]
async fn sqlite_https_local_password_admission_contract() {
    use crate::{
        FlowLimits, LocalAuthPolicy, LocalAuthStep, LocalPasswordAdmission,
        LocalPasswordAdmissionError, LocalPasswordAdmissionPolicy, LocalPasswordEngine,
        SqliteControlConfig, SqliteControlStore,
    };
    use broker_security::{
        CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
    };
    use rusqlite::Connection;
    use std::time::Instant;
    fn n(v: usize) -> NonZeroUsize {
        NonZeroUsize::new(v).unwrap()
    }
    fn end() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }
    fn digest() -> CredentialDigester {
        CredentialDigester::new(
            Zeroizing::new(vec![71; 32].into_boxed_slice()),
            DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
        )
        .unwrap()
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("private").join("broker.db");
    let config = SqliteControlConfig::new(
        path.clone(),
        Duration::from_secs(10),
        Duration::from_secs(20),
        Duration::from_secs(10),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(1024),
            continuation_bytes: n(4096),
        },
    )
    .unwrap();
    let store = SqliteControlStore::open(config, digest(), end())
        .await
        .unwrap();
    let engine = LocalPasswordEngine::new(
        LocalPasswordHasher::new(Zeroizing::new(vec![73; 32].into_boxed_slice())).unwrap(),
        n(1),
        end(),
    )
    .await
    .unwrap();
    let password = "synthetic native HTTPS SQLite password";
    let phc = engine.hash(password, end()).await.unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute("INSERT INTO local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','sqlite-https-subject','human',?1,'','','','[]',1,0,1,0,0)",[phc.as_str()]).unwrap();
    let site = Siteverify::new().await;
    let admission = LocalPasswordAdmission::new(
        LocalPasswordAdmissionPolicy {
            max_failures: n(2),
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            workers: n(1),
            saturation_multiplier: n(2),
            max_tracked: n(4096),
        },
        &engine,
        site.captcha(LocalCaptchaProvider::Turnstile, 0.0),
    )
    .unwrap();
    let view = store
        .admitted_local_passwords(&engine, &admission, LocalAuthPurpose::DeviceApprove)
        .unwrap();
    assert!(matches!(
        view.authenticate("alice", password, None, end()).await,
        Err(LocalPasswordAdmissionError::CaptchaRequired(_))
    ));
    assert_eq!(site.calls(), 0);
    for reply in [
        br#"{"success":true,"hostname":"wrong.example","action":"device-login"}"#.as_slice(),
        br#"{"success":true,"hostname":"broker.example","action":"oauth-login"}"#.as_slice(),
    ] {
        site.set(200, reply.to_vec(), true);
        assert!(matches!(
            view.authenticate("alice", password, Some("opaque-provider-proof"), end())
                .await,
            Err(LocalPasswordAdmissionError::CaptchaRequired(_))
        ));
    }
    assert_eq!(site.calls(), 2);
    site.set(
        200,
        br#"{"success":true,"hostname":"broker.example","action":"device-login"}"#.to_vec(),
        true,
    );
    assert!(matches!(
        view.authenticate(
            "alice",
            "wrong-password",
            Some("opaque-provider-proof"),
            end()
        )
        .await,
        Err(LocalPasswordAdmissionError::Unauthenticated)
    ));
    let proof = view
        .authenticate(" alice ", password, Some("opaque-provider-proof"), end())
        .await
        .unwrap();
    assert_eq!(proof.subject(), "sqlite-https-subject");
    let d = Arc::new(digest());
    let service = store.local_auth_service(
        d.clone(),
        Arc::new(LocalMfaProtector::new(Zeroizing::new(vec![79; 32].into_boxed_slice())).unwrap()),
        Arc::new(
            LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120)).unwrap(),
        ),
    );
    let LocalAuthStep::Complete(login) = service
        .begin(proof, LocalAuthBinding::DeviceApprove(b"NATIVE123"), end())
        .await
        .unwrap()
    else {
        panic!("explicit exemption must complete genuine LOCAL login");
    };
    login
        .verify_binding(&d, LocalAuthBinding::DeviceApprove(b"NATIVE123"))
        .unwrap();
    assert_eq!(login.auth_method(), "local-password");
    assert_eq!(site.calls(), 4);
    admission.close();
    engine.close().await;
    store.shutdown(end()).await.unwrap();
    drop(db);
    site.close().await;
}
