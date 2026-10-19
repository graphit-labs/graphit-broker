#[path = "browser_upstream.rs"]
pub mod browser;
#[path = "sqlite_oidc_fixture.rs"]
#[allow(
    unused_imports,
    reason = "OIDC fixture reexports serve different genuine journeys"
)]
pub mod fixture;
#[path = "../../../broker-server/tests/support/upstream.rs"]
pub mod upstream;
use broker_control::*;
use browser::{BrowserIssuer, ClientAuth, ClientRegistration};
use fixture::*;

pub fn limits() -> AdminCookieSessionLimits {
    AdminCookieSessionLimits {
        authorization: AdminBrokerSessionLimits {
            identity: IdentityReadLimits {
                username_bytes: n(128),
                subject_bytes: n(512),
                role_bytes: n(128),
                roles: n(16),
                rows: n(128),
            },
            profile_json_bytes: n(8192),
        },
        metadata: SessionLimits {
            text_bytes: n(2048),
            csrf_bytes: n(43),
            team_bytes: n(512),
            role_bytes: n(128),
            max_teams: n(16),
            max_roles: n(16),
            teams_json_bytes: n(8192),
            roles_json_bytes: n(8192),
            max_lifetime: Duration::from_secs(3600),
        },
    }
}
pub fn policy() -> AdminCookieSessionPolicy {
    AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(1800),
    }
}
pub fn allow_session(f: &Fixture) {
    f.db.execute_batch("INSERT OR IGNORE INTO roles(name,created_at)VALUES('user',0);INSERT OR IGNORE INTO role_permissions(role,action)VALUES('user','session.read')").unwrap();
}
pub fn local_policy() -> LocalAuthPolicy {
    LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(120)).unwrap()
}
pub async fn local_cookie(f: &Fixture) -> IssuedAdminCookie {
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, end())
        .await
        .unwrap();
    let p = Arc::new(local_policy());
    let auth = f.store.local_auth_service(
        Arc::new(digester()),
        Arc::new(LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap()),
        p.clone(),
    );
    let LocalAuthStep::Complete(login) = auth
        .begin(proof, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    else {
        panic!("completed LOCAL login")
    };
    f.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .issue_local(PreparedAdminLogin::try_from(login).unwrap(), &p, end())
        .await
        .unwrap()
}
pub async fn jwt(f: &Fixture) -> Zeroizing<String> {
    let code = f.code(false, false).await;
    let tokens = f
        .producer()
        .exchange(exchange(code.code(), false), end())
        .await
        .unwrap();
    Zeroizing::new(tokens.access_token().to_owned())
}
pub fn browser_client() -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: "Public".into(),
        client_id: "public".into(),
        client_secret: None,
        redirect_url: "https://broker.example/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: true,
        claims_source: UpstreamBrowserClaimsSource::IdToken,
        id_token_additional_audiences: vec![],
    }
}
pub fn config(
    issuer: &str,
    ca: &[u8],
    browser: bool,
    selector: Option<&str>,
) -> UpstreamProviderConfig {
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.into(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec!["admin:session".into()],
        allowed_algorithms: vec![Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["public".into()],
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "sub".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: selector.map(str::to_owned),
            scope: "scope".into(),
        },
        limits: UpstreamReadLimits {
            token_bytes: n(16384),
            response_bytes: n(65536),
            keys: n(16),
            selector_bytes: n(512),
            claim_string_bytes: n(2048),
            profile_json_bytes: n(8192),
            teams: n(32),
        },
        request_timeout: Duration::from_secs(5),
        cache_max_age: Duration::from_secs(300),
        min_refresh_interval: Duration::from_millis(10),
        allow_loopback_http: false,
        trusted_ca_pem: Some(ca.to_vec()),
        browser_clients: if browser {
            vec![browser_client()]
        } else {
            vec![]
        },
    }
}
pub fn trust(configs: Vec<UpstreamProviderConfig>) -> Arc<UpstreamBearerVerifier> {
    Arc::new(UpstreamBearerVerifier::new(ISSUER, n(16384), configs).unwrap())
}
pub async fn browser_op() -> BrowserIssuer {
    let op = BrowserIssuer::new().await;
    op.register(ClientRegistration {
        id: "public".into(),
        secret: None,
        redirect: browser_client().redirect_url.clone(),
        auth: ClientAuth::Public,
    });
    let mut fault = browser::Fault::default();
    fault
        .id_overrides
        .insert("roles".into(), json!(["unknown"]));
    op.fault(fault);
    op
}
pub async fn h1(
    f: &Fixture,
    op: &BrowserIssuer,
    v: &UpstreamBearerVerifier,
    purpose: FlowPurpose,
    original: Instant,
) -> VerifiedUpstreamLogin {
    let id = v.browser_options(end()).unwrap()[0].id.clone();
    let continuation = match purpose {
        FlowPurpose::Admin => FlowContinuation::Admin { provider_id: id },
        FlowPurpose::OAuth => FlowContinuation::OAuth {
            provider_id: id,
            request_id: "genuine-request".into(),
        },
    };
    let login = f.store.upstream_logins(v);
    let issued = login.begin(continuation, original).await.unwrap();
    let code = op.authorize(&issued).await;
    login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            original,
        )
        .await
        .unwrap()
}

// Controlled persisted opaque credential: read/verifier fixture only, not an issuance claim.
pub fn persisted_opaque(f: &Fixture) -> Zeroizing<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    let raw = Zeroizing::new(format!("gb_at_{}", URL_SAFE_NO_PAD.encode(bytes)));
    let hash = digester()
        .token(TokenKind::LocalAccess, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    let principal=json!({"issuer":"local","subject":"alice-subject","username":"alice","auth_method":"local-token","name":"persisted fixture","roles":[],"teams":[],"local_user_revision":1}).to_string();
    f.db.execute("INSERT INTO local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at)VALUES(?1,'persisted-opaque','access','alice-subject','opaque-pseudonym',?2,'client','admin-api','','[\"admin:session\"]',1,'',0,?3,0)",params![hash,principal,utc()+120_000_000]).unwrap();
    raw
}
