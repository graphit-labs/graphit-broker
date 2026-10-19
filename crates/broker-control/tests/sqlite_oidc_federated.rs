#[path = "support/browser_upstream.rs"]
pub mod browser;
#[path = "support/sqlite_oidc_fixture.rs"]
pub mod fixture;
use broker_control::{
    FlowContinuation, OidcUserInfoError, UpstreamAccessPolicy, UpstreamBearerVerifier,
    UpstreamBrowserClaimsSource, UpstreamBrowserClient, UpstreamClaimSelectors,
    UpstreamLoginCallback, UpstreamLoginFailure, UpstreamProviderConfig, UpstreamReadLimits,
    VerifiedUpstreamLogin,
};
use browser::{BrowserIssuer, ClientAuth, ClientRegistration};
use fixture::*;
pub fn client(id: &str) -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: id.into(),
        client_id: id.into(),
        client_secret: None,
        redirect_url: "https://broker.example/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: true,
        claims_source: UpstreamBrowserClaimsSource::IdToken,
        id_token_additional_audiences: vec![],
    }
}
pub fn register(issuer: &BrowserIssuer, id: &str) {
    issuer.register(ClientRegistration {
        id: id.into(),
        secret: None,
        redirect: client(id).redirect_url.clone(),
        auth: ClientAuth::Public,
    });
}
pub fn configured(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamProviderConfig {
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec![],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["public".into(), "other".into()],
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "mapped_subject".into(),
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
        trusted_ca_pem: Some(issuer.ca.clone()),
        browser_clients: clients,
    }
}
pub fn verifier(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamBearerVerifier {
    UpstreamBearerVerifier::new(
        ISSUER,
        n(16384),
        vec![configured(issuer, clients, selector)],
    )
    .unwrap()
}

async fn new_op() -> BrowserIssuer {
    let op = BrowserIssuer::new().await;
    let mut fault = browser::Fault::default();
    fault
        .id_overrides
        .insert("mapped_subject".into(), json!("alice-subject"));
    fault.id_overrides.insert("roles".into(), json!(["editor"]));
    op.fault(fault);
    op
}
async fn proof(
    f: &Fixture,
    op: &BrowserIssuer,
    verifier: &UpstreamBearerVerifier,
    request: &str,
    original: Instant,
) -> VerifiedUpstreamLogin {
    let login = f.store.upstream_logins(verifier);
    let issued = login
        .begin(
            FlowContinuation::OAuth {
                provider_id: verifier.browser_options(end()).unwrap()[0].id.clone(),
                request_id: request.into(),
            },
            original,
        )
        .await
        .unwrap();
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
async fn code(
    f: &Fixture,
    op: &BrowserIssuer,
    verifier: Arc<UpstreamBearerVerifier>,
    dynamic: bool,
) -> AuthorizedOidcAuthorization {
    let auth = f.store.browser_oidc_authorizations(f.authorization.clone());
    let mut input = request(dynamic, true);
    input.state = "literal-state\0kept";
    input.nonce = "literal-nonce\0kept";
    let pending = auth.create(input, end()).await.unwrap();
    let login = proof(f, op, &verifier, pending.request(), end()).await;
    auth.complete_upstream(login, verifier, end())
        .await
        .unwrap()
}
fn empty_trust() -> Arc<UpstreamBearerVerifier> {
    Arc::new(UpstreamBearerVerifier::new(ISSUER, n(16384), vec![]).unwrap())
}
fn unrevoked(f: &Fixture) -> i64 {
    f.db.query_row(
        "SELECT count(*) FROM local_tokens WHERE revoked_at IS NULL",
        [],
        |r| r.get(0),
    )
    .unwrap()
}
#[tokio::test]
async fn sqlite_userinfo_configuration_and_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let store = SqliteControlStore::open(
        config(&temp.path().join("quick/broker.db")),
        digester(),
        end(),
    )
    .await
    .unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer = BrokerAccessIssuer::new(ISSUER, AUDIENCE, "key", &key.serialize_der()).unwrap();
    let bad = Arc::new(
        broker_control::BrokerAccessVerifier::new(ISSUER, "other", None, issuer.jwks(), n(8192))
            .unwrap(),
    );
    assert!(matches!(
        store.oidc_userinfo(authorization(), bad),
        Err(OidcUserInfoError::InvalidConfiguration)
    ));
    let good = Arc::new(
        broker_control::BrokerAccessVerifier::new(ISSUER, AUDIENCE, None, issuer.jwks(), n(8192))
            .unwrap(),
    );
    let userinfo = store.oidc_userinfo(authorization(), good).unwrap();
    assert_eq!(
        userinfo.profile("invalid", end()).await.unwrap_err(),
        OidcUserInfoError::InvalidToken
    );
    assert_eq!(
        userinfo
            .profile("invalid", Instant::now())
            .await
            .unwrap_err(),
        OidcUserInfoError::Control(ControlError::Deadline)
    );
    store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real file SQLite and HTTPS OP, H1 SDK, S256, signed grants and offline UserInfo"]
async fn sqlite_genuine_h1_grants_refresh_and_userinfo_without_op() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    let v = Arc::new(verifier(&op, vec![client("public")], Some("roles")));
    let grant = code(&f, &op, v.clone(), true).await;
    assert_eq!(grant.amr(), ["federated"]);
    let hits = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    assert_eq!(hits.0, 1);
    let before = f.tokens();
    assert_eq!(
        f.producer()
            .exchange(exchange(grant.code(), true), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(f.tokens(), before);
    assert!(f.code_exists(grant.code()));
    let mut wrong = exchange(grant.code(), true);
    wrong.code_verifier = Some("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    assert_eq!(
        f.producer()
            .with_upstream(v.clone())
            .exchange(wrong, end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert!(f.code_exists(grant.code()));
    op.close().await;
    let issued = f
        .producer()
        .with_upstream(v.clone())
        .exchange(exchange(grant.code(), true), end())
        .await
        .unwrap();
    let access = claims(&f.issuer, issued.access_token(), AUDIENCE);
    let id = claims(&f.issuer, issued.id_token(), DYNAMIC);
    assert_eq!(id["amr"], json!(["federated"]));
    assert_eq!(id["nonce"], "literal-nonce\0kept");
    assert_eq!(id["auth_time"], grant.auth_time().as_i64() / 1_000_000);
    assert_eq!(id["sub"], grant.oidc_subject());
    assert_eq!(access["aud"], json!([AUDIENCE, RESOURCE]));
    assert!(!f.code_exists(grant.code()));
    let profile = f
        .store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(v.clone())
        .profile(issued.access_token(), end())
        .await
        .unwrap();
    let profile = serde_json::to_value(profile).unwrap();
    assert_eq!(profile["sub"], grant.oidc_subject());
    assert_eq!(profile["preferred_username"], access["preferred_username"]);
    assert_eq!(profile["roles"], access["roles"]);
    let snapshot: (String, i64, i64, i64) = f.db.query_row("SELECT principal_json,local_user_revision,auth_time,expires_at FROM local_tokens WHERE token_kind='refresh'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&snapshot.0).unwrap()["auth_method"],
        "oidc"
    );
    assert_eq!(snapshot.1, 0);
    let rotated = f
        .rotator()
        .with_upstream(v.clone())
        .rotate(refresh(issued.refresh_token().unwrap(), true), end())
        .await
        .unwrap();
    let nextid = claims(&f.issuer, rotated.id_token(), DYNAMIC);
    assert_eq!(nextid["amr"], json!(["oidc"]));
    assert_eq!(nextid["auth_time"], id["auth_time"]);
    assert_eq!(nextid["sub"], id["sub"]);
    assert_eq!(nextid["roles"], id["roles"]);
    assert_eq!(f.db.query_row("SELECT expires_at FROM local_tokens WHERE token_kind='refresh' AND consumed_at IS NULL", [], |r| r.get::<_,i64>(0)).unwrap(), snapshot.3);
    let denied = f
        .store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(empty_trust())
        .profile(rotated.access_token(), end())
        .await
        .unwrap_err();
    assert_eq!(denied, OidcUserInfoError::InvalidToken);
    assert_eq!(
        claims(&f.issuer, rotated.access_token(), AUDIENCE)["sub"],
        grant.oidc_subject(),
        "JWT local verification remains independent"
    );
    let count = unrevoked(&f);
    assert_eq!(
        f.rotator()
            .with_upstream(empty_trust())
            .rotate(refresh(issued.refresh_token().unwrap(), true), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(
        unrevoked(&f),
        count,
        "trust failure precedes reuse revocation"
    );
    assert_eq!(
        f.rotator()
            .with_upstream(v)
            .rotate(refresh(issued.refresh_token().unwrap(), true), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(unrevoked(&f), 0);
    assert_eq!((op.token_hits(), op.userinfo_hits(), op.jwks_hits()), hits);
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real SQLite matching H1 consumption, proof owner, Original SQL contention and purpose"]
async fn sqlite_h1_binding_owner_purpose_and_original() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    let v = Arc::new(verifier(&op, vec![client("public")], None));
    let auth = f.store.browser_oidc_authorizations(f.authorization.clone());
    let pending = auth.create(request(false, true), end()).await.unwrap();
    let continuation = || FlowContinuation::OAuth {
        provider_id: v.browser_options(end()).unwrap()[0].id.clone(),
        request_id: pending.request().into(),
    };
    let issued = f
        .store
        .upstream_logins(&v)
        .begin(continuation(), end())
        .await
        .unwrap();
    let code = op.authorize(&issued).await;
    let error = f
        .store
        .upstream_logins(&v)
        .complete(
            issued.state(),
            &"A".repeat(43),
            UpstreamLoginCallback::Code(&code),
            end(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.failure(),
        UpstreamLoginFailure::InvalidState
    ));
    assert!(error.continuation().is_none());
    assert_eq!(op.token_hits(), 0);
    let login = f
        .store
        .upstream_logins(&v)
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            end(),
        )
        .await
        .unwrap();
    let other = Arc::new(verifier(&op, vec![client("public")], None));
    assert_eq!(
        auth.complete_upstream(login, other, end())
            .await
            .unwrap_err(),
        AuthError::InvalidLogin
    );
    assert!(auth.load(pending.request(), end()).await.unwrap().is_some());
    let admin = f
        .store
        .upstream_logins(&v)
        .begin(
            FlowContinuation::Admin {
                provider_id: v.browser_options(end()).unwrap()[0].id.clone(),
            },
            end(),
        )
        .await
        .unwrap();
    let code = op.authorize(&admin).await;
    let admin = f
        .store
        .upstream_logins(&v)
        .complete(
            admin.state(),
            admin.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            end(),
        )
        .await
        .unwrap();
    assert_eq!(
        auth.complete_upstream(admin, v.clone(), end())
            .await
            .unwrap_err(),
        AuthError::InvalidLogin
    );
    let cutoff = Instant::now() + Duration::from_millis(1500);
    let login = proof(&f, &op, &v, pending.request(), cutoff).await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let start = Instant::now();
    let result = auth.complete_upstream(login, v.clone(), end()).await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(matches!(
        result,
        Err(AuthError::Control(ControlError::Deadline))
    ));
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "protected Original bounds actual SQL wait"
    );
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let login = proof(&f, &op, &v, pending.request(), end()).await;
    auth.complete_upstream(login, v, end()).await.unwrap();
    op.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine H1 snapshot with current issuer, selector and multiple OAuth channels"]
async fn sqlite_federated_current_trust_precedes_effects() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    register(&op, "other");
    let owner = Arc::new(verifier(
        &op,
        vec![client("public"), client("other")],
        Some("roles"),
    ));
    let grant = code(&f, &op, owner.clone(), true).await;
    for trust in [
        empty_trust(),
        Arc::new(verifier(&op, vec![], Some("roles"))),
        Arc::new(verifier(&op, vec![client("public")], None)),
        Arc::new(verifier(&op, vec![client("public")], Some("other_roles"))),
    ] {
        assert_eq!(
            f.producer()
                .with_upstream(trust)
                .exchange(exchange(grant.code(), true), end())
                .await
                .unwrap_err(),
            Error::InvalidGrant
        );
        assert!(f.code_exists(grant.code()));
        assert_eq!(f.tokens(), 0);
    }
    // Removing one channel preserves a persisted snapshot while the issuer still has another.
    let remaining = Arc::new(verifier(&op, vec![client("other")], Some("roles")));
    let issued = f
        .producer()
        .with_upstream(remaining.clone())
        .exchange(exchange(grant.code(), true), end())
        .await
        .unwrap();
    let raw = issued.refresh_token().unwrap();
    let count = unrevoked(&f);
    for trust in [
        empty_trust(),
        Arc::new(verifier(&op, vec![client("other")], None)),
        Arc::new(verifier(&op, vec![client("other")], Some("other_roles"))),
    ] {
        assert_eq!(
            f.rotator()
                .with_upstream(trust.clone())
                .rotate(refresh(raw, true), end())
                .await
                .unwrap_err(),
            Error::InvalidGrant
        );
        assert_eq!(
            f.store
                .oidc_userinfo(f.authorization.clone(), f.verifier())
                .unwrap()
                .with_upstream(trust)
                .profile(issued.access_token(), end())
                .await
                .unwrap_err(),
            OidcUserInfoError::InvalidToken
        );
        assert_eq!(unrevoked(&f), count);
    }
    let next = f
        .rotator()
        .with_upstream(remaining.clone())
        .rotate(refresh(raw, true), end())
        .await
        .unwrap();
    let without_roles = Arc::new(verifier(&op, vec![client("other")], None));
    let no_selector = code(&f, &op, without_roles.clone(), true).await;
    assert_eq!(
        f.producer()
            .with_upstream(remaining.clone())
            .exchange(exchange(no_selector.code(), true), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant,
        "adding a selector requires new login"
    );
    assert!(f.code_exists(no_selector.code()));
    let unselected = f
        .producer()
        .with_upstream(without_roles)
        .exchange(exchange(no_selector.code(), true), end())
        .await
        .unwrap();
    assert_eq!(
        f.store
            .oidc_userinfo(f.authorization.clone(), f.verifier())
            .unwrap()
            .with_upstream(remaining.clone())
            .profile(unselected.access_token(), end())
            .await
            .unwrap_err(),
        OidcUserInfoError::InvalidToken,
        "adding a selector invalidates an existing unselected profile snapshot"
    );
    let hits = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    op.close().await;
    f.db.execute(
        "DELETE FROM oauth_dynamic_clients WHERE client_id=?1",
        [DYNAMIC],
    )
    .unwrap();
    let profile = f
        .store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(remaining.clone())
        .profile(next.access_token(), end())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(profile).unwrap()["sub"],
        grant.oidc_subject(),
        "UserInfo has no current DCR dependency"
    );
    assert!(
        f.rotator()
            .with_upstream(remaining)
            .rotate(refresh(next.refresh_token().unwrap(), true), end())
            .await
            .is_err()
    );
    assert_eq!((op.token_hits(), op.userinfo_hits(), op.jwks_hits()), hits);
    f.close().await;
}
fn local_auth(f: &Fixture, required: bool) -> broker_control::SqliteLocalAuthService<'_> {
    f.store.local_auth_service(
        Arc::new(digester()),
        Arc::new(LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap()),
        Arc::new(
            LocalAuthPolicy::new(required, "Graphit Broker".into(), Duration::from_secs(120))
                .unwrap(),
        ),
    )
}
fn mfa_limiter() -> Arc<broker_control::LocalMfaAttemptLimiter> {
    Arc::new(broker_control::LocalMfaAttemptLimiter::new(
        broker_control::LocalMfaAttemptPolicy::new(
            std::num::NonZeroU32::new(5).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            n(16),
        )
        .unwrap(),
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine H1 and LOCAL same raw subject, native password change and enrollment with rollback"]
async fn sqlite_local_mutations_preserve_real_federated_grants() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    let v = Arc::new(verifier(&op, vec![client("public")], Some("roles")));
    let fed = code(&f, &op, v.clone(), false).await;
    let issued = f
        .producer()
        .with_upstream(v.clone())
        .exchange(exchange(fed.code(), false), end())
        .await
        .unwrap();
    let pending_fed = code(&f, &op, v.clone(), false).await;
    let local = f.code(false, true).await;
    let local_tokens = f
        .producer()
        .exchange(exchange(local.code(), false), end())
        .await
        .unwrap();
    let pending_local = f.code(false, false).await;
    f.db.execute(
        "UPDATE local_users SET name='Current SQLite Alice' WHERE username='alice'",
        [],
    )
    .unwrap();
    let current = f
        .store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .profile(local_tokens.access_token(), end())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(current).unwrap()["name"],
        "Current SQLite Alice",
        "LOCAL profile is current SQL identity"
    );
    let old=f.db.query_row("SELECT principal_json FROM local_tokens WHERE token_kind='refresh' AND local_user_revision=0",[],|r|r.get::<_,String>(0)).unwrap();
    let parsed: Value = serde_json::from_str(&old).unwrap();
    assert_eq!(parsed["subject"], "alice-subject");
    f.db.execute(
        "UPDATE local_users SET password_change_required=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, end())
        .await
        .unwrap();
    let auth = local_auth(&f, false);
    let LocalAuthStep::Pending(change) = auth
        .begin(proof, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    else {
        panic!("real password-change challenge required")
    };
    assert_eq!(
        change.stage(),
        broker_control::LocalAuthStage::PasswordChange
    );
    let hash = digester()
        .token(
            TokenKind::OidcAuthorizationCode,
            pending_fed.code().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let original =
        f.db.query_row(
            "SELECT request_json FROM oidc_auth_requests WHERE code_hash=?1",
            [&hash],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json='{' WHERE code_hash=?1",
        [&hash],
    )
    .unwrap();
    let before = unrevoked(&f);
    let next = "different synthetic native SQLite password";
    assert!(matches!(
        auth.complete_password_change(
            &f.engine,
            change.challenge(),
            LocalAuthBinding::AdminLogin,
            next,
            end()
        )
        .await,
        Err(broker_control::LocalAuthError::Control(
            ControlError::Storage
        ))
    ));
    assert_eq!(
        f.db.query_row(
            "SELECT revision FROM local_users WHERE username='alice'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(unrevoked(&f), before);
    assert!(f.code_exists(pending_local.code()));
    assert!(f.code_exists(pending_fed.code()));
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE code_hash=?2",
        params![original, hash],
    )
    .unwrap();
    let LocalAuthStep::Complete(_) = auth
        .complete_password_change(
            &f.engine,
            change.challenge(),
            LocalAuthBinding::AdminLogin,
            next,
            end(),
        )
        .await
        .unwrap()
    else {
        panic!("password change must complete")
    };
    assert!(!f.code_exists(pending_local.code()));
    assert!(f.code_exists(pending_fed.code()));
    assert_eq!(
        f.store
            .oidc_userinfo(f.authorization.clone(), f.verifier())
            .unwrap()
            .profile(local_tokens.access_token(), end())
            .await
            .unwrap_err(),
        OidcUserInfoError::InvalidToken
    );
    assert!(
        f.rotator()
            .rotate(refresh(local_tokens.refresh_token().unwrap(), false), end())
            .await
            .is_err()
    );
    assert_eq!(f.db.query_row("SELECT principal_json FROM local_tokens WHERE token_kind='refresh' AND local_user_revision=0",[],|r|r.get::<_,String>(0)).unwrap(),old);
    let profile = f
        .store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(v.clone())
        .profile(issued.access_token(), end())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(profile).unwrap()["sub"],
        fed.oidc_subject()
    );
    let required = local_auth(&f, true);
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", next, end())
        .await
        .unwrap();
    let LocalAuthStep::Pending(enroll) = required
        .begin(proof, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    else {
        panic!("real enrollment challenge required")
    };
    let otp = totp_rs::Totp::from_url(enroll.enrollment().unwrap().otpauth_uri())
        .unwrap()
        .generate((utc() / 1_000_000) as u64)
        .to_string();
    let valid_json =
        f.db.query_row(
            "SELECT request_json FROM oidc_auth_requests WHERE code_hash=?1",
            [&hash],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
    assert_eq!(
        valid_json, original,
        "LOCAL password mutation preserves exact federated request including NUL state/nonce"
    );
    let malformed = valid_json.replacen("\"principal\":{", "\"principal\":{invalid,", 1);
    assert_ne!(malformed, valid_json);
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE code_hash=?2",
        params![malformed, hash],
    )
    .unwrap();
    let before = unrevoked(&f);
    let failed = required
        .complete_mfa(
            mfa_limiter(),
            enroll.challenge(),
            LocalAuthBinding::AdminLogin,
            &otp,
            end(),
        )
        .await;
    assert!(
        matches!(
            failed,
            Err(broker_control::LocalAuthError::Control(
                ControlError::Storage
            ))
        ),
        "invalid principal enrollment result: {failed:?}"
    );
    assert_eq!(
        f.db.query_row(
            "SELECT revision FROM local_users WHERE username='alice'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM local_mfa_recovery_codes", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM local_mfa", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(unrevoked(&f), before);
    assert!(
        required
            .load(enroll.challenge(), LocalAuthBinding::AdminLogin, end())
            .await
            .is_ok()
    );
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE code_hash=?2",
        params![valid_json, hash],
    )
    .unwrap();
    let LocalAuthStep::Complete(mut login) = required
        .complete_mfa(
            mfa_limiter(),
            enroll.challenge(),
            LocalAuthBinding::AdminLogin,
            &otp,
            end(),
        )
        .await
        .unwrap()
    else {
        panic!("genuine TOTP enrollment must complete")
    };
    assert!(login.take_recovery_codes().is_some());
    assert_eq!(login.revision(), 3);
    assert!(f.code_exists(pending_fed.code()));
    f.producer()
        .with_upstream(v.clone())
        .exchange(exchange(pending_fed.code(), false), end())
        .await
        .unwrap();
    f.rotator()
        .with_upstream(v)
        .rotate(refresh(issued.refresh_token().unwrap(), false), end())
        .await
        .unwrap();
    op.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two real SQLite owners race a genuine federated code; bounded UserInfo corruption and H1 expiry"]
async fn sqlite_federated_two_owners_and_userinfo_guards() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    let v = Arc::new(verifier(&op, vec![client("public")], Some("roles")));
    let grant = code(&f, &op, v.clone(), true).await;
    let other = SqliteControlStore::open(config(&f.path), digester(), end())
        .await
        .unwrap();
    let left = f.producer().with_upstream(v.clone());
    let right = other
        .oidc_token_exchange(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
        .unwrap()
        .with_upstream(v.clone());
    let (left, right) = tokio::join!(
        left.exchange(exchange(grant.code(), true), end()),
        right.exchange(exchange(grant.code(), true), end())
    );
    let issued = match (left, right) {
        (Ok(value), Err(Error::InvalidGrant)) | (Err(Error::InvalidGrant), Ok(value)) => value,
        _ => panic!("exactly one real owner may consume the genuine code"),
    };
    assert_eq!(f.tokens(), 2);
    assert!(!f.code_exists(grant.code()));
    let access = claims(&f.issuer, issued.access_token(), AUDIENCE);
    assert_eq!(
        claims(&f.issuer, issued.id_token(), DYNAMIC)["nonce"],
        "literal-nonce\0kept"
    );
    let hash = digester()
        .token(
            TokenKind::OidcStoredAccess,
            access["jti"].as_str().unwrap().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let original: (String, i64) =
        f.db.query_row(
            "SELECT scopes_json,expires_at FROM local_tokens WHERE token_hash=?1",
            [&hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let userinfo = f
        .store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(v.clone());
    for (json, error) in [
        ("[\"changed\"]", OidcUserInfoError::InvalidToken),
        ("{", OidcUserInfoError::MalformedStored),
    ] {
        f.db.execute(
            "UPDATE local_tokens SET scopes_json=?1 WHERE token_hash=?2",
            params![json, hash],
        )
        .unwrap();
        assert_eq!(
            userinfo
                .profile(issued.access_token(), end())
                .await
                .unwrap_err(),
            error
        );
    }
    f.db.execute(
        "UPDATE local_tokens SET scopes_json=?1,expires_at=expires_at+1000000 WHERE token_hash=?2",
        params![original.0, hash],
    )
    .unwrap();
    assert_eq!(
        userinfo
            .profile(issued.access_token(), end())
            .await
            .unwrap_err(),
        OidcUserInfoError::InvalidToken
    );
    f.db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_hash=?2",
        params![original.1, hash],
    )
    .unwrap();
    userinfo
        .profile(issued.access_token(), end())
        .await
        .unwrap();
    let principal_json =
        f.db.query_row(
            "SELECT principal_json FROM local_tokens WHERE token_hash=?1",
            [&hash],
            |r| r.get::<_, String>(0),
        )
        .unwrap();
    f.db.execute(
        "UPDATE local_tokens SET principal_json=?1 WHERE token_hash=?2",
        params!["x".repeat(8193), hash],
    )
    .unwrap();
    assert_eq!(
        userinfo
            .profile(issued.access_token(), end())
            .await
            .unwrap_err(),
        OidcUserInfoError::ReadLimitExceeded
    );
    f.db.execute(
        "UPDATE local_tokens SET principal_json=?1 WHERE token_hash=?2",
        params![principal_json, hash],
    )
    .unwrap();
    let mut too_big = exchange("invalid", true);
    let oversized = "x".repeat(8193);
    too_big.code = Some(&oversized);
    assert_eq!(
        f.producer()
            .with_upstream(v.clone())
            .exchange(too_big, end())
            .await
            .unwrap_err(),
        Error::InvalidRequest
    );

    let bad = f
        .store
        .upstream_logins(&v)
        .begin(
            FlowContinuation::OAuth {
                provider_id: "missing".into(),
                request_id: "x".repeat(43),
            },
            end(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        bad.failure(),
        UpstreamLoginFailure::InvalidProvider
    ));
    let expired = f
        .store
        .upstream_logins(&v)
        .begin(
            FlowContinuation::OAuth {
                provider_id: v.browser_options(end()).unwrap()[0].id.clone(),
                request_id: "x".repeat(43),
            },
            end(),
        )
        .await
        .unwrap();
    f.db.execute("UPDATE oidc_flows SET expires_at=created_at+1", [])
        .unwrap();
    let hits = op.token_hits();
    let error = f
        .store
        .upstream_logins(&v)
        .complete(
            expired.state(),
            expired.browser_binding(),
            UpstreamLoginCallback::Code("unused"),
            end(),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error.failure(),
        UpstreamLoginFailure::InvalidState
    ));
    assert_eq!(op.token_hits(), hits);
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM oidc_flows", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "known consume removes matching expired flow"
    );
    other.shutdown(end()).await.unwrap();
    op.close().await;
    f.close().await;
}
