#[path = "support/browser_upstream.rs"]
mod browser;
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/browser_sql.rs"]
mod sql;
#[allow(
    dead_code,
    reason = "shared owned TLS PostgreSQL fixture methods serve the other SQL contracts"
)]
mod support;
use broker_control::{
    FlowContinuation, FlowPurpose, UpstreamAccessPolicy, UpstreamBearerVerifier,
    UpstreamBrowserClaimsSource, UpstreamBrowserClient, UpstreamClaimSelectors,
    UpstreamLoginCallback, UpstreamLoginFailure, UpstreamProviderConfig, UpstreamReadLimits,
};
use browser::{BrowserIssuer, ClientAuth, ClientRegistration, Fault};
use serde_json::{Value, json};
use sqlx_core::connection::Connection;
use std::time::Duration;
use std::time::Instant;
use support::{deadline, n};

async fn rows(admin: &mut sqlx_postgres::PgConnection) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_flows")
        .fetch_one(admin)
        .await
        .unwrap()
}
async fn flow_lock(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='browser_login_owner' AND wait_event_type='Lock' AND query LIKE '%public.oidc_flows%' LIMIT 1").fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual flow statement must wait on held table"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn withhold_commit(
    relay: &mut commit::CommitRelay,
    admin: &mut sqlx_postgres::PgConnection,
    pid: i32,
    expected: i64,
) {
    loop {
        let decision = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
            .await
            .unwrap()
            .unwrap();
        let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
            "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        if query == "COMMIT" && idle && rows(admin).await == expected {
            decision.send(false).unwrap();
            return;
        }
        decision.send(true).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual PostgreSQL COMMIT-idle TLS ACK withheld for both flow INSERT and one-use DELETE, cancellation and expiry"]
async fn postgres_upstream_login_uncertainty_contract() {
    let mut db = sql::BrowserSql::new().await;
    let mut issuer = BrowserIssuer::new().await;
    issuer.register(registration("public", ClientAuth::Public));
    let verifier = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )],
    );
    let mut relay = commit::CommitRelay::new(db.fixture.port).await;
    let store = broker_control::PostgresControlStore::open(
        sql::config(&db.fixture, relay.port, Duration::from_secs(2)),
        support::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let login = store.upstream_logins(&verifier);
    let mut locker = db.fixture.connection().await;
    sqlx_core::raw_sql::raw_sql("BEGIN; LOCK TABLE public.oidc_flows IN ACCESS EXCLUSIVE MODE")
        .execute(&mut locker)
        .await
        .unwrap();
    {
        let pending = login.begin(continuation(&verifier, 0), deadline());
        tokio::pin!(pending);
        let pid = tokio::select! {pid=flow_lock(&mut db.admin)=>pid,result=&mut pending=>panic!("real save must reach held SQL: {:?}",result.err().map(|e|e.failure()))};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        sqlx_core::raw_sql::raw_sql("ROLLBACK")
            .execute(&mut locker)
            .await
            .unwrap();
        tokio::select! {_=withhold_commit(&mut relay,&mut db.admin,pid,1)=>{},result=&mut pending=>panic!("real save COMMIT ACK must be held: {:?}",result.err().map(|e|e.failure()))};
        assert!(
            pending.await.unwrap_err().failure()
                == UpstreamLoginFailure::Control(broker_control::ControlError::OutcomeUncertain)
        );
    }
    assert!(
        rows(&mut db.admin).await == 1 && issuer.token_hits() == 0,
        "SQL may be committed while no issued browser authorization is returned"
    );
    relay.close().await;
    store.shutdown(deadline()).await.unwrap();
    sqlx_core::raw_sql::raw_sql("DELETE FROM public.oidc_flows")
        .execute(&mut db.admin)
        .await
        .unwrap();
    let mut relay = commit::CommitRelay::new(db.fixture.port).await;
    let store = broker_control::PostgresControlStore::open(
        sql::config(&db.fixture, relay.port, Duration::from_secs(2)),
        support::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let login = store.upstream_logins(&verifier);
    let issued = login
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    sqlx_core::raw_sql::raw_sql("BEGIN; LOCK TABLE public.oidc_flows IN ACCESS EXCLUSIVE MODE")
        .execute(&mut locker)
        .await
        .unwrap();
    {
        let pending = login.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        );
        tokio::pin!(pending);
        let pid = tokio::select! {pid=flow_lock(&mut db.admin)=>pid,result=&mut pending=>panic!("real consume must reach held SQL: {:?}",result.err().map(|e|e.failure()))};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        sqlx_core::raw_sql::raw_sql("ROLLBACK")
            .execute(&mut locker)
            .await
            .unwrap();
        tokio::select! {_=withhold_commit(&mut relay,&mut db.admin,pid,0)=>{},result=&mut pending=>panic!("real consume COMMIT ACK must be held: {:?}",result.err().map(|e|e.failure()))};
        let error = pending.await.unwrap_err();
        assert!(
            error.failure()
                == UpstreamLoginFailure::Control(broker_control::ControlError::OutcomeUncertain)
                && error.continuation().is_none()
        );
    }
    assert!(
        rows(&mut db.admin).await == 0 && issuer.token_hits() == 0,
        "unknown consumption never exchanges or returns a proof"
    );
    relay.close().await;
    store.shutdown(deadline()).await.unwrap();
    let login = db.store.upstream_logins(&verifier);
    let issued = login
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let proof = login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    proof.check(&verifier).unwrap();
    // Dropping the actual caller closes its waiting physical transaction, preserving an unconsumed flow.
    let issued = login
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    sqlx_core::raw_sql::raw_sql("BEGIN; LOCK TABLE public.oidc_flows IN ACCESS EXCLUSIVE MODE")
        .execute(&mut locker)
        .await
        .unwrap();
    let pid = {
        let pending = login.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        );
        tokio::pin!(pending);
        tokio::select! {pid=flow_lock(&mut db.admin)=>pid,result=&mut pending=>panic!("real cancelled caller must wait on SQL: {:?}",result.err().map(|e|e.failure()))}
    };
    let end = deadline();
    loop {
        let waiting: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
        )
        .bind(pid)
        .fetch_one(&mut db.admin)
        .await
        .unwrap();
        if !waiting {
            break;
        }
        assert!(
            Instant::now() < end,
            "caller Drop must close the pending physical connection"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sqlx_core::raw_sql::raw_sql("ROLLBACK")
        .execute(&mut locker)
        .await
        .unwrap();
    login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap()
        .check(&verifier)
        .unwrap();
    let issued = login
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    issuer.fault(Fault {
        token_delay: Duration::from_secs(3),
        ..Fault::default()
    });
    let error = login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap_err();
    assert!(
        error.failure() == UpstreamLoginFailure::Control(broker_control::ControlError::Deadline)
    );
    issuer.fault(Fault::default());
    let info = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::Userinfo,
        )],
    );
    let login = db.store.upstream_logins(&info);
    let mut fault = Fault {
        missing_profile: true,
        userinfo_delay: Duration::from_secs(3),
        ..Fault::default()
    };
    fault.id_overrides.insert(
        "exp".into(),
        json!(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 2
        ),
    );
    issuer.fault(fault);
    let issued = login
        .begin(continuation(&info, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        login
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::Control(broker_control::ControlError::Expired),
        "verified JWT expiring during real UserInfo IO never produces authority"
    );
    issuer.fault(Fault::default());
    let issued = login
        .begin(continuation(&info, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap()
        .check(&info)
        .unwrap();
    locker.close().await.unwrap();
    issuer.close().await;
    db.close().await;
}

fn client(
    id: &str,
    auth: ClientAuth,
    nonce: bool,
    source: UpstreamBrowserClaimsSource,
) -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: format!(" Browser {id} "),
        client_id: id.into(),
        client_secret: (auth != ClientAuth::Public).then(|| "fixture-secret".into()),
        redirect_url: "https://broker.example.invalid/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: nonce,
        claims_source: source,
        id_token_additional_audiences: vec![],
    }
}
fn configured(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
) -> UpstreamProviderConfig {
    let denied = clients.iter().map(|c| c.client_id.clone()).collect();
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec!["admin:session".into()],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: denied,
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "sub".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: Some("roles".into()),
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
fn build(issuer: &BrowserIssuer, clients: Vec<UpstreamBrowserClient>) -> UpstreamBearerVerifier {
    UpstreamBearerVerifier::new(
        "https://broker.example.invalid",
        n(16384),
        vec![configured(issuer, clients)],
    )
    .unwrap()
}
fn registration(id: &str, auth: ClientAuth) -> ClientRegistration {
    ClientRegistration {
        id: id.into(),
        secret: (auth != ClientAuth::Public).then(|| "fixture-secret".into()),
        redirect: "https://broker.example.invalid/oauth/oidc/callback".into(),
        auth,
    }
}
fn continuation(verifier: &UpstreamBearerVerifier, index: usize) -> FlowContinuation {
    FlowContinuation::Admin {
        provider_id: verifier.browser_options(deadline()).unwrap()[index]
            .id
            .clone(),
    }
}

#[tokio::test]
#[ignore = "owned real PostgreSQL TLS NOSUPERUSER and Rust HTTPS code issuer"]
async fn postgres_upstream_login_contract() {
    let mut db = sql::BrowserSql::new().await;
    let mut issuer = BrowserIssuer::new().await;
    for (id, auth) in [
        ("public", ClientAuth::Public),
        ("basic", ClientAuth::Basic),
        ("post", ClientAuth::Post),
    ] {
        issuer.register(registration(id, auth));
    }
    let verifier = build(
        &issuer,
        vec![
            client(
                "public",
                ClientAuth::Public,
                true,
                UpstreamBrowserClaimsSource::IdToken,
            ),
            client(
                "basic",
                ClientAuth::Basic,
                false,
                UpstreamBrowserClaimsSource::AccessToken,
            ),
        ],
    );
    // Deserialization and preparation are pure; defaults are sourced policies, not network guesses.
    let defaults: UpstreamBrowserClient = serde_json::from_value(json!({"display_name":"  Federação ☀  ","client_id":"defaults","redirect_url":"http://127.0.0.1:8787/callback"})).unwrap();
    assert!(
        defaults.require_nonce
            && defaults.claims_source == UpstreamBrowserClaimsSource::IdToken
            && defaults.scopes.is_empty()
            && defaults.id_token_additional_audiences.is_empty()
    );
    let pure = build(&issuer, vec![defaults]);
    assert!(
        pure.browser_options(deadline()).unwrap()[0].name == "Federação ☀"
            && issuer.jwks_hits() == 0
            && rows(&mut db.admin).await == 0
    );
    for (field, value) in [
        ("require_nonce", Value::Null),
        ("claims_source", json!("unverified")),
        ("unrecognized", json!(true)),
    ] {
        let mut raw = json!({"display_name":"Browser","client_id":"defaults","redirect_url":"https://broker.example.invalid/callback"});
        raw[field] = value;
        assert!(serde_json::from_value::<UpstreamBrowserClient>(raw).is_err());
    }
    for (field, value) in [
        ("display_name", json!("a\u{7}b")),
        ("display_name", json!("x".repeat(81))),
        (
            "redirect_url",
            json!("http://untrusted.example.invalid/callback"),
        ),
        ("scopes", json!(["space separated"])),
    ] {
        let mut raw = json!({"display_name":"Browser","client_id":"defaults","redirect_url":"https://broker.example.invalid/callback"});
        raw[field] = value;
        let c: UpstreamBrowserClient = serde_json::from_value(raw).unwrap();
        assert!(
            UpstreamBearerVerifier::new(
                "https://broker.example.invalid",
                n(16384),
                vec![configured(&issuer, vec![c])]
            )
            .is_err()
        );
    }
    let duplicated = vec![
        client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        ),
        client(
            " public ",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        ),
    ];
    assert!(
        UpstreamBearerVerifier::new(
            "https://broker.example.invalid",
            n(16384),
            vec![configured(&issuer, duplicated)]
        )
        .is_err()
    );
    let options = verifier.browser_options(deadline()).unwrap();
    assert!(
        options.len() == 2
            && options[0].name == "Browser public"
            && options[1].name == "Browser basic"
    );
    let logins = db.store.upstream_logins(&verifier);
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let params: std::collections::BTreeMap<_, _> = issued
        .location()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    assert!(
        params.get("nonce").is_some_and(|s| s.len() == 43)
            && params
                .get("code_challenge_method")
                .is_some_and(|s| s == "S256")
    );
    assert!(
        issued.state().starts_with("admin.")
            && issued.state().len() == broker_control::UPSTREAM_LOGIN_STATE_BYTES
    );
    let code = issuer.authorize(&issued).await;
    let swapped = format!("oauth.{}", issued.state().split_once('.').unwrap().1);
    let token_hits = issuer.token_hits();
    let wrong_hint = logins
        .complete(
            &swapped,
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap_err();
    assert_eq!(wrong_hint.failure(), UpstreamLoginFailure::InvalidState);
    assert!(wrong_hint.continuation().is_none());
    assert_eq!(
        rows(&mut db.admin).await,
        1,
        "altered prefix must not consume the genuine complete-state key"
    );
    assert_eq!(
        issuer.token_hits(),
        token_hits,
        "budget hint cannot choose an exchange"
    );
    let wrong_binding = logins
        .complete(
            issued.state(),
            "A".repeat(43).as_str(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap_err();
    assert!(
        wrong_binding.failure() == UpstreamLoginFailure::InvalidState
            && wrong_binding.continuation().is_none()
            && issuer.token_hits() == 0
    );
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        proof.purpose() == FlowPurpose::Admin
            && proof.profile().subject == "fixture-subject"
            && proof.username() == "id-user"
            && proof.profile().name == "ID Name"
    );
    assert!(proof.claim_roles().is_some_and(|r| r == ["user"]) && issuer.userinfo_hits() == 0);
    proof.check(&verifier).unwrap();
    assert!(
        logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::InvalidState
            && issuer.token_hits() == 1
    );
    issuer.fault(Fault {
        token_delay: Duration::from_millis(1200),
        ..Fault::default()
    });
    let issued = logins
        .begin(continuation(&verifier, 1), deadline())
        .await
        .unwrap();
    assert!(!issued.location().query_pairs().any(|(k, _)| k == "nonce"));
    let code = issuer.authorize(&issued).await;
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        proof.username() == "access-user"
            && proof.profile().name == "Access Name"
            && proof.organization() == "access-org"
            && proof.teams() == ["access-team"]
    );
    // Profile-only access JWT has an external service audience and no Graphit resource scopes.
    issuer.fault(Fault::default());
    let verifier = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::Userinfo,
        )],
    );
    let logins = db.store.upstream_logins(&verifier);
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(proof.profile().name == "ID Name" && issuer.userinfo_hits() == 0);
    issuer.fault(Fault {
        missing_profile: true,
        ..Fault::default()
    });
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        proof.username() == "id-user"
            && proof.profile().name == "Supplementary Name"
            && proof.organization() == "profile-org"
            && proof.teams() == ["profile-team"]
    );
    assert!(
        proof.claim_roles().is_some_and(|r| r == ["user"]) && issuer.userinfo_hits() == 1,
        "UserInfo does not replace subject/roles/available username"
    );
    issuer.fault(Fault::default());
    // New signed kid refreshes the SAME cache without replaying the token exchange.
    let verifier = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )],
    );
    let logins = db.store.upstream_logins(&verifier);
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let before_keys = issuer.jwks_hits();
    let before_tokens = issuer.token_hits();
    issuer.rotate("rotated-browser-key");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        proof.username() == "id-user"
            && issuer.jwks_hits() == before_keys + 1
            && issuer.token_hits() == before_tokens + 1
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cases: [(&str, Value); 10] = [
        ("nonce", json!("wrong-nonce")),
        ("nonce", Value::Null),
        ("iss", json!("https://untrusted.example.invalid")),
        ("aud", json!("other-client")),
        ("azp", json!("other-client")),
        ("sub", json!("")),
        ("iat", json!(now + 3600)),
        ("nbf", json!(now + 3600)),
        ("exp", json!(now - 1)),
        ("roles", json!(["unsafe|role"])),
    ];
    for (field, value) in cases {
        let mut fault = Fault::default();
        fault.id_overrides.insert(field.into(), value);
        issuer.fault(fault);
        let issued = logins
            .begin(continuation(&verifier, 0), deadline())
            .await
            .unwrap();
        let code = issuer.authorize(&issued).await;
        let denied = logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(
            denied.failure() == UpstreamLoginFailure::InvalidIdentity
                && denied.continuation().is_some(),
            "verified ID binding or identity rejection"
        );
    }
    for fault in [
        Fault {
            omit_id: true,
            ..Fault::default()
        },
        Fault {
            wrong_signature: true,
            ..Fault::default()
        },
        Fault {
            bad_hash: true,
            ..Fault::default()
        },
        Fault {
            extra_audiences: vec!["untrusted-extra".into()],
            ..Fault::default()
        },
    ] {
        issuer.fault(fault);
        let issued = logins
            .begin(continuation(&verifier, 0), deadline())
            .await
            .unwrap();
        let code = issuer.authorize(&issued).await;
        let denied = logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(
            denied.failure() == UpstreamLoginFailure::InvalidIdentity
                && denied.continuation().is_some(),
            "no proof from invalid ID/signature/hash/audience"
        );
    }
    issuer.fault(Fault {
        extra_audiences: vec!["trusted-extra".into()],
        ..Fault::default()
    });
    let mut c = client(
        "public",
        ClientAuth::Public,
        true,
        UpstreamBrowserClaimsSource::IdToken,
    );
    c.id_token_additional_audiences = vec!["trusted-extra".into()];
    let trusted = build(&issuer, vec![c]);
    let trusted_logins = db.store.upstream_logins(&trusted);
    let issued = trusted_logins
        .begin(continuation(&trusted, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    trusted_logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap()
        .check(&trusted)
        .unwrap();
    let mut fault = Fault {
        extra_audiences: vec!["trusted-extra".into()],
        ..Fault::default()
    };
    fault.id_overrides.insert("azp".into(), Value::Null);
    issuer.fault(fault);
    let issued = trusted_logins
        .begin(continuation(&trusted, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        trusted_logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::InvalidIdentity
    );
    let access = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::AccessToken,
        )],
    );
    let access_logins = db.store.upstream_logins(&access);
    for (field, value) in [
        ("sub", json!("other-subject")),
        ("iss", json!("https://other.example.invalid")),
        ("exp", json!(now - 1)),
        ("iat", json!(now + 3600)),
        ("roles", json!(123)),
    ] {
        let mut fault = Fault::default();
        fault.access_overrides.insert(field.into(), value);
        issuer.fault(fault);
        let issued = access_logins
            .begin(continuation(&access, 0), deadline())
            .await
            .unwrap();
        let code = issuer.authorize(&issued).await;
        assert!(
            access_logins
                .complete(
                    issued.state(),
                    issued.browser_binding(),
                    UpstreamLoginCallback::Code(&code),
                    deadline()
                )
                .await
                .unwrap_err()
                .failure()
                == UpstreamLoginFailure::InvalidIdentity
        );
    }
    let info = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::Userinfo,
        )],
    );
    let info_logins = db.store.upstream_logins(&info);
    let mut fault = Fault {
        missing_profile: true,
        ..Fault::default()
    };
    fault
        .userinfo_overrides
        .insert("sub".into(), json!("other-subject"));
    issuer.fault(fault);
    let issued = info_logins
        .begin(continuation(&info, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        info_logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::InvalidIdentity
    );
    let mut fault = Fault {
        missing_profile: true,
        ..Fault::default()
    };
    fault.id_overrides.insert("name".into(), Value::Null);
    issuer.fault(fault);
    let before = issuer.userinfo_hits();
    let issued = info_logins
        .begin(continuation(&info, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        info_logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::InvalidIdentity
            && issuer.userinfo_hits() == before,
        "invalid present data is not missing"
    );
    let mut fault = Fault {
        missing_username: true,
        ..Fault::default()
    };
    fault
        .userinfo_overrides
        .insert("preferred_username".into(), Value::Null);
    issuer.fault(fault);
    let issued = info_logins
        .begin(continuation(&info, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let failure = info_logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap_err()
        .failure();
    assert!(
        failure == UpstreamLoginFailure::Control(broker_control::ControlError::Unavailable),
        "missing required supplementary profile data is finite unavailable, not identity authority"
    );
    issuer.fault(Fault {
        token_duplicate: true,
        ..Fault::default()
    });
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        matches!(
            logins
                .complete(
                    issued.state(),
                    issued.browser_binding(),
                    UpstreamLoginCallback::Code(&code),
                    deadline()
                )
                .await
                .unwrap_err()
                .failure(),
            UpstreamLoginFailure::Control(_)
        ),
        "duplicate response cannot produce authority"
    );
    issuer.fault(Fault::default());
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let (a, b) = tokio::join!(
        logins.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline()
        ),
        logins.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline()
        )
    );
    assert!(
        usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1,
        "concurrent callback has one SQL consumer"
    );
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let before = issuer.token_hits();
    let error = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::ProviderError,
            deadline(),
        )
        .await
        .unwrap_err();
    assert!(
        error.failure() == UpstreamLoginFailure::ProviderError
            && error.continuation().is_some()
            && issuer.token_hits() == before
    );
    let oauth = FlowContinuation::OAuth {
        provider_id: options[0].id.clone(),
        request_id: "real-op-context".into(),
    };
    let issued = logins.begin(oauth, deadline()).await.unwrap();
    let code = issuer.authorize(&issued).await;
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        proof.purpose() == FlowPurpose::OAuth
            && proof.continuation().request_id() == Some("real-op-context"),
        "typed context does not fabricate an OP grant"
    );
    // Discovery selects POST once, never retries client authentication or code exchange.
    let mut metadata = issuer.metadata();
    metadata["token_endpoint_auth_methods_supported"] = json!(["client_secret_post"]);
    issuer.fault(Fault {
        metadata_override: Some(metadata),
        ..Fault::default()
    });
    let verifier = build(
        &issuer,
        vec![client(
            "post",
            ClientAuth::Post,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )],
    );
    let logins = db.store.upstream_logins(&verifier);
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let proof = logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    assert!(proof.username() == "id-user");
    issuer.fault(Fault::default());
    issuer.fault(Fault {
        omit_kid: true,
        ..Fault::default()
    });
    let no_kid = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::AccessToken,
        )],
    );
    let nk = db.store.upstream_logins(&no_kid);
    let issued = nk
        .begin(continuation(&no_kid, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        nk.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline()
        )
        .await
        .unwrap()
        .username()
            == "access-user",
        "valid ID and private access JWT without kid use the configured eligible key"
    );
    let mut anonymous_keys = issuer.keys();
    anonymous_keys["keys"][0]
        .as_object_mut()
        .unwrap()
        .remove("kid");
    anonymous_keys["keys"]
        .as_array_mut()
        .unwrap()
        .push(BrowserIssuer::unrelated_ec_key());
    issuer.fault(Fault {
        omit_kid: true,
        jwks_override: Some(anonymous_keys.clone()),
        ..Fault::default()
    });
    let anonymous = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::AccessToken,
        )],
    );
    let anon = db.store.upstream_logins(&anonymous);
    let issued = anon
        .begin(continuation(&anonymous, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        anon.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline()
        )
        .await
        .unwrap()
        .username()
            == "access-user",
        "trusted anonymous JWK and unrelated algorithm JWK are selected by the mature verifier"
    );
    let mut ambiguous_keys = anonymous_keys.clone();
    ambiguous_keys["keys"]
        .as_array_mut()
        .unwrap()
        .push(anonymous_keys["keys"][0].clone());
    issuer.fault(Fault {
        omit_kid: true,
        jwks_override: Some(ambiguous_keys),
        ..Fault::default()
    });
    let ambiguous = build(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )],
    );
    let ambiguous_login = db.store.upstream_logins(&ambiguous);
    let issued = ambiguous_login
        .begin(continuation(&ambiguous, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        ambiguous_login
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::InvalidIdentity,
        "mature SDK ambiguity remains a closed rejection"
    );
    // Hash verification is exercised with a valid SDK-generated hash, as well as the wrong hash above.
    issuer.fault(Fault {
        valid_hash: true,
        ..Fault::default()
    });
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    logins
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap()
        .check(&verifier)
        .unwrap();
    issuer.fault(Fault::default());
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let mut location = issued.location().clone();
    let query: Vec<_> = location
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    location.set_query(None);
    for (k, v) in query {
        location.query_pairs_mut().append_pair(
            &k,
            if k == "code_challenge" {
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            } else {
                &v
            },
        );
    }
    let code = issuer.authorize_at(&issued, location).await;
    let before = issuer.token_hits();
    assert!(
        logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code(&code),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::ProviderError
            && issuer.token_hits() == before + 1
    );
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    assert!(
        logins
            .complete(
                issued.state(),
                issued.browser_binding(),
                UpstreamLoginCallback::Code("unissued-code"),
                deadline()
            )
            .await
            .unwrap_err()
            .failure()
            == UpstreamLoginFailure::ProviderError
    );
    let issued = logins
        .begin(continuation(&verifier, 0), deadline())
        .await
        .unwrap();
    let disabled =
        UpstreamBearerVerifier::new("https://broker.example.invalid", n(16384), vec![]).unwrap();
    let before = issuer.token_hits();
    let error = db
        .store
        .upstream_logins(&disabled)
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code("never-exchanged"),
            deadline(),
        )
        .await
        .unwrap_err();
    assert!(
        error.failure() == UpstreamLoginFailure::InvalidProvider
            && error.continuation().is_some()
            && issuer.token_hits() == before
    );
    for (field, value) in [
        ("preferred_username", json!("x".repeat(2049))),
        ("name", json!("x".repeat(2049))),
        ("sub", json!("x".repeat(513))),
        (
            "groups",
            json!(
                (0..33)
                    .map(|i| json!({"name":format!("team-{i}")}))
                    .collect::<Vec<_>>()
            ),
        ),
    ] {
        let mut fault = Fault::default();
        fault.id_overrides.insert(field.into(), value);
        issuer.fault(fault);
        let issued = logins
            .begin(continuation(&verifier, 0), deadline())
            .await
            .unwrap();
        let code = issuer.authorize(&issued).await;
        assert!(
            logins
                .complete(
                    issued.state(),
                    issued.browser_binding(),
                    UpstreamLoginCallback::Code(&code),
                    deadline()
                )
                .await
                .unwrap_err()
                .failure()
                == UpstreamLoginFailure::InvalidIdentity,
            "bounded mapped claims"
        );
    }
    for fault in [
        Fault {
            token_padding: 65537,
            ..Fault::default()
        },
        {
            let mut fault = Fault::default();
            fault
                .id_overrides
                .insert("padding".into(), json!("x".repeat(16384)));
            fault
        },
    ] {
        issuer.fault(fault);
        let issued = logins
            .begin(continuation(&verifier, 0), deadline())
            .await
            .unwrap();
        let code = issuer.authorize(&issued).await;
        assert!(
            matches!(
                logins
                    .complete(
                        issued.state(),
                        issued.browser_binding(),
                        UpstreamLoginCallback::Code(&code),
                        deadline()
                    )
                    .await
                    .unwrap_err()
                    .failure(),
                UpstreamLoginFailure::Control(_) | UpstreamLoginFailure::InvalidIdentity
            ),
            "bounded token/HTTP data cannot produce proof"
        );
    }
    issuer.fault(Fault::default());
    let metadata = issuer.metadata();
    for (field, value) in [
        (
            "authorization_endpoint",
            json!("http://untrusted.example.invalid/authorize"),
        ),
        (
            "token_endpoint",
            json!("http://untrusted.example.invalid/token"),
        ),
        ("jwks_uri", json!("http://untrusted.example.invalid/jwks")),
        ("issuer", json!("https://different.example.invalid")),
    ] {
        let mut changed = metadata.clone();
        changed[field] = value;
        issuer.fault(Fault {
            metadata_override: Some(changed),
            ..Fault::default()
        });
        let v = build(
            &issuer,
            vec![client(
                "public",
                ClientAuth::Public,
                true,
                UpstreamBrowserClaimsSource::IdToken,
            )],
        );
        let before = rows(&mut db.admin).await;
        assert!(
            db.store
                .upstream_logins(&v)
                .begin(continuation(&v, 0), deadline())
                .await
                .is_err()
                && rows(&mut db.admin).await == before,
            "untrusted discovery has no SQL flow"
        );
    }
    issuer.fault(Fault::default());
    // Mapping subject is canonical identity; raw sub remains only the token-source binding.
    let mut cfg = configured(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )],
    );
    cfg.claims.subject = "preferred_username".into();
    let mapped =
        UpstreamBearerVerifier::new("https://broker.example.invalid", n(16384), vec![cfg]).unwrap();
    let ml = db.store.upstream_logins(&mapped);
    let issued = ml
        .begin(continuation(&mapped, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    assert!(
        ml.complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline()
        )
        .await
        .unwrap()
        .profile()
        .subject
            == "id-user"
    );
    let issued = ml
        .begin(continuation(&mapped, 0), deadline())
        .await
        .unwrap();
    let code = issuer.authorize(&issued).await;
    let proof = ml
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap();
    proof.check(&mapped).unwrap();
    let mut other_config = configured(
        &issuer,
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )],
    );
    other_config.claims.subject = "email".into();
    let different_owner = UpstreamBearerVerifier::new(
        "https://broker.example.invalid",
        n(16384),
        vec![other_config],
    )
    .unwrap();
    assert!(
        proof.check(&different_owner) == Err(broker_control::ControlError::InvalidFlow),
        "same issuer/client DATA never substitutes private producing owner provenance"
    );
    let count: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.admin_sessions")
            .fetch_one(&mut db.admin)
            .await
            .unwrap();
    assert!(count == 0, "producer never emits/seeds an Admin session");
    let mismatched = ml
        .begin(continuation(&mapped, 0), deadline())
        .await
        .unwrap();
    let mismatch_code = issuer.authorize(&mismatched).await;
    let hash = support::digester()
        .token(
            broker_security::TokenKind::OidcFlowState,
            mismatched.state().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let changed = sqlx_core::query::query("UPDATE public.oidc_flows SET purpose='oauth',continuation_json=$2 WHERE state_hash=$1")
        .bind(&hash).bind(json!({"provider_id":mapped.browser_options(deadline()).unwrap()[0].id,"request_id":"pending-fixture"}).to_string()).execute(&mut db.admin).await.unwrap();
    assert_eq!(changed.rows_affected(), 1);
    let hits = issuer.token_hits();
    let rejected = ml
        .complete(
            mismatched.state(),
            mismatched.browser_binding(),
            UpstreamLoginCallback::Code(&mismatch_code),
            deadline(),
        )
        .await
        .unwrap_err();
    assert_eq!(rejected.failure(), UpstreamLoginFailure::InvalidState);
    assert!(
        rejected.continuation().is_none(),
        "mismatched purpose never becomes a protected destination"
    );
    assert_eq!(
        issuer.token_hits(),
        hits,
        "persisted purpose must match before SDK exchange"
    );
    let remains: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.oidc_flows WHERE state_hash=$1",
    )
    .bind(hash)
    .fetch_one(&mut db.admin)
    .await
    .unwrap();
    assert_eq!(
        remains, 0,
        "known matching consumption is one-use even for corrupt purpose"
    );
    issuer.close().await;
    db.close().await;
}
