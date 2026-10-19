#[allow(
    dead_code,
    reason = "shared HTTPS issuer supports other protocol contracts"
)]
#[path = "support/browser_upstream.rs"]
mod browser;
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/oidc_federated.rs"]
mod federated;
#[allow(
    dead_code,
    reason = "shared genuine LOCAL fixture supports other contracts"
)]
#[path = "support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared owned TLS SQL fixture serves multiple contracts"
)]
mod support;
use broker_control::{
    BrokerAccessIssuer, BrokerAccessVerifier, ControlError, FlowContinuation,
    OidcAuthorizationError, OidcRefreshInput, OidcTokenExchangeError, OidcTokenExchangeInput,
    OidcTokenExchangePolicy, UpstreamBearerVerifier,
};
use browser::{BrowserIssuer, Fault};
use federated as fed;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use std::time::{Duration, Instant};
use support::{deadline, n};

fn exchange<'a>(code: &'a str, client: &'a str) -> OidcTokenExchangeInput<'a> {
    OidcTokenExchangeInput {
        grant_type: Some("authorization_code"),
        client_id: Some(client),
        code: Some(code),
        redirect_uri: Some(fed::REDIRECT),
        code_verifier: Some(VERIFIER),
        resource: Some(RESOURCE),
        authorization: None,
    }
}
fn refresh<'a>(raw: &'a str, client: &'a str) -> OidcRefreshInput<'a> {
    OidcRefreshInput {
        grant_type: Some("refresh_token"),
        client_id: Some(client),
        refresh_token: Some(raw),
        scope: None,
        resource: Some(RESOURCE),
        authorization: None,
    }
}
fn claims(issuer: &BrokerAccessIssuer, raw: &str, audience: &str) -> Value {
    let mut v = Validation::new(Algorithm::EdDSA);
    v.leeway = 0;
    v.set_issuer(&[ISSUER]);
    v.set_audience(&[audience]);
    decode::<Value>(
        raw,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &v,
    )
    .unwrap()
    .claims
}
fn subject(issuer: &str) -> String {
    oidc::digester()
        .oidc_subject(issuer.as_bytes(), b"alice-subject")
        .unwrap()
        .as_str()
        .into()
}
fn fault(roles: Value) -> Fault {
    Fault {
        id_overrides: [
            ("mapped_subject".into(), json!("alice-subject")),
            ("auth_time".into(), json!(1)),
            ("preferred_username".into(), json!("Usuário-联合")),
            ("name".into(), json!("  Authenticated Name  ")),
            ("roles".into(), roles),
        ]
        .into(),
        ..Fault::default()
    }
}
async fn requests(admin: &mut sqlx_postgres::PgConnection) -> i64 {
    sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.oidc_auth_requests WHERE code_hash IS NOT NULL",
    )
    .fetch_one(admin)
    .await
    .unwrap()
}
async fn wait_locks(admin: &mut sqlx_postgres::PgConnection, minimum: i64) {
    let end = deadline();
    loop {
        let count:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock'").fetch_one(&mut *admin).await.unwrap();
        if count >= minimum {
            return;
        }
        assert!(
            Instant::now() < end,
            "real refresh did not reach expected lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "owned real PostgreSQL TLS NOSUPERUSER and Rust HTTPS H1/OAuth grants"]
async fn postgres_oidc_federated_contract() {
    let mut f = OidcFixture::new().await;
    let mut upstream = BrowserIssuer::new().await;
    fed::register(&upstream, "public");
    fed::register(&upstream, "other");
    upstream.fault(fault(json!(["admin", "user", "admin"])));
    let v = fed::verifier(
        &upstream,
        vec![fed::client("public"), fed::client("other")],
        Some("roles"),
    );
    f.admin
        .execute("INSERT INTO public.roles(name,created_at) VALUES('sql-extra',1)")
        .await
        .unwrap();
    sqlx_core::query::query("INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'sql-extra',1),('alice-subject','sql-extra',1)").bind(format!("{}|alice-subject",upstream.issuer)).execute(&mut f.admin).await.unwrap();
    let client = fed::registered(&f).await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let signer =
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "federated-key", &key.serialize_der()).unwrap();
    let policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(30 * 86400))
            .unwrap();
    let token = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &signer)
        .unwrap()
        .with_upstream(&v);
    let rotation = f
        .store
        .oidc_refresh(&f.policy, &policy, &signer)
        .unwrap()
        .with_upstream(&v);
    let digester = oidc::digester();
    let completion = f.store.oidc_authorization_service(&digester, &f.policy);
    // Authority is the by-value H1 proof: Admin purpose, owner mismatch and absent request fail.
    let p = fed::pending(&f, &client).await;
    let admin = fed::proof(
        &f,
        &upstream,
        &v,
        FlowContinuation::Admin {
            provider_id: v.browser_options(deadline()).unwrap()[0].id.clone(),
        },
    )
    .await;
    assert_eq!(
        completion
            .complete_upstream(admin, &v, deadline())
            .await
            .unwrap_err(),
        OidcAuthorizationError::InvalidLogin
    );
    let foreign = fed::verifier(
        &upstream,
        vec![fed::client("public"), fed::client("other")],
        Some("roles"),
    );
    let login = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
    assert_eq!(
        completion
            .complete_upstream(login, &foreign, deadline())
            .await
            .unwrap_err(),
        OidcAuthorizationError::InvalidLogin
    );
    let missing = broker_security::new_local_auth_challenge().unwrap();
    let login = fed::proof(&f, &upstream, &v, fed::continuation(&v, &missing)).await;
    assert_eq!(
        completion
            .complete_upstream(login, &v, deadline())
            .await
            .unwrap_err(),
        OidcAuthorizationError::InvalidRequest
    );
    let login = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
    assert!(matches!(
        completion
            .complete_upstream(login, &v, Instant::now())
            .await,
        Err(OidcAuthorizationError::Control(ControlError::Deadline))
    ));
    assert!(
        completion
            .load(p.request(), deadline())
            .await
            .unwrap()
            .is_some()
    );
    // A change between the initial request read and its locked reread is denied.
    {
        let raced = fed::pending(&f, &client).await;
        let login = fed::proof(&f, &upstream, &v, fed::continuation(&v, raced.request())).await;
        let mut blocker = f.fixture.connection().await;
        blocker.execute("BEGIN").await.unwrap();
        sqlx_core::query::query(
            "SELECT client_id FROM public.oauth_dynamic_clients WHERE client_id=$1 FOR UPDATE",
        )
        .bind(&client)
        .execute(&mut blocker)
        .await
        .unwrap();
        let attempt = completion.complete_upstream(login, &v, deadline());
        tokio::pin!(attempt);
        tokio::select! {_=wait_locks(&mut f.admin,1)=>{},r=&mut attempt=>panic!("completion must reach current client lock: {:?}",r.err())}
        let hash = digester
            .token(
                broker_security::TokenKind::OidcAuthRequest,
                raced.request().as_bytes(),
            )
            .unwrap()
            .to_sql_hex();
        let raw: String = sqlx_core::query_scalar::query_scalar(
            "SELECT request_json FROM public.oidc_auth_requests WHERE request_hash=$1",
        )
        .bind(&hash)
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        let mut changed: Value = serde_json::from_str(&raw).unwrap();
        changed["state"] = json!("changed-under-lock");
        sqlx_core::query::query(
            "UPDATE public.oidc_auth_requests SET request_json=$1 WHERE request_hash=$2",
        )
        .bind(serde_json::to_string(&changed).unwrap())
        .bind(&hash)
        .execute(&mut f.admin)
        .await
        .unwrap();
        blocker.execute("ROLLBACK").await.unwrap();
        assert_eq!(
            attempt.await.unwrap_err(),
            OidcAuthorizationError::MalformedStored
        );
        sqlx_core::connection::Connection::close(blocker)
            .await
            .unwrap();
    }
    // A genuine proof completed twice for one protected pending request has one winner.
    let first = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
    let second = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
    let (a, b) = tokio::join!(
        completion.complete_upstream(first, &v, deadline()),
        completion.complete_upstream(second, &v, deadline())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let code = a.or(b).unwrap();
    assert_eq!(code.oidc_subject(), subject(&upstream.issuer));
    for case in 0..4 {
        let mut wrong = exchange(code.code(), &client);
        match case {
            0 => wrong.client_id = Some("graphit-cli"),
            1 => wrong.resource = Some("https://other.invalid"),
            2 => wrong.redirect_uri = Some("https://client.example/other"),
            _ => wrong.code_verifier = Some("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"),
        };
        assert!(token.exchange(wrong, deadline()).await.is_err());
    }
    assert!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &signer)
            .unwrap()
            .exchange(exchange(code.code(), &client), deadline())
            .await
            .is_err()
    );
    let (a, b) = tokio::join!(
        token.exchange(exchange(code.code(), &client), deadline()),
        token.exchange(exchange(code.code(), &client), deadline())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let issued = a.or(b).unwrap();
    let access = claims(&signer, issued.access_token(), AUDIENCE);
    let id = claims(&signer, issued.id_token(), &client);
    assert_eq!(access["iss"], ISSUER);
    assert_eq!(access["sub"], subject(&upstream.issuer));
    assert_ne!(access["sub"], "alice-subject");
    assert_eq!(access["name"], "Authenticated Name");
    assert_eq!(id["name"], "  Authenticated Name  ");
    assert_eq!(access["preferred_username"], "Usuário-联合");
    assert_eq!(access["roles"], json!(["admin", "user"]));
    assert_eq!(id["amr"], json!(["federated"]));
    assert_eq!(id["nonce"], "literal-nonce");
    assert_eq!(
        access["exp"].as_u64().unwrap() - access["iat"].as_u64().unwrap(),
        600
    );
    assert!(
        id["auth_time"].as_i64().unwrap() > 1,
        "completion captures fresh time instead of upstream auth_time"
    );
    let access_digest = oidc::digester()
        .token(
            broker_security::TokenKind::OidcStoredAccess,
            access["jti"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
    let data = f
        .store
        .oidc_access_grants(n(8192))
        .unwrap()
        .read(&access_digest, deadline())
        .await
        .unwrap()
        .unwrap();
    assert!(
        data.current_local_user().is_none(),
        "federated DATA does not expose the colliding LOCAL user row"
    );
    let before: (i64,i64,i64)=sqlx_core::query_as::query_as("SELECT local_user_revision,auth_time,expires_at FROM public.local_tokens WHERE token_hash=$1").bind(oidc::digester().token(broker_security::TokenKind::LocalRefresh,issued.refresh_token().unwrap().as_bytes()).unwrap().to_sql_hex()).fetch_one(&mut f.admin).await.unwrap();
    assert_eq!(before.0, 0);
    // No current-user row or SQL role fallback is consulted for the federated snapshot.
    f.admin.execute("UPDATE public.local_users SET name='changed-local',enabled=0,revision=revision+1 WHERE username='alice'").await.unwrap();
    let rotated = rotation
        .rotate(
            refresh(issued.refresh_token().unwrap(), &client),
            deadline(),
        )
        .await
        .unwrap();
    let rid = claims(&signer, rotated.id_token(), &client);
    assert_eq!(rid["amr"], json!(["oidc"]));
    assert_eq!(rid["auth_time"], id["auth_time"]);
    assert_eq!(
        claims(&signer, rotated.access_token(), AUDIENCE)["roles"],
        access["roles"]
    );
    let after: (i64, i64) = sqlx_core::query_as::query_as(
        "SELECT auth_time,expires_at FROM public.local_tokens WHERE token_hash=$1",
    )
    .bind(
        oidc::digester()
            .token(
                broker_security::TokenKind::LocalRefresh,
                rotated.refresh_token().unwrap().as_bytes(),
            )
            .unwrap()
            .to_sql_hex(),
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(after, (before.1, before.2));
    // Missing trust/last browser client/selector changes reject without consuming refresh.
    let none = UpstreamBearerVerifier::new(ISSUER, n(16384), vec![]).unwrap();
    let last = fed::verifier(&upstream, vec![], Some("roles"));
    let changed = fed::verifier(&upstream, vec![fed::client("other")], Some("$.roles"));
    let removed = fed::verifier(&upstream, vec![fed::client("other")], None);
    for current in [&none, &last, &changed, &removed] {
        assert!(
            f.store
                .oidc_refresh(&f.policy, &policy, &signer)
                .unwrap()
                .with_upstream(current)
                .rotate(
                    refresh(rotated.refresh_token().unwrap(), &client),
                    deadline()
                )
                .await
                .is_err()
        );
    }
    let remaining = fed::verifier(&upstream, vec![fed::client("other")], Some("roles"));
    let fresh = f
        .store
        .oidc_refresh(&f.policy, &policy, &signer)
        .unwrap()
        .with_upstream(&remaining)
        .rotate(
            refresh(rotated.refresh_token().unwrap(), &client),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        rotation
            .rotate(
                refresh(issued.refresh_token().unwrap(), &client),
                deadline()
            )
            .await
            .is_err()
    );
    assert!(
        rotation
            .rotate(refresh(fresh.refresh_token().unwrap(), &client), deadline())
            .await
            .is_err()
    );
    let verify =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), signer.jwks(), n(16384))
            .unwrap();
    assert!(
        verify
            .verify(issued.access_token(), &[], deadline())
            .is_ok()
    );
    // Code trust follows exactly the same current configuration and literal selector.
    let code = fed::code(&f, &upstream, &v, &client).await;
    for current in [&none, &last, &changed, &removed] {
        assert!(
            f.store
                .oidc_token_exchange(&f.policy, &policy, &signer)
                .unwrap()
                .with_upstream(current)
                .exchange(exchange(code.code(), &client), deadline())
                .await
                .is_err()
        );
    }
    assert!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &signer)
            .unwrap()
            .with_upstream(&remaining)
            .exchange(exchange(code.code(), &client), deadline())
            .await
            .is_ok()
    );
    {
        // Hold the descendant write while reuse of its ancestor waits on the same family.
        let ancestor_code = fed::code(&f, &upstream, &v, &client).await;
        let ancestor = token
            .exchange(exchange(ancestor_code.code(), &client), deadline())
            .await
            .unwrap();
        let descendant = rotation
            .rotate(
                refresh(ancestor.refresh_token().unwrap(), &client),
                deadline(),
            )
            .await
            .unwrap();
        let family: String = sqlx_core::query_scalar::query_scalar(
            "SELECT family_id FROM public.local_tokens WHERE token_hash=$1",
        )
        .bind(
            oidc::digester()
                .token(
                    broker_security::TokenKind::LocalRefresh,
                    ancestor.refresh_token().unwrap().as_bytes(),
                )
                .unwrap()
                .to_sql_hex(),
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        let sibling_code = fed::code(&f, &upstream, &v, &client).await;
        let sibling = token
            .exchange(exchange(sibling_code.code(), &client), deadline())
            .await
            .unwrap();
        let hashes: Vec<_> = [
            ancestor.refresh_token().unwrap(),
            sibling.refresh_token().unwrap(),
        ]
        .into_iter()
        .map(|raw| {
            oidc::digester()
                .token(broker_security::TokenKind::LocalRefresh, raw.as_bytes())
                .unwrap()
                .to_sql_hex()
        })
        .collect();
        let same_pair: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*)=2 AND count(DISTINCT oidc_subject)=1 AND count(DISTINCT client_id)=1 AND count(DISTINCT family_id)=2 FROM public.local_tokens WHERE token_hash=ANY($1)"
        ).bind(&hashes).fetch_one(&mut f.admin).await.unwrap();
        assert!(same_pair, "two genuine federated families of the same pair");
        let descendant_hash = oidc::digester()
            .token(
                broker_security::TokenKind::LocalRefresh,
                descendant.refresh_token().unwrap().as_bytes(),
            )
            .unwrap()
            .to_sql_hex();
        let mut blocker = f.fixture.connection().await;
        blocker.execute("BEGIN").await.unwrap();
        sqlx_core::query::query(
            "SELECT token_hash FROM public.local_tokens WHERE token_hash=$1 FOR UPDATE",
        )
        .bind(descendant_hash)
        .fetch_one(&mut blocker)
        .await
        .unwrap();
        let rotating = rotation.rotate(
            refresh(descendant.refresh_token().unwrap(), &client),
            deadline(),
        );
        tokio::pin!(rotating);
        tokio::select! { _=wait_locks(&mut f.admin,1)=>{}, r=&mut rotating=>panic!("descendant must reach held write: {:?}",r.err()) }
        // Shared pair coordination must not serialize the unrelated family.
        let sibling_rotating = rotation.rotate(
            refresh(sibling.refresh_token().unwrap(), &client),
            deadline(),
        );
        tokio::pin!(sibling_rotating);
        let sibling_child = tokio::select! {
            r = &mut sibling_rotating => r.unwrap(),
            r = &mut rotating => panic!("held descendant must still wait: {:?}", r.err()),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("independent family blocked by pair coordination"),
        };
        assert!(sibling_child.refresh_token().is_some());
        let reusing = rotation.rotate(
            refresh(ancestor.refresh_token().unwrap(), &client),
            deadline(),
        );
        tokio::pin!(reusing);
        tokio::select! { _=wait_locks(&mut f.admin,2)=>{}, r=&mut rotating=>panic!("write must remain held: {:?}",r.err()),r=&mut reusing=>panic!("ancestor must wait for family lock: {:?}",r.err()) }
        let advisory:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event='advisory'").fetch_one(&mut f.admin).await.unwrap();
        assert_eq!(advisory, 1, "reuse is serialized before family effects");
        blocker.execute("COMMIT").await.unwrap();
        let (a, b) = tokio::join!(rotating, reusing);
        assert!(a.is_ok());
        assert_eq!(b.unwrap_err(), OidcTokenExchangeError::InvalidGrant);
        let active: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM public.local_tokens WHERE family_id=$1 AND revoked_at IS NULL",
        )
        .bind(&family)
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert_eq!(active, 0);
        sqlx_core::connection::Connection::close(blocker)
            .await
            .unwrap();
    }
    // None and an authenticated empty selector both yield implicit user only.
    upstream.fault(fault(json!([])));
    for selector in [None, Some("roles")] {
        let current = fed::verifier(&upstream, vec![fed::client("public")], selector);
        let code = fed::code(&f, &upstream, &current, &client).await;
        if selector.is_none() {
            assert!(
                token
                    .exchange(exchange(code.code(), &client), deadline())
                    .await
                    .is_err()
            );
        }
        let issued = f
            .store
            .oidc_token_exchange(&f.policy, &policy, &signer)
            .unwrap()
            .with_upstream(&current)
            .exchange(exchange(code.code(), &client), deadline())
            .await
            .unwrap();
        assert_eq!(
            claims(&signer, issued.access_token(), AUDIENCE)["roles"],
            json!(["user"])
        );
    }
    // Issuer and mapped subject determine distinct native subjects, including LOCAL.
    f.admin
        .execute("UPDATE public.local_users SET enabled=1,revision=1 WHERE username='alice'")
        .await
        .unwrap();
    let local = f.code(false, false).await;
    assert_eq!(local.oidc_subject(), subject("local"));
    assert_ne!(local.oidc_subject(), subject(&upstream.issuer));
    let mut other = BrowserIssuer::new().await;
    fed::register(&other, "public");
    other.fault(fault(json!(["user"])));
    let ov = fed::verifier(&other, vec![fed::client("public")], Some("roles"));
    let othercode = fed::code(&f, &other, &ov, &client).await;
    assert_ne!(othercode.oidc_subject(), code.oidc_subject());
    assert_ne!(othercode.oidc_subject(), local.oidc_subject());
    assert_eq!(othercode.oidc_subject(), subject(&other.issuer));
    // Federated H1 identity is literal; LOCAL canonical rules cannot rewrite it.
    let raw = "  usuário|联合  ";
    let username = format!("  {}  ", "用户".repeat(260));
    let name = "界".repeat(600);
    let mut literal = fault(json!(["user"]));
    literal
        .id_overrides
        .insert("mapped_subject".into(), json!(raw));
    literal
        .id_overrides
        .insert("preferred_username".into(), json!(username));
    literal.id_overrides.insert("name".into(), json!(name));
    upstream.fault(literal);
    let literal = fed::code(&f, &upstream, &v, &client).await;
    let expected = oidc::digester()
        .oidc_subject(upstream.issuer.as_bytes(), raw.as_bytes())
        .unwrap();
    let normalized = oidc::digester()
        .oidc_subject(upstream.issuer.as_bytes(), raw.trim().as_bytes())
        .unwrap();
    assert_eq!(literal.oidc_subject(), expected.as_str());
    assert_ne!(literal.oidc_subject(), normalized.as_str());
    let issued = token
        .exchange(exchange(literal.code(), &client), deadline())
        .await
        .unwrap();
    let literalclaims = claims(&signer, issued.access_token(), AUDIENCE);
    assert!(
        verify
            .verify(issued.access_token(), &[], deadline())
            .is_ok(),
        "literal H1 profile remains a verifiable Broker access JWT"
    );
    assert_eq!(literalclaims["sub"], expected.as_str());
    assert_eq!(literalclaims["preferred_username"], username);
    assert_eq!(literalclaims["name"], name);
    let jti = literalclaims["jti"].as_str().unwrap();
    let digest = oidc::digester()
        .token(broker_security::TokenKind::OidcStoredAccess, jti.as_bytes())
        .unwrap();
    let snapshot = f
        .store
        .oidc_access_grants(n(8192))
        .unwrap()
        .read(&digest, deadline())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.stored_principal().subject(), raw);
    assert_eq!(snapshot.stored_principal().username(), username);
    assert!(snapshot.current_local_user().is_none());
    let refreshed = rotation
        .rotate(
            refresh(issued.refresh_token().unwrap(), &client),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        claims(&signer, refreshed.access_token(), AUDIENCE)["preferred_username"],
        username
    );
    upstream.fault(fault(json!(["user"])));
    // Native codec corruption is denied before removal or token effects.
    let corrupt = fed::code(&f, &upstream, &v, &client).await;
    let hash = oidc::digester()
        .token(
            broker_security::TokenKind::OidcAuthorizationCode,
            corrupt.code().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    sqlx_core::query::query("UPDATE public.oidc_auth_requests SET request_json=jsonb_set(request_json::jsonb,'{principal,local_user_revision}','1')::text WHERE code_hash=$1").bind(&hash).execute(&mut f.admin).await.unwrap();
    let count = requests(&mut f.admin).await;
    let tokens =
        sqlx_core::query_scalar::query_scalar::<_, i64>("SELECT count(*) FROM public.local_tokens")
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
    assert_eq!(
        token
            .exchange(exchange(corrupt.code(), &client), deadline())
            .await
            .unwrap_err(),
        OidcTokenExchangeError::MalformedStored
    );
    assert_eq!(requests(&mut f.admin).await, count);
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>("SELECT count(*) FROM public.local_tokens")
            .fetch_one(&mut f.admin)
            .await
            .unwrap(),
        tokens
    );
    other.close().await;
    upstream.close().await;
    f.close().await;
}

async fn completion_wait(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE '%public.oidc_auth_requests%' LIMIT 1").fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual completion must reach held SQL"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn completion_commit(
    relay: &mut commit::CommitRelay,
    admin: &mut sqlx_postgres::PgConnection,
    pid: i32,
    hash: &str,
) -> tokio::sync::oneshot::Sender<bool> {
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
        let authorized: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT code_hash IS NOT NULL FROM public.oidc_auth_requests WHERE request_hash=$1",
        )
        .bind(hash)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        if query == "COMMIT" && idle && authorized {
            return decision;
        }
        decision.send(true).unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual completion row lock, cancellation/deadline and committed-idle PostgreSQL TLS ACK withheld"]
async fn postgres_oidc_federated_uncertainty_contract() {
    use sqlx_core::connection::Connection;
    let mut f = OidcFixture::new().await;
    let mut upstream = BrowserIssuer::new().await;
    fed::register(&upstream, "public");
    upstream.fault(fault(json!(["user"])));
    let v = fed::verifier(&upstream, vec![fed::client("public")], Some("roles"));
    let client = fed::registered(&f).await;
    let d = oidc::digester();
    let mut blocker = f.fixture.connection().await;
    // Deadline and cancellation before COMMIT retain a pending request without code.
    for cancel in [false, true] {
        let p = fed::pending(&f, &client).await;
        let login = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
        blocker
            .execute("BEGIN; LOCK TABLE public.oidc_auth_requests IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        let service = f.store.oidc_authorization_service(&d, &f.policy);
        {
            let pending = service.complete_upstream(
                login,
                &v,
                if cancel {
                    deadline()
                } else {
                    Instant::now() + Duration::from_millis(250)
                },
            );
            tokio::pin!(pending);
            tokio::select! {_=completion_wait(&mut f.admin)=>{},r=&mut pending=>panic!("held statement must be observed: {:?}",r.err())}
            if !cancel {
                assert_eq!(
                    pending.await.unwrap_err(),
                    OidcAuthorizationError::Control(ControlError::Deadline)
                );
            }
        }
        blocker.execute("ROLLBACK").await.unwrap();
        assert!(
            service
                .load(p.request(), deadline())
                .await
                .unwrap()
                .is_some()
        );
    }
    let p = fed::pending(&f, &client).await;
    let login = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
    let hash = d
        .token(
            broker_security::TokenKind::OidcAuthRequest,
            p.request().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let store = broker_control::PostgresControlStore::open(
        oidc::config_at(&f.fixture, relay.port),
        oidc::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let service = store.oidc_authorization_service(&d, &f.policy);
    blocker
        .execute("BEGIN; LOCK TABLE public.oidc_auth_requests IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let pending = service.complete_upstream(login, &v, Instant::now() + Duration::from_secs(2));
        tokio::pin!(pending);
        let pid = tokio::select! {pid=completion_wait(&mut f.admin)=>pid,r=&mut pending=>panic!("completion must reach real SQL: {:?}",r.err())};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        blocker.execute("ROLLBACK").await.unwrap();
        let held = tokio::select! {held=completion_commit(&mut relay,&mut f.admin,pid,&hash)=>held,r=&mut pending=>panic!("actual COMMIT ACK must remain held: {:?}",r.err())};
        assert_eq!(
            pending.await.unwrap_err(),
            OidcAuthorizationError::Control(ControlError::OutcomeUncertain)
        );
        let _ = held.send(false);
    }
    let committed: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT code_hash IS NOT NULL FROM public.oidc_auth_requests WHERE request_hash=$1",
    )
    .bind(&hash)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(
        committed,
        "known SQL effects do not release a code when the completion outcome is uncertain"
    );
    relay.close().await;
    store.shutdown(deadline()).await.unwrap();
    let fresh = fed::proof(&f, &upstream, &v, fed::continuation(&v, p.request())).await;
    assert_eq!(
        f.store
            .oidc_authorization_service(&d, &f.policy)
            .complete_upstream(fresh, &v, deadline())
            .await
            .unwrap_err(),
        OidcAuthorizationError::InvalidRequest
    );
    assert!(
        fed::code(&f, &upstream, &v, &client)
            .await
            .oidc_subject()
            .len()
            == 43,
        "fresh authorization recovers through the existing healthy owner"
    );
    blocker.close().await.unwrap();
    upstream.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "genuine HTTPS H1 and PostgreSQL TLS federated revocation/rotation"]
async fn postgres_oidc_federated_revocation_contract() {
    let mut f = OidcFixture::new().await;
    let mut upstream = BrowserIssuer::new().await;
    fed::register(&upstream, "public");
    upstream.fault(fault(json!(["user"])));
    let trust = fed::verifier(&upstream, vec![fed::client("public")], Some("roles"));
    let client = fed::registered(&f).await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let signer = BrokerAccessIssuer::new(
        ISSUER,
        AUDIENCE,
        "revocation-federated",
        &key.serialize_der(),
    )
    .unwrap();
    let policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(86400)).unwrap();
    let code = fed::code(&f, &upstream, &trust, &client).await;
    let issued = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &signer)
        .unwrap()
        .with_upstream(&trust)
        .exchange(exchange(code.code(), &client), deadline())
        .await
        .unwrap();
    let verify =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), signer.jwks(), n(16384))
            .unwrap();
    {
        let revoker = f.store.oidc_revocation(&f.policy, &verify).unwrap();
        revoker
            .revoke(
                broker_control::OidcRevocationInput {
                    token: Some(issued.access_token()),
                    client_id: Some(&client),
                    token_type_hint: Some("refresh_token"),
                    authorization: None,
                },
                deadline(),
            )
            .await
            .unwrap();
        assert!(
            verify
                .verify(issued.access_token(), &[], deadline())
                .is_ok()
        );
        let rotation = f
            .store
            .oidc_refresh(&f.policy, &policy, &signer)
            .unwrap()
            .with_upstream(&trust);
        let descendant = rotation
            .rotate(
                refresh(issued.refresh_token().unwrap(), &client),
                deadline(),
            )
            .await
            .unwrap();
        let family: String = sqlx_core::query_scalar::query_scalar(
            "SELECT family_id FROM public.local_tokens WHERE token_hash=$1",
        )
        .bind(
            oidc::digester()
                .token(
                    broker_security::TokenKind::LocalRefresh,
                    descendant.refresh_token().unwrap().as_bytes(),
                )
                .unwrap()
                .to_sql_hex(),
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        // Current LOCAL identity and upstream network availability are irrelevant to disposal.
        f.admin
            .execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
            .await
            .unwrap();
        upstream.close().await;
        sqlx_core::query::query("SELECT pg_advisory_lock(hashtextextended($1, 4750301))")
            .bind(&family)
            .execute(&mut f.admin)
            .await
            .unwrap();
        let revoking = revoker.revoke(
            broker_control::OidcRevocationInput {
                token: Some(descendant.refresh_token().unwrap()),
                client_id: Some(&client),
                token_type_hint: None,
                authorization: None,
            },
            deadline(),
        );
        let rotating = rotation.rotate(
            refresh(descendant.refresh_token().unwrap(), &client),
            deadline(),
        );
        tokio::pin!(revoking, rotating);
        tokio::select! {
            _=wait_locks(&mut f.admin,2)=>{},
            r=&mut revoking=>panic!("revoke must wait at the native family lock: {r:?}"),
            r=&mut rotating=>panic!("rotate must wait at the native family lock: {:?}",r.err()),
        }
        sqlx_core::query::query("SELECT pg_advisory_unlock(hashtextextended($1, 4750301))")
            .bind(&family)
            .execute(&mut f.admin)
            .await
            .unwrap();
        let (ended, rotated) = tokio::join!(revoking, rotating);
        ended.unwrap();
        assert!(rotated.is_ok() || matches!(rotated, Err(OidcTokenExchangeError::InvalidGrant)));
        let active: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_tokens WHERE family_id=$1 AND token_kind='refresh' AND revoked_at IS NULL")
        .bind(&family).fetch_one(&mut f.admin).await.unwrap();
        assert_eq!(active, 0);
        assert!(
            verify
                .verify(descendant.access_token(), &[], deadline())
                .is_ok()
        );
    }
    f.close().await;
}
