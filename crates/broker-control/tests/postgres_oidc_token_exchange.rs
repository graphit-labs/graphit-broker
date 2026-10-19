#[path = "support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture supports multiple protocol suites"
)]
mod support;
use broker_control::{
    BrokerAccessIssuer, BrokerAccessVerifier, ControlError, OidcTokenExchangeError as Error,
    OidcTokenExchangeInput, OidcTokenExchangePolicy,
};
use broker_security::TokenKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, RESOURCE, VERIFIER};
use serde_json::Value;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use support::{deadline, n};
use zeroize::Zeroizing;
fn input(raw: &str, dynamic: bool) -> OidcTokenExchangeInput<'_> {
    OidcTokenExchangeInput {
        grant_type: Some("authorization_code"),
        client_id: Some(if dynamic { "web-client" } else { "graphit-cli" }),
        code: Some(raw),
        redirect_uri: Some(if dynamic {
            "https://client.example/cb"
        } else {
            "http://localhost:49152/oauth/callback"
        }),
        code_verifier: Some(VERIFIER),
        resource: dynamic.then_some(RESOURCE),
        authorization: None,
    }
}
fn claims(issuer: &BrokerAccessIssuer, raw: &str) -> Value {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.leeway = 0;
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[ISSUER]);
    decode::<Value>(
        raw,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims
}
async fn pending(f: &mut OidcFixture, raw: &str) -> bool {
    let hash = oidc::digester()
        .token(TokenKind::OidcAuthorizationCode, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    sqlx_core::query_scalar::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.oidc_auth_requests WHERE code_hash=$1)",
    )
    .bind(hash)
    .fetch_one(&mut f.admin)
    .await
    .unwrap()
}
async fn wait_lock(f: &mut OidcFixture, query: &str) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let count: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE $1").bind(format!("%{query}%")).fetch_one(&mut f.admin).await.unwrap();
        if count > 0 {
            return;
        }
        assert!(
            Instant::now() < end,
            "native SQL exchange did not reach the expected lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test]
#[ignore = "requires actual PostgreSQL TLS container"]
async fn postgres_native_oidc_authorization_code_exchange() {
    let mut f = OidcFixture::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer = Arc::new(
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "exchange-key", &key.serialize_der()).unwrap(),
    );
    let policy = Arc::new(
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(30 * 86400))
            .unwrap(),
    );
    let dynamic = f.code(true, true).await;
    let before = f.token_count().await;
    let mut wrong = input(dynamic.code(), true);
    wrong.code_verifier = Some("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(wrong, deadline())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert!(pending(&mut f, dynamic.code()).await);
    assert_eq!(f.token_count().await, before);
    for case in 0..4 {
        let mut wrong = input(dynamic.code(), true);
        match case {
            0 => wrong.client_id = Some("graphit-cli"),
            1 => wrong.redirect_uri = Some("https://client.example/cb/"),
            2 => wrong.resource = Some("https://other.example/v1"),
            _ => wrong.resource = None,
        }
        assert!(
            f.store
                .oidc_token_exchange(&f.policy, &policy, &issuer)
                .unwrap()
                .exchange(wrong, deadline())
                .await
                .is_err()
        );
        assert!(pending(&mut f, dynamic.code()).await);
        assert_eq!(f.token_count().await, before);
    }
    let result = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
        .unwrap()
        .exchange(input(dynamic.code(), true), deadline())
        .await
        .unwrap();
    assert!(!pending(&mut f, dynamic.code()).await);
    assert_eq!(f.token_count().await, before + 2);
    let access = claims(&issuer, result.access_token());
    let id = claims(&issuer, result.id_token());
    assert_eq!(access["sub"], dynamic.oidc_subject());
    assert_eq!(access["aud"], serde_json::json!([AUDIENCE, RESOURCE]));
    assert_eq!(
        access["exp"].as_u64().unwrap() - access["iat"].as_u64().unwrap(),
        600
    );
    assert_eq!(id["exp"], access["exp"]);
    assert_eq!(id["amr"], serde_json::json!(["pwd"]));
    assert_eq!(
        id["auth_time"].as_i64().unwrap(),
        dynamic.auth_time().as_i64() / 1_000_000
    );
    assert_eq!(id["nonce"], "literal-nonce");
    assert_eq!(id["name"], "Alice");
    assert_eq!(id["email"], "alice@example.invalid");
    let verifier =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(8192))
            .unwrap();
    verifier
        .verify(result.access_token(), &["openid".into()], deadline())
        .unwrap();
    assert!(verifier.verify(result.id_token(), &[], deadline()).is_err());
    let digest = oidc::digester()
        .token(
            TokenKind::OidcStoredAccess,
            access["jti"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
    assert!(
        f.store
            .oidc_access_grants(n(8192))
            .unwrap()
            .read(&digest, deadline())
            .await
            .unwrap()
            .is_some()
    );
    let refresh = result.refresh_token().unwrap();
    assert!(refresh.starts_with("gb_rt_"));
    let refresh_hash = oidc::digester()
        .token(TokenKind::LocalRefresh, refresh.as_bytes())
        .unwrap()
        .to_sql_hex();
    let stored: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.local_tokens WHERE token_hash=$1 AND token_kind='refresh' AND family_id<>'' AND consumed_at IS NULL AND revoked_at IS NULL)")
        .bind(refresh_hash).fetch_one(&mut f.admin).await.unwrap();
    assert!(stored);
    let leaked: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.local_tokens WHERE principal_json LIKE $1 OR token_hash=$2 OR token_id=$2)")
        .bind(format!("%{}%", result.access_token())).bind(refresh).fetch_one(&mut f.admin).await.unwrap();
    assert!(!leaked);
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(dynamic.code(), true), deadline())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );

    let cli = f.code(false, false).await;
    let cli_result = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
        .unwrap()
        .exchange(input(cli.code(), false), deadline())
        .await
        .unwrap();
    assert!(cli_result.refresh_token().is_none());
    assert_eq!(
        claims(&issuer, cli_result.access_token())["aud"],
        serde_json::json!([AUDIENCE])
    );

    let empty = f.code(false, false).await;
    f.admin.execute("UPDATE public.local_users SET name='  ',email='',organization='  ' WHERE subject='alice-subject'").await.unwrap();
    let profile = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
        .unwrap()
        .exchange(input(empty.code(), false), deadline())
        .await
        .unwrap();
    let ac = claims(&issuer, profile.access_token());
    let ic = claims(&issuer, profile.id_token());
    for absent in ["name", "email", "organization"] {
        assert!(ac.get(absent).is_none());
    }
    assert_eq!(ic["name"], "  ");
    assert!(ic.get("email").is_none());
    assert!(ic.get("organization").is_none());
    f.admin.execute("UPDATE public.local_users SET name='Alice',email='alice@example.invalid',organization='org' WHERE subject='alice-subject'").await.unwrap();

    // Stale current identity and password-change state cannot mint or consume a genuine code.
    for update in [
        "enabled=0",
        "password_change_required=1",
        "revision=2",
        "identity_kind='service'",
    ] {
        let code = f.code(false, false).await;
        f.admin
            .execute(sqlx_core::sql_str::AssertSqlSafe(format!(
                "UPDATE public.local_users SET {update} WHERE subject='alice-subject'"
            )))
            .await
            .unwrap();
        let count = f.token_count().await;
        assert_eq!(
            f.store
                .oidc_token_exchange(&f.policy, &policy, &issuer)
                .unwrap()
                .exchange(input(code.code(), false), deadline())
                .await
                .unwrap_err(),
            Error::InvalidGrant
        );
        assert!(pending(&mut f, code.code()).await);
        assert_eq!(f.token_count().await, count);
        f.admin.execute("UPDATE public.local_users SET enabled=1,password_change_required=0,revision=1,identity_kind='human' WHERE subject='alice-subject'").await.unwrap();
    }
    // SQL failure after access insert rolls the entire pair back and leaves this same code usable.
    let rollback = f.code(true, true).await;
    f.admin.execute("CREATE FUNCTION reject_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.token_kind='refresh' THEN RAISE EXCEPTION 'fixture SQL rejection'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_refresh BEFORE INSERT ON public.local_tokens FOR EACH ROW EXECUTE FUNCTION reject_refresh()").await.unwrap();
    let count = f.token_count().await;
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(rollback.code(), true), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    assert!(pending(&mut f, rollback.code()).await);
    assert_eq!(f.token_count().await, count);
    f.admin
        .execute(
            "DROP TRIGGER reject_refresh ON public.local_tokens; DROP FUNCTION reject_refresh()",
        )
        .await
        .unwrap();
    f.store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
        .unwrap()
        .exchange(input(rollback.code(), true), deadline())
        .await
        .unwrap();

    // Two actual SQL exchanges contend on one request; precisely one commits.
    let concurrent = f.code(false, false).await;
    let count = f.token_count().await;
    let (s, a, p, k) = (
        f.store.clone(),
        f.policy.clone(),
        policy.clone(),
        issuer.clone(),
    );
    let spawn = move |raw: Zeroizing<String>| {
        let (s, a, p, k) = (s.clone(), a.clone(), p.clone(), k.clone());
        tokio::spawn(async move {
            s.oidc_token_exchange(&a, &p, &k)
                .unwrap()
                .exchange(input(&raw, false), deadline())
                .await
        })
    };
    let (a, b) = tokio::join!(
        spawn(Zeroizing::new(concurrent.code().into())),
        spawn(Zeroizing::new(concurrent.code().into()))
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(f.token_count().await, count + 1);

    // A cancelled SQL wait cannot expose a bearer or consume the code.
    let cancel = f.code(false, false).await;
    let mut blocker = f.fixture.connection().await;
    let mut tx = blocker.begin().await.unwrap();
    tx.execute("SELECT subject FROM public.local_users WHERE subject='alice-subject' FOR UPDATE")
        .await
        .unwrap();
    let running = spawn(Zeroizing::new(cancel.code().into()));
    wait_lock(&mut f, "local_users").await;
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    blocker.close().await.unwrap();
    assert!(pending(&mut f, cancel.code()).await);
    f.store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
        .unwrap()
        .exchange(input(cancel.code(), false), deadline())
        .await
        .unwrap();

    // Strict native DATA decoding refuses missing/unknown fields without consuming the code.
    for patch in [
        "request_json=(request_json::jsonb || '{\"alien\":true}'::jsonb)::text",
        "request_json=(request_json::jsonb - 'resource')::text",
        "request_json=jsonb_set(request_json::jsonb,'{principal}','[]'::jsonb)::text",
    ] {
        let corrupt = f.code(false, false).await;
        let hash = oidc::digester()
            .token(TokenKind::OidcAuthorizationCode, corrupt.code().as_bytes())
            .unwrap()
            .to_sql_hex();
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!(
            "UPDATE public.oidc_auth_requests SET {patch} WHERE code_hash=$1"
        )))
        .bind(hash)
        .execute(&mut f.admin)
        .await
        .unwrap();
        let before = f.token_count().await;
        assert_eq!(
            f.store
                .oidc_token_exchange(&f.policy, &policy, &issuer)
                .unwrap()
                .exchange(input(corrupt.code(), false), deadline())
                .await
                .unwrap_err(),
            Error::MalformedStored
        );
        assert!(pending(&mut f, corrupt.code()).await);
        assert_eq!(f.token_count().await, before);
    }
    let changed = f.code(true, false).await;
    f.admin.execute("UPDATE public.oauth_dynamic_clients SET redirect_uris_json='[\"https://client.example/changed\"]' WHERE client_id='web-client'").await.unwrap();
    let before = f.token_count().await;
    assert!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(changed.code(), true), deadline())
            .await
            .is_err()
    );
    assert!(pending(&mut f, changed.code()).await);
    assert_eq!(f.token_count().await, before);
    f.admin.execute("UPDATE public.oauth_dynamic_clients SET redirect_uris_json='[\"https://client.example/cb\"]' WHERE client_id='web-client'").await.unwrap();

    // The actual server stalls an issued COMMIT, so timeout is uncertain, never a fabricated rollback/output.
    let uncertain = f.code(false, false).await;
    let before = f.token_count().await;
    f.admin.execute("CREATE FUNCTION slow_token_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER slow_token_commit AFTER INSERT ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION slow_token_commit()").await.unwrap();
    let end = Instant::now() + Duration::from_millis(750);
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(uncertain.code(), false), end)
            .await
            .unwrap_err(),
        Error::Control(ControlError::OutcomeUncertain)
    );
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let active:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND state='active'").fetch_one(&mut f.admin).await.unwrap();
        if active == 0 {
            break;
        }
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f.admin.execute("DROP TRIGGER slow_token_commit ON public.local_tokens; DROP FUNCTION slow_token_commit()").await.unwrap();
    let remains = pending(&mut f, uncertain.code()).await;
    let after = f.token_count().await;
    assert!(
        (remains && after == before) || (!remains && after == before + 1),
        "uncertain outcome must still be transactionally atomic"
    );

    let expired = f.code(false, false).await;
    sqlx_core::query::query("UPDATE public.oidc_auth_requests SET expires_at=$1,created_at=$1-60000000 WHERE code_hash=$2")
        .bind(oidc::micros()-1).bind(oidc::digester().token(TokenKind::OidcAuthorizationCode,expired.code().as_bytes()).unwrap().to_sql_hex()).execute(&mut f.admin).await.unwrap();
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(expired.code(), false), deadline())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    let deadline_code = f.code(false, false).await;
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(deadline_code.code(), false), Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    assert!(pending(&mut f, deadline_code.code()).await);
    f.store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        f.store
            .oidc_token_exchange(&f.policy, &policy, &issuer)
            .unwrap()
            .exchange(input(deadline_code.code(), false), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.close().await;
}
