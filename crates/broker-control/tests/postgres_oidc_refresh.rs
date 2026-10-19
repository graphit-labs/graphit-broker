#[path = "support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared actual PostgreSQL TLS fixture supports multiple suites"
)]
mod support;
use broker_control::{
    BrokerAccessIssuer, BrokerAccessVerifier, ControlError, OidcRefreshInput,
    OidcTokenExchangeError as Error, OidcTokenExchangeInput, OidcTokenExchangePolicy,
    OidcTokenExchangeResult,
};
use broker_security::TokenKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, RESOURCE, VERIFIER};
use serde_json::Value;
use sqlx_core::{connection::Connection, executor::Executor, row::Row};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use support::{deadline, n};

fn input(raw: &str, dynamic: bool) -> OidcRefreshInput<'_> {
    OidcRefreshInput {
        grant_type: Some("refresh_token"),
        client_id: Some(if dynamic { "web-client" } else { "graphit-cli" }),
        refresh_token: Some(raw),
        scope: None,
        resource: dynamic.then_some(RESOURCE),
        authorization: None,
    }
}
async fn initial(
    f: &OidcFixture,
    issuer: &BrokerAccessIssuer,
    policy: &OidcTokenExchangePolicy,
    dynamic: bool,
) -> OidcTokenExchangeResult {
    let code = f.code(dynamic, true).await;
    f.store
        .oidc_token_exchange(&f.policy, policy, issuer)
        .unwrap()
        .exchange(
            OidcTokenExchangeInput {
                grant_type: Some("authorization_code"),
                client_id: Some(if dynamic { "web-client" } else { "graphit-cli" }),
                code: Some(code.code()),
                redirect_uri: Some(if dynamic {
                    "https://client.example/cb"
                } else {
                    "http://localhost:49152/oauth/callback"
                }),
                code_verifier: Some(VERIFIER),
                resource: dynamic.then_some(RESOURCE),
                authorization: None,
            },
            deadline(),
        )
        .await
        .unwrap()
}
fn claims(issuer: &BrokerAccessIssuer, raw: &str) -> Value {
    let mut v = Validation::new(Algorithm::EdDSA);
    v.leeway = 0;
    v.set_audience(&[AUDIENCE]);
    v.set_issuer(&[ISSUER]);
    decode::<Value>(
        raw,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &v,
    )
    .unwrap()
    .claims
}
fn hash(raw: &str) -> String {
    oidc::digester()
        .token(TokenKind::LocalRefresh, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
async fn row(f: &mut OidcFixture, raw: &str) -> sqlx_postgres::PgRow {
    sqlx_core::query::query("SELECT family_id,auth_time,expires_at,consumed_at,revoked_at,resource,scopes_json FROM public.local_tokens WHERE token_hash=$1")
        .bind(hash(raw)).fetch_one(&mut f.admin).await.unwrap()
}
async fn active(f: &mut OidcFixture, family: &str) -> i64 {
    sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_tokens WHERE family_id=$1 AND revoked_at IS NULL",
    )
    .bind(family)
    .fetch_one(&mut f.admin)
    .await
    .unwrap()
}
async fn wait_locks(f: &mut OidcFixture, minimum: i64) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let count:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock'")
            .fetch_one(&mut f.admin).await.unwrap();
        if count >= minimum {
            return;
        }
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test]
#[ignore = "requires actual PostgreSQL TLS NOSUPERUSER fixture"]
async fn postgres_native_oidc_refresh_rotation_contract() {
    let mut f = OidcFixture::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer = Arc::new(
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "refresh-key", &key.serialize_der()).unwrap(),
    );
    let policy = Arc::new(
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(30 * 86400))
            .unwrap(),
    );
    let original = initial(&f, &issuer, &policy, true).await;
    let raw = original.refresh_token().unwrap();
    let before = row(&mut f, raw).await;
    let expiry: i64 = before.get("expires_at");
    let auth_time: i64 = before.get("auth_time");
    let family: String = before.get("family_id");
    let count = f.token_count().await;
    for case in 0..8 {
        let mut wrong = input(raw, true);
        match case {
            0 => wrong.client_id = Some("graphit-cli"),
            1 => wrong.resource = None,
            2 => wrong.resource = Some("https://other.example/v1"),
            3 => wrong.scope = Some(""),
            4 => wrong.scope = Some("address"),
            5 => wrong.scope = Some("openid "),
            6 => wrong.scope = Some("openid  profile"),
            _ => wrong.authorization = Some(("web-client", b"secret")),
        }
        assert!(
            f.store
                .oidc_refresh(&f.policy, &policy, &issuer)
                .unwrap()
                .rotate(wrong, deadline())
                .await
                .is_err()
        );
        assert_eq!(f.token_count().await, count);
        assert!(
            row(&mut f, raw)
                .await
                .get::<Option<i64>, _>("consumed_at")
                .is_none()
        );
    }
    f.admin
        .execute(
            "UPDATE public.local_users SET name='Current Alice',email='' WHERE username='alice'",
        )
        .await
        .unwrap();
    let mut narrow = input(raw, true);
    narrow.scope = Some("openid profile openid");
    let rotated = f
        .store
        .oidc_refresh(&f.policy, &policy, &issuer)
        .unwrap()
        .rotate(narrow, deadline())
        .await
        .unwrap();
    let access = claims(&issuer, rotated.access_token());
    let id = claims(&issuer, rotated.id_token());
    assert_eq!(access["name"], "Current Alice");
    assert!(access.get("email").is_none());
    assert_eq!(access["scope"], "openid profile");
    assert_eq!(id["amr"], serde_json::json!(["local-token"]));
    assert_eq!(id["auth_time"], auth_time / 1_000_000);
    assert_eq!(id["exp"], access["exp"]);
    assert_eq!(
        access["exp"].as_u64().unwrap() - access["iat"].as_u64().unwrap(),
        600
    );
    assert!(
        id.get("nonce").is_none() && id.get("c_hash").is_none() && id.get("token_use").is_none()
    );
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha512};
    assert_eq!(
        id["at_hash"],
        URL_SAFE_NO_PAD.encode(&Sha512::digest(rotated.access_token().as_bytes())[..32])
    );
    let verifier =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(8192))
            .unwrap();
    assert!(
        verifier
            .verify(rotated.access_token(), &[], deadline())
            .is_ok()
    );
    assert!(
        verifier
            .verify(rotated.id_token(), &[], deadline())
            .is_err()
    );
    let childraw = rotated.refresh_token().unwrap();
    let child = row(&mut f, childraw).await;
    assert_eq!(child.get::<i64, _>("expires_at"), expiry);
    assert_eq!(child.get::<String, _>("family_id"), family);
    assert_eq!(child.get::<i64, _>("auth_time"), auth_time);
    assert_eq!(
        child.get::<String, _>("scopes_json"),
        "[\"openid\",\"profile\"]"
    );
    let third = f
        .store
        .oidc_refresh(&f.policy, &policy, &issuer)
        .unwrap()
        .rotate(input(childraw, true), deadline())
        .await
        .unwrap();
    assert!(third.refresh_token().is_some());
    assert_eq!(third.scope(), "openid profile");
    // Wrong bindings to a consumed ancestor cannot revoke its family.
    let current_active = active(&mut f, &family).await;
    for case in 0..3 {
        let mut wrong = input(raw, true);
        let expected = match case {
            0 => {
                wrong.scope = Some("address");
                Error::InvalidScope
            }
            1 => {
                wrong.client_id = Some("graphit-cli");
                Error::InvalidGrant
            }
            _ => {
                wrong.resource = Some("https://other.example/v1");
                Error::InvalidTarget
            }
        };
        assert_eq!(
            f.store
                .oidc_refresh(&f.policy, &policy, &issuer)
                .unwrap()
                .rotate(wrong, deadline())
                .await
                .unwrap_err(),
            expected
        );
        assert_eq!(active(&mut f, &family).await, current_active);
    }

    assert_eq!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(raw, true), deadline())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(active(&mut f, &family).await, 0);
    assert!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(third.refresh_token().unwrap(), true), deadline())
            .await
            .is_err()
    );
    assert!(
        verifier
            .verify(rotated.access_token(), &[], deadline())
            .is_ok()
    );
    let cli = initial(&f, &issuer, &policy, false).await;
    let cli2 = f
        .store
        .oidc_refresh(&f.policy, &policy, &issuer)
        .unwrap()
        .rotate(input(cli.refresh_token().unwrap(), false), deadline())
        .await
        .unwrap();
    assert_eq!(
        claims(&issuer, cli2.access_token())["aud"],
        serde_json::json!([AUDIENCE])
    );
    // Real failure after consuming old refresh rolls back old consumption and both inserts.
    let rollback = initial(&f, &issuer, &policy, true).await;
    let raw = rollback.refresh_token().unwrap();
    let count = f.token_count().await;
    f.admin.execute("CREATE FUNCTION deny_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.token_kind='refresh' THEN RAISE EXCEPTION 'fixture denied'; END IF; RETURN NEW; END $$; CREATE TRIGGER deny_refresh BEFORE INSERT ON public.local_tokens FOR EACH ROW EXECUTE FUNCTION deny_refresh()").await.unwrap();
    assert!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(raw, true), deadline())
            .await
            .is_err()
    );
    assert_eq!(f.token_count().await, count);
    assert!(
        row(&mut f, raw)
            .await
            .get::<Option<i64>, _>("consumed_at")
            .is_none()
    );
    f.admin
        .execute("DROP TRIGGER deny_refresh ON public.local_tokens; DROP FUNCTION deny_refresh()")
        .await
        .unwrap();
    assert!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(raw, true), deadline())
            .await
            .is_ok()
    );
    // The same exact refresh has one rotation winner; the other performs reuse revocation.
    let concurrent = initial(&f, &issuer, &policy, true).await;
    let raw = concurrent.refresh_token().unwrap();
    let family: String = row(&mut f, raw).await.get("family_id");
    let factory = f.store.oidc_refresh(&f.policy, &policy, &issuer).unwrap();
    let (a, b) = tokio::join!(
        factory.rotate(input(raw, true), deadline()),
        factory.rotate(input(raw, true), deadline())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(active(&mut f, &family).await, 0);
    // Force rotation of a child to hold the strong user lock while ancestral reuse waits.
    let ancestor = initial(&f, &issuer, &policy, true).await;
    let child = f
        .store
        .oidc_refresh(&f.policy, &policy, &issuer)
        .unwrap()
        .rotate(input(ancestor.refresh_token().unwrap(), true), deadline())
        .await
        .unwrap();
    let family: String = row(&mut f, child.refresh_token().unwrap())
        .await
        .get("family_id");
    let mut blocker = f.fixture.connection().await;
    blocker
        .execute("BEGIN; LOCK TABLE public.local_tokens IN SHARE MODE")
        .await
        .unwrap();
    let sharedstore = Arc::clone(&f.store);
    let sharedauth = Arc::clone(&f.policy);
    let spawn = |raw: &str| {
        let raw = raw.to_owned();
        let store = Arc::clone(&sharedstore);
        let auth = Arc::clone(&sharedauth);
        let issuer = Arc::clone(&issuer);
        let policy = Arc::clone(&policy);
        tokio::spawn(async move {
            store
                .oidc_refresh(&auth, &policy, &issuer)
                .unwrap()
                .rotate(input(&raw, true), deadline())
                .await
        })
    };
    let rotation = spawn(child.refresh_token().unwrap());
    wait_locks(&mut f, 1).await;
    let reuse = spawn(ancestor.refresh_token().unwrap());
    wait_locks(&mut f, 2).await;
    blocker.execute("COMMIT").await.unwrap();
    blocker.close().await.unwrap();
    assert!(rotation.await.unwrap().is_ok());
    assert_eq!(reuse.await.unwrap().unwrap_err(), Error::InvalidGrant);
    assert_eq!(active(&mut f, &family).await, 0);
    // Current identity/canonical DATA/UTC expiry guards preserve unused tokens.
    for case in 0..6 {
        let original = initial(&f, &issuer, &policy, true).await;
        let raw = original.refresh_token().unwrap();
        let count = f.token_count().await;
        match case {
            0 => {
                f.admin
                    .execute("UPDATE public.local_users SET enabled=0 WHERE username='alice'")
                    .await
                    .unwrap();
            }
            1 => {
                f.admin.execute("UPDATE public.local_users SET password_change_required=1 WHERE username='alice'").await.unwrap();
            }
            2 => {
                f.admin
                    .execute("UPDATE public.local_users SET revision=2 WHERE username='alice'")
                    .await
                    .unwrap();
            }
            3 => {
                sqlx_core::query::query(
                    "UPDATE public.local_tokens SET principal_json='[]' WHERE token_hash=$1",
                )
                .bind(hash(raw))
                .execute(&mut f.admin)
                .await
                .unwrap();
            }
            4 => {
                sqlx_core::query::query(
                    "UPDATE public.local_tokens SET expires_at=$1 WHERE token_hash=$2",
                )
                .bind(oidc::micros() - 1)
                .bind(hash(raw))
                .execute(&mut f.admin)
                .await
                .unwrap();
            }
            _ => {
                f.admin.execute("UPDATE public.local_users SET identity_kind='service' WHERE username='alice'").await.unwrap();
            }
        }
        assert!(
            f.store
                .oidc_refresh(&f.policy, &policy, &issuer)
                .unwrap()
                .rotate(input(raw, true), deadline())
                .await
                .is_err()
        );
        assert_eq!(f.token_count().await, count);
        assert!(
            row(&mut f, raw)
                .await
                .get::<Option<i64>, _>("consumed_at")
                .is_none()
        );
        f.admin.execute("UPDATE public.local_users SET enabled=1,password_change_required=0,revision=1,identity_kind='human' WHERE username='alice'").await.unwrap();
    }
    // Cancellation while blocked never consumes the credential.
    let original = initial(&f, &issuer, &policy, true).await;
    let raw = original.refresh_token().unwrap();
    let mut blocker = f.fixture.connection().await;
    blocker
        .execute("BEGIN; SELECT subject FROM public.local_users FOR UPDATE")
        .await
        .unwrap();
    let store = Arc::clone(&f.store);
    let auth = Arc::clone(&f.policy);
    let owner = Arc::clone(&issuer);
    let tokenpolicy = Arc::clone(&policy);
    let owned = raw.to_owned();
    let blocked = tokio::spawn(async move {
        store
            .oidc_refresh(&auth, &tokenpolicy, &owner)
            .unwrap()
            .rotate(input(&owned, true), deadline())
            .await
    });
    wait_locks(&mut f, 1).await;
    blocked.abort();
    assert!(blocked.await.unwrap_err().is_cancelled());
    blocker.execute("ROLLBACK").await.unwrap();
    blocker.close().await.unwrap();
    assert!(
        row(&mut f, raw)
            .await
            .get::<Option<i64>, _>("consumed_at")
            .is_none()
    );
    assert!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(raw, true), deadline())
            .await
            .is_ok()
    );
    // Actually issued deferred COMMIT times out; never manufacture rollback or output.
    let original = initial(&f, &issuer, &policy, true).await;
    let raw = original.refresh_token().unwrap();
    let count = f.token_count().await;
    f.admin.execute("CREATE FUNCTION delay_refresh_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER delay_refresh_commit AFTER UPDATE ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION delay_refresh_commit()").await.unwrap();
    assert_eq!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(
                input(raw, true),
                Instant::now() + Duration::from_millis(750)
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::OutcomeUncertain)
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = f.token_count().await;
    let consumed: Option<i64> = row(&mut f, raw).await.get("consumed_at");
    assert!((after == count && consumed.is_none()) || (after == count + 2 && consumed.is_some()));
    f.admin.execute("DROP TRIGGER delay_refresh_commit ON public.local_tokens; DROP FUNCTION delay_refresh_commit()").await.unwrap();
    assert!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(raw, true), Instant::now())
            .await
            .is_err()
    );
    let untouched_family: String = row(&mut f, cli2.refresh_token().unwrap())
        .await
        .get("family_id");
    assert!(active(&mut f, &untouched_family).await > 0);
    f.store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(input(raw, true), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.close().await;
}

fn pair_exchange_input(raw: &str) -> OidcTokenExchangeInput<'_> {
    OidcTokenExchangeInput {
        grant_type: Some("authorization_code"),
        client_id: Some("web-client"),
        code: Some(raw),
        redirect_uri: Some("https://client.example/cb"),
        code_verifier: Some(VERIFIER),
        resource: Some(RESOURCE),
        authorization: None,
    }
}
async fn pair_waiters(f: &mut OidcFixture, wanted: i64) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let count: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock_shared(%'"
        ).fetch_one(&mut f.admin).await.unwrap();
        if count == wanted {
            return;
        }
        assert!(
            Instant::now() < end,
            "bounded pair wait observation: wanted {wanted}, observed {count}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER and genuine P3/P4/revocation pair coordination"]
async fn postgres_native_oidc_shared_pair_contract() {
    let mut f = OidcFixture::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer = Arc::new(
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "pair-key", &key.serialize_der()).unwrap(),
    );
    let policy = Arc::new(
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(3600)).unwrap(),
    );
    let verifier = Arc::new(
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(8192))
            .unwrap(),
    );
    let parent = initial(&f, &issuer, &policy, true).await;
    let subject = claims(&issuer, parent.access_token())["sub"]
        .as_str()
        .unwrap()
        .to_owned();
    let pair_key = serde_json::to_string(&(&subject, "web-client")).unwrap();
    let family: String = row(&mut f, parent.refresh_token().unwrap())
        .await
        .get("family_id");
    let spawn_exchange = {
        let store = f.store.clone();
        let authorization = f.policy.clone();
        let policy = policy.clone();
        let issuer = issuer.clone();
        move |code: String, end: Instant| {
            let store = store.clone();
            let authorization = authorization.clone();
            let policy = policy.clone();
            let issuer = issuer.clone();
            tokio::spawn(async move {
                store
                    .oidc_token_exchange(&authorization, &policy, &issuer)
                    .unwrap()
                    .exchange(pair_exchange_input(&code), end)
                    .await
            })
        }
    };
    let spawn_rotate = {
        let store = f.store.clone();
        let authorization = f.policy.clone();
        let policy = policy.clone();
        let issuer = issuer.clone();
        move |raw: String, end: Instant| {
            let store = store.clone();
            let authorization = authorization.clone();
            let policy = policy.clone();
            let issuer = issuer.clone();
            tokio::spawn(async move {
                store
                    .oidc_refresh(&authorization, &policy, &issuer)
                    .unwrap()
                    .rotate(input(&raw, true), end)
                    .await
            })
        }
    };
    let spawn_revoke = {
        let store = f.store.clone();
        let authorization = f.policy.clone();
        let verifier = verifier.clone();
        move |raw: String| {
            let store = store.clone();
            let authorization = authorization.clone();
            let verifier = verifier.clone();
            tokio::spawn(async move {
                store
                    .oidc_revocation(&authorization, &verifier)
                    .unwrap()
                    .revoke(
                        broker_control::OidcRevocationInput {
                            token: Some(&raw),
                            client_id: Some("web-client"),
                            token_type_hint: None,
                            authorization: None,
                        },
                        deadline(),
                    )
                    .await
            })
        }
    };
    let pending = f.code(true, true).await.code().to_owned();
    let before = f.token_count().await;
    let mut blocker = f.fixture.connection().await;
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock(4750302, hashtext($1))")
        .bind(&pair_key)
        .execute(&mut blocker)
        .await
        .unwrap();
    let issuing = spawn_exchange(pending, deadline());
    let rotating = spawn_rotate(parent.refresh_token().unwrap().to_owned(), deadline());
    // The fixture pool has two connections; exercise disposal in a second round.
    pair_waiters(&mut f, 2).await;
    assert_eq!(
        f.token_count().await,
        before,
        "exclusive pair prevents any partial insert"
    );
    let unchanged = row(&mut f, parent.refresh_token().unwrap()).await;
    assert!(unchanged.get::<Option<i64>, _>("consumed_at").is_none());
    assert!(unchanged.get::<Option<i64>, _>("revoked_at").is_none());
    blocker.execute("COMMIT").await.unwrap();
    let issued = issuing.await.unwrap().unwrap();
    let rotated = rotating.await.unwrap().unwrap();
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock(4750302, hashtext($1))")
        .bind(&pair_key)
        .execute(&mut blocker)
        .await
        .unwrap();
    let revoking = spawn_revoke(parent.refresh_token().unwrap().to_owned());
    pair_waiters(&mut f, 1).await;
    assert_eq!(active(&mut f, &family).await, 4);
    blocker.execute("COMMIT").await.unwrap();
    revoking.await.unwrap().unwrap();
    assert_eq!(active(&mut f, &family).await, 0);
    assert!(
        verifier
            .verify(rotated.access_token(), &[], deadline())
            .is_ok()
    );
    assert!(
        verifier
            .verify(issued.access_token(), &[], deadline())
            .is_ok()
    );
    let issued_family: String = row(&mut f, issued.refresh_token().unwrap())
        .await
        .get("family_id");
    assert_ne!(issued_family, family);
    assert_eq!(active(&mut f, &issued_family).await, 2);

    // The original deadline expires while waiting, leaving the genuine code usable.
    let pending = f.code(true, true).await.code().to_owned();
    let before = f.token_count().await;
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock(4750302, hashtext($1))")
        .bind(&pair_key)
        .execute(&mut blocker)
        .await
        .unwrap();
    let overdue = spawn_exchange(pending.clone(), Instant::now() + Duration::from_secs(1));
    pair_waiters(&mut f, 1).await;
    assert_eq!(
        overdue.await.unwrap().unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    pair_waiters(&mut f, 0).await;
    assert_eq!(f.token_count().await, before);
    blocker.execute("COMMIT").await.unwrap();
    spawn_exchange(pending, deadline()).await.unwrap().unwrap();

    // Dropping a waiting real rotation also leaves its refresh unconsumed.
    let fresh = initial(&f, &issuer, &policy, true).await;
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock(4750302, hashtext($1))")
        .bind(&pair_key)
        .execute(&mut blocker)
        .await
        .unwrap();
    let canceled = spawn_rotate(fresh.refresh_token().unwrap().to_owned(), deadline());
    pair_waiters(&mut f, 1).await;
    canceled.abort();
    assert!(canceled.await.unwrap_err().is_cancelled());
    pair_waiters(&mut f, 0).await;
    assert!(
        row(&mut f, fresh.refresh_token().unwrap())
            .await
            .get::<Option<i64>, _>("consumed_at")
            .is_none()
    );
    blocker.execute("COMMIT").await.unwrap();
    spawn_rotate(fresh.refresh_token().unwrap().to_owned(), deadline())
        .await
        .unwrap()
        .unwrap();

    // A numerically corresponding one-bigint lock is a different PostgreSQL keyspace.
    let pending = f.code(true, true).await.code().to_owned();
    blocker.execute("BEGIN").await.unwrap();
    sqlx_core::query::query("SELECT pg_advisory_xact_lock((4750302::bigint << 32) | (hashtext($1)::bigint & 4294967295))")
        .bind(&pair_key).execute(&mut blocker).await.unwrap();
    let independent =
        tokio::time::timeout(Duration::from_secs(5), spawn_exchange(pending, deadline()))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    assert!(
        verifier
            .verify(independent.access_token(), &[], deadline())
            .is_ok()
    );
    blocker.execute("COMMIT").await.unwrap();
    blocker.close().await.unwrap();
    f.close().await;
}
