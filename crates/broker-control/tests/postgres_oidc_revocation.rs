#[path = "support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared genuine LOCAL fixture retains independent inspection helpers"
)]
mod oidc;
#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture supports other suites"
)]
mod support;
use broker_control::{
    BrokerAccessIssuer, BrokerAccessTokenInput, BrokerAccessVerifier, ControlError,
    OidcRefreshInput, OidcRevocationInput, OidcTokenExchangeError as Error, OidcTokenExchangeInput,
    OidcTokenExchangePolicy, OidcTokenExchangeResult, PostgresControlStore,
};
use broker_security::{CredentialDigester, DigestLimits, TokenKind};
use oidc::{AUDIENCE, ISSUER, OidcFixture, RESOURCE, VERIFIER};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{deadline, n};

fn revoke_input<'a>(
    raw: &'a str,
    client: &'a str,
    hint: Option<&'a str>,
) -> OidcRevocationInput<'a> {
    OidcRevocationInput {
        token: Some(raw),
        client_id: Some(client),
        token_type_hint: hint,
        authorization: None,
    }
}
fn refresh_input(raw: &str) -> OidcRefreshInput<'_> {
    OidcRefreshInput {
        grant_type: Some("refresh_token"),
        client_id: Some("web-client"),
        refresh_token: Some(raw),
        scope: None,
        resource: Some(RESOURCE),
        authorization: None,
    }
}
async fn initial(
    f: &OidcFixture,
    issuer: &BrokerAccessIssuer,
    policy: &OidcTokenExchangePolicy,
) -> OidcTokenExchangeResult {
    let code = f.code(true, true).await;
    f.store
        .oidc_token_exchange(&f.policy, policy, issuer)
        .unwrap()
        .exchange(
            OidcTokenExchangeInput {
                grant_type: Some("authorization_code"),
                client_id: Some("web-client"),
                code: Some(code.code()),
                redirect_uri: Some("https://client.example/cb"),
                code_verifier: Some(VERIFIER),
                resource: Some(RESOURCE),
                authorization: None,
            },
            deadline(),
        )
        .await
        .unwrap()
}
fn issuer() -> BrokerAccessIssuer {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    BrokerAccessIssuer::new(ISSUER, AUDIENCE, "revocation-key", &key.serialize_der()).unwrap()
}
fn verifier(issuer: &BrokerAccessIssuer, resource: Option<&str>) -> BrokerAccessVerifier {
    BrokerAccessVerifier::new(ISSUER, AUDIENCE, resource, issuer.jwks(), n(8192)).unwrap()
}
fn hash(raw: &str) -> String {
    oidc::digester()
        .token(TokenKind::LocalRefresh, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
async fn family(f: &mut OidcFixture, raw: &str) -> String {
    sqlx_core::query_scalar::query_scalar(
        "SELECT family_id FROM public.local_tokens WHERE token_hash=$1",
    )
    .bind(hash(raw))
    .fetch_one(&mut f.admin)
    .await
    .unwrap()
}
async fn active(f: &mut OidcFixture, family: &str, kind: Option<&str>) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_tokens WHERE family_id=$1 AND revoked_at IS NULL AND ($2::text IS NULL OR token_kind=$2)")
        .bind(family).bind(kind).fetch_one(&mut f.admin).await.unwrap()
}
async fn wait_locks(f: &mut OidcFixture, minimum: i64) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let count: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock'")
            .fetch_one(&mut f.admin).await.unwrap();
        if count >= minimum {
            return;
        }
        assert!(
            Instant::now() < end,
            "owned operation did not reach the SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
#[ignore = "requires actual PostgreSQL TLS NOSUPERUSER fixture"]
async fn postgres_native_oidc_revocation_contract() {
    let mut f = OidcFixture::new().await;
    let issuer = issuer();
    let policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(86400)).unwrap();
    let public = verifier(&issuer, None);
    // An API resource binding must stay strict, while explicit disposal works for this issuer's other resource.
    let bound = verifier(&issuer, Some("https://other-resource.example/v1"));
    let original = initial(&f, &issuer, &policy).await;
    let raw = original.refresh_token().unwrap();
    let fam = family(&mut f, raw).await;
    assert!(
        public
            .verify(original.access_token(), &[], deadline())
            .is_ok()
    );
    assert!(
        bound
            .verify(original.access_token(), &[], deadline())
            .is_err()
    );
    for token in [original.access_token(), raw, fam.as_str(), "unknown"] {
        f.store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(
                revoke_input(token, "graphit-cli", Some("wrong")),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(active(&mut f, &fam, None).await, 2);
    }
    assert_eq!(
        f.store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(revoke_input(raw, "unknown-client", None), deadline())
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    let mut basic = revoke_input(raw, "web-client", None);
    basic.authorization = Some(("web-client", b"secret"));
    assert_eq!(
        f.store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(basic, deadline())
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    let access_row: (String, String, i64) = sqlx_core::query_as::query_as("SELECT token_id,oidc_subject,expires_at FROM public.local_tokens WHERE family_id=$1 AND token_kind='oidc_access'")
        .bind(&fam).fetch_one(&mut f.admin).await.unwrap();
    for invalid in [
        format!("{}x", original.access_token()),
        original.id_token().to_owned(),
        fam.clone(),
        access_row.0.clone(),
    ] {
        f.store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(
                revoke_input(&invalid, "web-client", Some("access_token")),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(active(&mut f, &fam, None).await, 2);
    }
    // Signed tokens outside the native ledger shape remain unknown even when
    // their JTI exceeds a valid deployment's credential digest cap.
    let small_digest = CredentialDigester::new(
        zeroize::Zeroizing::new(oidc::PEPPER.as_bytes().to_vec().into_boxed_slice()),
        DigestLimits::new(n(256), n(64), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap();
    let small_store =
        PostgresControlStore::open(oidc::config(&f.fixture), small_digest, deadline())
            .await
            .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (jti, expiry) in [
        ("not-native".to_owned(), now + 600),
        ("x".repeat(512), now + 600),
        (access_row.0.clone(), (i64::MAX as u64 / 1_000_000) + 1),
    ] {
        let signed = issuer
            .sign_access(
                BrokerAccessTokenInput {
                    subject: &access_row.1,
                    client_id: "web-client",
                    resource: Some(RESOURCE),
                    scope: "openid",
                    jti: &jti,
                    issued_at: now,
                    expires_at: expiry,
                    preferred_username: None,
                    name: None,
                    email: None,
                    organization: None,
                    groups: &[],
                    roles: &[],
                },
                deadline(),
            )
            .unwrap();
        assert!(public.verify(&signed, &[], deadline()).is_ok());
        small_store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(revoke_input(&signed, "web-client", None), deadline())
            .await
            .unwrap();
        assert_eq!(active(&mut f, &fam, None).await, 2);
        assert_eq!(
            small_store
                .oidc_revocation(&f.policy, &bound)
                .unwrap()
                .revoke(revoke_input(&signed, "unknown-client", None), deadline())
                .await
                .unwrap_err(),
            Error::InvalidClient
        );
    }
    small_store.shutdown(deadline()).await.unwrap();
    for changed in [
        "token_id='unbound'",
        "oidc_subject='unbound'",
        "client_id='graphit-cli'",
        "expires_at=expires_at+1000000",
        "expires_at=expires_at+1",
    ] {
        sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("UPDATE public.local_tokens SET {changed} WHERE family_id=$1 AND token_kind='oidc_access'")))
            .bind(&fam).execute(&mut f.admin).await.unwrap();
        f.store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(
                revoke_input(original.access_token(), "web-client", None),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(active(&mut f, &fam, None).await, 2);
        sqlx_core::query::query("UPDATE public.local_tokens SET token_id=$2,oidc_subject=$3,client_id='web-client',expires_at=$4 WHERE family_id=$1 AND token_kind='oidc_access'")
            .bind(&fam).bind(&access_row.0).bind(&access_row.1).bind(access_row.2).execute(&mut f.admin).await.unwrap();
    }
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(
            revoke_input(original.access_token(), "web-client", Some("refresh_token")),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(active(&mut f, &fam, Some("oidc_access")).await, 0);
    assert_eq!(active(&mut f, &fam, Some("refresh")).await, 1);
    assert!(
        public
            .verify(original.access_token(), &[], deadline())
            .is_ok()
    );
    assert!(
        bound
            .verify(original.access_token(), &[], deadline())
            .is_err()
    );
    let child = f
        .store
        .oidc_refresh(&f.policy, &policy, &issuer)
        .unwrap()
        .rotate(refresh_input(raw), deadline())
        .await
        .unwrap();
    // A consumed ancestor still closes its actual family, with an incorrect hint.
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(
            revoke_input(raw, "web-client", Some("access_token")),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(active(&mut f, &fam, None).await, 0);
    assert_eq!(
        f.store
            .oidc_refresh(&f.policy, &policy, &issuer)
            .unwrap()
            .rotate(refresh_input(child.refresh_token().unwrap()), deadline())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(revoke_input(raw, "web-client", None), deadline())
        .await
        .unwrap();
    assert!(public.verify(child.access_token(), &[], deadline()).is_ok());

    let independent = initial(&f, &issuer, &policy).await;
    let own_family = family(&mut f, independent.refresh_token().unwrap()).await;
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(revoke_input(raw, "web-client", None), deadline())
        .await
        .unwrap();
    assert_eq!(active(&mut f, &own_family, None).await, 2);
    // Current client removal cannot be bypassed by a still-live credential.
    f.admin
        .execute("DELETE FROM public.oauth_dynamic_clients WHERE client_id='web-client'")
        .await
        .unwrap();
    assert_eq!(
        f.store
            .oidc_revocation(&f.policy, &bound)
            .unwrap()
            .revoke(
                revoke_input(independent.refresh_token().unwrap(), "web-client", None),
                deadline()
            )
            .await
            .unwrap_err(),
        Error::InvalidClient
    );
    assert_eq!(active(&mut f, &own_family, None).await, 2);
    sqlx_core::query::query("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('web-client','Client','[\"https://client.example/cb\"]','[\"openid\",\"offline_access\"]','web',$1)")
        .bind(oidc::micros()).execute(&mut f.admin).await.unwrap();
    // Disabled identity and changed revision must not prevent disposal.
    f.admin
        .execute(
            "UPDATE public.local_users SET enabled=0,revision=revision+1 WHERE username='alice'",
        )
        .await
        .unwrap();
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(
            revoke_input(independent.refresh_token().unwrap(), "web-client", None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(active(&mut f, &own_family, None).await, 0);
    f.admin
        .execute("UPDATE public.local_users SET enabled=1 WHERE username='alice'")
        .await
        .unwrap();
    let expired = initial(&f, &issuer, &policy).await;
    let expiry_family = family(&mut f, expired.refresh_token().unwrap()).await;
    sqlx_core::query::query(
        "UPDATE public.local_tokens SET expires_at=created_at+1 WHERE token_hash=$1",
    )
    .bind(hash(expired.refresh_token().unwrap()))
    .execute(&mut f.admin)
    .await
    .unwrap();
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(
            revoke_input(expired.refresh_token().unwrap(), "web-client", None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(active(&mut f, &expiry_family, None).await, 2);
    let absent = initial(&f, &issuer, &policy).await;
    let absent_family = family(&mut f, absent.refresh_token().unwrap()).await;
    // Deliberately retain an orphan to exercise the optional row lock; never restore it.
    f.admin
        .execute("DELETE FROM public.local_users WHERE username='alice'")
        .await
        .unwrap();
    f.store
        .oidc_revocation(&f.policy, &bound)
        .unwrap()
        .revoke(
            revoke_input(absent.refresh_token().unwrap(), "web-client", None),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(active(&mut f, &absent_family, None).await, 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires actual PostgreSQL TLS NOSUPERUSER fixture"]
async fn postgres_oidc_revocation_races_and_rollback() {
    let mut f = OidcFixture::new().await;
    let issuer = Arc::new(issuer());
    let verifier = Arc::new(verifier(&issuer, None));
    let policy = Arc::new(
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(86400)).unwrap(),
    );
    for revoker_first in [true, false] {
        let original = initial(&f, &issuer, &policy).await;
        let raw = original.refresh_token().unwrap().to_owned();
        let fam = family(&mut f, &raw).await;
        let mut lock = f.fixture.connection().await;
        let mut tx = lock.begin().await.unwrap();
        tx.execute("SELECT subject FROM public.local_users WHERE username='alice' FOR UPDATE")
            .await
            .unwrap();
        let revoke = {
            let store = f.store.clone();
            let authorization = f.policy.clone();
            let verifier = verifier.clone();
            let raw = raw.clone();
            async move {
                store
                    .oidc_revocation(&authorization, &verifier)
                    .unwrap()
                    .revoke(revoke_input(&raw, "web-client", None), deadline())
                    .await
            }
        };
        let rotate = {
            let store = f.store.clone();
            let authorization = f.policy.clone();
            let issuer = issuer.clone();
            let policy = policy.clone();
            let raw = raw.clone();
            async move {
                store
                    .oidc_refresh(&authorization, &policy, &issuer)
                    .unwrap()
                    .rotate(refresh_input(&raw), deadline())
                    .await
            }
        };
        let (revoked, rotated);
        if revoker_first {
            revoked = tokio::spawn(revoke);
            wait_locks(&mut f, 1).await;
            rotated = tokio::spawn(rotate);
        } else {
            rotated = tokio::spawn(rotate);
            wait_locks(&mut f, 1).await;
            revoked = tokio::spawn(revoke);
        }
        wait_locks(&mut f, 2).await;
        tx.commit().await.unwrap();
        revoked.await.unwrap().unwrap();
        let result = rotated.await.unwrap();
        assert!(result.is_ok() || matches!(result, Err(Error::InvalidGrant)));
        assert_eq!(active(&mut f, &fam, Some("refresh")).await, 0);
        assert!(
            verifier
                .verify(original.access_token(), &[], deadline())
                .is_ok()
        );
    }
    let original = initial(&f, &issuer, &policy).await;
    let raw = original.refresh_token().unwrap();
    let fam = family(&mut f, raw).await;
    f.admin.execute("CREATE FUNCTION deny_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture denied'; END $$; CREATE TRIGGER deny_revocation BEFORE UPDATE ON public.local_tokens FOR EACH ROW EXECUTE FUNCTION deny_revocation()").await.unwrap();
    assert!(
        f.store
            .oidc_revocation(&f.policy, &verifier)
            .unwrap()
            .revoke(revoke_input(raw, "web-client", None), deadline())
            .await
            .is_err()
    );
    assert_eq!(active(&mut f, &fam, None).await, 2);
    f.admin
        .execute(
            "DROP TRIGGER deny_revocation ON public.local_tokens; DROP FUNCTION deny_revocation()",
        )
        .await
        .unwrap();
    let mut lock = f.fixture.connection().await;
    let mut tx = lock.begin().await.unwrap();
    tx.execute("SELECT subject FROM public.local_users WHERE username='alice' FOR UPDATE")
        .await
        .unwrap();
    assert_eq!(
        f.store
            .oidc_revocation(&f.policy, &verifier)
            .unwrap()
            .revoke(
                revoke_input(raw, "web-client", None),
                Instant::now() + Duration::from_millis(150)
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    let old_waiting: Vec<i32> = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock'")
        .fetch_all(&mut f.admin).await.unwrap();
    let pending = {
        let store = f.store.clone();
        let authorization = f.policy.clone();
        let verifier = verifier.clone();
        let raw = raw.to_owned();
        tokio::spawn(async move {
            store
                .oidc_revocation(&authorization, &verifier)
                .unwrap()
                .revoke(revoke_input(&raw, "web-client", None), deadline())
                .await
        })
    };
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let waiting: Vec<i32> = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock'")
            .fetch_all(&mut f.admin).await.unwrap();
        if waiting.iter().any(|pid| !old_waiting.contains(pid)) {
            break;
        }
        assert!(
            Instant::now() < end,
            "new cancellation operation did not reach its SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    tx.commit().await.unwrap();
    assert_eq!(active(&mut f, &fam, None).await, 2);
    f.store
        .oidc_revocation(&f.policy, &verifier)
        .unwrap()
        .revoke(revoke_input(raw, "web-client", None), deadline())
        .await
        .unwrap();
    assert_eq!(active(&mut f, &fam, None).await, 0);
    f.close().await;
}
