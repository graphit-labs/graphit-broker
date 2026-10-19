#[path = "support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared real TLS PostgreSQL fixture serves other suites"
)]
mod support;
use broker_control::{
    AdminBrokerSession, AdminBrokerSessionError as Error, AdminBrokerSessionLimits,
    BrokerAccessError, BrokerAccessIssuer, BrokerAccessVerifier, ControlError, IdentityReadLimits,
    OidcTokenExchangeInput, OidcTokenExchangePolicy, PostgresControlStore,
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, RESOURCE, VERIFIER};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use support::{deadline, n};

fn limits() -> AdminBrokerSessionLimits {
    AdminBrokerSessionLimits {
        identity: IdentityReadLimits {
            username_bytes: n(128),
            subject_bytes: n(512),
            role_bytes: n(128),
            roles: n(16),
            rows: n(128),
        },
        profile_json_bytes: n(8192),
    }
}
async fn read<'a>(
    store: &PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    token: &str,
    original: Instant,
) -> Result<AdminBrokerSession<'a>, Error> {
    let proof = verifier.verify(token, &[], original)?;
    store
        .admin_broker_sessions(verifier, limits())?
        .read(proof, original)
        .await
}
fn signed(key: &rcgen::KeyPair, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("admin-key".into());
    encode(
        &header,
        claims,
        &EncodingKey::from_ed_der(&key.serialize_der()),
    )
    .unwrap()
}
async fn wait_lock(f: &mut OidcFixture) {
    let end = deadline();
    loop {
        let count: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE '%FROM public.local_users u%'").fetch_one(&mut f.admin).await.unwrap();
        if count > 0 {
            return;
        }
        assert!(Instant::now() < end, "real Admin SELECT did not reach lock");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "genuine LOCAL P3 exchange and actual TLS PostgreSQL NOSUPERUSER"]
async fn postgres_native_admin_broker_session() {
    let mut f = OidcFixture::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer =
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "admin-key", &key.serialize_der()).unwrap();
    let policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(86400)).unwrap();
    let code = f.code(true, true).await;
    let result = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
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
        .unwrap();
    let token = result.access_token();
    let verifier = Arc::new(
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(8192))
            .unwrap(),
    );
    let count_before_read = f.token_count().await;
    let current = read(&f.store, &verifier, token, deadline()).await.unwrap();
    assert_eq!(f.token_count().await, count_before_read);
    assert_eq!(current.profile().subject, "alice-subject");
    assert_eq!(current.profile().name, "Alice");
    assert_eq!(current.principal().issuer, "local");
    assert_eq!(current.roles(), ["user"]);
    assert!(
        current
            .permissions()
            .iter()
            .any(|p| p.as_str() == "session.read")
    );
    current.check().unwrap();
    assert!(!format!("{current:?}").contains("alice"));
    // Current profile/revision/kind do not alter authentic JWT validity.
    f.admin.execute("UPDATE public.local_users SET name='Current',email='current@example.invalid',organization='new-org',teams_json='[\" z \",\"a\",\"z\",\"\"]',revision=revision+1,identity_kind='service',password_change_required=1 WHERE username='alice'").await.unwrap();
    let current = read(&f.store, &verifier, token, deadline()).await.unwrap();
    assert_eq!(current.profile().name, "Current");
    assert_eq!(current.principal().teams, ["a", "z"]);
    assert_eq!(current.principal().local_user_revision, 2);
    // Signed roles and bare raw-subject assignments cannot grant Admin.
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[ISSUER]);
    let claims = decode::<Value>(
        token,
        &DecodingKey::from_jwk(&issuer.jwks().keys[0]).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    let mut injected = claims.clone();
    injected["roles"] = json!(["admin"]);
    injected["permissions"] = json!(["*"]);
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'; INSERT INTO public.role_assignments(subject,role,created_at) VALUES('alice-subject','admin',0)").await.unwrap();
    assert_eq!(
        read(&f.store, &verifier, &signed(&key, &injected), deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    f.admin.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('local|alice-subject','admin',0)").await.unwrap();
    assert!(
        read(&f.store, &verifier, token, deadline())
            .await
            .unwrap()
            .roles()
            .iter()
            .any(|r| r == "admin")
    );
    f.admin.execute("DELETE FROM public.role_assignments; INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')").await.unwrap();
    // Missing username remains an authentic signed JWT, with no LOCAL binding.
    let mut absent = claims.clone();
    absent.as_object_mut().unwrap().remove("preferred_username");
    let absent = signed(&key, &absent);
    verifier.verify(&absent, &[], deadline()).unwrap();
    assert_eq!(
        read(&f.store, &verifier, &absent, deadline())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    // Even identical trust data in another verifier cannot supply this owner's proof.
    let foreign =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(8192))
            .unwrap();
    let foreign_proof = foreign.verify(token, &[], deadline()).unwrap();
    assert_eq!(
        f.store
            .admin_broker_sessions(&verifier, limits())
            .unwrap()
            .read(foreign_proof, deadline())
            .await
            .unwrap_err(),
        Error::Authentication(BrokerAccessError::InvalidToken)
    );
    for mutation in [
        "UPDATE public.local_users SET enabled=0 WHERE username='alice'",
        "UPDATE public.local_users SET subject='different' WHERE username='alice'",
        "UPDATE public.local_users SET username='renamed' WHERE username='alice'",
    ] {
        f.admin.execute(mutation).await.unwrap();
        assert_eq!(
            read(&f.store, &verifier, token, deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
        f.admin
            .execute(
                "UPDATE public.local_users SET enabled=1,username='alice',subject='alice-subject'",
            )
            .await
            .unwrap();
    }
    // Neither access ledger nor refresh family revocation is JWT authentication.
    f.admin
        .execute("DELETE FROM public.local_tokens")
        .await
        .unwrap();
    read(&f.store, &verifier, token, deadline()).await.unwrap();
    let mut tiny = limits();
    tiny.identity.rows = n(1);
    assert_eq!(
        f.store
            .admin_broker_sessions(&verifier, tiny)
            .unwrap()
            .read(verifier.verify(token, &[], deadline()).unwrap(), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::IdentityLimitExceeded)
    );
    f.admin
        .execute("UPDATE public.local_users SET teams_json='{}'")
        .await
        .unwrap();
    assert_eq!(
        read(&f.store, &verifier, token, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::CorruptIdentity)
    );
    f.admin.execute("UPDATE public.local_users SET teams_json='[]'; INSERT INTO public.role_permissions(role,action) VALUES('user','unknown.action')").await.unwrap();
    assert_eq!(
        read(&f.store, &verifier, token, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::CorruptRbac)
    );
    f.admin.execute("DELETE FROM public.role_permissions WHERE action='unknown.action'; REVOKE SELECT ON public.role_permissions FROM exchange_owner").await.unwrap();
    assert_eq!(
        read(&f.store, &verifier, token, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    f.admin
        .execute("GRANT SELECT ON public.role_permissions TO exchange_owner")
        .await
        .unwrap();
    let stale = read(
        &f.store,
        &verifier,
        token,
        Instant::now() + Duration::from_millis(200),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(210)).await;
    assert_eq!(stale.check(), Err(Error::Control(ControlError::Deadline)));
    // Actual lock timeout and cancellation are before COMMIT, never uncertain ACK.
    let mut locker = f.fixture.connection().await;
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE public.local_users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let store = f.store.clone();
    let verify = verifier.clone();
    let raw = token.to_owned();
    let timed = tokio::spawn(async move {
        read(
            &store,
            &verify,
            &raw,
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .map(|_| ())
    });
    wait_lock(&mut f).await;
    assert_eq!(
        timed.await.unwrap(),
        Err(Error::Control(ControlError::Deadline))
    );
    let store = f.store.clone();
    let verify = verifier.clone();
    let raw = token.to_owned();
    let cancelled =
        tokio::spawn(async move { read(&store, &verify, &raw, deadline()).await.map(|_| ()) });
    wait_lock(&mut f).await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    locker.close().await.unwrap();
    read(&f.store, &verifier, token, deadline()).await.unwrap();
    f.store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        read(&f.store, &verifier, token, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.close().await;
}

#[test]
fn explicit_admin_limits_reject_unrepresentable_sql_and_allocation() {
    let mut invalid = limits();
    invalid.identity.rows = std::num::NonZeroUsize::MAX;
    assert_eq!(invalid.validate(), Err(ControlError::Configuration));
    let mut invalid = limits();
    invalid.profile_json_bytes = std::num::NonZeroUsize::MAX;
    assert_eq!(invalid.validate(), Err(ControlError::Configuration));
}

#[tokio::test]
#[ignore = "genuine P3 TTL60 and actual missing-row SQL reply consumed after expiry"]
async fn postgres_admin_negative_reply_rechecks_actual_authentication_expiry() {
    let mut f = OidcFixture::new().await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer =
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "admin-key", &key.serialize_der()).unwrap();
    let policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(60), Duration::from_secs(86400)).unwrap();
    let code = f.code(true, false).await;
    let token = f
        .store
        .oidc_token_exchange(&f.policy, &policy, &issuer)
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
        .unwrap();
    let verifier =
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, Some(RESOURCE), issuer.jwks(), n(8192))
            .unwrap();
    let original = Instant::now() + Duration::from_secs(120);
    let proof = verifier
        .verify(token.access_token(), &[], original)
        .unwrap();
    let (utc, mono) = proof.authentication_expiry();
    // Make the signed locator absent before the statement takes its snapshot.
    f.admin
        .execute("UPDATE public.local_users SET username='renamed' WHERE username='alice'")
        .await
        .unwrap();
    let mut locker = f.fixture.connection().await;
    let mut tx = locker.begin().await.unwrap();
    tx.execute("LOCK TABLE public.local_users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let until = utc.duration_since(std::time::SystemTime::now()).unwrap();
    tokio::time::sleep(until.saturating_sub(Duration::from_secs(3))).await;
    proof.check().unwrap();
    let store = f.store.clone();
    let reader = store.admin_broker_sessions(&verifier, limits()).unwrap();
    let pending = reader.read(proof, original);
    tokio::pin!(pending);
    tokio::select! {
        _ = wait_lock(&mut f) => {},
        _ = &mut pending => panic!("real SELECT must be pending on the held PostgreSQL lock"),
    }
    // Withhold polling the actual reader until Exp and until PostgreSQL has sent
    // the zero-row completion. This exercises the ready negative outcome too,
    // rather than proving only the timer's pending branch.
    tokio::time::sleep(
        utc.duration_since(std::time::SystemTime::now())
            .unwrap_or_default()
            + Duration::from_millis(30),
    )
    .await;
    assert!(Instant::now() >= mono);
    assert!(Instant::now() < original);
    tx.rollback().await.unwrap();
    let end = deadline();
    loop {
        let ready: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE usename='exchange_owner' AND state='idle in transaction' AND query LIKE '%FROM public.local_users u%')").fetch_one(&mut f.admin).await.unwrap();
        if ready {
            break;
        }
        assert!(
            Instant::now() < end,
            "PostgreSQL must complete the zero-row SELECT before final polling"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        pending.await.unwrap_err(),
        Error::Authentication(BrokerAccessError::Expired)
    );
    locker.close().await.unwrap();
    f.close().await;
}
