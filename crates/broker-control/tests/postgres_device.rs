#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "reuse genuine LOCAL/SQL startup, not a fabricated login"
)]
#[path = "support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared actual TLS fixture supports independent suites"
)]
mod support;
use broker_control::{
    BrokerAccessIssuer, BrokerAccessVerifier, CompletedLocalLogin, ControlError,
    DeviceAuthorizationCodes, DeviceAuthorizationPolicy, DeviceConsent, DeviceError as Error,
    LocalAuthPolicy, LocalAuthStep, LocalMfaAttemptLimiter, LocalMfaAttemptPolicy,
    OidcTokenExchangeError as Protocol, PostgresControlStore, ProjectResourceAction,
    ProjectResourceModule,
};
use broker_security::{LocalAuthBinding, LocalMfaProtector, TokenKind};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use oidc::{AUDIENCE, ISSUER, OidcFixture, PASSWORD};
use serde_json::Value;
use sqlx_core::{connection::Connection, executor::Executor, row::Row};
use std::{
    num::NonZeroU32,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use support::{deadline, n};
use zeroize::Zeroizing;

fn policy() -> Arc<DeviceAuthorizationPolicy> {
    Arc::new(
        DeviceAuthorizationPolicy::new(
            Duration::from_secs(600),
            Duration::from_secs(1),
            Duration::from_secs(600),
        )
        .unwrap(),
    )
}
fn issuer() -> Arc<BrokerAccessIssuer> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    Arc::new(BrokerAccessIssuer::new(ISSUER, AUDIENCE, "device-key", &key.serialize_der()).unwrap())
}
fn hash(kind: TokenKind, raw: &str) -> String {
    oidc::digester()
        .token(kind, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
fn complete(step: LocalAuthStep) -> CompletedLocalLogin {
    match step {
        LocalAuthStep::Complete(v) => v,
        _ => panic!("genuine completed LOCAL proof required"),
    }
}
async fn login(f: &OidcFixture, context: LocalAuthBinding<'_>) -> CompletedLocalLogin {
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, deadline())
        .await
        .unwrap();
    let d = oidc::digester();
    let m = LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap();
    let p = LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    complete(
        f.store
            .local_auth_service(&d, &m, &p)
            .begin(proof, context, deadline())
            .await
            .unwrap(),
    )
}
async fn prepare(
    f: &OidcFixture,
    p: &DeviceAuthorizationPolicy,
    i: &BrokerAccessIssuer,
    c: &DeviceAuthorizationCodes,
) -> DeviceConsent {
    let normalized = broker_control::normalize_device_user_code(c.user_code()).unwrap();
    let login = login(f, LocalAuthBinding::DeviceApprove(normalized.as_bytes())).await;
    f.store
        .device_authorizations(&f.policy, p, i)
        .unwrap()
        .prepare(c.user_code(), login, deadline())
        .await
        .unwrap()
}
async fn approved(
    f: &OidcFixture,
    p: &DeviceAuthorizationPolicy,
    i: &BrokerAccessIssuer,
) -> DeviceAuthorizationCodes {
    let s = f.store.device_authorizations(&f.policy, p, i).unwrap();
    let c = s.issue("graphit-cli", "", deadline()).await.unwrap();
    let consent = prepare(f, p, i, &c).await;
    s.decide(
        c.user_code(),
        "graphit-cli",
        consent.secret(deadline()).unwrap(),
        true,
        deadline(),
    )
    .await
    .unwrap();
    c
}
async fn scalar(f: &mut OidcFixture, sql: &str) -> i64 {
    sqlx_core::query_scalar::query_scalar(sqlx_core::sql_str::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&mut f.admin)
        .await
        .unwrap()
}
async fn last_poll_clear(f: &mut OidcFixture, c: &DeviceAuthorizationCodes) {
    sqlx_core::query::query(
        "UPDATE public.oauth_device_codes SET last_poll_at=NULL WHERE device_hash=$1",
    )
    .bind(hash(TokenKind::DeviceCode, c.device_code()))
    .execute(&mut f.admin)
    .await
    .unwrap();
}
fn claims(i: &BrokerAccessIssuer, raw: &str) -> Value {
    let mut v = Validation::new(Algorithm::EdDSA);
    v.leeway = 0;
    v.set_audience(&[AUDIENCE]);
    v.set_issuer(&[ISSUER]);
    decode::<Value>(raw, &DecodingKey::from_jwk(&i.jwks().keys[0]).unwrap(), &v)
        .unwrap()
        .claims
}
async fn wait_locks(f: &mut OidcFixture, needle: &str, minimum: i64) {
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let n:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock' AND query LIKE $1")
            .bind(format!("%{needle}%")).fetch_one(&mut f.admin).await.unwrap();
        if n >= minimum {
            return;
        }
        assert!(Instant::now() < end, "real Device SQL wait not observed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn wait_lock(f: &mut OidcFixture, needle: &str) {
    wait_locks(f, needle, 1).await;
}
fn poll_job(
    f: &OidcFixture,
    p: &Arc<DeviceAuthorizationPolicy>,
    i: &Arc<BrokerAccessIssuer>,
    c: &DeviceAuthorizationCodes,
    end: Instant,
) -> tokio::task::JoinHandle<Result<broker_control::DeviceAccessToken, Error>> {
    let (store, authorization, p, i, raw) = (
        f.store.clone(),
        f.policy.clone(),
        p.clone(),
        i.clone(),
        Zeroizing::new(c.device_code().to_owned()),
    );
    tokio::spawn(async move {
        store
            .device_authorizations(&authorization, &p, &i)
            .unwrap()
            .poll("graphit-cli", &raw, end)
            .await
    })
}

#[tokio::test]
#[ignore = "real PostgreSQL TLS ordinary role, genuine LOCAL login and native JWT access grant"]
async fn postgres_device_authorization_contract() {
    let mut f = OidcFixture::new().await;
    let p = policy();
    let i = issuer();
    let store = f.store.clone();
    let authorization = f.policy.clone();
    let s = store.device_authorizations(&authorization, &p, &i).unwrap();
    for client in ["", "web-client", " graphit-cli"] {
        assert!(s.issue(client, "", deadline()).await.is_err());
    }
    for scope in [
        "custom",
        "offline_access",
        "openid",
        "profile",
        "email",
        " ",
        "\t",
        "openid custom",
        "bad\"scope",
    ] {
        assert_eq!(
            s.issue("graphit-cli", scope, deadline()).await.unwrap_err(),
            Error::Protocol(Protocol::InvalidScope)
        );
        assert_eq!(
            scalar(&mut f, "SELECT count(*) FROM public.oauth_device_codes").await,
            0
        );
    }
    let c = s.issue("graphit-cli", "", deadline()).await.unwrap();
    let normalized = broker_control::normalize_device_user_code(c.user_code()).unwrap();
    let row=sqlx_core::query::query("SELECT device_hash,user_hash,subject,local_user_revision,status,scopes_json,last_poll_at,expires_at-created_at AS ttl FROM public.oauth_device_codes")
        .fetch_one(&mut f.admin).await.unwrap();
    assert_eq!(
        row.get::<String, _>("device_hash"),
        hash(TokenKind::DeviceCode, c.device_code())
    );
    assert_eq!(
        row.get::<String, _>("user_hash"),
        hash(TokenKind::DeviceUserCode, &normalized)
    );
    assert_ne!(
        row.get::<String, _>("device_hash"),
        hash(TokenKind::DeviceUserCode, c.device_code())
    );
    assert_eq!(row.get::<String, _>("subject"), "");
    assert_eq!(row.get::<i64, _>("local_user_revision"), 0);
    assert_eq!(row.get::<String, _>("status"), "pending");
    assert_eq!(row.get::<i64, _>("ttl"), 600_000_000);
    assert!(row.get::<Option<i64>, _>("last_poll_at").is_none());
    assert_eq!(row.get::<String, _>("scopes_json"), "[]");
    for context in [
        LocalAuthBinding::AdminLogin,
        LocalAuthBinding::OauthAuthorize(normalized.as_bytes()),
        LocalAuthBinding::DeviceApprove(b"ZZZZZZZZ"),
    ] {
        let proof = login(&f, context).await;
        assert_eq!(
            s.prepare(c.user_code(), proof, deadline())
                .await
                .unwrap_err(),
            Error::Protocol(Protocol::InvalidGrant)
        );
    }
    let consent = prepare(&f, &p, &i, &c).await;
    assert_eq!(
        s.poll("graphit-cli", c.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::AuthorizationPending
    );
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.local_tokens").await,
        0
    );
    assert_eq!(
        scalar(
            &mut f,
            "SELECT count(*) FROM public.oauth_device_codes WHERE status='approved'"
        )
        .await,
        0
    );
    for (code, client, secret) in [
        (
            "ZZZZ-ZZZZ",
            "graphit-cli",
            consent.secret(deadline()).unwrap(),
        ),
        (
            c.user_code(),
            "web-client",
            consent.secret(deadline()).unwrap(),
        ),
        (c.user_code(), "graphit-cli", "wrong"),
    ] {
        assert!(
            s.decide(code, client, secret, true, deadline())
                .await
                .is_err()
        );
    }
    s.decide(
        c.user_code(),
        "graphit-cli",
        consent.secret(deadline()).unwrap(),
        true,
        deadline(),
    )
    .await
    .unwrap();
    assert!(
        s.decide(
            c.user_code(),
            "graphit-cli",
            consent.secret(deadline()).unwrap(),
            true,
            deadline()
        )
        .await
        .is_err()
    );
    for scopes in ["[\"custom\"]", "[\"offline_access\"]", "[\"openid\"]"] {
        sqlx_core::query::query(
            "UPDATE public.oauth_device_codes SET scopes_json=$1 WHERE device_hash=$2",
        )
        .bind(scopes)
        .bind(hash(TokenKind::DeviceCode, c.device_code()))
        .execute(&mut f.admin)
        .await
        .unwrap();
        assert_eq!(
            s.poll("graphit-cli", c.device_code(), deadline())
                .await
                .unwrap_err(),
            Error::Protocol(Protocol::MalformedStored)
        );
        assert_eq!(
            scalar(&mut f, "SELECT count(*) FROM public.local_tokens").await,
            0
        );
        assert_eq!(
            scalar(&mut f, "SELECT count(*) FROM public.oauth_device_codes").await,
            1
        );
    }
    f.admin
        .execute("UPDATE public.oauth_device_codes SET scopes_json='[]'")
        .await
        .unwrap();
    last_poll_clear(&mut f, &c).await;
    f.admin
        .execute("UPDATE public.local_users SET name='Current Device Profile'")
        .await
        .unwrap();
    let token = s
        .poll("graphit-cli", c.device_code(), deadline())
        .await
        .unwrap();
    assert_eq!(token.scope(), "");
    let v = claims(&i, token.access_token());
    assert_eq!(v["token_use"], "access");
    assert_eq!(v["client_id"], "graphit-cli");
    assert_eq!(v["aud"], serde_json::json!([AUDIENCE]));
    assert_eq!(v["name"], "Current Device Profile");
    assert_eq!(v["roles"], serde_json::json!(["user"]));
    assert!(v.get("auth_time").is_none());
    assert!(v.get("amr").is_none());
    assert_eq!(v["exp"].as_i64().unwrap() - v["iat"].as_i64().unwrap(), 600);
    let verifier = BrokerAccessVerifier::new(ISSUER, AUDIENCE, None, i.jwks(), n(8192)).unwrap();
    assert!(
        verifier
            .verify(token.access_token(), &[], deadline())
            .is_ok()
    );
    assert_eq!(v["scope"], "");
    for scope in ["custom", "openid", "offline_access", "broker"] {
        assert!(
            verifier
                .verify(token.access_token(), &[scope.into()], deadline())
                .is_err()
        );
    }
    assert!(
        verifier
            .verify(token.access_token(), &["unknown".into()], deadline())
            .is_err()
    );
    assert!(
        s.poll("graphit-cli", c.device_code(), deadline())
            .await
            .is_err()
    );
    let row = sqlx_core::query::query(
        "SELECT token_kind,family_id,resource,principal_json FROM public.local_tokens",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("token_kind"), "oidc_access");
    assert_eq!(row.get::<String, _>("family_id"), "");
    assert_eq!(row.get::<String, _>("resource"), "");
    let principal: Value = serde_json::from_str(&row.get::<String, _>("principal_json")).unwrap();
    assert_eq!(principal["auth_method"], "local-token");
    assert_eq!(principal["local_user_revision"], 1);
    let auth = f
        .store
        .broker_project_authorizer(&verifier, n(8192))
        .unwrap();
    assert!(matches!(
        auth.authorize(
            token.access_token(),
            &[],
            ProjectResourceModule::Task,
            ProjectResourceAction::Read,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            deadline()
        )
        .await,
        Err(broker_control::BrokerProjectAuthorizationError::Forbidden)
    ));
    f.admin
        .execute("UPDATE public.local_tokens SET revoked_at=created_at")
        .await
        .unwrap();
    assert!(
        verifier
            .verify(token.access_token(), &[], deadline())
            .is_ok(),
        "SQL revocation does not blacklist JWTs"
    );
    let empty = s.issue("graphit-cli", "", deadline()).await.unwrap();
    let consent = prepare(&f, &p, &i, &empty).await;
    assert_eq!(
        s.poll("graphit-cli", empty.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::AuthorizationPending
    );
    s.decide(
        empty.user_code(),
        "graphit-cli",
        consent.secret(deadline()).unwrap(),
        false,
        deadline(),
    )
    .await
    .unwrap();
    assert_eq!(
        s.poll("graphit-cli", empty.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::AccessDenied
    );
    assert!(
        s.poll("graphit-cli", empty.device_code(), deadline())
            .await
            .is_err()
    );
    let stale = s.issue("graphit-cli", "", deadline()).await.unwrap();
    let stale_consent = prepare(&f, &p, &i, &stale).await;
    f.admin
        .execute("UPDATE public.local_users SET revision=revision+1")
        .await
        .unwrap();
    assert!(
        s.decide(
            stale.user_code(),
            "graphit-cli",
            stale_consent.secret(deadline()).unwrap(),
            true,
            deadline()
        )
        .await
        .is_err()
    );
    assert_eq!(
        scalar(
            &mut f,
            "SELECT count(*) FROM public.oauth_device_codes WHERE status='approved'"
        )
        .await,
        0
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "actual LOCAL enrollment/TOTP/recovery ownership precedes Device consent"]
async fn postgres_device_recovery_consent_contract() {
    let mut f = OidcFixture::new().await;
    let p = policy();
    let i = issuer();
    let store = f.store.clone();
    let authorization = f.policy.clone();
    let s = store.device_authorizations(&authorization, &p, &i).unwrap();
    let c = s.issue("graphit-cli", "", deadline()).await.unwrap();
    let normalized = broker_control::normalize_device_user_code(c.user_code()).unwrap();
    let d = oidc::digester();
    let m = LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap();
    let local =
        LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    let auth = store.local_auth_service(&d, &m, &local);
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", PASSWORD, deadline())
        .await
        .unwrap();
    let LocalAuthStep::Pending(pending) = auth
        .begin(
            proof,
            LocalAuthBinding::DeviceApprove(normalized.as_bytes()),
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("real enrollment required");
    };
    let sdk = totp_rs::Totp::from_url(pending.enrollment().unwrap().otpauth_uri()).unwrap();
    let limiter = LocalMfaAttemptLimiter::new(
        LocalMfaAttemptPolicy::new(
            NonZeroU32::new(5).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            n(2),
        )
        .unwrap(),
    );
    let code = sdk.generate(oidc::micros() as u64 / 1_000_000).to_string();
    let login = complete(
        auth.complete_mfa(
            &limiter,
            pending.challenge(),
            LocalAuthBinding::DeviceApprove(normalized.as_bytes()),
            &code,
            deadline(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(login.auth_method(), "local-password+totp");
    assert_eq!(login.revision(), 2);
    let mut consent = s.prepare(c.user_code(), login, deadline()).await.unwrap();
    assert_eq!(
        scalar(
            &mut f,
            "SELECT count(*) FROM public.oauth_device_codes WHERE status='approved'"
        )
        .await,
        0
    );
    assert_eq!(
        s.poll("graphit-cli", c.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::AuthorizationPending
    );
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.local_tokens").await,
        0
    );
    assert!(
        consent.secret(deadline()).is_err(),
        "continuation cannot escape with undispatched recovery ownership"
    );
    let codes = consent.take_recovery_codes().unwrap();
    assert_eq!(codes.iter().count(), 10);
    assert!(consent.take_recovery_codes().is_none());
    assert!(
        auth.load(
            consent.secret(deadline()).unwrap(),
            LocalAuthBinding::DeviceApprove(normalized.as_bytes()),
            deadline()
        )
        .await
        .is_err(),
        "consent cannot be a factor challenge"
    );
    s.decide(
        c.user_code(),
        "graphit-cli",
        consent.secret(deadline()).unwrap(),
        true,
        deadline(),
    )
    .await
    .unwrap();
    last_poll_clear(&mut f, &c).await;
    let token = s
        .poll("graphit-cli", c.device_code(), deadline())
        .await
        .unwrap();
    assert_eq!(
        claims(&i, token.access_token())["sub"],
        oidc::digester()
            .oidc_subject(b"local", b"alice-subject")
            .unwrap()
            .as_str()
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "actual PostgreSQL interval state, one-use races, malformed rows, cancellation and SQL rollback"]
async fn postgres_device_sql_outcomes_contract() {
    let mut f = OidcFixture::new().await;
    let p = policy();
    let i = issuer();
    let store = f.store.clone();
    let authorization = f.policy.clone();
    let s = store.device_authorizations(&authorization, &p, &i).unwrap();
    let c = s.issue("graphit-cli", "", deadline()).await.unwrap();
    assert_eq!(
        s.poll("graphit-cli", c.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::AuthorizationPending
    );
    for expected in [6, 11] {
        assert_eq!(
            s.poll("graphit-cli", c.device_code(), deadline())
                .await
                .unwrap_err(),
            Error::SlowDown
        );
        let interval: i64 = sqlx_core::query_scalar::query_scalar(
            "SELECT interval_seconds FROM public.oauth_device_codes",
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap();
        assert_eq!(interval, expected);
    }
    let original = sqlx_core::query_scalar::query_scalar::<_, String>(
        "SELECT row_to_json(d)::text FROM public.oauth_device_codes d",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    for sql in [
        "UPDATE public.oauth_device_codes SET status='unexpected'",
        "UPDATE public.oauth_device_codes SET interval_seconds=2",
        "UPDATE public.oauth_device_codes SET scopes_json='{}'",
        "UPDATE public.oauth_device_codes SET scopes_json=repeat('x',8193)",
        "UPDATE public.oauth_device_codes SET subject='fabricated'",
        "UPDATE public.oauth_device_codes SET last_poll_at=expires_at+1",
    ] {
        f.admin.execute("BEGIN").await.unwrap();
        f.admin.execute(sql).await.unwrap();
        // Corruption must be committed for the application's distinct SQL handle to observe it.
        f.admin.execute("COMMIT").await.unwrap();
        assert!(
            s.poll("graphit-cli", c.device_code(), deadline())
                .await
                .is_err()
        );
        f.admin
            .execute("DELETE FROM public.oauth_device_codes")
            .await
            .unwrap();
        sqlx_core::query::query("INSERT INTO public.oauth_device_codes SELECT * FROM json_populate_record(NULL::public.oauth_device_codes,($1::text)::json)").bind(&original).execute(&mut f.admin).await.unwrap();
    }
    let now = oidc::micros();
    sqlx_core::query::query(
        "UPDATE public.oauth_device_codes SET created_at=$1,expires_at=$2,last_poll_at=NULL",
    )
    .bind(now - 601_000_000)
    .bind(now - 1_000_000)
    .execute(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(
        s.poll("graphit-cli", c.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::ExpiredToken
    );
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.oauth_device_codes").await,
        0
    );
    let expired_approved = approved(&f, &p, &i).await;
    let now = oidc::micros();
    sqlx_core::query::query("UPDATE public.oauth_device_codes SET created_at=$1,expires_at=$2,last_poll_at=NULL WHERE device_hash=$3").bind(now-601_000_000).bind(now-1_000_000).bind(hash(TokenKind::DeviceCode,expired_approved.device_code())).execute(&mut f.admin).await.unwrap();
    assert_eq!(
        s.poll("graphit-cli", expired_approved.device_code(), deadline())
            .await
            .unwrap_err(),
        Error::ExpiredToken
    );
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.oauth_device_codes").await,
        0
    );
    let c = approved(&f, &p, &i).await;
    f.admin
        .execute("REVOKE INSERT ON public.local_tokens FROM exchange_owner")
        .await
        .unwrap();
    assert!(matches!(
        s.poll("graphit-cli", c.device_code(), deadline()).await,
        Err(Error::Protocol(Protocol::Control(ControlError::Storage)))
    ));
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.local_tokens").await,
        0
    );
    assert_eq!(
        scalar(
            &mut f,
            "SELECT count(*) FROM public.oauth_device_codes WHERE status='approved'"
        )
        .await,
        1
    );
    f.admin
        .execute("GRANT INSERT ON public.local_tokens TO exchange_owner")
        .await
        .unwrap();
    let mut blocker = f.fixture.connection().await;
    blocker
        .execute("BEGIN; SELECT device_hash FROM public.oauth_device_codes FOR UPDATE")
        .await
        .unwrap();
    let job = poll_job(&f, &p, &i, &c, deadline());
    wait_lock(&mut f, "oauth_device_codes").await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    let end = deadline();
    loop {
        f.admin
            .execute("SELECT pg_stat_clear_snapshot()")
            .await
            .unwrap();
        let count=scalar(&mut f,"SELECT count(*) FROM pg_stat_activity WHERE usename='exchange_owner' AND wait_event_type='Lock'").await;
        if count == 0 {
            break;
        }
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let timeout = poll_job(&f, &p, &i, &c, Instant::now() + Duration::from_millis(500));
    wait_lock(&mut f, "oauth_device_codes").await;
    assert_eq!(
        timeout.await.unwrap().unwrap_err(),
        Error::Protocol(Protocol::Control(ControlError::Deadline))
    );
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.local_tokens").await,
        0
    );
    let a = poll_job(&f, &p, &i, &c, deadline());
    let b = poll_job(&f, &p, &i, &c, deadline());
    wait_locks(&mut f, "oauth_device_codes", 2).await;
    blocker.execute("COMMIT").await.unwrap();
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.local_tokens").await,
        1
    );
    let next = approved(&f, &p, &i).await;
    blocker
        .execute("BEGIN; SELECT subject FROM public.local_users WHERE username='alice' FOR UPDATE")
        .await
        .unwrap();
    let job = poll_job(&f, &p, &i, &next, deadline());
    wait_lock(&mut f, "FROM public.local_users").await;
    blocker
        .execute("UPDATE public.local_users SET revision=revision+1; COMMIT")
        .await
        .unwrap();
    assert!(job.await.unwrap().is_err());
    let short = poll_job(&f, &p, &i, &next, Instant::now());
    assert_eq!(
        short.await.unwrap().unwrap_err(),
        Error::Protocol(Protocol::Control(ControlError::Deadline))
    );
    blocker.close().await.unwrap();
    f.store.shutdown(deadline()).await.unwrap();
    for scope in ["custom", "openid", "offline_access", " "] {
        assert_eq!(
            s.issue("graphit-cli", scope, deadline()).await.unwrap_err(),
            Error::Protocol(Protocol::InvalidScope)
        );
    }
    assert_eq!(
        s.issue("graphit-cli", "", deadline()).await.unwrap_err(),
        Error::Protocol(Protocol::Control(ControlError::Closed))
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "actual durable code consumption and JWT row while TLS COMMIT ACK is withheld"]
async fn postgres_device_commit_ack_contract() {
    let mut f = OidcFixture::new().await;
    let p = policy();
    let i = issuer();
    let c = approved(&f, &p, &i).await;
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let store = Arc::new(
        PostgresControlStore::open(
            oidc::config_at(&f.fixture, relay.port),
            oidc::digester(),
            deadline(),
        )
        .await
        .unwrap(),
    );
    f.admin.execute("CREATE FUNCTION hold_device_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(718365); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER hold_device_commit AFTER INSERT ON public.local_tokens DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hold_device_commit(); SELECT pg_advisory_lock(718365)").await.unwrap();
    let pending = {
        let (store, auth, p, i, raw) = (
            store.clone(),
            f.policy.clone(),
            p.clone(),
            i.clone(),
            Zeroizing::new(c.device_code().to_owned()),
        );
        tokio::spawn(async move {
            store
                .device_authorizations(&auth, &p, &i)
                .unwrap()
                .poll("graphit-cli", &raw, deadline())
                .await
        })
    };
    wait_lock(&mut f, "COMMIT").await;
    relay.armed.store(true, Ordering::SeqCst);
    f.admin
        .execute("SELECT pg_advisory_unlock(718365)")
        .await
        .unwrap();
    let ack = tokio::time::timeout_at(deadline().into(), relay.replies.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        scalar(&mut f, "SELECT count(*) FROM public.oauth_device_codes").await,
        0
    );
    assert_eq!(
        scalar(
            &mut f,
            "SELECT count(*) FROM public.local_tokens WHERE token_kind='oidc_access'"
        )
        .await,
        1
    );
    ack.send(false).unwrap();
    assert_eq!(
        pending.await.unwrap().unwrap_err(),
        Error::Protocol(Protocol::Control(ControlError::OutcomeUncertain))
    );
    relay.armed.store(false, Ordering::SeqCst);
    relay.close().await;
    store.shutdown(deadline()).await.unwrap();
    f.close().await;
}
