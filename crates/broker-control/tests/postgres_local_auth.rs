#[allow(
    dead_code,
    reason = "shared real HTTPS issuer serves multiple contracts"
)]
#[path = "support/browser_upstream.rs"]
mod browser;
#[allow(dead_code, reason = "shared genuine H1 composition also serves HTTP")]
#[path = "support/oidc_federated.rs"]
mod federated;
#[allow(
    dead_code,
    reason = "shared genuine P2/LOCAL fixture serves multiple contracts"
)]
#[path = "support/oidc_exchange.rs"]
mod oidc;
#[allow(
    dead_code,
    reason = "shared PostgreSQL support also serves other native suites"
)]
mod support;
use broker_control::{
    ConnectionLimits, ControlError, LocalAuthError, LocalAuthPolicy, LocalAuthStage, LocalAuthStep,
    LocalPasswordEngine, PendingLocalAuth, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, VerifiedLocalPassword,
};
use broker_security::{
    CredentialDigest, CredentialDigester, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
    TokenKind,
};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, digester, n};
use zeroize::Zeroizing;
const PASSWORD: &str = "fixture-only native LOCAL password";
fn utc() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
async fn fixture() -> (
    Fixture,
    Arc<PostgresControlStore>,
    Arc<LocalPasswordEngine>,
    PgConnection,
) {
    let fixture = Fixture::new(true).await;
    let mut admin = fixture.connection().await;
    admin.execute("CREATE ROLE local_auth_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION local_auth_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO local_auth_owner").await.unwrap();
    let config = PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(fixture.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "local_auth_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        fixture.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config, digester(), deadline())
            .await
            .unwrap(),
    );
    let engine = Arc::new(
        LocalPasswordEngine::new(
            LocalPasswordHasher::new(Zeroizing::new(vec![29; 32].into_boxed_slice())).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            deadline(),
        )
        .await
        .unwrap(),
    );
    let superuser: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='local_auth_owner'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(!superuser);
    let phc = engine.hash(PASSWORD, deadline()).await.unwrap();
    sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',$1,'','','','[]',1,0,1,0,0)").bind(phc.as_str()).execute(&mut admin).await.unwrap();
    (fixture, store, engine, admin)
}
async fn proof(
    store: &PostgresControlStore,
    engine: &LocalPasswordEngine,
) -> VerifiedLocalPassword {
    store
        .local_password_verifier(engine)
        .verify("alice", PASSWORD, deadline())
        .await
        .unwrap()
}
fn pending(step: LocalAuthStep) -> PendingLocalAuth {
    match step {
        LocalAuthStep::Pending(p) => p,
        _ => panic!("expected pending LOCAL stage"),
    }
}
async fn count(admin: &mut PgConnection) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_auth_challenges")
        .fetch_one(admin)
        .await
        .unwrap()
}
async fn wait_lock(admin: &mut PgConnection, needle: &str) {
    let end = deadline();
    loop {
        let waits:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='local_auth_owner' AND wait_event_type='Lock' AND query LIKE $1")
            .bind(format!("%{needle}%")).fetch_one(&mut *admin).await.unwrap();
        if waits > 0 {
            return;
        }
        assert!(
            Instant::now() < end,
            "actual LOCAL authentication row lock not observed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn valid_user(admin: &mut PgConnection) {
    admin.execute("UPDATE public.local_users SET username='alice',subject='alice-subject',identity_kind='human',enabled=1,password_change_required=0,revision=1").await.unwrap();
}
async fn current_stages_and_private_authority(
    store: &Arc<PostgresControlStore>,
    engine: &LocalPasswordEngine,
    admin: &mut PgConnection,
    d: &CredentialDigester,
    m: &LocalMfaProtector,
    required: &LocalAuthPolicy,
    exempt: &LocalAuthPolicy,
) {
    let service = store.local_auth_service(d, m, exempt);
    let step = service
        .begin(
            proof(store, engine).await,
            LocalAuthBinding::OauthAuthorize(b"request"),
            deadline(),
        )
        .await
        .unwrap();
    let LocalAuthStep::Complete(complete) = step else {
        panic!("explicit MFA exemption should complete LOCAL login");
    };
    assert_eq!(complete.username(), "alice");
    assert_eq!(complete.subject(), "alice-subject");
    assert_eq!(complete.revision(), 1);
    assert_eq!(complete.auth_method(), "local-password");
    assert!(complete.observed_at().as_i64() > 0);
    complete
        .verify_binding(d, LocalAuthBinding::OauthAuthorize(b"request"))
        .unwrap();
    assert!(
        complete
            .verify_binding(d, LocalAuthBinding::OauthAuthorize(b"other"))
            .is_err()
    );
    assert!(
        complete
            .verify_binding(d, LocalAuthBinding::AdminLogin)
            .is_err()
    );
    assert_eq!(format!("{complete:?}"), "CompletedLocalLogin([REDACTED])");
    assert_eq!(count(admin).await, 0);
    // Current mandatory flag supersedes both earlier proof and explicit exemption.
    let previous = proof(store, engine).await;
    admin
        .execute("UPDATE public.local_users SET password_change_required=1")
        .await
        .unwrap();
    let change = pending(
        service
            .begin(previous, LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap(),
    );
    assert_eq!(change.stage(), LocalAuthStage::PasswordChange);
    assert!(change.enrollment().is_none());
    assert_eq!(
        service
            .load(change.challenge(), LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap()
            .stage(),
        LocalAuthStage::PasswordChange
    );
    admin
        .execute("UPDATE public.local_users SET password_change_required=0")
        .await
        .unwrap();
    let service = store.local_auth_service(d, m, required);
    let enrollment = pending(
        service
            .begin(
                proof(store, engine).await,
                LocalAuthBinding::OauthAuthorize(b"request"),
                deadline(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(enrollment.stage(), LocalAuthStage::Enrollment);
    let presentation = enrollment.enrollment().unwrap();
    let hash = d
        .token(
            TokenKind::LocalAuthChallenge,
            enrollment.challenge().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let row:(String,String,String,String,i64,i64)=sqlx_core::query_as::query_as("SELECT challenge_hash,binding_hash,stage,secret_ciphertext,expires_at,created_at FROM public.local_auth_challenges WHERE challenge_hash=$1").bind(&hash).fetch_one(&mut *admin).await.unwrap();
    CredentialDigest::parse_sql_hex(&row.0).unwrap();
    CredentialDigest::parse_sql_hex(&row.1).unwrap();
    assert!(row.0 != enrollment.challenge());
    assert_eq!(row.2, "mfa-enrollment");
    assert_eq!(row.3.len(), 90);
    assert!(
        !row.3.contains(presentation.secret()),
        "plaintext secret must not be persisted"
    );
    assert_eq!(row.4 - row.5, 600_000_000);
    let stored = service
        .load(
            enrollment.challenge(),
            LocalAuthBinding::OauthAuthorize(b"request"),
            deadline(),
        )
        .await
        .unwrap();
    assert!(
        stored.enrollment().unwrap().secret() == presentation.secret(),
        "enrollment secret should survive native encryption"
    );
    assert!(
        stored.enrollment().unwrap().qr_png() == presentation.qr_png(),
        "SDK QR should match reconstituted enrollment"
    );
    assert_eq!(format!("{stored:?}"), "PendingLocalAuth([REDACTED])");
    for context in [
        LocalAuthBinding::AdminLogin,
        LocalAuthBinding::OauthAuthorize(b"other"),
        LocalAuthBinding::DeviceApprove(b"request"),
    ] {
        assert_eq!(
            service
                .load(enrollment.challenge(), context, deadline())
                .await
                .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
    }
    assert_eq!(count(admin).await, 2);
    for raw in [
        "local-auth.invalid",
        "",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert_eq!(
            service
                .load(raw, LocalAuthBinding::AdminLogin, deadline())
                .await
                .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
    }
    sqlx_core::query::query("INSERT INTO public.local_mfa(subject,secret_ciphertext,last_totp_step,confirmed_at) VALUES('alice-subject',$1,0,$2)").bind(row.3).bind(utc()).execute(&mut *admin).await.unwrap();
    assert_eq!(
        service
            .load(
                enrollment.challenge(),
                LocalAuthBinding::OauthAuthorize(b"request"),
                deadline()
            )
            .await
            .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    let mfa = pending(
        service
            .begin(
                proof(store, engine).await,
                LocalAuthBinding::DeviceApprove(b"ABCD-EFGH"),
                deadline(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(mfa.stage(), LocalAuthStage::Mfa);
    assert!(mfa.enrollment().is_none());
    service
        .load(
            mfa.challenge(),
            LocalAuthBinding::DeviceApprove(b"ABCD-EFGH"),
            deadline(),
        )
        .await
        .unwrap();
    admin.execute("DELETE FROM public.local_mfa").await.unwrap();
    assert_eq!(
        service
            .load(
                mfa.challenge(),
                LocalAuthBinding::DeviceApprove(b"ABCD-EFGH"),
                deadline()
            )
            .await
            .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    // Valid password evidence cannot survive a current identity mutation.
    for statement in [
        "UPDATE public.local_users SET revision=2",
        "UPDATE public.local_users SET username='alice-other'",
        "UPDATE public.local_users SET subject='changed-subject'",
        "UPDATE public.local_users SET enabled=0",
        "UPDATE public.local_users SET enabled=2",
        "UPDATE public.local_users SET identity_kind='service'",
        "UPDATE public.local_users SET password_change_required=2",
        "UPDATE public.local_users SET revision=0",
    ] {
        admin
            .execute("DELETE FROM public.local_auth_challenges")
            .await
            .unwrap();
        valid_user(admin).await;
        let original = proof(store, engine).await;
        admin.execute(statement).await.unwrap();
        assert_eq!(
            service
                .begin(original, LocalAuthBinding::AdminLogin, deadline())
                .await
                .unwrap_err(),
            LocalAuthError::Unauthenticated
        );
    }
    valid_user(admin).await;
}
async fn bound_load_corruption_and_expiry(
    fixture: &Fixture,
    store: &Arc<PostgresControlStore>,
    engine: &LocalPasswordEngine,
    admin: &mut PgConnection,
    d: &Arc<CredentialDigester>,
    m: &Arc<LocalMfaProtector>,
    policy: &Arc<LocalAuthPolicy>,
) {
    admin
        .execute("UPDATE public.local_users SET password_change_required=1")
        .await
        .unwrap();
    let service = store.local_auth_service(d, m, policy);
    let challenge = pending(
        service
            .begin(
                proof(store, engine).await,
                LocalAuthBinding::AdminLogin,
                deadline(),
            )
            .await
            .unwrap(),
    );
    let hash = d
        .token(
            TokenKind::LocalAuthChallenge,
            challenge.challenge().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let original:(String,String,String,i64,i64)=sqlx_core::query_as::query_as("SELECT purpose,binding_hash,stage,expires_at,created_at FROM public.local_auth_challenges WHERE challenge_hash=$1").bind(&hash).fetch_one(&mut *admin).await.unwrap();
    for statement in [
        "UPDATE public.local_auth_challenges SET stage='unknown'",
        "UPDATE public.local_auth_challenges SET stage='mfa'",
        "UPDATE public.local_auth_challenges SET purpose='unknown'",
        "UPDATE public.local_auth_challenges SET binding_hash=repeat('A',64)",
        "UPDATE public.local_auth_challenges SET secret_ciphertext=repeat('x',91)",
        "UPDATE public.local_auth_challenges SET expires_at=created_at",
        "UPDATE public.local_auth_challenges SET expires_at=1",
        "UPDATE public.local_auth_challenges SET local_user_revision=2",
        "UPDATE public.local_auth_challenges SET created_at=expires_at+1",
    ] {
        admin.execute(statement).await.unwrap();
        assert_eq!(
            service
                .load(
                    challenge.challenge(),
                    LocalAuthBinding::AdminLogin,
                    deadline()
                )
                .await
                .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
        assert_eq!(count(admin).await, 1);
        sqlx_core::query::query("UPDATE public.local_auth_challenges SET purpose=$1,binding_hash=$2,stage=$3,expires_at=$4,created_at=$5,secret_ciphertext='',local_user_revision=1").bind(&original.0).bind(&original.1).bind(&original.2).bind(original.3).bind(original.4).execute(&mut *admin).await.unwrap();
    }
    // Exact elapsed UTC persisted value is denied and never consumed.
    sqlx_core::query::query("UPDATE public.local_auth_challenges SET expires_at=$1")
        .bind(utc())
        .execute(&mut *admin)
        .await
        .unwrap();
    assert_eq!(
        service
            .load(
                challenge.challenge(),
                LocalAuthBinding::AdminLogin,
                deadline()
            )
            .await
            .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert_eq!(count(admin).await, 1);
    // A future challenge crosses expiry during a genuine user row wait.
    sqlx_core::query::query("UPDATE public.local_auth_challenges SET expires_at=$1")
        .bind(utc() + 2_000_000)
        .execute(&mut *admin)
        .await
        .unwrap();
    let mut locking = fixture.connection().await;
    locking.execute("BEGIN").await.unwrap();
    locking
        .execute("SELECT username FROM public.local_users FOR UPDATE")
        .await
        .unwrap();
    let (s, di, mi, po) = (
        Arc::clone(store),
        Arc::clone(d),
        Arc::clone(m),
        Arc::clone(policy),
    );
    let raw = Zeroizing::new(challenge.challenge().to_owned());
    let caller = tokio::spawn(async move {
        s.local_auth_service(&di, &mi, &po)
            .load(&raw, LocalAuthBinding::AdminLogin, deadline())
            .await
    });
    wait_lock(admin, "local_users").await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    locking.execute("COMMIT").await.unwrap();
    locking.close().await.unwrap();
    assert_eq!(
        caller.await.unwrap().unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert_eq!(count(admin).await, 1);
    // Initial unlocked read cannot mask a mutation while final FOR SHARE waits.
    sqlx_core::query::query("UPDATE public.local_auth_challenges SET expires_at=$1")
        .bind(original.3)
        .execute(&mut *admin)
        .await
        .unwrap();
    let mut locking = fixture.connection().await;
    locking.execute("BEGIN").await.unwrap();
    locking.execute("UPDATE public.local_auth_challenges SET created_at=created_at+1,expires_at=expires_at+1").await.unwrap();
    let (s, di, mi, po) = (
        Arc::clone(store),
        Arc::clone(d),
        Arc::clone(m),
        Arc::clone(policy),
    );
    let raw = Zeroizing::new(challenge.challenge().to_owned());
    let caller = tokio::spawn(async move {
        s.local_auth_service(&di, &mi, &po)
            .load(&raw, LocalAuthBinding::AdminLogin, deadline())
            .await
    });
    wait_lock(admin, "local_auth_challenges").await;
    locking.execute("COMMIT").await.unwrap();
    locking.close().await.unwrap();
    assert_eq!(
        caller.await.unwrap().unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert_eq!(count(admin).await, 1);
}
fn begin_job(
    store: &Arc<PostgresControlStore>,
    d: &Arc<CredentialDigester>,
    m: &Arc<LocalMfaProtector>,
    policy: &Arc<LocalAuthPolicy>,
    proof: VerifiedLocalPassword,
    end: Instant,
) -> tokio::task::JoinHandle<Result<LocalAuthStep, LocalAuthError>> {
    let (s, d, m, p) = (
        Arc::clone(store),
        Arc::clone(d),
        Arc::clone(m),
        Arc::clone(policy),
    );
    tokio::spawn(async move {
        s.local_auth_service(&d, &m, &p)
            .begin(proof, LocalAuthBinding::AdminLogin, end)
            .await
    })
}
async fn replacement_rollback_permissions_and_cancel(
    fixture: &Fixture,
    store: &Arc<PostgresControlStore>,
    engine: &LocalPasswordEngine,
    admin: &mut PgConnection,
    d: &Arc<CredentialDigester>,
    m: &Arc<LocalMfaProtector>,
    policy: &Arc<LocalAuthPolicy>,
) {
    admin
        .execute("DELETE FROM public.local_auth_challenges")
        .await
        .unwrap();
    let service = store.local_auth_service(d, m, policy);
    let first = pending(
        service
            .begin(
                proof(store, engine).await,
                LocalAuthBinding::AdminLogin,
                deadline(),
            )
            .await
            .unwrap(),
    );
    for privilege in ["INSERT", "DELETE", "SELECT"] {
        let proof = proof(store, engine).await;
        let statement = match privilege {
            "INSERT" => "REVOKE INSERT ON public.local_auth_challenges FROM local_auth_owner",
            "DELETE" => "REVOKE DELETE ON public.local_auth_challenges FROM local_auth_owner",
            _ => "REVOKE SELECT ON public.local_auth_challenges FROM local_auth_owner",
        };
        admin.execute(statement).await.unwrap();
        let result = if privilege == "SELECT" {
            service
                .load(first.challenge(), LocalAuthBinding::AdminLogin, deadline())
                .await
                .map(LocalAuthStep::Pending)
        } else {
            service
                .begin(proof, LocalAuthBinding::AdminLogin, deadline())
                .await
        };
        assert_eq!(
            result.unwrap_err(),
            LocalAuthError::Control(ControlError::Storage)
        );
        admin
            .execute(
                "GRANT SELECT,INSERT,DELETE ON public.local_auth_challenges TO local_auth_owner",
            )
            .await
            .unwrap();
        assert_eq!(count(admin).await, 1);
        service
            .load(first.challenge(), LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap();
    }
    // Real INSERT rejection occurs after the previous challenge DELETE.
    admin.execute("ALTER TABLE public.local_auth_challenges ADD CONSTRAINT fixture_reject_insert CHECK(created_at<0) NOT VALID").await.unwrap();
    assert_eq!(
        service
            .begin(
                proof(store, engine).await,
                LocalAuthBinding::AdminLogin,
                deadline()
            )
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::Storage)
    );
    admin
        .execute("ALTER TABLE public.local_auth_challenges DROP CONSTRAINT fixture_reject_insert")
        .await
        .unwrap();
    assert_eq!(count(admin).await, 1);
    service
        .load(first.challenge(), LocalAuthBinding::AdminLogin, deadline())
        .await
        .unwrap();
    // A genuine deferred trigger fails COMMIT after INSERT, with conservative outcome classification.
    admin.execute("CREATE FUNCTION public.fixture_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture-only deferred failure'; END; $$; CREATE CONSTRAINT TRIGGER fixture_commit_failure AFTER INSERT ON public.local_auth_challenges DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fixture_commit_failure()").await.unwrap();
    assert_eq!(
        service
            .begin(
                proof(store, engine).await,
                LocalAuthBinding::AdminLogin,
                deadline()
            )
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::OutcomeUncertain)
    );
    admin.execute("DROP TRIGGER fixture_commit_failure ON public.local_auth_challenges; DROP FUNCTION public.fixture_commit_failure()").await.unwrap();
    assert_eq!(count(admin).await, 1);
    service
        .load(first.challenge(), LocalAuthBinding::AdminLogin, deadline())
        .await
        .unwrap();
    // Two independently verified passwords contend at the real current-user lock.
    let (p1, p2) = (proof(store, engine).await, proof(store, engine).await);
    let c1 = begin_job(store, d, m, policy, p1, deadline());
    let c2 = begin_job(store, d, m, policy, p2, deadline());
    let (a, b) = (
        pending(c1.await.unwrap().unwrap()),
        pending(c2.await.unwrap().unwrap()),
    );
    assert_eq!(count(admin).await, 1);
    let a_ok = service
        .load(a.challenge(), LocalAuthBinding::AdminLogin, deadline())
        .await
        .is_ok();
    let b_ok = service
        .load(b.challenge(), LocalAuthBinding::AdminLogin, deadline())
        .await
        .is_ok();
    assert!(
        a_ok ^ b_ok,
        "exactly one concurrently replaced challenge should remain"
    );
    assert_eq!(
        service
            .load(first.challenge(), LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    for cancel in [true, false] {
        let p = proof(store, engine).await;
        let mut locking = fixture.connection().await;
        locking.execute("BEGIN").await.unwrap();
        locking
            .execute("SELECT username FROM public.local_users FOR UPDATE")
            .await
            .unwrap();
        let end = if cancel {
            deadline()
        } else {
            Instant::now() + Duration::from_secs(2)
        };
        let caller = begin_job(store, d, m, policy, p, end);
        wait_lock(admin, "local_users").await;
        if cancel {
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                caller.await.unwrap().unwrap_err(),
                LocalAuthError::Control(ControlError::Deadline)
            );
        }
        locking.execute("ROLLBACK").await.unwrap();
        locking.close().await.unwrap();
        let recovered = pending(
            service
                .begin(
                    proof(store, engine).await,
                    LocalAuthBinding::AdminLogin,
                    deadline(),
                )
                .await
                .unwrap(),
        );
        service
            .load(
                recovered.challenge(),
                LocalAuthBinding::AdminLogin,
                deadline(),
            )
            .await
            .unwrap();
    }
    let p = proof(store, engine).await;
    assert_eq!(
        service
            .begin(p, LocalAuthBinding::AdminLogin, Instant::now())
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::Deadline)
    );
    let p = proof(store, engine).await;
    store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        service
            .begin(p, LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::Closed)
    );
}
#[tokio::test]
#[ignore = "native ordinary PostgreSQL TLS, real password KDF, AEAD/QR, races and lifecycle"]
async fn postgres_local_auth_native_contract() {
    let (fixture, store, engine, mut admin) = fixture().await;
    let d = Arc::new(digester());
    let m =
        Arc::new(LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap());
    let required = Arc::new(
        LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(600)).unwrap(),
    );
    let exempt =
        LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    current_stages_and_private_authority(&store, &engine, &mut admin, &d, &m, &required, &exempt)
        .await;
    bound_load_corruption_and_expiry(&fixture, &store, &engine, &mut admin, &d, &m, &required)
        .await;
    replacement_rollback_permissions_and_cancel(
        &fixture, &store, &engine, &mut admin, &d, &m, &required,
    )
    .await;
    admin.close().await.unwrap();
    store.shutdown(deadline()).await.unwrap();
    fixture.shutdown().unwrap();
}

const NEW_PASSWORD: &str = "fixture-only changed native LOCAL password";

struct PasswordChangeFixture {
    fixture: Fixture,
    store: Arc<PostgresControlStore>,
    engine: Arc<LocalPasswordEngine>,
    admin: PgConnection,
    d: Arc<CredentialDigester>,
    m: Arc<LocalMfaProtector>,
    required: Arc<LocalAuthPolicy>,
    exempt: Arc<LocalAuthPolicy>,
    old_hash: Zeroizing<String>,
}
impl PasswordChangeFixture {
    async fn new() -> Self {
        let (fixture, store, engine, mut admin) = fixture().await;
        let old_hash = Zeroizing::new(
            sqlx_core::query_scalar::query_scalar::<_, String>(
                "SELECT password_hash FROM public.local_users WHERE subject='alice-subject'",
            )
            .fetch_one(&mut admin)
            .await
            .unwrap(),
        );
        Self {
            fixture,
            store,
            engine,
            admin,
            old_hash,
            d: Arc::new(digester()),
            m: Arc::new(
                LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap(),
            ),
            required: Arc::new(
                LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(600))
                    .unwrap(),
            ),
            exempt: Arc::new(
                LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600))
                    .unwrap(),
            ),
        }
    }
    async fn reset(&mut self) {
        self.admin.execute("DELETE FROM public.local_mfa_recovery_codes; DELETE FROM public.local_mfa; DELETE FROM public.local_auth_challenges; DELETE FROM public.local_tokens; DELETE FROM public.oidc_auth_requests; DELETE FROM public.oauth_device_codes; DELETE FROM public.local_users WHERE subject<>'alice-subject'").await.unwrap();
        sqlx_core::query::query("UPDATE public.local_users SET username='alice',identity_kind='human',enabled=1,password_hash=$1,password_change_required=1,revision=1,updated_at=0 WHERE subject='alice-subject'")
            .bind(self.old_hash.as_str()).execute(&mut self.admin).await.unwrap();
    }
    async fn challenge(&self, context: LocalAuthBinding<'_>) -> PendingLocalAuth {
        let password = proof(&self.store, &self.engine).await;
        pending(
            self.store
                .local_auth_service(&self.d, &self.m, &self.required)
                .begin(password, context, deadline())
                .await
                .unwrap(),
        )
    }
    async fn change(
        &self,
        raw: &str,
        context: LocalAuthBinding<'_>,
        password: &str,
        required: bool,
    ) -> Result<LocalAuthStep, LocalAuthError> {
        let policy = if required {
            &self.required
        } else {
            &self.exempt
        };
        self.store
            .local_auth_service(&self.d, &self.m, policy)
            .complete_password_change(&self.engine, raw, context, password, deadline())
            .await
    }
    // Entire relevant SQL state, including PHC/cipher, compares without Debug output.
    async fn snapshot(&mut self) -> Zeroizing<String> {
        Zeroizing::new(sqlx_core::query_scalar::query_scalar::<_,String>(
            "SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(t) ORDER BY username) FROM public.local_users t),'factors',(SELECT jsonb_agg(to_jsonb(t) ORDER BY subject) FROM public.local_mfa t),'recovery',(SELECT jsonb_agg(to_jsonb(t) ORDER BY subject,code_hash) FROM public.local_mfa_recovery_codes t),'tokens',(SELECT jsonb_agg(to_jsonb(t) ORDER BY token_hash) FROM public.local_tokens t),'requests',(SELECT jsonb_agg(to_jsonb(t) ORDER BY request_hash) FROM public.oidc_auth_requests t),'devices',(SELECT jsonb_agg(to_jsonb(t) ORDER BY device_hash) FROM public.oauth_device_codes t),'challenges',(SELECT jsonb_agg(to_jsonb(t) ORDER BY challenge_hash) FROM public.local_auth_challenges t))::text",
        ).fetch_one(&mut self.admin).await.unwrap())
    }
    async fn seed_artifacts(&mut self) {
        // Native SQL representations qualify invalidation only, not OAuth/device issuance.
        sqlx_core::query::query("INSERT INTO public.local_users SELECT 'bob','bob-subject','human',$1,'','','','[]',1,0,1,0,0")
            .bind(self.old_hash.as_str()).execute(&mut self.admin).await.unwrap();
        self.admin.execute("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,revoked_at,consumed_at,last_used_at,created_at) VALUES(repeat('a',64),'active','access','alice-subject','','{}','','','','[]',1,'',1,9999999999999999,NULL,NULL,NULL,1),(repeat('b',64),'revoked','refresh','alice-subject','','{}','','','','[]',1,'',1,9999999999999999,12345,NULL,NULL,1),(repeat('c',64),'other','access','bob-subject','','{}','','','','[]',1,'',1,9999999999999999,NULL,NULL,NULL,1); INSERT INTO public.oidc_auth_requests(request_hash,identity_subject,request_json,expires_at,created_at) VALUES(repeat('a',64),'alice-subject','{}',9999999999999999,1),(repeat('b',64),'','{}',9999999999999999,1),(repeat('c',64),'bob-subject','{}',9999999999999999,1); INSERT INTO public.oauth_device_codes(device_hash,user_hash,client_id,scopes_json,subject,local_user_revision,status,interval_seconds,expires_at,created_at) VALUES(repeat('a',64),repeat('a',64),'client','[]','alice-subject',1,'approved',5,9999999999999999,1),(repeat('b',64),repeat('b',64),'client','[]','alice-subject',1,'pending',5,9999999999999999,1),(repeat('c',64),repeat('c',64),'client','[]','bob-subject',1,'approved',5,9999999999999999,1),(repeat('d',64),repeat('d',64),'client','[]','',0,'pending',5,9999999999999999,1); INSERT INTO public.local_auth_challenges SELECT repeat('e',64),'alice-subject',1,'device-approve',binding_hash,'password-change','',expires_at,created_at FROM public.local_auth_challenges LIMIT 1; INSERT INTO public.local_auth_challenges SELECT repeat('f',64),'bob-subject',1,'admin-login',binding_hash,'password-change','',expires_at,created_at FROM public.local_auth_challenges LIMIT 1").await.unwrap();
    }
    async fn factor(&mut self) {
        let prepared = self
            .m
            .prepare("alice-subject", "Graphit Broker", "alice")
            .unwrap();
        sqlx_core::query::query("INSERT INTO public.local_mfa(subject,secret_ciphertext,last_totp_step,confirmed_at) VALUES('alice-subject',$1,42,123)")
            .bind(prepared.ciphertext()).execute(&mut self.admin).await.unwrap();
        self.admin.execute("INSERT INTO public.local_mfa_recovery_codes VALUES('alice-subject',repeat('a',64),123)").await.unwrap();
    }
    async fn scalar(&mut self, sql: &'static str) -> i64 {
        sqlx_core::query_scalar::query_scalar(sql)
            .fetch_one(&mut self.admin)
            .await
            .unwrap()
    }
    fn job(
        &self,
        raw: &str,
        end: Instant,
    ) -> tokio::task::JoinHandle<Result<LocalAuthStep, LocalAuthError>> {
        let (s, e, d, m, p) = (
            Arc::clone(&self.store),
            Arc::clone(&self.engine),
            Arc::clone(&self.d),
            Arc::clone(&self.m),
            Arc::clone(&self.exempt),
        );
        let raw = Zeroizing::new(raw.to_owned());
        tokio::spawn(async move {
            s.local_auth_service(&d, &m, &p)
                .complete_password_change(&e, &raw, LocalAuthBinding::AdminLogin, NEW_PASSWORD, end)
                .await
        })
    }
}

async fn password_change_denials(f: &mut PasswordChangeFixture) {
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let before = f.snapshot().await;
    for value in ["short".to_owned(), "é".repeat(14), "x".repeat(4097)] {
        assert_eq!(
            f.change(p.challenge(), LocalAuthBinding::AdminLogin, &value, false)
                .await
                .unwrap_err(),
            LocalAuthError::Password(broker_security::LocalPasswordError::InvalidPassword)
        );
        assert!(
            before == f.snapshot().await,
            "invalid new password mutated SQL"
        );
    }
    assert_eq!(
        f.change(p.challenge(), LocalAuthBinding::AdminLogin, PASSWORD, false)
            .await
            .unwrap_err(),
        LocalAuthError::PasswordUnchanged
    );
    assert!(
        before == f.snapshot().await,
        "unchanged password consumed challenge"
    );
    for (raw, context) in [
        (p.challenge(), LocalAuthBinding::OauthAuthorize(b"wrong")),
        ("invalid", LocalAuthBinding::AdminLogin),
    ] {
        assert_eq!(
            f.change(raw, context, NEW_PASSWORD, false)
                .await
                .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
        assert!(before == f.snapshot().await, "wrong input mutated SQL");
    }
    let corruptions = [
        (
            "UPDATE public.local_users SET enabled=0",
            "UPDATE public.local_users SET enabled=1",
        ),
        (
            "UPDATE public.local_users SET identity_kind='service'",
            "UPDATE public.local_users SET identity_kind='human'",
        ),
        (
            "UPDATE public.local_users SET username='bad name'",
            "UPDATE public.local_users SET username='alice'",
        ),
        (
            "UPDATE public.local_users SET password_change_required=0",
            "UPDATE public.local_users SET password_change_required=1",
        ),
        (
            "UPDATE public.local_users SET revision=2",
            "UPDATE public.local_users SET revision=1",
        ),
        (
            "UPDATE public.local_auth_challenges SET stage='mfa'",
            "UPDATE public.local_auth_challenges SET stage='password-change'",
        ),
        (
            "UPDATE public.local_auth_challenges SET binding_hash=repeat('0',64)",
            "",
        ),
    ];
    for (bad, restore) in corruptions {
        f.admin.execute(bad).await.unwrap();
        let corrupted = f.snapshot().await;
        assert_eq!(
            f.change(
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                false
            )
            .await
            .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
        assert!(
            corrupted == f.snapshot().await,
            "invalid current identity/stage/context changed SQL"
        );
        if restore.is_empty() {
            break;
        }
        f.admin.execute(restore).await.unwrap();
    }
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    f.admin
        .execute("UPDATE public.local_users SET password_hash='malformed-native-PHC'")
        .await
        .unwrap();
    let before = f.snapshot().await;
    assert_eq!(
        f.change(
            p.challenge(),
            LocalAuthBinding::AdminLogin,
            NEW_PASSWORD,
            false
        )
        .await
        .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert!(before == f.snapshot().await, "malformed PHC mutated SQL");
    f.reset().await;
    f.admin
        .execute("UPDATE public.local_users SET revision=9223372036854775807")
        .await
        .unwrap();
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let before = f.snapshot().await;
    assert_eq!(
        f.change(
            p.challenge(),
            LocalAuthBinding::AdminLogin,
            NEW_PASSWORD,
            false
        )
        .await
        .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert!(
        before == f.snapshot().await,
        "revision overflow mutated SQL"
    );
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    sqlx_core::query::query("UPDATE public.local_auth_challenges SET expires_at=$1")
        .bind(utc())
        .execute(&mut f.admin)
        .await
        .unwrap();
    let before = f.snapshot().await;
    assert_eq!(
        f.change(
            p.challenge(),
            LocalAuthBinding::AdminLogin,
            NEW_PASSWORD,
            false
        )
        .await
        .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert!(
        before == f.snapshot().await,
        "expired challenge mutated SQL"
    );
}

async fn password_change_stages_and_invalidation(f: &mut PasswordChangeFixture) {
    for (context, required, factor) in [
        (LocalAuthBinding::AdminLogin, false, false),
        (
            LocalAuthBinding::OauthAuthorize(b"current-request"),
            true,
            false,
        ),
        (LocalAuthBinding::DeviceApprove(b"CURRENT-CODE"), true, true),
    ] {
        f.reset().await;
        if factor {
            f.factor().await;
        }
        let p = f.challenge(context).await;
        f.seed_artifacts().await;
        let factor_before=Zeroizing::new(sqlx_core::query_scalar::query_scalar::<_,String>("SELECT jsonb_build_object('factor',(SELECT to_jsonb(t) FROM public.local_mfa t),'recovery',(SELECT jsonb_agg(to_jsonb(t)) FROM public.local_mfa_recovery_codes t))::text").fetch_one(&mut f.admin).await.unwrap());
        let result = f
            .change(p.challenge(), context, NEW_PASSWORD, required)
            .await
            .unwrap();
        let state:(i64,i64,i64)=sqlx_core::query_as::query_as("SELECT revision,password_change_required::bigint,updated_at FROM public.local_users WHERE subject='alice-subject'").fetch_one(&mut f.admin).await.unwrap();
        assert_eq!((state.0, state.1), (2, 0));
        assert!(state.2 > 0);
        assert!(
            f.store
                .local_password_verifier(&f.engine)
                .verify("alice", PASSWORD, deadline())
                .await
                .is_err()
        );
        let fresh = f
            .store
            .local_password_verifier(&f.engine)
            .verify("alice", NEW_PASSWORD, deadline())
            .await
            .unwrap();
        assert_eq!(fresh.revision(), 2);
        assert!(!fresh.password_change_required());
        match result {
            LocalAuthStep::Complete(c) => {
                assert!(!required);
                assert_eq!(c.revision(), 2);
                assert_eq!(c.auth_method(), "local-password");
                c.verify_binding(&f.d, context).unwrap();
            }
            LocalAuthStep::Pending(next) => {
                assert!(required);
                assert_eq!(
                    next.stage(),
                    if factor {
                        LocalAuthStage::Mfa
                    } else {
                        LocalAuthStage::Enrollment
                    }
                );
                if !factor {
                    assert!(
                        next.enrollment()
                            .unwrap()
                            .qr_png()
                            .starts_with(b"\x89PNG\r\n\x1a\n")
                    );
                }
                assert_eq!(
                    f.store
                        .local_auth_service(&f.d, &f.m, &f.required)
                        .load(next.challenge(), context, deadline())
                        .await
                        .unwrap()
                        .stage(),
                    next.stage()
                );
            }
        }
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_tokens WHERE token_id='active' AND revoked_at= (SELECT updated_at FROM public.local_users WHERE subject='alice-subject')").await,1);
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_tokens WHERE token_id='revoked' AND revoked_at=12345").await,1);
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_tokens WHERE token_id='other' AND revoked_at IS NULL").await,1);
        assert_eq!(f.scalar("SELECT count(*) FROM public.oidc_auth_requests WHERE identity_subject='alice-subject'").await,0);
        assert_eq!(f.scalar("SELECT count(*) FROM public.oidc_auth_requests WHERE identity_subject IN ('','bob-subject')").await,2);
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.oauth_device_codes WHERE subject IN ('','bob-subject')"
            )
            .await,
            2
        );
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.oauth_device_codes WHERE subject='alice-subject'"
            )
            .await,
            if matches!(context, LocalAuthBinding::DeviceApprove(_)) {
                2
            } else {
                0
            }
        );
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_auth_challenges WHERE subject='alice-subject' AND local_user_revision=1").await,0);
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_auth_challenges WHERE subject='alice-subject' AND local_user_revision=2").await,i64::from(required));
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.local_auth_challenges WHERE subject='bob-subject'"
            )
            .await,
            1
        );
        let factor_after=Zeroizing::new(sqlx_core::query_scalar::query_scalar::<_,String>("SELECT jsonb_build_object('factor',(SELECT to_jsonb(t) FROM public.local_mfa t),'recovery',(SELECT jsonb_agg(to_jsonb(t)) FROM public.local_mfa_recovery_codes t))::text").fetch_one(&mut f.admin).await.unwrap());
        assert!(
            factor_before == factor_after,
            "password change reset MFA or recovery"
        );
        assert_eq!(
            f.change(p.challenge(), context, NEW_PASSWORD, required)
                .await
                .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
    }
}

async fn password_change_rollback(f: &mut PasswordChangeFixture) {
    // Real SDK presentation failure after all mutation/invalidation statements.
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    f.seed_artifacts().await;
    let before = f.snapshot().await;
    let bad =
        LocalAuthPolicy::new(true, "invalid:issuer".into(), Duration::from_secs(600)).unwrap();
    assert_eq!(
        f.store
            .local_auth_service(&f.d, &f.m, &bad)
            .complete_password_change(
                &f.engine,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                deadline()
            )
            .await
            .unwrap_err(),
        LocalAuthError::Mfa(broker_security::LocalMfaError::Presentation)
    );
    assert!(
        before == f.snapshot().await,
        "QR failure left partial password/invalidation"
    );
    // UPDATE lock privilege stays available; actual write is rejected by a constraint.
    for (setup, teardown, expected) in [
        (
            "ALTER TABLE public.local_users ADD CONSTRAINT fixture_change_update CHECK(password_change_required=1) NOT VALID",
            "ALTER TABLE public.local_users DROP CONSTRAINT fixture_change_update",
            ControlError::Storage,
        ),
        (
            "REVOKE UPDATE ON public.local_tokens FROM local_auth_owner",
            "GRANT UPDATE ON public.local_tokens TO local_auth_owner",
            ControlError::Storage,
        ),
        (
            "REVOKE DELETE ON public.oidc_auth_requests FROM local_auth_owner",
            "GRANT DELETE ON public.oidc_auth_requests TO local_auth_owner",
            ControlError::Storage,
        ),
        (
            "REVOKE DELETE ON public.local_auth_challenges FROM local_auth_owner",
            "GRANT DELETE ON public.local_auth_challenges TO local_auth_owner",
            ControlError::Storage,
        ),
        (
            "REVOKE DELETE ON public.oauth_device_codes FROM local_auth_owner",
            "GRANT DELETE ON public.oauth_device_codes TO local_auth_owner",
            ControlError::Storage,
        ),
        (
            "ALTER TABLE public.local_auth_challenges ADD CONSTRAINT fixture_change_insert CHECK(created_at<0) NOT VALID",
            "ALTER TABLE public.local_auth_challenges DROP CONSTRAINT fixture_change_insert",
            ControlError::Storage,
        ),
        (
            "CREATE FUNCTION public.fixture_change_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture-only commit failure'; END; $$; CREATE CONSTRAINT TRIGGER fixture_change_commit AFTER UPDATE ON public.local_users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fixture_change_commit()",
            "DROP TRIGGER fixture_change_commit ON public.local_users; DROP FUNCTION public.fixture_change_commit()",
            ControlError::OutcomeUncertain,
        ),
    ] {
        f.admin.execute(setup).await.unwrap();
        let before = f.snapshot().await;
        assert_eq!(
            f.change(
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                true
            )
            .await
            .unwrap_err(),
            LocalAuthError::Control(expected)
        );
        assert!(
            before == f.snapshot().await,
            "SQL failure left partial password/invalidation/next challenge"
        );
        f.admin.execute(teardown).await.unwrap();
        f.store
            .local_auth_service(&f.d, &f.m, &f.required)
            .load(p.challenge(), LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap();
    }
}

async fn password_change_races_and_deadlines(f: &mut PasswordChangeFixture) {
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let (a, b) = (
        f.job(p.challenge(), deadline()),
        f.job(p.challenge(), deadline()),
    );
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        a.err().or_else(|| b.err()).unwrap(),
        LocalAuthError::InvalidChallenge
    );
    assert_eq!(
        f.scalar("SELECT revision FROM public.local_users WHERE subject='alice-subject'")
            .await,
        2
    );
    // Final challenge has changed while its initial committed snapshot was observed.
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let mut locking = f.fixture.connection().await;
    locking.execute("BEGIN").await.unwrap();
    sqlx_core::query::query(
        "UPDATE public.local_auth_challenges SET created_at=created_at-1 WHERE challenge_hash=$1",
    )
    .bind(
        f.d.token(TokenKind::LocalAuthChallenge, p.challenge().as_bytes())
            .unwrap()
            .to_sql_hex(),
    )
    .execute(&mut locking)
    .await
    .unwrap();
    let caller = f.job(p.challenge(), deadline());
    wait_lock(&mut f.admin, "local_auth_challenges").await;
    locking.execute("COMMIT").await.unwrap();
    assert_eq!(
        caller.await.unwrap().unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    // A real user-row wait crosses UTC expiry while Original still remains live.
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    sqlx_core::query::query("UPDATE public.local_auth_challenges SET expires_at=$1")
        .bind(utc() + 1_000_000)
        .execute(&mut f.admin)
        .await
        .unwrap();
    locking.execute("BEGIN; SELECT subject FROM public.local_users WHERE subject='alice-subject' FOR UPDATE").await.unwrap();
    let caller = f.job(p.challenge(), deadline());
    wait_lock(&mut f.admin, "local_users").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    locking.execute("COMMIT").await.unwrap();
    assert_eq!(
        caller.await.unwrap().unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert_eq!(
        f.scalar("SELECT revision FROM public.local_users WHERE subject='alice-subject'")
            .await,
        1
    );
    for abort in [true, false] {
        f.reset().await;
        let p = f.challenge(LocalAuthBinding::AdminLogin).await;
        let before = f.snapshot().await;
        locking.execute("BEGIN; SELECT subject FROM public.local_users WHERE subject='alice-subject' FOR UPDATE").await.unwrap();
        let caller = f.job(p.challenge(), Instant::now() + Duration::from_secs(2));
        wait_lock(&mut f.admin, "local_users").await;
        if abort {
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                caller.await.unwrap().unwrap_err(),
                LocalAuthError::Control(ControlError::Deadline)
            );
        }
        locking.execute("COMMIT").await.unwrap();
        assert!(before == f.snapshot().await, "deadline/cancel changed SQL");
        assert!(matches!(
            f.change(
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                false
            )
            .await
            .unwrap(),
            LocalAuthStep::Complete(_)
        ));
    }
    locking.close().await.unwrap();
    f.reset().await;
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    assert_eq!(
        f.store
            .local_auth_service(&f.d, &f.m, &f.exempt)
            .complete_password_change(
                &f.engine,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                Instant::now()
            )
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::Deadline)
    );
    f.store.shutdown(deadline()).await.unwrap();
    assert_eq!(
        f.change(
            p.challenge(),
            LocalAuthBinding::AdminLogin,
            NEW_PASSWORD,
            false
        )
        .await
        .unwrap_err(),
        LocalAuthError::Control(ControlError::Closed)
    );
}

#[tokio::test]
#[ignore = "native ordinary PostgreSQL TLS, mandatory password mutation/invalidation/advance, real KDF and failure/race/lifecycle"]
async fn postgres_password_change_native_contract() {
    let mut f = PasswordChangeFixture::new().await;
    password_change_denials(&mut f).await;
    password_change_stages_and_invalidation(&mut f).await;
    password_change_rollback(&mut f).await;
    password_change_races_and_deadlines(&mut f).await;
    f.admin.close().await.unwrap();
    f.store.shutdown(deadline()).await.unwrap();
    f.fixture.shutdown().unwrap();
}

fn mfa_limiter(failures: u32, capacity: usize) -> broker_control::LocalMfaAttemptLimiter {
    broker_control::LocalMfaAttemptLimiter::new(
        broker_control::LocalMfaAttemptPolicy::new(
            std::num::NonZeroU32::new(failures).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            NonZeroUsize::new(capacity).unwrap(),
        )
        .unwrap(),
    )
}
fn sdk_code(sdk: &totp_rs::Totp, offset: u64) -> Zeroizing<String> {
    Zeroizing::new(
        sdk.generate((utc() as u64 / 1_000_000) + offset)
            .to_string(),
    )
}
fn completed(step: LocalAuthStep) -> broker_control::CompletedLocalLogin {
    match step {
        LocalAuthStep::Complete(value) => value,
        _ => panic!("expected verified LOCAL completion"),
    }
}
impl PasswordChangeFixture {
    async fn reset_mfa(&mut self) {
        self.reset().await;
        self.admin
            .execute("UPDATE public.local_users SET password_change_required=0")
            .await
            .unwrap();
    }
    async fn complete_factor(
        &self,
        limiter: &broker_control::LocalMfaAttemptLimiter,
        p: &PendingLocalAuth,
        context: LocalAuthBinding<'_>,
        code: &str,
    ) -> Result<LocalAuthStep, LocalAuthError> {
        self.store
            .local_auth_service(&self.d, &self.m, &self.required)
            .complete_mfa(limiter, p.challenge(), context, code, deadline())
            .await
    }
    fn factor_job(
        &self,
        limiter: &Arc<broker_control::LocalMfaAttemptLimiter>,
        p: &PendingLocalAuth,
        code: &str,
        end: Instant,
    ) -> tokio::task::JoinHandle<Result<LocalAuthStep, LocalAuthError>> {
        let (s, d, m, policy, limiter) = (
            Arc::clone(&self.store),
            Arc::clone(&self.d),
            Arc::clone(&self.m),
            Arc::clone(&self.required),
            Arc::clone(limiter),
        );
        let raw = Zeroizing::new(p.challenge().to_owned());
        let code = Zeroizing::new(code.to_owned());
        tokio::spawn(async move {
            s.local_auth_service(&d, &m, &policy)
                .complete_mfa(&limiter, &raw, LocalAuthBinding::AdminLogin, &code, end)
                .await
        })
    }
}
async fn mfa_enrollment_and_one_time_consumption(f: &mut PasswordChangeFixture) {
    for context in [
        LocalAuthBinding::AdminLogin,
        LocalAuthBinding::OauthAuthorize(b"native-request"),
        LocalAuthBinding::DeviceApprove(b"native-user-code"),
    ] {
        f.reset_mfa().await;
        let limiter = Arc::new(mfa_limiter(10, 4));
        let p = f.challenge(context).await;
        assert_eq!(p.stage(), LocalAuthStage::Enrollment);
        let sdk = totp_rs::Totp::from_url(p.enrollment().unwrap().otpauth_uri()).unwrap();
        f.seed_artifacts().await;
        let started = utc();
        let enrollment_code = sdk_code(&sdk, 0);
        let mut login = completed(
            f.complete_factor(&limiter, &p, context, &enrollment_code)
                .await
                .unwrap(),
        );
        assert_eq!(login.auth_method(), "local-password+totp");
        assert_eq!(login.revision(), 2);
        assert!(login.observed_at().as_i64() >= started);
        login.verify_binding(&f.d, context).unwrap();
        let codes = login.take_recovery_codes().unwrap();
        assert!(login.take_recovery_codes().is_none());
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='alice-subject'"
            )
            .await,
            10
        );
        assert_eq!(
            f.scalar("SELECT revision FROM public.local_users WHERE subject='alice-subject'")
                .await,
            2
        );
        let cipher = Zeroizing::new(
            sqlx_core::query_scalar::query_scalar::<_, String>(
                "SELECT secret_ciphertext FROM public.local_mfa WHERE subject='alice-subject'",
            )
            .fetch_one(&mut f.admin)
            .await
            .unwrap(),
        );
        let restored =
            f.m.load("alice-subject", &cipher, "Graphit Broker", "alice")
                .unwrap();
        assert!(
            restored.secret() == p.enrollment().unwrap().secret(),
            "enrollment must persist the verified secret"
        );
        for code in codes.iter() {
            let normalized = broker_security::normalize_local_recovery_code(code).unwrap();
            let digest =
                f.d.recovery(b"alice-subject", normalized.as_bytes())
                    .unwrap()
                    .to_sql_hex();
            let stored: bool=sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.local_mfa_recovery_codes WHERE subject='alice-subject' AND code_hash=$1)").bind(digest).fetch_one(&mut f.admin).await.unwrap();
            assert!(stored, "SQL must hold the subject-bound MAC");
        }
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_tokens WHERE token_id='active' AND revoked_at IS NOT NULL").await,1);
        assert_eq!(
            f.scalar("SELECT revoked_at FROM public.local_tokens WHERE token_id='revoked'")
                .await,
            12345
        );
        assert_eq!(f.scalar("SELECT count(*) FROM public.local_tokens WHERE token_id='other' AND revoked_at IS NULL").await,1);
        assert_eq!(f.scalar("SELECT count(*) FROM public.oidc_auth_requests WHERE identity_subject='alice-subject'").await,0);
        assert_eq!(f.scalar("SELECT count(*) FROM public.oidc_auth_requests WHERE identity_subject='' OR identity_subject='bob-subject'").await,2);
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.local_auth_challenges WHERE subject='alice-subject'"
            )
            .await,
            0
        );
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.local_auth_challenges WHERE subject='bob-subject'"
            )
            .await,
            1
        );
        let expected = if matches!(context, LocalAuthBinding::DeviceApprove(_)) {
            2
        } else {
            0
        };
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.oauth_device_codes WHERE subject='alice-subject'"
            )
            .await,
            expected
        );
        assert_eq!(f.scalar("SELECT count(*) FROM public.oauth_device_codes WHERE subject='' OR subject='bob-subject'").await,2);
        assert_eq!(
            f.complete_factor(&limiter, &p, context, &enrollment_code)
                .await
                .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
        let code0 = Zeroizing::new(codes.iter().next().unwrap().to_owned());
        let code1 = Zeroizing::new(codes.iter().nth(1).unwrap().to_owned());
        let q = f.challenge(LocalAuthBinding::AdminLogin).await;
        assert_eq!(q.stage(), LocalAuthStage::Mfa);
        // The enrollment step cannot be reused for a second authentication.
        assert!(matches!(
            f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, &enrollment_code)
                .await
                .unwrap(),
            LocalAuthStep::Pending(_)
        ));
        let mut strong = completed(
            f.complete_factor(
                &limiter,
                &q,
                LocalAuthBinding::AdminLogin,
                &sdk_code(&sdk, 30),
            )
            .await
            .unwrap(),
        );
        assert_eq!(strong.auth_method(), "local-password+totp");
        assert_eq!(strong.revision(), 2);
        assert!(strong.take_recovery_codes().is_none());
        let q = f.challenge(LocalAuthBinding::AdminLogin).await;
        completed(
            f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, &code0)
                .await
                .unwrap(),
        );
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='alice-subject'"
            )
            .await,
            9
        );
        let q = f.challenge(LocalAuthBinding::AdminLogin).await;
        assert!(matches!(
            f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, &code0)
                .await
                .unwrap(),
            LocalAuthStep::Pending(_)
        ));
        let before = f.snapshot().await;
        let a = f.factor_job(&limiter, &q, &code1, deadline());
        let b = f.factor_job(&limiter, &q, &code1, deadline());
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert!(
            a.is_ok() ^ b.is_ok(),
            "one concurrent factor completion must win"
        );
        let error = if let Err(error) = a {
            error
        } else {
            b.unwrap_err()
        };
        assert!(matches!(
            error,
            LocalAuthError::InvalidChallenge | LocalAuthError::MfaBusy
        ));
        assert_eq!(
            f.scalar(
                "SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='alice-subject'"
            )
            .await,
            8
        );
        assert!(before.as_str() != f.snapshot().await.as_str());
        // Factor presence alone still supplies only local-password when policy exempts MFA.
        let mut exempt = completed(
            f.store
                .local_auth_service(&f.d, &f.m, &f.exempt)
                .begin(
                    proof(&f.store, &f.engine).await,
                    LocalAuthBinding::AdminLogin,
                    deadline(),
                )
                .await
                .unwrap(),
        );
        assert_eq!(exempt.auth_method(), "local-password");
        assert!(exempt.take_recovery_codes().is_none());
    }
}
async fn mfa_denials_and_admission(f: &mut PasswordChangeFixture) {
    f.reset_mfa().await;
    let limiter = mfa_limiter(1, 1);
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let sdk = totp_rs::Totp::from_url(p.enrollment().unwrap().otpauth_uri()).unwrap();
    let before = f.snapshot().await;
    assert_eq!(
        f.complete_factor(
            &limiter,
            &p,
            LocalAuthBinding::OauthAuthorize(b"wrong"),
            "invalid"
        )
        .await
        .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert_eq!(
        f.complete_factor(&limiter, &p, LocalAuthBinding::AdminLogin, &"x".repeat(65))
            .await
            .unwrap_err(),
        LocalAuthError::InvalidMfaCode
    );
    assert!(before.as_str() == f.snapshot().await.as_str());
    for (bad, restore) in [
        (
            "UPDATE public.local_users SET enabled=0",
            "UPDATE public.local_users SET enabled=1",
        ),
        (
            "UPDATE public.local_users SET identity_kind='service'",
            "UPDATE public.local_users SET identity_kind='human'",
        ),
        (
            "UPDATE public.local_users SET username=' unsafe'",
            "UPDATE public.local_users SET username='alice'",
        ),
        (
            "UPDATE public.local_users SET password_change_required=1",
            "UPDATE public.local_users SET password_change_required=0",
        ),
        (
            "UPDATE public.local_users SET revision=2",
            "UPDATE public.local_users SET revision=1",
        ),
        (
            "UPDATE public.local_users SET revision=9223372036854775807; UPDATE public.local_auth_challenges SET local_user_revision=9223372036854775807",
            "UPDATE public.local_users SET revision=1; UPDATE public.local_auth_challenges SET local_user_revision=1",
        ),
        (
            "UPDATE public.local_auth_challenges SET stage='mfa',secret_ciphertext=''",
            "",
        ),
    ] {
        let saved=Zeroizing::new(sqlx_core::query_scalar::query_scalar::<_,String>("SELECT secret_ciphertext FROM public.local_auth_challenges WHERE subject='alice-subject'").fetch_one(&mut f.admin).await.unwrap());
        f.admin.execute(bad).await.unwrap();
        let state = f.snapshot().await;
        assert_eq!(
            f.complete_factor(
                &limiter,
                &p,
                LocalAuthBinding::AdminLogin,
                &sdk_code(&sdk, 0)
            )
            .await
            .unwrap_err(),
            LocalAuthError::InvalidChallenge
        );
        assert!(state.as_str() == f.snapshot().await.as_str());
        if restore.is_empty() {
            sqlx_core::query::query("UPDATE public.local_auth_challenges SET stage='mfa-enrollment',secret_ciphertext=$1").bind(saved.as_str()).execute(&mut f.admin).await.unwrap();
        } else {
            f.admin.execute(restore).await.unwrap();
        }
    }
    f.admin.execute("INSERT INTO public.local_mfa_recovery_codes VALUES('alice-subject',repeat('a',64),123)").await.unwrap();
    let orphan = f.snapshot().await;
    assert_eq!(
        f.complete_factor(
            &limiter,
            &p,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 0)
        )
        .await
        .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    assert!(orphan.as_str() == f.snapshot().await.as_str());
    f.admin
        .execute("DELETE FROM public.local_mfa_recovery_codes")
        .await
        .unwrap();
    let wrong = LocalMfaProtector::new(Zeroizing::new(vec![99; 32].into_boxed_slice())).unwrap();
    assert!(matches!(
        f.store
            .local_auth_service(&f.d, &wrong, &f.required)
            .complete_mfa(
                &limiter,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                &sdk_code(&sdk, 0),
                deadline()
            )
            .await,
        Err(LocalAuthError::Mfa(
            broker_security::LocalMfaError::InvalidCiphertext
        ))
    ));
    // No denial/corruption charged a guess: threshold1 still admits the actual factor.
    completed(
        f.complete_factor(
            &limiter,
            &p,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 0),
        )
        .await
        .unwrap(),
    );
    let q = f.challenge(LocalAuthBinding::AdminLogin).await;
    let saved: (String,i64,i64)=sqlx_core::query_as::query_as("SELECT secret_ciphertext,last_totp_step,confirmed_at FROM public.local_mfa WHERE subject='alice-subject'").fetch_one(&mut f.admin).await.unwrap();
    let saved_cipher = Zeroizing::new(saved.0);
    for sql in [
        "UPDATE public.local_mfa SET last_totp_step=-1",
        "UPDATE public.local_mfa SET confirmed_at=0",
        "UPDATE public.local_mfa SET secret_ciphertext=repeat('x',90)",
    ] {
        f.admin.execute(sql).await.unwrap();
        let state = f.snapshot().await;
        assert!(matches!(
            f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, "invalid")
                .await,
            Err(LocalAuthError::InvalidChallenge
                | LocalAuthError::Mfa(broker_security::LocalMfaError::InvalidCiphertext))
        ));
        assert!(state.as_str() == f.snapshot().await.as_str());
        sqlx_core::query::query(
            "UPDATE public.local_mfa SET secret_ciphertext=$1,last_totp_step=$2,confirmed_at=$3",
        )
        .bind(saved_cipher.as_str())
        .bind(saved.1)
        .bind(saved.2)
        .execute(&mut f.admin)
        .await
        .unwrap();
    }
    assert!(matches!(
        f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, "invalid")
            .await
            .unwrap(),
        LocalAuthStep::Pending(_)
    ));
    let blocked = f.snapshot().await;
    proof(&f.store, &f.engine).await;
    assert!(matches!(
        f.complete_factor(
            &limiter,
            &q,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 30)
        )
        .await,
        Err(LocalAuthError::MfaRateLimited(_))
    ));
    assert!(blocked.as_str() == f.snapshot().await.as_str());
    f.seed_artifacts().await;
    let bob = f
        .store
        .local_password_verifier(&f.engine)
        .verify("bob", PASSWORD, deadline())
        .await
        .unwrap();
    let bob = pending(
        f.store
            .local_auth_service(&f.d, &f.m, &f.required)
            .begin(bob, LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap(),
    );
    let state = f.snapshot().await;
    assert_eq!(
        f.complete_factor(&limiter, &bob, LocalAuthBinding::AdminLogin, "invalid")
            .await
            .unwrap_err(),
        LocalAuthError::MfaCapacity
    );
    assert!(state.as_str() == f.snapshot().await.as_str());
    // Active wrong enrollment codes count even if presentation subsequently fails.
    f.reset_mfa().await;
    let limiter = mfa_limiter(1, 1);
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let invalid =
        LocalAuthPolicy::new(true, "bad:issuer".into(), Duration::from_secs(600)).unwrap();
    assert!(matches!(
        f.store
            .local_auth_service(&f.d, &f.m, &invalid)
            .complete_mfa(
                &limiter,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                "invalid",
                deadline()
            )
            .await,
        Err(LocalAuthError::Mfa(
            broker_security::LocalMfaError::Presentation
        ))
    ));
    let sdk = totp_rs::Totp::from_url(p.enrollment().unwrap().otpauth_uri()).unwrap();
    assert!(matches!(
        f.complete_factor(
            &limiter,
            &p,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 0)
        )
        .await,
        Err(LocalAuthError::MfaRateLimited(_))
    ));
}
async fn mfa_rollback_and_deadlines(f: &mut PasswordChangeFixture) {
    f.reset_mfa().await;
    let limiter = Arc::new(mfa_limiter(1, 2));
    let p = f.challenge(LocalAuthBinding::AdminLogin).await;
    let sdk = totp_rs::Totp::from_url(p.enrollment().unwrap().otpauth_uri()).unwrap();
    f.seed_artifacts().await;
    let before = f.snapshot().await;
    for (revoke, grant) in [
        (
            "REVOKE UPDATE ON public.local_users FROM local_auth_owner",
            "GRANT UPDATE ON public.local_users TO local_auth_owner",
        ),
        (
            "REVOKE INSERT ON public.local_mfa FROM local_auth_owner",
            "GRANT INSERT ON public.local_mfa TO local_auth_owner",
        ),
        (
            "REVOKE INSERT ON public.local_mfa_recovery_codes FROM local_auth_owner",
            "GRANT INSERT ON public.local_mfa_recovery_codes TO local_auth_owner",
        ),
        (
            "REVOKE UPDATE ON public.local_tokens FROM local_auth_owner",
            "GRANT UPDATE ON public.local_tokens TO local_auth_owner",
        ),
        (
            "REVOKE DELETE ON public.oidc_auth_requests FROM local_auth_owner",
            "GRANT DELETE ON public.oidc_auth_requests TO local_auth_owner",
        ),
        (
            "REVOKE DELETE ON public.local_auth_challenges FROM local_auth_owner",
            "GRANT DELETE ON public.local_auth_challenges TO local_auth_owner",
        ),
        (
            "REVOKE DELETE ON public.oauth_device_codes FROM local_auth_owner",
            "GRANT DELETE ON public.oauth_device_codes TO local_auth_owner",
        ),
    ] {
        f.admin.execute(revoke).await.unwrap();
        assert_eq!(
            f.complete_factor(
                &limiter,
                &p,
                LocalAuthBinding::AdminLogin,
                &sdk_code(&sdk, 0)
            )
            .await
            .unwrap_err(),
            LocalAuthError::Control(ControlError::Storage)
        );
        f.admin.execute(grant).await.unwrap();
        assert!(
            before.as_str() == f.snapshot().await.as_str(),
            "every SQL effect must roll back"
        );
    }
    for (add, drop) in [
        (
            "ALTER TABLE public.local_mfa ADD CONSTRAINT fixture_mfa_failure CHECK(confirmed_at<0) NOT VALID",
            "ALTER TABLE public.local_mfa DROP CONSTRAINT fixture_mfa_failure",
        ),
        (
            "ALTER TABLE public.local_mfa_recovery_codes ADD CONSTRAINT fixture_recovery_failure CHECK(created_at<0) NOT VALID",
            "ALTER TABLE public.local_mfa_recovery_codes DROP CONSTRAINT fixture_recovery_failure",
        ),
    ] {
        f.admin.execute(add).await.unwrap();
        assert_eq!(
            f.complete_factor(
                &limiter,
                &p,
                LocalAuthBinding::AdminLogin,
                &sdk_code(&sdk, 0)
            )
            .await
            .unwrap_err(),
            LocalAuthError::Control(ControlError::Storage)
        );
        f.admin.execute(drop).await.unwrap();
        assert!(before.as_str() == f.snapshot().await.as_str());
    }
    f.admin.execute("CREATE FUNCTION public.fixture_mfa_commit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture-only deferred failure'; END; $$; CREATE CONSTRAINT TRIGGER fixture_mfa_commit_failure AFTER INSERT ON public.local_mfa DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fixture_mfa_commit_failure()").await.unwrap();
    assert_eq!(
        f.complete_factor(
            &limiter,
            &p,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 0)
        )
        .await
        .unwrap_err(),
        LocalAuthError::Control(ControlError::OutcomeUncertain)
    );
    f.admin.execute("DROP TRIGGER fixture_mfa_commit_failure ON public.local_mfa; DROP FUNCTION public.fixture_mfa_commit_failure()").await.unwrap();
    assert!(before.as_str() == f.snapshot().await.as_str());
    // Actual lock wait consumes Original and cancellation releases the attempt/connection.
    for abort in [false, true] {
        let mut lock = f.fixture.connection().await;
        lock.execute("BEGIN; SELECT subject FROM public.local_users WHERE subject='alice-subject' FOR UPDATE").await.unwrap();
        let job = f.factor_job(
            &limiter,
            &p,
            &sdk_code(&sdk, 0),
            Instant::now() + Duration::from_secs(2),
        );
        wait_lock(&mut f.admin, "local_users").await;
        if abort {
            job.abort();
            assert!(job.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                job.await.unwrap().unwrap_err(),
                LocalAuthError::Control(ControlError::Deadline)
            );
        }
        lock.execute("ROLLBACK").await.unwrap();
        lock.close().await.unwrap();
        assert!(before.as_str() == f.snapshot().await.as_str());
    }
    // Same input's UTC expiry is revalidated after an observed row wait.
    let original_expiry: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT expires_at FROM public.local_auth_challenges WHERE challenge_hash=$1",
    )
    .bind(
        f.d.token(TokenKind::LocalAuthChallenge, p.challenge().as_bytes())
            .unwrap()
            .to_sql_hex(),
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    let mut lock = f.fixture.connection().await;
    lock.execute(
        "BEGIN; SELECT subject FROM public.local_users WHERE subject='alice-subject' FOR UPDATE",
    )
    .await
    .unwrap();
    let expires = utc() + 300_000;
    sqlx_core::query::query(
        "UPDATE public.local_auth_challenges SET expires_at=$1 WHERE subject='alice-subject'",
    )
    .bind(expires)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let mut job = f.factor_job(&limiter, &p, &sdk_code(&sdk, 0), deadline());
    tokio::select! {
        () = wait_lock(&mut f.admin, "local_users") => {},
        result = &mut job => match result.unwrap() {
            Err(error) => panic!("MFA UTC fixture completed before observed row wait: {error:?}"),
            Ok(_) => panic!("MFA UTC fixture unexpectedly authenticated before row wait"),
        },
    }
    assert!(
        utc() < expires,
        "MFA input must still be live when its row wait is observed"
    );
    let wait_end = deadline();
    while utc() <= expires {
        assert!(
            Instant::now() < wait_end,
            "fixture UTC did not reach unchanged input expiry"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    lock.execute("COMMIT").await.unwrap();
    lock.close().await.unwrap();
    assert_eq!(
        job.await.unwrap().unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    sqlx_core::query::query(
        "UPDATE public.local_auth_challenges SET expires_at=$1 WHERE subject='alice-subject'",
    )
    .bind(original_expiry)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let mut login = completed(
        f.complete_factor(
            &limiter,
            &p,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 0),
        )
        .await
        .unwrap(),
    );
    let codes = login.take_recovery_codes().unwrap();
    let code = Zeroizing::new(codes.iter().next().unwrap().to_owned());
    let q = f.challenge(LocalAuthBinding::AdminLogin).await;
    let before = f.snapshot().await;
    for abort in [false, true] {
        let mut lock = f.fixture.connection().await;
        lock.execute("BEGIN; SELECT code_hash FROM public.local_mfa_recovery_codes WHERE subject='alice-subject' FOR UPDATE").await.unwrap();
        let job = f.factor_job(&limiter, &q, &code, Instant::now() + Duration::from_secs(2));
        wait_lock(&mut f.admin, "local_mfa_recovery_codes").await;
        if abort {
            job.abort();
            assert!(job.await.unwrap_err().is_cancelled());
        } else {
            assert_eq!(
                job.await.unwrap().unwrap_err(),
                LocalAuthError::Control(ControlError::Deadline)
            );
        }
        lock.execute("ROLLBACK").await.unwrap();
        lock.close().await.unwrap();
        assert!(
            before.as_str() == f.snapshot().await.as_str(),
            "cancellation after admission must release the guard without consuming a code"
        );
    }
    // A canonical unknown recovery guess executes DELETE with zero affected rows.
    // A statement trigger arranges an actual deferred COMMIT error, without accepting a factor.
    let unknown = broker_security::LocalRecoveryCodes::generate().unwrap();
    let unknown = Zeroizing::new(unknown.iter().next().unwrap().to_owned());
    f.admin.execute("CREATE TABLE public.fixture_mfa_commit_gate(value integer); CREATE FUNCTION public.fixture_mfa_guess_statement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO public.fixture_mfa_commit_gate VALUES(1); RETURN NULL; END; $$; CREATE TRIGGER fixture_mfa_guess_statement AFTER DELETE ON public.local_mfa_recovery_codes FOR EACH STATEMENT EXECUTE FUNCTION public.fixture_mfa_guess_statement(); CREATE FUNCTION public.fixture_mfa_guess_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture-only guess commit failure'; END; $$; CREATE CONSTRAINT TRIGGER fixture_mfa_guess_commit AFTER INSERT ON public.fixture_mfa_commit_gate DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fixture_mfa_guess_commit()").await.unwrap();
    f.admin
        .execute("GRANT INSERT ON public.fixture_mfa_commit_gate TO local_auth_owner")
        .await
        .unwrap();
    assert_eq!(
        f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, &unknown)
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::OutcomeUncertain)
    );
    f.admin.execute("DROP TRIGGER fixture_mfa_guess_statement ON public.local_mfa_recovery_codes; DROP TABLE public.fixture_mfa_commit_gate; DROP FUNCTION public.fixture_mfa_guess_statement(); DROP FUNCTION public.fixture_mfa_guess_commit()").await.unwrap();
    assert!(
        before.as_str() == f.snapshot().await.as_str(),
        "bad-code commit failure must not consume SQL or charge the threshold-one limiter"
    );
    // Mutation occurs first, then challenge deletion fails; recovery/step must roll back.
    f.admin
        .execute("REVOKE DELETE ON public.local_auth_challenges FROM local_auth_owner")
        .await
        .unwrap();
    for value in [sdk_code(&sdk, 30), code] {
        assert_eq!(
            f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, &value)
                .await
                .unwrap_err(),
            LocalAuthError::Control(ControlError::Storage)
        );
        assert!(before.as_str() == f.snapshot().await.as_str());
    }
    f.admin
        .execute("GRANT DELETE ON public.local_auth_challenges TO local_auth_owner")
        .await
        .unwrap();
    completed(
        f.complete_factor(
            &limiter,
            &q,
            LocalAuthBinding::AdminLogin,
            &sdk_code(&sdk, 30),
        )
        .await
        .unwrap(),
    );
    // Deferred COMMIT crosses the input UTC expiry: effects may commit, no proof.
    // A prior wrong guess must not be cleared by this late successful verification.
    let limiter = mfa_limiter(2, 2);
    let q = f.challenge(LocalAuthBinding::AdminLogin).await;
    pending(
        f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, "invalid")
            .await
            .unwrap(),
    );
    f.admin.execute("CREATE FUNCTION public.fixture_mfa_late_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NULL; END; $$; CREATE CONSTRAINT TRIGGER fixture_mfa_late_commit AFTER DELETE ON public.local_mfa_recovery_codes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.fixture_mfa_late_commit()").await.unwrap();
    let hash =
        f.d.token(TokenKind::LocalAuthChallenge, q.challenge().as_bytes())
            .unwrap()
            .to_sql_hex();
    sqlx_core::query::query(
        "UPDATE public.local_auth_challenges SET expires_at=$1 WHERE challenge_hash=$2",
    )
    .bind(utc() + 1_500_000)
    .bind(&hash)
    .execute(&mut f.admin)
    .await
    .unwrap();
    let late_code = Zeroizing::new(codes.iter().nth(1).unwrap().to_owned());
    assert_eq!(
        f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, &late_code)
            .await
            .unwrap_err(),
        LocalAuthError::InvalidChallenge
    );
    f.admin.execute("DROP TRIGGER fixture_mfa_late_commit ON public.local_mfa_recovery_codes; DROP FUNCTION public.fixture_mfa_late_commit()").await.unwrap();
    let remaining: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.local_auth_challenges WHERE challenge_hash=$1",
    )
    .bind(hash)
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(remaining, 0);
    assert_eq!(
        f.scalar(
            "SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='alice-subject'"
        )
        .await,
        9
    );
    let q = f.challenge(LocalAuthBinding::AdminLogin).await;
    pending(
        f.complete_factor(&limiter, &q, LocalAuthBinding::AdminLogin, "invalid")
            .await
            .unwrap(),
    );
    assert!(matches!(
        f.complete_factor(
            &limiter,
            &q,
            LocalAuthBinding::AdminLogin,
            codes.iter().nth(2).unwrap()
        )
        .await,
        Err(LocalAuthError::MfaRateLimited(_))
    ));
    assert_eq!(
        f.store
            .local_auth_service(&f.d, &f.m, &f.required)
            .complete_mfa(
                &limiter,
                q.challenge(),
                LocalAuthBinding::AdminLogin,
                "invalid",
                Instant::now()
            )
            .await
            .unwrap_err(),
        LocalAuthError::Control(ControlError::Deadline)
    );
}
#[tokio::test]
#[ignore = "requires native PostgreSQL Docker TLS fixture"]
async fn postgres_mfa_native_contract() {
    let mut f = PasswordChangeFixture::new().await;
    mfa_enrollment_and_one_time_consumption(&mut f).await;
    mfa_denials_and_admission(&mut f).await;
    mfa_rollback_and_deadlines(&mut f).await;
    f.admin.close().await.unwrap();
    f.store.shutdown(deadline()).await.unwrap();
    f.fixture.shutdown().unwrap();
}

async fn invalidation_snapshot(admin: &mut PgConnection) -> Zeroizing<String> {
    Zeroizing::new(sqlx_core::query_scalar::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t) ORDER BY username) FROM public.local_users t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY token_hash) FROM public.local_tokens t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY request_hash) FROM public.oidc_auth_requests t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY challenge_hash) FROM public.local_auth_challenges t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY subject) FROM public.local_mfa t),(SELECT jsonb_agg(to_jsonb(t) ORDER BY code_hash) FROM public.local_mfa_recovery_codes t))::text").fetch_one(admin).await.unwrap())
}
#[tokio::test]
#[ignore = "real H1 HTTPS and PostgreSQL TLS: LOCAL password/MFA isolation and invalid JSON whole-transaction rollback"]
async fn postgres_local_invalidation_preserves_federated_grants() {
    use broker_control::{
        BrokerAccessIssuer, OidcRefreshInput, OidcTokenExchangeInput, OidcTokenExchangePolicy,
    };
    use federated as fed;
    use serde_json::json;
    let mut f = oidc::OidcFixture::new().await;
    let mut issuer = browser::BrowserIssuer::new().await;
    fed::register(&issuer, "public");
    issuer.fault(browser::Fault {
        id_overrides: [("mapped_subject".into(), json!("alice-subject"))].into(),
        ..browser::Fault::default()
    });
    let v = fed::verifier(&issuer, vec![fed::client("public")], Some("roles"));
    let client = fed::registered(&f).await;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let signer = BrokerAccessIssuer::new(
        oidc::ISSUER,
        oidc::AUDIENCE,
        "invalidation-key",
        &key.serialize_der(),
    )
    .unwrap();
    let policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(30 * 86400))
            .unwrap();
    let d = oidc::digester();
    let m = LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice())).unwrap();
    let exempt =
        LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    let required =
        LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(600)).unwrap();
    fn exchange<'a>(code: &'a str, client: &'a str, dynamic: bool) -> OidcTokenExchangeInput<'a> {
        OidcTokenExchangeInput {
            grant_type: Some("authorization_code"),
            client_id: Some(client),
            code: Some(code),
            redirect_uri: Some(if dynamic {
                fed::REDIRECT
            } else {
                "http://localhost:49152/oauth/callback"
            }),
            code_verifier: Some(oidc::VERIFIER),
            resource: dynamic.then_some(oidc::RESOURCE),
            authorization: None,
        }
    }
    for enroll in [false, true] {
        let hash = f.engine.hash(oidc::PASSWORD, deadline()).await.unwrap();
        sqlx_core::query::query(
            "UPDATE public.local_users SET password_hash=$1,revision=1,password_change_required=0",
        )
        .bind(hash.as_str())
        .execute(&mut f.admin)
        .await
        .unwrap();
        f.admin.execute("DELETE FROM public.local_mfa_recovery_codes;DELETE FROM public.local_mfa;DELETE FROM public.local_auth_challenges;DELETE FROM public.local_tokens;DELETE FROM public.oidc_auth_requests").await.unwrap();
        let localcode = f.code(false, true).await;
        let local = f
            .store
            .oidc_token_exchange(&f.policy, &policy, &signer)
            .unwrap()
            .exchange(exchange(localcode.code(), "graphit-cli", false), deadline())
            .await
            .unwrap();
        let _localrequest = f.code(false, false).await;
        let fedcode = fed::code(&f, &issuer, &v, &client).await;
        let remote = f
            .store
            .oidc_token_exchange(&f.policy, &policy, &signer)
            .unwrap()
            .with_upstream(&v)
            .exchange(exchange(fedcode.code(), &client, true), deadline())
            .await
            .unwrap();
        let nul_pending =
            fed::pending_with_bindings(&f, &client, "literal\0state", "literal\0nonce").await;
        let nul_proof = fed::proof(
            &f,
            &issuer,
            &v,
            fed::continuation(&v, nul_pending.request()),
        )
        .await;
        let preserved = f
            .store
            .oidc_authorization_service(&d, &f.policy)
            .complete_upstream(nul_proof, &v, deadline())
            .await
            .unwrap();
        if !enroll {
            f.admin
                .execute("UPDATE public.local_users SET password_change_required=1")
                .await
                .unwrap();
        }
        let login = f
            .store
            .local_password_verifier(&f.engine)
            .verify("alice", oidc::PASSWORD, deadline())
            .await
            .unwrap();
        let auth = f
            .store
            .local_auth_service(&d, &m, if enroll { &required } else { &exempt });
        let p = pending(
            auth.begin(login, LocalAuthBinding::AdminLogin, deadline())
                .await
                .unwrap(),
        );
        assert_eq!(
            p.stage(),
            if enroll {
                LocalAuthStage::Enrollment
            } else {
                LocalAuthStage::PasswordChange
            }
        );
        let sdk = if enroll {
            Some(totp_rs::Totp::from_url(p.enrollment().unwrap().otpauth_uri()).unwrap())
        } else {
            None
        };
        let factor = sdk.as_ref().map(|s| sdk_code(s, 0));
        let limiter = mfa_limiter(10, 4);
        for (privilege, revoke, grant) in [
            (
                "SELECT",
                "REVOKE SELECT ON public.oidc_auth_requests FROM exchange_owner",
                "GRANT SELECT ON public.oidc_auth_requests TO exchange_owner",
            ),
            (
                "UPDATE",
                "REVOKE UPDATE ON public.oidc_auth_requests FROM exchange_owner",
                "GRANT UPDATE ON public.oidc_auth_requests TO exchange_owner",
            ),
        ] {
            f.admin.execute(revoke).await.unwrap();
            let before = invalidation_snapshot(&mut f.admin).await;
            let denied = if enroll {
                auth.complete_mfa(
                    &limiter,
                    p.challenge(),
                    LocalAuthBinding::AdminLogin,
                    factor.as_ref().unwrap(),
                    deadline(),
                )
                .await
            } else {
                auth.complete_password_change(
                    &f.engine,
                    p.challenge(),
                    LocalAuthBinding::AdminLogin,
                    NEW_PASSWORD,
                    deadline(),
                )
                .await
            };
            assert!(
                matches!(denied, Err(LocalAuthError::Control(ControlError::Storage))),
                "missing request {privilege} privilege is a finite storage error"
            );
            assert!(
                before.as_str() == invalidation_snapshot(&mut f.admin).await.as_str(),
                "missing request {privilege} privilege rolls back all affected state"
            );
            f.admin.execute(grant).await.unwrap();
        }
        f.admin.execute("INSERT INTO public.oidc_auth_requests(request_hash,identity_subject,request_json,code_hash,expires_at,created_at) VALUES(repeat('f',64),'alice-subject','{',NULL,9000000000000000,1)").await.unwrap();
        let before = invalidation_snapshot(&mut f.admin).await;
        let denied = if enroll {
            auth.complete_mfa(
                &limiter,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                factor.as_ref().unwrap(),
                deadline(),
            )
            .await
        } else {
            auth.complete_password_change(
                &f.engine,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                deadline(),
            )
            .await
        };
        assert!(
            matches!(denied, Err(LocalAuthError::Control(ControlError::Storage))),
            "invalid JSON is a finite storage error"
        );
        assert!(
            before.as_str() == invalidation_snapshot(&mut f.admin).await.as_str(),
            "invalid JSON rolls back user/password/revision/factor/tokens/challenges/requests"
        );
        f.admin.execute("UPDATE public.oidc_auth_requests SET request_json='{}' WHERE request_hash=repeat('f',64)").await.unwrap();
        let done = if enroll {
            auth.complete_mfa(
                &limiter,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                factor.as_ref().unwrap(),
                deadline(),
            )
            .await
        } else {
            auth.complete_password_change(
                &f.engine,
                p.challenge(),
                LocalAuthBinding::AdminLogin,
                NEW_PASSWORD,
                deadline(),
            )
            .await
        };
        assert!(matches!(done.unwrap(), LocalAuthStep::Complete(_)));
        let states:(i64,i64,i64)=sqlx_core::query_as::query_as("SELECT count(*) FILTER(WHERE local_user_revision>0 AND revoked_at IS NULL),count(*) FILTER(WHERE local_user_revision=0 AND revoked_at IS NULL),count(*) FILTER(WHERE local_user_revision>0 AND revoked_at IS NOT NULL) FROM public.local_tokens").fetch_one(&mut f.admin).await.unwrap();
        assert_eq!(states, (0, 2, 2));
        let requests: i64 =
            sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.oidc_auth_requests")
                .fetch_one(&mut f.admin)
                .await
                .unwrap();
        assert_eq!(
            requests, 1,
            "only genuine authorized federated request remains"
        );
        let input = |raw| OidcRefreshInput {
            grant_type: Some("refresh_token"),
            client_id: Some(client.as_str()),
            refresh_token: Some(raw),
            scope: None,
            resource: Some(oidc::RESOURCE),
            authorization: None,
        };
        assert!(
            f.store
                .oidc_refresh(&f.policy, &policy, &signer)
                .unwrap()
                .with_upstream(&v)
                .rotate(input(remote.refresh_token().unwrap()), deadline())
                .await
                .is_ok()
        );
        let mut localinput = input(local.refresh_token().unwrap());
        localinput.client_id = Some("graphit-cli");
        localinput.resource = None;
        assert!(
            f.store
                .oidc_refresh(&f.policy, &policy, &signer)
                .unwrap()
                .rotate(localinput, deadline())
                .await
                .is_err()
        );
        assert!(
            f.store
                .oidc_token_exchange(&f.policy, &policy, &signer)
                .unwrap()
                .with_upstream(&v)
                .exchange(exchange(preserved.code(), &client, true), deadline())
                .await
                .is_ok()
        );
    }
    issuer.close().await;
    f.close().await;
}
