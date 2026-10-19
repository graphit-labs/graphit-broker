use super::*;
use crate::{
    LocalCaptchaConfiguration,
    admin_cookie_fixture::{CookieFixture, PASSWORD},
    support::{deadline, n},
};
use broker_security::LocalAuthPurpose;
use broker_security::LocalPasswordHasher;
use sqlx_core::executor::Executor;
use zeroize::Zeroizing;
fn policy(saturation: usize) -> LocalPasswordAdmissionPolicy {
    LocalPasswordAdmissionPolicy {
        max_failures: n(2),
        window: Duration::from_secs(60),
        lockout: Duration::from_secs(1),
        workers: n(1),
        saturation_multiplier: n(saturation),
        max_tracked: n(4096),
    }
}
fn admission(engine: &LocalPasswordEngine, saturation: usize) -> LocalPasswordAdmission {
    LocalPasswordAdmission::new(
        policy(saturation),
        engine,
        LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(saturation)).unwrap(),
    )
    .unwrap()
}
async fn engine() -> Arc<LocalPasswordEngine> {
    Arc::new(
        LocalPasswordEngine::new(
            LocalPasswordHasher::new(Zeroizing::new(vec![0x57; 32].into_boxed_slice())).unwrap(),
            n(1),
            deadline(),
        )
        .await
        .unwrap(),
    )
}
async fn running(engine: &LocalPasswordEngine) {
    let end = deadline();
    while engine.physical_available_permits() != 0 {
        assert!(
            Instant::now() < end,
            "actual SDK worker must take the physical permit"
        );
        tokio::task::yield_now().await;
    }
}

#[test]
fn fixed_window_equality_and_checked_policy_boundaries() {
    let good = policy(2);
    assert!(good.validate().is_ok());
    let mut invalid = good;
    invalid.window = Duration::ZERO;
    assert_eq!(invalid.validate(), Err(ControlError::Configuration));
    invalid = good;
    invalid.lockout = Duration::ZERO;
    assert_eq!(invalid.validate(), Err(ControlError::Configuration));
    invalid = good;
    invalid.max_tracked = n(4097);
    assert_eq!(invalid.validate(), Err(ControlError::Configuration));
    invalid = good;
    invalid.saturation_multiplier = n(tokio::sync::Semaphore::MAX_PERMITS + 1);
    assert_eq!(invalid.validate(), Err(ControlError::Configuration));
    let now = Instant::now();
    let window = Duration::from_secs(1);
    let mut entry = Attempt {
        window_start: now,
        failures: 2,
        blocked_until: None,
        last_seen: now,
        active: 1,
    };
    entry.refresh_window(now + window - Duration::from_nanos(1), window);
    assert_eq!(entry.failures, 2);
    entry.refresh_window(now + window, window);
    assert_eq!(entry.failures, 0);
    assert_eq!(entry.window_start, now + window);
    // The second active worker crosses the failure-window boundary while
    // the first worker's lockout still has independent time remaining.
    let blocked_until = now + window + Duration::from_secs(5);
    entry.blocked_until = Some(blocked_until);
    entry.failures = 2;
    entry.refresh_window(now + window + window, window);
    assert_eq!(entry.failures, 0);
    assert_eq!(entry.blocked_until, Some(blocked_until));
    entry.refresh_window(blocked_until, window);
    assert_eq!(entry.blocked_until, None);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logical_lease_survives_caller_abort_until_real_worker_exit() {
    let engine = engine().await;
    let admission = admission(&engine, 1);
    let hash = engine.hash(PASSWORD, deadline()).await.unwrap();
    let (lease, _) = admission.admit(Some("alice"), deadline()).unwrap();
    let worker = Arc::clone(&engine);
    let caller = tokio::spawn(async move {
        worker
            .verify_admitted(PASSWORD, Some(&hash), lease, deadline())
            .await
    });
    running(&engine).await;
    caller.abort();
    let _ = caller.await;
    assert!(
        matches!(admission.admit(None,deadline()),Err(LocalPasswordAdmissionError::RateLimited(wait)) if wait==Duration::from_secs(1))
    );
    assert_eq!(admission.state.state.lock().unwrap().occupied, 1);
    admission.close();
    engine.close().await;
    assert_eq!(admission.state.state.lock().unwrap().occupied, 0);
    assert_eq!(engine.physical_available_permits(), 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_worker_rechecks_locked_username_inside_blocking_closure() {
    let engine = engine().await;
    let admission = admission(&engine, 2);
    let hash = engine.hash(PASSWORD, deadline()).await.unwrap();
    let (work, _) = admission.admit(None, deadline()).unwrap();
    let worker = Arc::clone(&engine);
    let first =
        tokio::spawn(async move { worker.hash_for_change(PASSWORD, work, deadline()).await });
    running(&engine).await;
    let (lease, _) = admission.admit(Some("alice"), deadline()).unwrap();
    let worker = Arc::clone(&engine);
    let second = tokio::spawn(async move {
        worker
            .verify_admitted(PASSWORD, Some(&hash), lease, deadline())
            .await
    });
    // Private policy DATA condition, never fabricated password evidence. The actual
    // SDK false/charge path is qualified separately against real PostgreSQL.
    admission
        .state
        .state
        .lock()
        .unwrap()
        .attempts
        .get_mut("alice")
        .unwrap()
        .blocked_until = Some(Instant::now() + Duration::from_secs(60));
    first.await.unwrap().unwrap();
    assert!(matches!(
        second.await.unwrap(),
        Err(LocalPasswordAdmissionError::RateLimited(_))
    ));
    assert_eq!(admission.state.state.lock().unwrap().occupied, 0);
    admission.close();
    engine.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER and Argon2; bounded policy map data cannot bypass capacity before SQL/KDF"]
async fn postgres_admission_capacity_preserves_active_entries() {
    let mut f = CookieFixture::new().await;
    let admission = admission(&f.engine, 2);
    let now = Instant::now();
    {
        let mut state = admission.state.state.lock().unwrap();
        for index in 0..TRACKED_USERNAMES {
            state.attempts.insert(
                format!("tracked-{index}"),
                Attempt {
                    window_start: now,
                    failures: 1,
                    blocked_until: None,
                    last_seen: now,
                    active: 0,
                },
            );
        }
    }
    f.admin
        .execute("REVOKE SELECT ON public.local_users FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(
        matches!(
            f.store
                .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
                .unwrap()
                .authenticate("alice", PASSWORD, None, deadline())
                .await,
            Err(LocalPasswordAdmissionError::Capacity)
        ),
        "capacity denies before even forbidden SQL or actual KDF"
    );
    f.admin
        .execute("GRANT SELECT ON public.local_users TO admin_cookie_owner")
        .await
        .unwrap();
    admission
        .state
        .state
        .lock()
        .unwrap()
        .attempts
        .remove("tracked-0");
    assert!(
        f.store
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate("alice", PASSWORD, None, deadline())
            .await
            .is_ok()
    );
    let (active, _) = admission.admit(Some("alice"), deadline()).unwrap();
    {
        let mut state = admission.state.state.lock().unwrap();
        let entry = state.attempts.get_mut("alice").unwrap();
        entry.last_seen = Instant::now() - Duration::from_secs(62);
        entry.window_start = entry.last_seen;
    }
    assert!(
        matches!(
            admission.admit(Some("new-name"), deadline()),
            Err(LocalPasswordAdmissionError::Capacity)
        ),
        "active stale entry cannot be pruned to admit an untracked guess"
    );
    drop(active);
    let (healthy, _) = admission.admit(Some("new-name"), deadline()).unwrap();
    drop(healthy);
    admission.close();
    f.engine.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn options_challenge_observes_shared_occupancy_without_reserving_work() {
    use crate::{LocalCaptchaConfiguration, LocalCaptchaProvider};
    let engine = engine().await;
    let owner = LocalPasswordAdmission::new(
        policy(2),
        &engine,
        LocalCaptcha::new(
            LocalCaptchaConfiguration::Enabled {
                provider: LocalCaptchaProvider::Turnstile,
                site_key: "public-site-key".into(),
                secret_key: Zeroizing::new("fixture-only-provider-secret".into()),
                public_url: url::Url::parse("https://broker.example.test").unwrap(),
                trigger_multiplier: 1.5,
                verification_timeout: Duration::from_secs(3),
            },
            n(1),
            n(2),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        owner
            .next_password_challenge(LocalAuthPurpose::AdminLogin)
            .unwrap()
            .is_none()
    );
    let lease = owner.admit_password_change(&engine, deadline()).unwrap();
    assert!(
        owner
            .next_password_challenge(LocalAuthPurpose::AdminLogin)
            .unwrap()
            .is_some()
    );
    let admin = owner
        .next_password_challenge(LocalAuthPurpose::AdminLogin)
        .unwrap()
        .unwrap();
    let oauth = owner
        .next_password_challenge(LocalAuthPurpose::OauthAuthorize)
        .unwrap()
        .unwrap();
    assert_eq!(admin.action(), Some("admin-login"));
    assert_eq!(oauth.action(), Some("oauth-login"));
    // Observation reserves no slot: the second existing slot remains available.
    let second = owner.admit_password_change(&engine, deadline()).unwrap();
    drop(second);
    drop(lease);
    assert!(
        owner
            .next_password_challenge(LocalAuthPurpose::AdminLogin)
            .unwrap()
            .is_none()
    );
    owner.close();
    assert!(matches!(
        owner.next_password_challenge(LocalAuthPurpose::AdminLogin),
        Err(ControlError::Closed)
    ));
    engine.close().await;
}
