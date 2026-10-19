#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/admin_cookie.rs"]
#[allow(dead_code, reason = "shared fixture includes cookie-only consumers")]
mod cookie;
#[allow(
    dead_code,
    reason = "shared genuine LOCAL/PostgreSQL fixture serves other suites"
)]
mod support;
use broker_control::{
    ControlError, LocalAuthStage, LocalAuthStep, LocalCaptcha, LocalCaptchaConfiguration,
    LocalPasswordAdmission, LocalPasswordAdmissionError, LocalPasswordAdmissionPolicy,
};
use broker_security::{LocalAuthBinding, LocalAuthPurpose};
use cookie::{CookieFixture, PASSWORD};
use sqlx_core::{connection::Connection, executor::Executor};
use std::time::{Duration, Instant};
use support::{deadline, n};

fn owner(f: &CookieFixture) -> LocalPasswordAdmission {
    LocalPasswordAdmission::new(
        LocalPasswordAdmissionPolicy {
            max_failures: n(2),
            window: Duration::from_secs(60),
            lockout: Duration::from_millis(500),
            workers: n(1),
            saturation_multiplier: n(2),
            max_tracked: n(4096),
        },
        &f.engine,
        LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2)).unwrap(),
    )
    .unwrap()
}
async fn wrong(f: &CookieFixture, owner: &LocalPasswordAdmission) {
    assert!(matches!(
        f.store
            .admitted_local_passwords(&f.engine, owner, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate(
                "alice",
                "a real incorrect native password",
                None,
                deadline()
            )
            .await,
        Err(LocalPasswordAdmissionError::Unauthenticated)
    ));
}
async fn wait_lock(f: &mut CookieFixture) {
    let end = deadline();
    loop {
        let count:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE '%FOR SHARE%'").fetch_one(&mut f.admin).await.unwrap();
        if count > 0 {
            return;
        }
        assert!(
            Instant::now() < end,
            "actual final password revalidation must reach user lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual Argon2, PostgreSQL TLS NOSUPERUSER, current revision races, no infra guess charge and genuine mandatory password change"]
async fn postgres_local_password_admission_contract() {
    let mut f = CookieFixture::new().await;
    let admission = owner(&f);
    let view = f
        .store
        .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
        .unwrap();
    for (user, password) in [
        ("", PASSWORD),
        (" alice x", PASSWORD),
        ("alice", ""),
        ("alice", &"x".repeat(4097)),
    ] {
        assert!(matches!(
            view.authenticate(user, password, None, deadline()).await,
            Err(LocalPasswordAdmissionError::Unauthenticated)
        ));
    }
    let proof = view
        .authenticate(" alice ", PASSWORD, None, deadline())
        .await
        .unwrap();
    assert_eq!(proof.username(), "alice");
    assert_eq!(proof.revision(), 1);
    wrong(&f, &admission).await;
    f.admin
        .execute("REVOKE SELECT ON public.local_users FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(matches!(
        view.authenticate("alice", PASSWORD, None, deadline()).await,
        Err(LocalPasswordAdmissionError::Control(ControlError::Storage))
    ));
    f.admin
        .execute("GRANT SELECT ON public.local_users TO admin_cookie_owner")
        .await
        .unwrap();
    assert!(
        view.authenticate("alice", PASSWORD, None, deadline())
            .await
            .is_ok(),
        "storage failure cannot charge the second guess"
    );
    wrong(&f, &admission).await;
    f.admin
        .execute("REVOKE SELECT ON public.local_users FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(matches!(
        view.authenticate("alice", PASSWORD, None, deadline()).await,
        Err(LocalPasswordAdmissionError::Control(ControlError::Storage))
    ));
    f.admin
        .execute("GRANT SELECT ON public.local_users TO admin_cookie_owner")
        .await
        .unwrap();
    wrong(&f, &admission).await;
    assert!(
        matches!(
            view.authenticate("alice", PASSWORD, None, deadline()).await,
            Err(LocalPasswordAdmissionError::RateLimited(_))
        ),
        "storage failure cannot clear the first guess"
    );
    tokio::time::sleep(Duration::from_millis(510)).await;
    assert!(
        view.authenticate("alice", PASSWORD, None, deadline())
            .await
            .is_ok()
    );
    let first = admission
        .admit_password_change(&f.engine, deadline())
        .unwrap();
    let second = admission
        .admit_password_change(&f.engine, deadline())
        .unwrap();
    assert!(
        matches!(view.authenticate("alice",PASSWORD,None,deadline()).await,Err(LocalPasswordAdmissionError::RateLimited(wait)) if wait==Duration::from_secs(1))
    );
    drop(first);
    drop(second);

    // Actual correct KDF followed by a current revision race must neither charge
    // nor clear the preceding known wrong password.
    wrong(&f, &admission).await;
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; UPDATE public.local_users SET revision=revision+1 WHERE username='alice'")
        .await
        .unwrap();
    {
        let store = std::sync::Arc::clone(&f.store);
        let engine = std::sync::Arc::clone(&f.engine);
        let pending = store
            .admitted_local_passwords(&engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap();
        let attempt = pending.authenticate("alice", PASSWORD, None, deadline());
        tokio::pin!(attempt);
        tokio::select! {_=wait_lock(&mut f)=>{},result=&mut attempt=>panic!("must reach real revision lock, result {}",result.is_ok())}
        locker.execute("COMMIT").await.unwrap();
        assert!(matches!(
            attempt.await,
            Err(LocalPasswordAdmissionError::Unauthenticated)
        ));
    }
    locker.close().await.unwrap();
    wrong(&f, &admission).await;
    assert!(matches!(
        f.store
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate("alice", PASSWORD, None, deadline())
            .await,
        Err(LocalPasswordAdmissionError::RateLimited(_))
    ));
    tokio::time::sleep(Duration::from_millis(510)).await;
    assert_eq!(
        f.store
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate("alice", PASSWORD, None, deadline())
            .await
            .unwrap()
            .revision(),
        2
    );

    f.admin.execute("UPDATE public.local_users SET password_change_required=1,revision=revision+1 WHERE username='alice'").await.unwrap();
    let original = deadline();
    let password = f
        .store
        .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
        .unwrap()
        .authenticate("alice", PASSWORD, None, original)
        .await
        .unwrap();
    let auth = f
        .store
        .local_auth_service(&f.digester, &f.protector, &f.exempt);
    let pending = match auth
        .begin(password, LocalAuthBinding::AdminLogin, original)
        .await
        .unwrap()
    {
        LocalAuthStep::Pending(pending) => pending,
        _ => panic!("actual current password-change flag must select pending stage"),
    };
    assert_eq!(pending.stage(), LocalAuthStage::PasswordChange);
    let next = "another real native password with sufficient length";
    let step = admission
        .admit_password_change(&f.engine, original)
        .unwrap()
        .complete(
            &auth,
            pending.challenge(),
            LocalAuthBinding::AdminLogin,
            next,
        )
        .await
        .unwrap();
    assert!(matches!(step, LocalAuthStep::Complete(_)));
    assert!(matches!(
        f.store
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate("alice", PASSWORD, None, deadline())
            .await,
        Err(LocalPasswordAdmissionError::Unauthenticated)
    ));
    assert!(
        f.store
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate("alice", next, None, deadline())
            .await
            .is_ok()
    );
    admission.close();
    f.engine.close().await;
    f.close().await;
}

async fn wait_password_pid(admin: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE '%FOR SHARE%' LIMIT 1").fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual password final revalidation must wait on the held user row"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual PostgreSQL COMMIT idle/TLS ACK withheld after genuine Argon2 and current revalidation; no guess charge or success clear"]
async fn postgres_admission_commit_uncertainty_contract() {
    use broker_control::PostgresControlStore;
    let mut f = CookieFixture::new().await;
    let admission = LocalPasswordAdmission::new(
        LocalPasswordAdmissionPolicy {
            max_failures: n(2),
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            workers: n(1),
            saturation_multiplier: n(2),
            max_tracked: n(4096),
        },
        &f.engine,
        LocalCaptcha::new(LocalCaptchaConfiguration::Disabled, n(1), n(2)).unwrap(),
    )
    .unwrap();
    wrong(&f, &admission).await;
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let proxy = PostgresControlStore::open(
        cookie::config(&f.fixture, relay.port),
        cookie::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT subject FROM public.local_users WHERE username='alice' FOR UPDATE")
        .await
        .unwrap();
    {
        let view = proxy
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap();
        let pending = view.authenticate(
            "alice",
            PASSWORD,
            None,
            Instant::now() + Duration::from_secs(8),
        );
        tokio::pin!(pending);
        let pid = tokio::select! {pid=wait_password_pid(&mut f.admin)=>pid,result=&mut pending=>panic!("genuine KDF must reach locked final SQL before result, success {}",result.is_ok())};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        locker.execute("ROLLBACK").await.unwrap();
        loop {
            let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("must withhold actual COMMIT ACK, success {}",result.is_ok())};
            let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(pid)
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
            if query == "COMMIT" && idle {
                decision.send(false).unwrap();
                break;
            }
            decision.send(true).unwrap();
        }
        assert!(matches!(
            pending.await,
            Err(LocalPasswordAdmissionError::Control(
                ControlError::OutcomeUncertain
            ))
        ));
    }
    locker.close().await.unwrap();
    relay.close().await;
    proxy.shutdown(deadline()).await.unwrap();
    // If uncertain correct work charged, this wrong attempt would already be
    // locked. If it cleared, the next correct attempt would not be locked.
    wrong(&f, &admission).await;
    assert!(matches!(
        f.store
            .admitted_local_passwords(&f.engine, &admission, LocalAuthPurpose::AdminLogin)
            .unwrap()
            .authenticate("alice", PASSWORD, None, deadline())
            .await,
        Err(LocalPasswordAdmissionError::RateLimited(_))
    ));
    admission.close();
    f.engine.close().await;
    f.close().await;
}
