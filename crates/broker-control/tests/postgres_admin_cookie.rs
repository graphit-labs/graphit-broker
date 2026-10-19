#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[allow(dead_code, reason = "shared native cookie fixture also serves HTTP")]
#[path = "support/admin_cookie.rs"]
mod cookie;
#[allow(
    dead_code,
    reason = "shared native TLS fixture is also consumed by actual HTTP tests"
)]
mod support;
use broker_control::{
    AdminCookieLogoutDisposition, AdminCookieSessionError as Error, AdminLoginPreparationError,
    ControlError, LocalAuthStep, LocalMfaAttemptLimiter, LocalMfaAttemptPolicy,
    PostgresControlStore, PreparedAdminLogin,
};
use broker_security::{LocalAuthBinding, TokenKind};
use cookie::{CookieFixture, limits, policy};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{deadline, n};
use zeroize::Zeroizing;
fn hash(raw: &str) -> String {
    cookie::digester()
        .token(TokenKind::AdminSession, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
async fn current_and_logout(f: &mut CookieFixture) {
    let c = f.cookie().await;
    assert_eq!(c.secret().len(), 43);
    assert_eq!(format!("{c:?}"), "IssuedAdminCookie([REDACTED])");
    let view = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap();
    let s = view.read(c.secret(), deadline()).await.unwrap();
    assert_eq!(s.profile().subject, "alice-subject");
    assert_eq!(s.principal().username, "alice");
    assert!(s.roles().iter().any(|r| r == "user"));
    assert_eq!(s.csrf_token().len(), 43);
    let csrf = Zeroizing::new(s.csrf_token().to_owned());
    assert_ne!(csrf.as_str(), c.secret());
    let stored: String = sqlx_core::query_scalar::query_scalar(
        "SELECT jsonb_agg(to_jsonb(s))::text FROM public.admin_sessions s",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    assert!(
        !stored.contains(c.secret()),
        "raw cookie must never enter SQL"
    );
    assert!(stored.contains(&hash(c.secret())));
    f.admin
        .execute("UPDATE public.local_users SET name='Current',teams_json='[\"operations\"]'")
        .await
        .unwrap();
    assert_eq!(
        view.read(c.secret(), deadline())
            .await
            .unwrap()
            .profile()
            .name,
        "Current"
    );
    // Reducing the issuance TTL does not shrink an existing stored session's lifetime.
    let reduced = broker_control::AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(300),
    };
    f.store
        .admin_cookie_sessions(limits(), reduced, None)
        .unwrap()
        .read(c.secret(), deadline())
        .await
        .unwrap();
    for change in [
        "UPDATE public.local_users SET enabled=0",
        "UPDATE public.local_users SET revision=2",
        "UPDATE public.local_users SET password_change_required=1",
        "UPDATE public.local_users SET identity_kind='service'",
    ] {
        f.admin.execute(change).await.unwrap();
        assert_eq!(
            view.read(c.secret(), deadline()).await.unwrap_err(),
            Error::Unauthorized
        );
        f.admin.execute("UPDATE public.local_users SET enabled=1,revision=1,password_change_required=0,identity_kind='human'").await.unwrap();
    }
    f.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user' AND action='session.read'")
        .await
        .unwrap();
    assert_eq!(
        view.read(c.secret(), deadline()).await.unwrap_err(),
        Error::Forbidden
    );
    for supplied in [None, Some("invalid"), Some(c.secret())] {
        assert_eq!(
            view.logout(c.secret(), supplied, deadline())
                .await
                .unwrap_err(),
            Error::CsrfFailed
        );
    }
    assert_eq!(
        view.logout(c.secret(), Some(&csrf), deadline())
            .await
            .unwrap()
            .disposition(),
        AdminCookieLogoutDisposition::Revoked
    );
    assert_eq!(
        view.logout(c.secret(), None, deadline())
            .await
            .unwrap()
            .disposition(),
        AdminCookieLogoutDisposition::Absent
    );
    assert_eq!(
        view.read(c.secret(), deadline()).await.unwrap_err(),
        Error::Unauthorized
    );
    f.admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')")
        .await
        .unwrap();
}
async fn issuer_and_recovery(f: &mut CookieFixture) {
    let wrong = f
        .login(LocalAuthBinding::OauthAuthorize(b"other-journey"))
        .await;
    let wrong = PreparedAdminLogin::try_from(wrong).unwrap_err();
    assert!(matches!(
        wrong,
        AdminLoginPreparationError::InvalidPurpose(_)
    ));
    assert!(matches!(
        wrong.into_login().purpose(),
        broker_security::LocalAuthPurpose::OauthAuthorize
    ));
    let login = f.login(LocalAuthBinding::AdminLogin).await;
    assert_eq!(
        f.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_local(
                PreparedAdminLogin::try_from(login).unwrap(),
                &f.required,
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    let login = f.login(LocalAuthBinding::AdminLogin).await;
    f.admin
        .execute("UPDATE public.local_users SET revision=2")
        .await
        .unwrap();
    assert_eq!(
        f.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_local(
                PreparedAdminLogin::try_from(login).unwrap(),
                &f.exempt,
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    f.admin
        .execute("UPDATE public.local_users SET revision=1")
        .await
        .unwrap();
    assert_eq!(f.count().await, 0);
    // Enroll using the mature TOTP SDK and the actual SQL LOCAL completion.
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", cookie::PASSWORD, deadline())
        .await
        .unwrap();
    let auth = f
        .store
        .local_auth_service(&f.digester, &f.protector, &f.required);
    let LocalAuthStep::Pending(pending) = auth
        .begin(proof, LocalAuthBinding::AdminLogin, deadline())
        .await
        .unwrap()
    else {
        panic!("actual enrollment required");
    };
    let sdk = totp_rs::Totp::from_url(pending.enrollment().unwrap().otpauth_uri()).unwrap();
    let code = Zeroizing::new(
        sdk.generate(cookie::micros() as u64 / 1_000_000)
            .to_string(),
    );
    let limiter = LocalMfaAttemptLimiter::new(
        LocalMfaAttemptPolicy::new(
            NonZeroU32::new(5).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(300),
            n(4096),
        )
        .unwrap(),
    );
    let LocalAuthStep::Complete(login) = auth
        .complete_mfa(
            &limiter,
            pending.challenge(),
            LocalAuthBinding::AdminLogin,
            &code,
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("actual factor must complete");
    };
    let failure = PreparedAdminLogin::try_from(login).unwrap_err();
    assert!(matches!(
        failure,
        AdminLoginPreparationError::RecoveryCodesPending(_)
    ));
    let mut login = failure.into_login();
    let codes = login.take_recovery_codes().unwrap();
    let c = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .issue_local(
            PreparedAdminLogin::try_from(login).unwrap(),
            &f.required,
            deadline(),
        )
        .await
        .unwrap();
    let read = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .read(c.secret(), deadline())
        .await
        .unwrap();
    f.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .logout(c.secret(), Some(read.csrf_token()), deadline())
        .await
        .unwrap();
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", cookie::PASSWORD, deadline())
        .await
        .unwrap();
    let LocalAuthStep::Pending(pending) = auth
        .begin(proof, LocalAuthBinding::AdminLogin, deadline())
        .await
        .unwrap()
    else {
        panic!("actual MFA required");
    };
    let recovery = codes.iter().next().unwrap();
    let LocalAuthStep::Complete(login) = auth
        .complete_mfa(
            &limiter,
            pending.challenge(),
            LocalAuthBinding::AdminLogin,
            recovery,
            deadline(),
        )
        .await
        .unwrap()
    else {
        panic!("recovery must complete");
    };
    let c = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .issue_local(
            PreparedAdminLogin::try_from(login).unwrap(),
            &f.required,
            deadline(),
        )
        .await
        .unwrap();
    let read = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .read(c.secret(), deadline())
        .await
        .unwrap();
    f.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .logout(c.secret(), Some(read.csrf_token()), deadline())
        .await
        .unwrap();
    f.admin
        .execute("DELETE FROM public.local_mfa; UPDATE public.local_users SET revision=1")
        .await
        .unwrap();
}
async fn corruption_expiry_and_cancel(f: &mut CookieFixture) {
    let c = f.cookie().await;
    let h = hash(c.secret());
    let view = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap();
    let csrf = Zeroizing::new(
        view.read(c.secret(), deadline())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    sqlx_core::query::query(
        "UPDATE public.admin_sessions SET csrf_token='corrupt' WHERE token_hash=$1",
    )
    .bind(&h)
    .execute(&mut f.admin)
    .await
    .unwrap();
    for result in [
        view.read(c.secret(), deadline()).await.map(|_| ()),
        view.logout(c.secret(), Some(&csrf), deadline())
            .await
            .map(|_| ()),
    ] {
        assert_eq!(
            result.unwrap_err(),
            Error::Control(ControlError::CorruptSession)
        );
    }
    sqlx_core::query::query("UPDATE public.admin_sessions SET csrf_token=$1 WHERE token_hash=$2")
        .bind(csrf.as_str())
        .bind(&h)
        .execute(&mut f.admin)
        .await
        .unwrap();
    let expiry = cookie::micros() - 1;
    sqlx_core::query::query(
        "UPDATE public.admin_sessions SET expires_at=$1,created_at=$1-1000000 WHERE token_hash=$2",
    )
    .bind(expiry)
    .bind(&h)
    .execute(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(
        view.read(c.secret(), deadline()).await.unwrap_err(),
        Error::Control(ControlError::SessionExpired)
    );
    assert_eq!(f.count().await, 0);
    let c = f.cookie().await;
    let raw = Zeroizing::new(c.secret().to_owned());
    let mut blocker = f.fixture.connection().await;
    let mut tx = blocker.begin().await.unwrap();
    sqlx_core::query::query(
        "SELECT token_hash FROM public.admin_sessions WHERE token_hash=$1 FOR UPDATE",
    )
    .bind(hash(&raw))
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let original = Instant::now() + Duration::from_millis(120);
    assert_eq!(
        f.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .read(&raw, original)
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    let owner = f.store.clone();
    let raw2 = raw.clone();
    let job = tokio::spawn(async move {
        owner
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .read(&raw2, deadline())
            .await
    });
    wait_lock(&mut f.admin, "%pg_catalog.octet_length(s.subject)%").await;
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    tx.rollback().await.unwrap();
    blocker.close().await.unwrap();
    let read = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .read(&raw, deadline())
        .await
        .unwrap();
    f.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .logout(&raw, Some(read.csrf_token()), deadline())
        .await
        .unwrap();
    assert_eq!(f.count().await, 0);
}
async fn wait_lock(admin: &mut sqlx_postgres::PgConnection, pattern: &str) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='admin_cookie_owner' AND wait_event_type='Lock' AND query LIKE $1")
            .bind(pattern).fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "actual cookie SQL lock must be observed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
async fn actual_commit_uncertainty(f: &mut CookieFixture) {
    for operation in ["issue", "read", "logout"] {
        let mut relay = commit::CommitRelay::new(f.fixture.port).await;
        let owner = Arc::new(
            PostgresControlStore::open(
                cookie::config(&f.fixture, relay.port),
                cookie::digester(),
                deadline(),
            )
            .await
            .unwrap(),
        );
        let login = if operation == "issue" {
            Some(PreparedAdminLogin::try_from(f.login(LocalAuthBinding::AdminLogin).await).unwrap())
        } else {
            None
        };
        let credential = if operation != "issue" {
            Some(f.cookie().await)
        } else {
            None
        };
        let csrf = if let Some(c) = &credential {
            Some(Zeroizing::new(
                f.store
                    .admin_cookie_sessions(limits(), policy(), None)
                    .unwrap()
                    .read(c.secret(), deadline())
                    .await
                    .unwrap()
                    .csrf_token()
                    .to_owned(),
            ))
        } else {
            None
        };
        if operation == "read" {
            // Change only expiry of a genuinely issued session, never seed authority.
            // Leave enough room to observe the real COMMIT before this window expires.
            // Expiry still precedes the read Original and the eight-second operation budget.
            let expiry = cookie::micros() + 6_000_000;
            sqlx_core::query::query(
                "UPDATE public.admin_sessions SET expires_at=$1 WHERE token_hash=$2",
            )
            .bind(expiry)
            .bind(hash(credential.as_ref().unwrap().secret()))
            .execute(&mut f.admin)
            .await
            .unwrap();
        }
        let mut locker = f.fixture.connection().await;
        locker.execute("BEGIN").await.unwrap();
        let pattern = if operation == "logout" {
            sqlx_core::query::query(
                "SELECT token_hash FROM public.admin_sessions WHERE token_hash=$1 FOR UPDATE",
            )
            .bind(hash(credential.as_ref().unwrap().secret()))
            .fetch_one(&mut locker)
            .await
            .unwrap();
            "%pg_catalog.octet_length(s.subject)%"
        } else {
            locker
                .execute("LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
                .await
                .unwrap();
            "%octet_length(u.username)%"
        };
        let view = owner
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap();
        let original =
            Instant::now() + Duration::from_secs(if operation == "read" { 10 } else { 3 });
        {
            let pending = async {
                match operation {
                    "issue" => view
                        .issue_local(login.unwrap(), &f.exempt, original)
                        .await
                        .map(|_| ()),
                    "read" => view
                        .read(credential.as_ref().unwrap().secret(), original)
                        .await
                        .map(|_| ()),
                    "logout" => view
                        .logout(
                            credential.as_ref().unwrap().secret(),
                            csrf.as_deref().map(|s| s.as_str()),
                            original,
                        )
                        .await
                        .map(|_| ()),
                    _ => unreachable!("fixture operation is finite"),
                }
            };
            tokio::pin!(pending);
            let pid = tokio::select! { pid=wait_lock(&mut f.admin,pattern)=>pid,result=&mut pending=>panic!("cookie {operation} must reach actual SQL lock: {:?}",result.err()) };
            relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            locker.execute("ROLLBACK").await.unwrap();
            loop {
                let decision = tokio::select! { decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("actual COMMIT ACK must be withheld for {operation}: {:?}",result.err()) };
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
            assert_eq!(
                pending.await.unwrap_err(),
                Error::Control(ControlError::OutcomeUncertain)
            );
        }
        locker.close().await.unwrap();
        relay.close().await;
        owner.shutdown(deadline()).await.unwrap();
        // The acknowledged-to-PostgreSQL mutation really happened; no replay is authorized.
        let count = f.count().await;
        if operation == "logout" {
            assert_eq!(count, 0);
        } else {
            assert_eq!(count, 1);
        }
        f.admin
            .execute("DELETE FROM public.admin_sessions")
            .await
            .unwrap();
    }
}

async fn binding_rollback_and_revision_race(f: &mut CookieFixture) {
    let original = deadline();
    let password = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", cookie::PASSWORD, original)
        .await
        .unwrap();
    let other_digest = support::digester();
    let LocalAuthStep::Complete(login) = f
        .store
        .local_auth_service(&other_digest, &f.protector, &f.exempt)
        .begin(password, LocalAuthBinding::AdminLogin, original)
        .await
        .unwrap()
    else {
        panic!("genuine exempt login must complete");
    };
    assert_eq!(
        f.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_local(
                PreparedAdminLogin::try_from(login).unwrap(),
                &f.exempt,
                original
            )
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(f.count().await, 0);

    let prepared =
        PreparedAdminLogin::try_from(f.login(LocalAuthBinding::AdminLogin).await).unwrap();
    f.admin
        .execute("REVOKE INSERT ON public.admin_session_principals FROM admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        f.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_local(prepared, &f.exempt, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    f.admin
        .execute("GRANT INSERT ON public.admin_session_principals TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        f.count().await,
        0,
        "a parent insert must not become partially visible after child failure"
    );

    let original = deadline();
    let prepared = PreparedAdminLogin::try_from(
        f.login_with_original(LocalAuthBinding::AdminLogin, original)
            .await,
    )
    .unwrap();
    let mut locker = f.fixture.connection().await;
    let mut tx = locker.begin().await.unwrap();
    tx.execute("UPDATE public.local_users SET revision=revision+1 WHERE username='alice'")
        .await
        .unwrap();
    let owner = f.store.clone();
    let job = tokio::spawn(async move {
        let local = broker_control::LocalAuthPolicy::new(
            false,
            "Graphit Broker".into(),
            Duration::from_secs(600),
        )
        .unwrap();
        owner
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_local(prepared, &local, original)
            .await
    });
    wait_lock(&mut f.admin, "%SELECT subject FROM public.local_users%").await;
    tx.commit().await.unwrap();
    assert_eq!(job.await.unwrap().unwrap_err(), Error::Unauthorized);
    locker.close().await.unwrap();
    assert_eq!(f.count().await, 0);
    f.admin
        .execute("UPDATE public.local_users SET revision=1")
        .await
        .unwrap();
    let c = f.cookie().await;
    let view = f
        .store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap();
    let s = view.read(c.secret(), deadline()).await.unwrap();
    f.admin
        .execute("REVOKE DELETE ON public.admin_sessions FROM admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        view.logout(c.secret(), Some(s.csrf_token()), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    f.admin
        .execute("GRANT DELETE ON public.admin_sessions TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(f.count().await, 1);
    f.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .logout(c.secret(), Some(s.csrf_token()), deadline())
        .await
        .unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real PostgreSQL Docker TLS fixture"]
async fn postgres_admin_cookie_contract() {
    let mut f = CookieFixture::new().await;
    current_and_logout(&mut f).await;
    issuer_and_recovery(&mut f).await;
    corruption_expiry_and_cancel(&mut f).await;
    actual_commit_uncertainty(&mut f).await;
    binding_rollback_and_revision_race(&mut f).await;
    f.close().await;
}
