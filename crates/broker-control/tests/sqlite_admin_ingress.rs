#[path = "support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine protocol fixtures are exercised across Control and Presence"
)]
mod ingress;
use broker_control::{
    AdminBrokerSessionError as Error, AdminCookieSessionError as CookieError, BrokerAccessError,
    ControlError, FlowPurpose,
};
use ingress as s;
use ingress::fixture::*;
use std::{
    future::Future,
    task::{Context, Wake, Waker},
};
struct CompletionWake(tokio::sync::Notify);
impl Wake for CompletionWake {
    fn wake(self: Arc<Self>) {
        self.0.notify_one();
    }
}

#[tokio::test]
async fn sqlite_admin_ingress_configuration_and_closed_owner() {
    let root = tempfile::tempdir().unwrap();
    let store =
        SqliteControlStore::open(config(&root.path().join("private/db")), digester(), end())
            .await
            .unwrap();
    let mut bad = s::limits();
    bad.metadata.max_lifetime = Duration::from_secs(1);
    assert!(matches!(
        store.admin_cookie_sessions(bad, s::policy(), None),
        Err(ControlError::Configuration)
    ));
    let v = s::trust(vec![]);
    let view = store
        .admin_upstream_sessions(&v, s::limits().authorization)
        .unwrap();
    assert_eq!(
        format!("{view:?}"),
        "SqliteAdminUpstreamSessions([REDACTED])"
    );
    store.shutdown(end()).await.unwrap();
    let raw = URL_SAFE_NO_PAD.encode([12u8; 32]);
    assert_eq!(
        store
            .admin_cookie_sessions(s::limits(), s::policy(), None)
            .unwrap()
            .read(&raw, end())
            .await
            .unwrap_err(),
        CookieError::Control(ControlError::Closed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine LOCAL password, SQLite authorization code and Ed25519 JWT"]
async fn sqlite_broker_jwt_uses_current_local_identity_and_rbac_without_new_revocation_rules() {
    let f = Fixture::new().await;
    s::allow_session(&f);
    let raw = s::jwt(&f).await;
    let v = f.verifier();
    let read = || {
        f.store
            .admin_broker_sessions(&v, s::limits().authorization)
            .unwrap()
    };
    let before = read()
        .read(v.verify(&raw, &[], end()).unwrap(), end())
        .await
        .unwrap();
    assert_eq!(before.profile().name, "Alice");
    f.db.execute_batch("UPDATE local_users SET name='SQL current',revision=2,password_change_required=1;DELETE FROM local_tokens").unwrap();
    let current = read()
        .read(v.verify(&raw, &[], end()).unwrap(), end())
        .await
        .unwrap();
    assert_eq!(current.profile().name, "SQL current");
    assert_eq!(current.principal().local_user_revision, 2);
    f.db.execute_batch("UPDATE local_users SET identity_kind='service'")
        .unwrap();
    assert_eq!(
        read()
            .read(v.verify(&raw, &[], end()).unwrap(), end())
            .await
            .unwrap()
            .principal()
            .username,
        "alice"
    );
    for sql in [
        "UPDATE local_users SET enabled=0",
        "UPDATE local_users SET enabled=1,subject='other-subject'",
        "UPDATE local_users SET subject='alice-subject',username='other'",
    ] {
        f.db.execute_batch(sql).unwrap();
        assert_eq!(
            read()
                .read(v.verify(&raw, &[], end()).unwrap(), end())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
    }
    f.db.execute_batch(
        "UPDATE local_users SET username='alice';DELETE FROM role_permissions WHERE role='user'",
    )
    .unwrap();
    assert_eq!(
        read()
            .read(v.verify(&raw, &[], end()).unwrap(), end())
            .await
            .unwrap_err(),
        Error::Forbidden
    );
    s::allow_session(&f);
    let other = f.verifier();
    assert_eq!(
        read()
            .read(other.verify(&raw, &[], end()).unwrap(), end())
            .await
            .unwrap_err(),
        Error::Authentication(BrokerAccessError::InvalidToken)
    );
    let mut cap = s::limits().authorization;
    cap.profile_json_bytes = n(10);
    assert!(matches!(
        f.store
            .admin_broker_sessions(&v, cap)
            .unwrap()
            .read(v.verify(&raw, &[], end()).unwrap(), end())
            .await,
        Err(Error::Control(
            ControlError::CorruptIdentity | ControlError::IdentityLimitExceeded
        ))
    ));
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let observed = read()
        .read(
            v.verify(&raw, &[], end()).unwrap(),
            Instant::now() + Duration::from_millis(40),
        )
        .await
        .unwrap_err();
    assert_eq!(observed, Error::Control(ControlError::Deadline));
    f.db.execute_batch("ROLLBACK").unwrap();
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        read()
            .read(v.verify(&raw, &[], end()).unwrap(), end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTPS discovery/JWKS, signed external bearer and native SQLite"]
async fn sqlite_f1_preserves_claims_assignments_empty_selection_and_current_definitions() {
    let f = Fixture::new().await;
    s::allow_session(&f);
    let op = s::upstream::UpstreamFixture::new().await;
    let mut cfg = s::config(&op.issuer, &op.ca, false, Some("roles"));
    cfg.predicates = vec![broker_control::UpstreamClaimPredicate {
        selector: "token_use".into(),
        value: "access".into(),
    }];
    let v = s::trust(vec![cfg]);
    let mut claims = op.claims();
    claims["roles"] = json!(["unknown", "reader"]);
    let raw = op.sign(&claims, "upstream-key", "at+jwt");
    f.db.execute_batch("INSERT INTO roles(name,created_at)VALUES('reader',0);INSERT INTO role_permissions(role,action)VALUES('reader','session.read');DELETE FROM role_permissions WHERE role='user'").unwrap();
    let read = || {
        f.store
            .admin_upstream_sessions(&v, s::limits().authorization)
            .unwrap()
    };
    let session = read().read(&raw, end()).await.unwrap();
    assert_eq!(session.profile().name, "Federated");
    assert_eq!(session.role_source(), "claims");
    assert!(session.roles().iter().any(|r| r == "unknown"));
    let subject = format!("{}|external|subject", op.issuer);
    f.db.execute(
        "INSERT INTO role_assignments(subject,role,created_at)VALUES(?1,'reader',0)",
        [&subject],
    )
    .unwrap();
    claims["roles"] = json!([]);
    let empty = op.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        read().read(&empty, end()).await.unwrap_err(),
        Error::Forbidden
    );
    let mut db_cfg = s::config(&op.issuer, &op.ca, false, None);
    db_cfg.claims.roles = None;
    let db_v = s::trust(vec![db_cfg]);
    let db_session = f
        .store
        .admin_upstream_sessions(&db_v, s::limits().authorization)
        .unwrap()
        .read(&empty, end())
        .await
        .unwrap();
    assert_eq!(db_session.role_source(), "database");
    assert_eq!(db_session.roles(), ["reader", "user"]);
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='reader'")
        .unwrap();
    assert_eq!(
        read().read(&raw, end()).await.unwrap_err(),
        Error::Forbidden
    );
    f.db.execute_batch(
        "INSERT INTO role_permissions(role,action)VALUES('reader','invalid.action')",
    )
    .unwrap();
    assert_eq!(
        read().read(&raw, end()).await.unwrap_err(),
        Error::Control(ControlError::CorruptRbac)
    );
    for (key, value) in [
        ("scope", json!("other")),
        ("token_use", json!("id")),
        ("iss", json!("https://unconfigured.invalid")),
    ] {
        let mut invalid = claims.clone();
        invalid[key] = value;
        let token = op.sign(&invalid, "upstream-key", "at+jwt");
        assert!(matches!(
            read().read(&token, end()).await,
            Err(Error::Authentication(_))
        ));
    }
    claims["aud"] = json!("public");
    let bad = op.sign(&claims, "upstream-key", "at+jwt");
    assert!(matches!(
        read().read(&bad, end()).await,
        Err(Error::Authentication(_))
    ));
    assert!(op.hits() >= 2);
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine H1 Admin HTTPS consumption, H2 cookie and current SQLite RBAC"]
async fn sqlite_h2_uses_browser_owner_current_cookie_selector_and_structural_logout() {
    let f = Fixture::new().await;
    s::allow_session(&f);
    let op = s::browser_op().await;
    let cfg = s::config(&op.issuer, &op.ca, true, Some("roles"));
    let v = s::trust(vec![s::config(&op.issuer, &op.ca, true, Some("roles"))]);
    let h1 = s::h1(&f, &op, &v, FlowPurpose::Admin, end()).await;
    let cookies = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(v.clone()))
        .unwrap();
    let issued = cookies.issue_upstream(h1, end()).await.unwrap();
    let raw = issued.secret();
    let current = cookies.read(raw, end()).await.unwrap();
    assert_eq!(current.principal().local_user_revision, 0);
    assert_eq!(current.principal().issuer, op.issuer);
    assert_eq!(current.role_source(), "claims");
    let csrf = current.csrf_token().to_owned();
    assert_ne!(raw, csrf);
    assert!(
        issued
            .authentication_expiry()
            .0
            .duration_since(SystemTime::now())
            .unwrap()
            > Duration::from_secs(1200)
    );
    let count = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    let mut removed_browser = s::config(&op.issuer, &op.ca, true, Some("roles"));
    removed_browser.browser_clients.clear();
    let no_browser = s::trust(vec![removed_browser]);
    assert!(
        f.store
            .admin_cookie_sessions(s::limits(), s::policy(), Some(no_browser))
            .unwrap()
            .read(raw, end())
            .await
            .is_ok()
    );
    let none = s::trust(vec![s::config(&op.issuer, &op.ca, true, None)]);
    assert_eq!(
        f.store
            .admin_cookie_sessions(s::limits(), s::policy(), Some(none.clone()))
            .unwrap()
            .read(raw, end())
            .await
            .unwrap()
            .role_source(),
        "database"
    );
    let mut changed = s::config(&op.issuer, &op.ca, true, Some("roles"));
    changed.claims.roles = Some("different".into());
    let changed = s::trust(vec![changed]);
    assert_eq!(
        f.store
            .admin_cookie_sessions(s::limits(), s::policy(), Some(changed))
            .unwrap()
            .read(raw, end())
            .await
            .unwrap_err(),
        CookieError::Unauthorized
    );
    assert_eq!((op.token_hits(), op.userinfo_hits(), op.jwks_hits()), count);
    let wrong = s::h1(&f, &op, &v, FlowPurpose::OAuth, end()).await;
    assert_eq!(
        cookies.issue_upstream(wrong, end()).await.unwrap_err(),
        CookieError::Unauthorized
    );
    let other = s::trust(vec![cfg]);
    let wrong = s::h1(&f, &op, &other, FlowPurpose::Admin, end()).await;
    assert_eq!(
        cookies.issue_upstream(wrong, end()).await.unwrap_err(),
        CookieError::Unauthorized
    );
    let removed = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(s::trust(vec![])))
        .unwrap();
    assert_eq!(
        removed.read(raw, end()).await.unwrap_err(),
        CookieError::Unauthorized
    );
    assert_eq!(
        removed.logout(raw, Some("wrong"), end()).await.unwrap_err(),
        CookieError::CsrfFailed
    );
    removed.logout(raw, Some(&csrf), end()).await.unwrap();
    assert!(removed.read(raw, end()).await.is_err());
    let plain = s::h1(&f, &op, &none, FlowPurpose::Admin, end()).await;
    let cookie_none = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(none))
        .unwrap()
        .issue_upstream(plain, end())
        .await
        .unwrap();
    assert_eq!(
        cookies.read(cookie_none.secret(), end()).await.unwrap_err(),
        CookieError::Unauthorized
    );
    let local = s::local_cookie(&f).await;
    let local_read = cookies.read(local.secret(), end()).await.unwrap();
    assert_eq!(local_read.principal().issuer, "local");
    cookies
        .logout(local.secret(), Some(local_read.csrf_token()), end())
        .await
        .unwrap();
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real retained cookie/H1 proofs and causal native lock/expiry"]
async fn sqlite_admin_cookie_late_denial_and_h1_expiry_keep_their_categories() {
    let f = Fixture::new().await;
    s::allow_session(&f);
    let op = s::browser_op().await;
    let v = s::trust(vec![s::config(&op.issuer, &op.ca, true, None)]);
    let proof = s::h1(&f, &op, &v, FlowPurpose::Admin, end()).await;
    let short = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(v.clone()))
        .unwrap();
    let issued = short.issue_upstream(proof, end()).await.unwrap();
    // Preserve the productive 300s minimum policy. Shorten only this genuine
    // persisted session's current expiry to exercise the read cutoff causally.
    let expiry = utc() + 2_000_000;
    let cutoff = Instant::now() + Duration::from_secs(2);
    f.db.execute("UPDATE admin_sessions SET expires_at=?1", [expiry])
        .unwrap();
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='user';BEGIN IMMEDIATE")
        .unwrap();
    let mut future = Box::pin(short.read(issued.secret(), end()));
    let signal = Arc::new(CompletionWake(tokio::sync::Notify::new()));
    let waker = Waker::from(signal.clone());
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    f.db.execute_batch("COMMIT").unwrap();
    // The free owner's first poll waits on its native job: its wake records job
    // completion without consuming ACK. Original's timer is much later.
    tokio::time::timeout_at(cutoff.into(), signal.0.notified())
        .await
        .unwrap();
    assert!(
        Instant::now() < cutoff,
        "the worker denial must precede cookie expiry"
    );
    tokio::time::sleep(
        cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(30),
    )
    .await;
    assert_eq!(
        future.await.unwrap_err(),
        CookieError::Control(ControlError::SessionExpired)
    );
    s::allow_session(&f);
    let mut fault = s::browser::Fault::default();
    fault.id_overrides.insert(
        "exp".into(),
        json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 2
        ),
    );
    op.fault(fault);
    let proof = s::h1(&f, &op, &v, FlowPurpose::Admin, end()).await;
    let cookies = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(v))
        .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = cookies.issue_upstream(proof, end()).await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        result.unwrap_err(),
        CookieError::Control(ControlError::Expired)
    );
    // A longer caller deadline must not renew the H1 producer's Original.
    op.fault(s::browser::Fault::default());
    let v = s::trust(vec![s::config(&op.issuer, &op.ca, true, None)]);
    let original = Instant::now() + Duration::from_secs(1);
    let proof = s::h1(&f, &op, &v, FlowPurpose::Admin, original).await;
    let count: i64 =
        f.db.query_row("SELECT count(*) FROM admin_sessions", [], |r| r.get(0))
            .unwrap();
    let cookies = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(v))
        .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let outcome = cookies.issue_upstream(proof, end()).await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        outcome.unwrap_err(),
        CookieError::Control(ControlError::Deadline)
    );
    assert_eq!(
        f.db.query_row("SELECT count(*) FROM admin_sessions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        count
    );
    f.store.shutdown(end()).await.unwrap();
}
