#[path = "support/sqlite_admin_fixture.rs"]
mod fixture;
use broker_control::{
    AdminBrokerSessionError as Error, AdminLocalBearerSession, BrokerAccessError, ControlError,
};
use fixture::{Fixture, end, limits, n, now};
use std::time::{Duration, Instant};
async fn read(f: &Fixture, raw: &str) -> Result<AdminLocalBearerSession, Error> {
    f.store
        .admin_local_bearer_sessions("admin-api", n(8192), limits())
        .unwrap()
        .read(raw, &["admin:session".into()], end())
        .await
}
#[tokio::test]
async fn opaque_human_service_read_current_profile_roles_and_permission() {
    let f = Fixture::new().await;
    let db = f.db();
    for (raw, user, subject) in [
        (&f.access, "alice", "alice-subject"),
        (&f.service, "bot", "bot-subject"),
    ] {
        let s = read(&f, raw).await.unwrap();
        assert_eq!(s.principal().username, user);
        assert_eq!(s.profile().subject, subject);
        assert_eq!(s.profile().name, "Current");
        assert_eq!(s.principal().teams, ["a", "z"]);
        assert_eq!(s.roles(), ["user"]);
        assert!(s.permissions().iter().any(|p| p.as_str() == "session.read"));
        assert_eq!(format!("{s:?}"), "AdminLocalBearerSession([REDACTED])");
    }
    db.execute_batch("DELETE FROM role_permissions WHERE role='user'; INSERT INTO roles(name,created_at) VALUES('observer',0); INSERT INTO role_permissions(role,action)VALUES('observer','session.read'); INSERT INTO role_assignments(subject,role,created_at)VALUES('foreign|alice-subject','observer',0)").unwrap();
    assert_eq!(read(&f, &f.access).await.unwrap_err(), Error::Forbidden);
    db.execute("INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','observer',0)",[]).unwrap();
    db.execute(
        r#"UPDATE local_users SET name='Changed',teams_json='["current"]' WHERE username='alice'"#,
        [],
    )
    .unwrap();
    let s = read(&f, &f.access).await.unwrap();
    assert_eq!(s.profile().name, "Changed");
    assert_eq!(s.roles(), ["observer", "user"]);
    assert_eq!(s.principal().teams, ["current"]);
    db.execute(
        "DELETE FROM role_assignments WHERE subject='local|alice-subject'",
        [],
    )
    .unwrap();
    assert_eq!(read(&f, &f.access).await.unwrap_err(), Error::Forbidden);
    db.execute(
        "INSERT INTO role_permissions(role,action) VALUES('user','*')",
        [],
    )
    .unwrap();
    assert!(read(&f, &f.service).await.is_ok());
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test]
async fn raw_authentication_and_current_binding_cannot_be_replaced_by_metadata() {
    let f = Fixture::new().await;
    let db = f.db();
    let denied = Error::Authentication(BrokerAccessError::InvalidToken);
    assert!(matches!(
        f.store.admin_local_bearer_sessions("  ", n(8192), limits()),
        Err(ControlError::Configuration)
    ));
    for raw in ["", "gb_at_missing", "gb_rt_refresh", "ey.fake.jwt"] {
        assert_eq!(read(&f, raw).await.unwrap_err(), denied);
    }
    assert_eq!(
        f.store
            .admin_local_bearer_sessions("other", n(8192), limits())
            .unwrap()
            .read(&f.access, &[], end())
            .await
            .unwrap_err(),
        denied
    );
    assert_eq!(
        f.store
            .admin_local_bearer_sessions("admin-api", n(8192), limits())
            .unwrap()
            .read(&f.access, &["other".into()], end())
            .await
            .unwrap_err(),
        denied
    );
    for sql in [
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        "UPDATE local_users SET revision=2 WHERE username='alice'",
        "UPDATE local_users SET identity_kind='service' WHERE username='alice'",
        "UPDATE local_users SET subject='changed' WHERE username='alice'",
    ] {
        db.execute(sql, []).unwrap();
        assert_eq!(read(&f, &f.access).await.unwrap_err(), denied);
        db.execute("UPDATE local_users SET enabled=1,revision=1,identity_kind='human',subject='alice-subject' WHERE username='alice'",[]).unwrap();
    }
    db.execute(
        "UPDATE local_tokens SET revoked_at=?1 WHERE token_kind='access'",
        [now()],
    )
    .unwrap();
    assert_eq!(read(&f, &f.access).await.unwrap_err(), denied);
    db.execute(
        "UPDATE local_tokens SET revoked_at=NULL,expires_at=?1 WHERE token_kind='access'",
        [now() - 1],
    )
    .unwrap();
    assert_eq!(read(&f, &f.access).await.unwrap_err(), denied);
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test]
async fn corrupt_or_oversized_current_rbac_never_returns_an_admin_session() {
    let f = Fixture::new().await;
    let db = f.db();
    db.execute(
        "UPDATE local_users SET name=?1 WHERE username='alice'",
        ["界".repeat(513)],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access).await.unwrap_err(),
        Error::Control(ControlError::CorruptIdentity)
    );
    db.execute(
        "UPDATE local_users SET name='Current' WHERE username='alice'",
        [],
    )
    .unwrap();
    let mut small = limits();
    small.profile_json_bytes = n(20);
    assert!(matches!(
        f.store
            .admin_local_bearer_sessions("admin-api", n(8192), small)
            .unwrap()
            .read(&f.access, &[], end())
            .await,
        Err(Error::Control(
            ControlError::CorruptIdentity | ControlError::IdentityLimitExceeded
        ))
    ));
    db.execute_batch("INSERT INTO roles(name,created_at)VALUES('extra',0);INSERT INTO role_assignments(subject,role,created_at)VALUES('local|alice-subject','extra',0)").unwrap();
    let mut small = limits();
    small.identity.rows = n(1);
    assert_eq!(
        f.store
            .admin_local_bearer_sessions("admin-api", n(8192), small)
            .unwrap()
            .read(&f.access, &[], end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::IdentityLimitExceeded)
    );
    db.execute(
        "INSERT INTO role_permissions(role,action)VALUES('extra','unknown')",
        [],
    )
    .unwrap();
    assert_eq!(
        read(&f, &f.access).await.unwrap_err(),
        Error::Control(ControlError::CorruptRbac)
    );
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test]
async fn physical_lock_deadline_and_expiry_do_not_release_session() {
    let f = Fixture::new().await;
    let db = f.db();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = f
        .store
        .admin_local_bearer_sessions("admin-api", n(8192), limits())
        .unwrap()
        .read(&f.access, &[], Instant::now() + Duration::from_millis(30))
        .await;
    assert_eq!(result.unwrap_err(), Error::Control(ControlError::Deadline));
    db.execute_batch("ROLLBACK").unwrap();
    db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_kind='access'",
        [now() + 100_000],
    )
    .unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let store = f.store.clone();
    let raw = f.access.clone();
    let pending = tokio::spawn(async move {
        store
            .admin_local_bearer_sessions("admin-api", n(8192), limits())
            .unwrap()
            .read(&raw, &[], end())
            .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    db.execute_batch("ROLLBACK").unwrap();
    assert!(matches!(
        pending.await.unwrap(),
        Err(Error::Authentication(
            BrokerAccessError::InvalidToken | BrokerAccessError::Expired
        ))
    ));
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        read(&f, &f.service).await.unwrap_err(),
        Error::Control(ControlError::Closed)
    );
}
