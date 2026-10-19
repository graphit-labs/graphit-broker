#[path = "support/sqlite_oidc_fixture.rs"]
pub mod fixture;
use broker_control::{
    BrokerAccessVerifier, OidcEndSessionInput, OidcIntrospectionError, OidcRevocationInput,
    OidcTokenExchangeResult,
};
use fixture::*;

async fn issued(f: &Fixture, dynamic: bool, user: &str) -> OidcTokenExchangeResult {
    let code = f.code_for(dynamic, true, user).await;
    f.producer()
        .exchange(exchange(code.code(), dynamic), end())
        .await
        .unwrap()
}
fn revoke<'a>(token: &'a str, client: &'a str) -> OidcRevocationInput<'a> {
    OidcRevocationInput {
        token: Some(token),
        client_id: Some(client),
        token_type_hint: Some("unknown-advisory"),
        authorization: None,
    }
}
fn hint(raw: &str) -> OidcEndSessionInput<'_> {
    OidcEndSessionInput {
        id_token_hint: Some(raw),
        client_id: None,
    }
}
fn access_hash(f: &Fixture, raw: &str) -> String {
    digester()
        .token(
            TokenKind::OidcStoredAccess,
            claims(&f.issuer, raw, AUDIENCE)["jti"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
        .to_sql_hex()
}
fn live(f: &Fixture, raw: &str) -> bool {
    f.db.query_row(
        "SELECT revoked_at IS NULL FROM local_tokens WHERE token_hash=?1",
        [access_hash(f, raw)],
        |r| r.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn sqlite_lifecycle_configuration_deadline_and_unknown_disposal() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private/quick.db");
    let store = SqliteControlStore::open(config(&path), digester(), end())
        .await
        .unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let issuer =
        BrokerAccessIssuer::new(ISSUER, AUDIENCE, "quick-key", &key.serialize_der()).unwrap();
    let verifier = Arc::new(
        BrokerAccessVerifier::new(ISSUER, AUDIENCE, None, issuer.jwks(), n(8192)).unwrap(),
    );
    let wrong = Arc::new(
        BrokerAccessVerifier::new(ISSUER, "other-api", None, issuer.jwks(), n(8192)).unwrap(),
    );
    assert!(
        store
            .oidc_introspection(authorization(), wrong.clone())
            .is_err()
    );
    assert!(
        store
            .oidc_revocation(authorization(), wrong.clone())
            .is_err()
    );
    assert!(store.oidc_end_session(authorization(), wrong).is_err());
    let disposal = store
        .oidc_revocation(authorization(), verifier.clone())
        .unwrap();
    disposal
        .revoke(revoke("unknown", "graphit-cli"), end())
        .await
        .unwrap();
    assert!(matches!(
        disposal
            .revoke(revoke("unknown", "graphit-cli"), Instant::now())
            .await,
        Err(Error::Control(ControlError::Deadline))
    ));
    assert!(matches!(
        disposal
            .revoke(revoke("unknown", "missing-client"), end())
            .await,
        Err(Error::InvalidClient)
    ));
    assert!(matches!(
        store
            .oidc_introspection(authorization(), verifier.clone())
            .unwrap()
            .introspect("invalid", None, end())
            .await,
        Err(OidcIntrospectionError::InvalidAuthority)
    ));
    assert!(matches!(
        store
            .oidc_end_session(authorization(), verifier.clone())
            .unwrap()
            .end_session(hint("invalid"), end())
            .await,
        Err(Error::InvalidRequest)
    ));
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM local_tokens", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    store.shutdown(end()).await.unwrap();
    assert!(matches!(
        store
            .oidc_revocation(authorization(), verifier)
            .unwrap()
            .revoke(revoke("unknown", "graphit-cli"), end())
            .await,
        Err(Error::Control(ControlError::Closed))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine LOCAL Argon2/code exchange, SQLite access/family/pair disposal"]
async fn sqlite_lifecycle_authority_and_three_disposal_scopes() {
    let f = Fixture::new().await;
    f.add_user("bob", "bob-subject").await;
    let a = issued(&f, false, "alice").await;
    let b = issued(&f, false, "alice").await;
    let dynamic = issued(&f, true, "alice").await;
    let bob = issued(&f, false, "bob").await;
    let verifier = f.verifier();
    let inspector = f
        .store
        .oidc_introspection(f.authorization.clone(), verifier.clone())
        .unwrap();
    let disposer = f
        .store
        .oidc_revocation(f.authorization.clone(), verifier.clone())
        .unwrap();
    let logout = f
        .store
        .oidc_end_session(f.authorization.clone(), verifier.clone())
        .unwrap();
    let result = serde_json::to_value(
        inspector
            .introspect(a.access_token(), Some(b.access_token()), end())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(result["active"], true);
    assert_eq!(result["client_id"], "graphit-cli");
    assert_eq!(result.as_object().unwrap().len(), 4);
    assert!(
        f.db.query_row(
            "SELECT last_used_at IS NULL FROM local_tokens WHERE token_hash=?1",
            [access_hash(&f, a.access_token())],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
    assert!(
        f.db.query_row(
            "SELECT last_used_at IS NOT NULL FROM local_tokens WHERE token_hash=?1",
            [access_hash(&f, b.access_token())],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
    for target in [
        None,
        Some(""),
        Some("invalid"),
        Some(a.id_token()),
        a.refresh_token(),
        Some(dynamic.access_token()),
        Some(bob.access_token()),
    ] {
        assert_eq!(
            serde_json::to_value(
                inspector
                    .introspect(a.access_token(), target, end())
                    .await
                    .unwrap()
            )
            .unwrap(),
            json!({"active":false})
        );
    }
    assert_eq!(
        serde_json::to_value(
            inspector
                .introspect(a.access_token(), Some(&"x".repeat(8193)), end())
                .await
                .unwrap()
        )
        .unwrap(),
        json!({"active":false})
    );
    assert!(matches!(
        inspector
            .introspect(a.id_token(), Some(a.access_token()), end())
            .await,
        Err(OidcIntrospectionError::InvalidAuthority)
    ));
    f.db.execute(
        "UPDATE local_users SET enabled=0,revision=revision+1 WHERE username='alice'",
        [],
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(
            inspector
                .introspect(a.access_token(), Some(b.access_token()), end())
                .await
                .unwrap()
        )
        .unwrap()["active"],
        true
    );
    disposer
        .revoke(revoke(a.access_token(), "graphit-cli"), end())
        .await
        .unwrap();
    assert!(!live(&f, a.access_token()));
    assert!(live(&f, b.access_token()));
    verifier.verify(a.access_token(), &[], end()).unwrap();
    assert_eq!(
        serde_json::to_value(
            inspector
                .introspect(b.access_token(), Some(a.access_token()), end())
                .await
                .unwrap()
        )
        .unwrap(),
        json!({"active":false})
    );
    f.db.execute(
        "UPDATE local_users SET enabled=1,revision=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    let rotated = f
        .rotator()
        .rotate(refresh(a.refresh_token().unwrap(), false), end())
        .await
        .unwrap();
    disposer
        .revoke(revoke(a.refresh_token().unwrap(), "graphit-cli"), end())
        .await
        .unwrap();
    assert!(!live(&f, rotated.access_token()));
    assert!(matches!(
        f.rotator()
            .rotate(refresh(rotated.refresh_token().unwrap(), false), end())
            .await,
        Err(Error::InvalidGrant)
    ));
    assert!(live(&f, b.access_token()));
    disposer
        .revoke(revoke(b.refresh_token().unwrap(), DYNAMIC), end())
        .await
        .unwrap();
    assert!(live(&f, b.access_token()));
    f.db.execute(
        "DELETE FROM oauth_dynamic_clients WHERE client_id=?1",
        [DYNAMIC],
    )
    .unwrap();
    assert!(matches!(
        disposer
            .revoke(revoke(dynamic.refresh_token().unwrap(), DYNAMIC), end())
            .await,
        Err(Error::InvalidClient)
    ));
    logout
        .end_session(hint(dynamic.id_token()), end())
        .await
        .unwrap();
    assert!(!live(&f, dynamic.access_token()));
    assert!(live(&f, bob.access_token()));
    logout.end_session(hint(b.id_token()), end()).await.unwrap();
    assert!(!live(&f, b.access_token()));
    assert!(live(&f, bob.access_token()));
    verifier.verify(b.access_token(), &[], end()).unwrap();
    let stamp: i64 =
        f.db.query_row(
            "SELECT revoked_at FROM local_tokens WHERE token_hash=?1",
            [access_hash(&f, b.access_token())],
            |r| r.get(0),
        )
        .unwrap();
    logout.end_session(hint(b.id_token()), end()).await.unwrap();
    assert_eq!(
        stamp,
        f.db.query_row(
            "SELECT revoked_at FROM local_tokens WHERE token_hash=?1",
            [access_hash(&f, b.access_token())],
            |r| r.get::<_, i64>(0)
        )
        .unwrap()
    );
    assert!(matches!(
        f.rotator()
            .rotate(refresh(b.refresh_token().unwrap(), false), end())
            .await,
        Err(Error::InvalidGrant)
    ));
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine LOCAL grants and two physical SQLite owners, corruption and expiry"]
async fn sqlite_lifecycle_snapshot_limits_races_and_expired_hint() {
    let mut f = Fixture::new().await;
    let a = issued(&f, false, "alice").await;
    let b = issued(&f, false, "alice").await;
    let verifier = f.verifier();
    let inspector = f
        .store
        .oidc_introspection(f.authorization.clone(), verifier.clone())
        .unwrap();
    let target = access_hash(&f, b.access_token());
    let old: String =
        f.db.query_row(
            "SELECT principal_json FROM local_tokens WHERE token_hash=?1",
            [&target],
            |r| r.get(0),
        )
        .unwrap();
    f.db.execute(
        "UPDATE local_tokens SET principal_json=?1 WHERE token_hash=?2",
        params![vec![b'x'; 8193], target],
    )
    .unwrap();
    let authority_hash = access_hash(&f, a.access_token());
    f.db.execute(
        "UPDATE local_tokens SET revoked_at=?1 WHERE token_hash=?2",
        params![utc(), authority_hash],
    )
    .unwrap();
    assert!(matches!(
        inspector
            .introspect(a.access_token(), Some(b.access_token()), end())
            .await,
        Err(OidcIntrospectionError::InvalidAuthority)
    ));
    f.db.execute(
        "UPDATE local_tokens SET revoked_at=NULL WHERE token_hash=?1",
        [authority_hash],
    )
    .unwrap();
    assert!(matches!(
        inspector
            .introspect(a.access_token(), Some(b.access_token()), end())
            .await,
        Err(OidcIntrospectionError::MalformedStored)
    ));
    f.db.execute(
        "UPDATE local_tokens SET principal_json=?1 WHERE token_hash=?2",
        params!["x".repeat(8193), target],
    )
    .unwrap();
    assert!(matches!(
        inspector
            .introspect(a.access_token(), Some(b.access_token()), end())
            .await,
        Err(OidcIntrospectionError::ReadLimitExceeded)
    ));
    f.db.execute(
        "UPDATE local_tokens SET principal_json=?1 WHERE token_hash=?2",
        params![old, target],
    )
    .unwrap();
    let lock = Connection::open(&f.path).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        inspector
            .introspect(
                a.access_token(),
                Some(b.access_token()),
                Instant::now() + Duration::from_millis(30)
            )
            .await,
        Err(OidcIntrospectionError::Control(ControlError::Deadline))
    ));
    lock.execute_batch("ROLLBACK").unwrap();
    assert!(live(&f, b.access_token()));
    let other = SqliteControlStore::open(config(&f.path), digester(), end())
        .await
        .unwrap();
    let rotator = other
        .oidc_refresh(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
        .unwrap();
    let logout = f
        .store
        .oidc_end_session(f.authorization.clone(), verifier.clone())
        .unwrap();
    let (refresh_result, logout_result) = tokio::join!(
        rotator.rotate(refresh(b.refresh_token().unwrap(), false), end()),
        logout.end_session(hint(a.id_token()), end())
    );
    logout_result.unwrap();
    match refresh_result {
        Ok(tokens) => assert!(!live(&f, tokens.access_token())),
        Err(Error::InvalidGrant) => {}
        Err(e) => panic!("unexpected refresh result: {e:?}"),
    }
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let code = f.code(false, true).await;
    let exchange_other = other
        .oidc_token_exchange(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
        .unwrap();
    let (emitted, ended) = tokio::join!(
        exchange_other.exchange(exchange(code.code(), false), end()),
        logout.end_session(hint(a.id_token()), end())
    );
    ended.unwrap();
    let emitted = emitted.unwrap();
    verifier.verify(emitted.access_token(), &[], end()).unwrap();
    let family: String =
        f.db.query_row(
            "SELECT family_id FROM local_tokens WHERE token_hash=?1",
            [access_hash(&f, emitted.access_token())],
            |r| r.get(0),
        )
        .unwrap();
    let (total, revoked): (i64, i64) =
        f.db.query_row(
            "SELECT count(*),sum(revoked_at IS NOT NULL) FROM local_tokens WHERE family_id=?1",
            [family],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(total, 2);
    assert!(revoked == 0 || revoked == total);
    other.shutdown(end()).await.unwrap();
    // A valid code completed after logout may establish a new family.
    let fresh = issued(&f, false, "alice").await;
    assert!(live(&f, fresh.access_token()));
    f.policy = Arc::new(
        OidcTokenExchangePolicy::new(Duration::from_secs(60), Duration::from_secs(120)).unwrap(),
    );
    let expiring = issued(&f, true, "alice").await;
    let exp = claims(&f.issuer, expiring.id_token(), DYNAMIC)["exp"]
        .as_i64()
        .unwrap();
    while utc() / 1_000_000 <= exp {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f.db.execute(
        "DELETE FROM oauth_dynamic_clients WHERE client_id=?1",
        [DYNAMIC],
    )
    .unwrap();
    f.store
        .oidc_end_session(f.authorization.clone(), verifier)
        .unwrap()
        .end_session(hint(expiring.id_token()), end())
        .await
        .unwrap();
    let refresh_hash = digester()
        .token(
            TokenKind::LocalRefresh,
            expiring.refresh_token().unwrap().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    assert!(
        f.db.query_row(
            "SELECT revoked_at IS NOT NULL FROM local_tokens WHERE token_hash=?1",
            [refresh_hash],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
    assert!(live(&f, fresh.access_token()));
    f.close().await;
}
