#[path = "support/sqlite_oidc_fixture.rs"]
pub mod fixture;
use fixture::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native file SQLite, Argon2 LOCAL preparation, S256 and signed JWTs"]
async fn sqlite_pending_completion_and_signed_grants() {
    let f = Fixture::new().await;
    let service = f.store.browser_oidc_authorizations(f.authorization.clone());
    let BrowserOidcAuthorization::Pending(pending) = service
        .admit_browser(request(false, true), end())
        .await
        .unwrap()
    else {
        panic!("current browser admission must yield genuine pending metadata");
    };
    assert!(
        service
            .load(pending.request(), end())
            .await
            .unwrap()
            .is_some()
    );
    let wrong = service.create(request(false, false), end()).await.unwrap();
    let login = f.prepared(wrong.request()).await;
    assert_eq!(
        service
            .complete(pending.request(), login, end())
            .await
            .unwrap_err(),
        AuthError::InvalidLogin
    );
    for change in [
        "enabled=0",
        "password_change_required=1",
        "revision=2",
        "identity_kind='service'",
    ] {
        let candidate = service.create(request(false, false), end()).await.unwrap();
        let login = f.prepared(candidate.request()).await;
        f.db.execute_batch(&format!("UPDATE local_users SET {change}"))
            .unwrap();
        assert_eq!(
            service
                .complete(candidate.request(), login, end())
                .await
                .unwrap_err(),
            AuthError::InvalidLogin
        );
        assert_eq!(
            f.db.query_row(
                "SELECT count(*) FROM oidc_auth_requests WHERE code_hash IS NOT NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        f.db.execute_batch("UPDATE local_users SET enabled=1,password_change_required=0,revision=1,identity_kind='human'").unwrap();
    }
    let login = f.prepared(pending.request()).await;
    f.db.execute_batch("UPDATE local_users SET name='Current Alice';INSERT INTO roles(name,created_at) VALUES('maintainer',1);INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','maintainer',1)").unwrap();
    let code = service
        .complete(pending.request(), login, end())
        .await
        .unwrap();
    assert!(
        service
            .load(pending.request(), end())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(code.amr(), ["pwd"]);
    let tokens = f
        .producer()
        .exchange(exchange(code.code(), false), end())
        .await
        .unwrap();
    let access = claims(&f.issuer, tokens.access_token(), AUDIENCE);
    let id = claims(&f.issuer, tokens.id_token(), "graphit-cli");
    assert_eq!(access["sub"], code.oidc_subject());
    assert_eq!(access["aud"], json!([AUDIENCE]));
    assert_eq!(id["nonce"], "literal-nonce");
    assert_eq!(id["amr"], json!(["pwd"]));
    assert_eq!(id["auth_time"], code.auth_time().as_i64() / 1_000_000);
    assert_eq!(id["name"], "Current Alice");
    assert_eq!(id["groups"], json!(["engineering"]));
    assert_eq!(id["roles"], json!(["maintainer", "user"]));
    for (claim, raw) in [("at_hash", tokens.access_token()), ("c_hash", code.code())] {
        let hash = Sha512::digest(raw.as_bytes());
        assert_eq!(id[claim], URL_SAFE_NO_PAD.encode(&hash[..32]));
    }
    let access_hash = digester()
        .token(
            TokenKind::OidcStoredAccess,
            access["jti"].as_str().unwrap().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    assert!(
        f.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM local_tokens WHERE token_hash=?1)",
            [access_hash],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()
    );
    assert_eq!(f.tokens(), 2);
    assert!(!f.code_exists(code.code()));
    assert!(tokens.refresh_token().unwrap().starts_with("gb_rt_"));
    let dynamic = f.code(true, false).await;
    let result = f
        .producer()
        .exchange(exchange(dynamic.code(), true), end())
        .await
        .unwrap();
    assert!(result.refresh_token().is_none());
    assert_eq!(
        claims(&f.issuer, result.access_token(), AUDIENCE)["aud"],
        json!([AUDIENCE, RESOURCE])
    );
    let mut bad = request(true, false);
    bad.scope = "email";
    assert!(matches!(
        service.admit_browser(bad, end()).await.unwrap(),
        BrowserOidcAuthorization::Rejected(_)
    ));
    let mut bad = request(true, false);
    bad.redirect_uri = "https://evil.example/cb";
    assert!(matches!(
        service.admit_browser(bad, end()).await,
        Err(AuthError::InvalidRedirect)
    ));
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native SQLite guards, corruption, rollback, reopen and two-store code race"]
async fn sqlite_exchange_guards_atomicity_and_races() {
    let mut f = Fixture::new().await;
    let code = f.code(true, true).await;
    for case in 0..5 {
        let mut bad = exchange(code.code(), true);
        match case {
            0 => bad.code_verifier = Some("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            1 => bad.client_id = Some("graphit-cli"),
            2 => bad.redirect_uri = Some("https://client.example/cb/"),
            3 => bad.resource = Some("https://evil.example"),
            _ => bad.resource = None,
        };
        assert!(f.producer().exchange(bad, end()).await.is_err());
        assert!(f.code_exists(code.code()));
        assert_eq!(f.tokens(), 0);
    }
    for change in [
        "enabled=0",
        "password_change_required=1",
        "revision=2",
        "identity_kind='service'",
    ] {
        f.db.execute_batch(&format!("UPDATE local_users SET {change}"))
            .unwrap();
        assert_eq!(
            f.producer()
                .exchange(exchange(code.code(), true), end())
                .await
                .unwrap_err(),
            Error::InvalidGrant
        );
        assert!(f.code_exists(code.code()));
        f.db.execute_batch("UPDATE local_users SET enabled=1,password_change_required=0,revision=1,identity_kind='human'").unwrap();
    }
    f.db.execute_batch(
        "UPDATE oauth_dynamic_clients SET redirect_uris_json='[\"https://other.example/cb\"]'",
    )
    .unwrap();
    assert!(
        f.producer()
            .exchange(exchange(code.code(), true), end())
            .await
            .is_err()
    );
    assert!(f.code_exists(code.code()));
    f.db.execute_batch(
        "UPDATE oauth_dynamic_clients SET redirect_uris_json='[\"https://client.example/cb\"]'",
    )
    .unwrap();
    // Catalog integrity rejects unapproved schema before any token mutation.
    // Physical rollback/uncertain ACK is reused from the common executor proof.
    f.db.execute_batch("CREATE TRIGGER reject_refresh BEFORE INSERT ON local_tokens WHEN NEW.token_kind='refresh' BEGIN SELECT RAISE(ABORT,'fixture rollback'); END").unwrap();
    assert_eq!(
        f.producer()
            .exchange(exchange(code.code(), true), end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::SchemaRejected)
    );
    assert_eq!(f.tokens(), 0);
    assert!(f.code_exists(code.code()));
    f.db.execute_batch("DROP TRIGGER reject_refresh").unwrap();
    // The owner pins schema generation: restoring DDL still needs explicit reopen.
    f.store.shutdown(end()).await.unwrap();
    f.store = Arc::new(
        SqliteControlStore::open(config(&f.path), digester(), end())
            .await
            .unwrap(),
    );
    let other = SqliteControlStore::open(config(&f.path), digester(), end())
        .await
        .unwrap();
    let a = f.producer();
    let b = other
        .oidc_token_exchange(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
        .unwrap();
    let (a, b) = tokio::join!(
        a.exchange(exchange(code.code(), true), end()),
        b.exchange(exchange(code.code(), true), end())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(f.tokens(), 2);
    other.shutdown(end()).await.unwrap();
    let fresh = f.code(false, false).await;
    let json: String =
        f.db.query_row(
            "SELECT request_json FROM oidc_auth_requests WHERE code_hash IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE code_hash IS NOT NULL",
        [vec![0xff; 12]],
    )
    .unwrap();
    assert_eq!(
        f.producer()
            .exchange(exchange(fresh.code(), false), end())
            .await
            .unwrap_err(),
        Error::MalformedStored
    );
    assert!(f.code_exists(fresh.code()));
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE code_hash IS NOT NULL",
        ["x".repeat(8193)],
    )
    .unwrap();
    assert_eq!(
        f.producer()
            .exchange(exchange(fresh.code(), false), end())
            .await
            .unwrap_err(),
        Error::ReadLimitExceeded
    );
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE code_hash IS NOT NULL",
        [json],
    )
    .unwrap();
    f.store.shutdown(end()).await.unwrap();
    let reopened = SqliteControlStore::open(config(&f.path), digester(), end())
        .await
        .unwrap();
    assert!(
        reopened
            .oidc_token_exchange(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
            .unwrap()
            .exchange(exchange(fresh.code(), false), end())
            .await
            .is_ok()
    );
    reopened.shutdown(end()).await.unwrap();
    f.engine.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native absolute refresh rotation, narrowing, one winner and committed reuse revocation"]
async fn sqlite_refresh_rotation_narrowing_and_reuse() {
    let f = Fixture::new().await;
    let code = f.code(true, true).await;
    let initial = f
        .producer()
        .exchange(exchange(code.code(), true), end())
        .await
        .unwrap();
    let raw = initial.refresh_token().unwrap();
    let old: (String, i64, i64) =
        f.db.query_row(
            "SELECT family_id,expires_at,auth_time FROM local_tokens WHERE token_kind='refresh'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    for scope in ["", " ", "openid ", "openid  email", "address"] {
        let mut bad = refresh(raw, true);
        bad.scope = Some(scope);
        assert_eq!(
            f.rotator().rotate(bad, end()).await.unwrap_err(),
            Error::InvalidScope
        );
        assert_eq!(f.tokens(), 2);
    }
    let mut narrow = refresh(raw, true);
    narrow.scope = Some("openid email");
    let next = f.rotator().rotate(narrow, end()).await.unwrap();
    assert_eq!(next.scope(), "openid email");
    let id = claims(&f.issuer, next.id_token(), DYNAMIC);
    assert_eq!(id["auth_time"], old.2 / 1_000_000);
    assert_eq!(id["amr"], json!(["local-token"]));
    assert!(id.get("nonce").is_none());
    assert!(id.get("c_hash").is_none());
    let current:(String,i64,i64)=f.db.query_row("SELECT family_id,expires_at,auth_time FROM local_tokens WHERE token_kind='refresh' AND consumed_at IS NULL",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(current, old);
    let mut widen = refresh(next.refresh_token().unwrap(), true);
    widen.scope = Some("openid offline_access");
    assert_eq!(
        f.rotator().rotate(widen, end()).await.unwrap_err(),
        Error::InvalidScope
    );
    let other = SqliteControlStore::open(config(&f.path), digester(), end())
        .await
        .unwrap();
    let a = f.rotator();
    let b = other
        .oidc_refresh(f.authorization.clone(), f.policy.clone(), f.issuer.clone())
        .unwrap();
    let (a, b) = tokio::join!(
        a.rotate(refresh(next.refresh_token().unwrap(), true), end()),
        b.rotate(refresh(next.refresh_token().unwrap(), true), end())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE family_id=?1 AND revoked_at IS NULL",
            [old.0],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    other.shutdown(end()).await.unwrap();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native refresh guards precede reuse, consumed expired ancestor still revokes"]
async fn sqlite_consumed_expired_refresh_guard_precedence() {
    let f = Fixture::new().await;
    let code = f.code(false, true).await;
    let tokens = f
        .producer()
        .exchange(exchange(code.code(), false), end())
        .await
        .unwrap();
    let raw = tokens.refresh_token().unwrap();
    let rotated = f
        .rotator()
        .rotate(refresh(raw, false), end())
        .await
        .unwrap();
    let hash = digester()
        .token(TokenKind::LocalRefresh, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    f.db.execute(
        "UPDATE local_tokens SET expires_at=created_at+1 WHERE token_hash=?1",
        [hash],
    )
    .unwrap();
    let mut bad = refresh(raw, false);
    bad.client_id = Some(DYNAMIC);
    bad.resource = Some(RESOURCE);
    assert_eq!(
        f.rotator().rotate(bad, end()).await.unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE revoked_at IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let mut wrong = refresh(raw, false);
    wrong.resource = Some("https://evil.example");
    assert_eq!(
        f.rotator().rotate(wrong, end()).await.unwrap_err(),
        Error::InvalidTarget
    );
    let mut wrong = refresh(raw, false);
    wrong.scope = Some("address");
    assert_eq!(
        f.rotator().rotate(wrong, end()).await.unwrap_err(),
        Error::InvalidScope
    );
    f.db.execute_batch("UPDATE local_users SET revision=2")
        .unwrap();
    assert_eq!(
        f.rotator()
            .rotate(refresh(raw, false), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    f.db.execute_batch("UPDATE local_users SET revision=1")
        .unwrap();
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE revoked_at IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        f.rotator()
            .rotate(refresh(raw, false), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        f.rotator()
            .rotate(refresh(rotated.refresh_token().unwrap(), false), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    let fresh = f.code(false, true).await;
    let tokens = f
        .producer()
        .exchange(exchange(fresh.code(), false), end())
        .await
        .unwrap();
    let raw = tokens.refresh_token().unwrap();
    let hash = digester()
        .token(TokenKind::LocalRefresh, raw.as_bytes())
        .unwrap()
        .to_sql_hex();
    f.db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_hash=?2",
        params![utc() + 500_000, hash],
    )
    .unwrap();
    let next = f
        .rotator()
        .rotate(refresh(raw, false), end())
        .await
        .unwrap();
    assert!(next.expires_in(end()).is_ok());
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(next.expires_in(end()).unwrap_err(), Error::InvalidGrant);
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native lock wait, original deadline, current UTC expiry and closed owner"]
async fn sqlite_oidc_deadline_expiry_and_closed_owner() {
    let f = Fixture::new().await;
    let code = f.code(false, false).await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let short = Instant::now() + Duration::from_millis(100);
    assert_eq!(
        f.producer()
            .exchange(exchange(code.code(), false), short)
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(f.code_exists(code.code()));
    assert_eq!(f.tokens(), 0);
    assert_eq!(
        f.producer()
            .exchange(exchange(code.code(), false), Instant::now())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    let expired = f.code(false, false).await;
    f.db.execute(
        "UPDATE oidc_auth_requests SET expires_at=created_at+1 WHERE code_hash=?1",
        [digester()
            .token(TokenKind::OidcAuthorizationCode, expired.code().as_bytes())
            .unwrap()
            .to_sql_hex()],
    )
    .unwrap();
    assert_eq!(
        f.producer()
            .exchange(exchange(expired.code(), false), end())
            .await
            .unwrap_err(),
        Error::InvalidGrant
    );
    assert!(f.code_exists(expired.code()));
    assert_eq!(f.tokens(), 0);
    let pending = f
        .store
        .browser_oidc_authorizations(f.authorization.clone())
        .create(request(false, false), end())
        .await
        .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut bad = request(false, false);
    bad.scope = "email";
    assert!(matches!(
        f.store
            .browser_oidc_authorizations(f.authorization.clone())
            .admit_browser(bad, Instant::now() + Duration::from_millis(100))
            .await,
        Err(AuthError::Control(ControlError::Deadline))
    ));
    f.db.execute_batch("ROLLBACK").unwrap();
    let waiting = f.code(false, false).await;
    let hash = digester()
        .token(TokenKind::OidcAuthorizationCode, waiting.code().as_bytes())
        .unwrap()
        .to_sql_hex();
    f.db.execute(
        "UPDATE oidc_auth_requests SET expires_at=?1 WHERE code_hash=?2",
        params![utc() + 200_000, hash],
    )
    .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let store = f.store.clone();
    let authorization = f.authorization.clone();
    let policy = f.policy.clone();
    let issuer = f.issuer.clone();
    let raw = Zeroizing::new(waiting.code().to_owned());
    let task = tokio::spawn(async move {
        store
            .oidc_token_exchange(authorization, policy, issuer)
            .unwrap()
            .exchange(exchange(&raw, false), end())
            .await
    });
    tokio::time::sleep(Duration::from_millis(350)).await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(task.await.unwrap().unwrap_err(), Error::InvalidGrant);
    assert!(f.code_exists(waiting.code()));
    let request_hash = digester()
        .token(TokenKind::OidcAuthRequest, pending.request().as_bytes())
        .unwrap()
        .to_sql_hex();
    f.db.execute(
        "UPDATE oidc_auth_requests SET expires_at=?1 WHERE request_hash=?2",
        params![utc() + 200_000, request_hash],
    )
    .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let store = f.store.clone();
    let authorization = f.authorization.clone();
    let raw = Zeroizing::new(pending.request().to_owned());
    let task = tokio::spawn(async move {
        store
            .browser_oidc_authorizations(authorization)
            .load(&raw, end())
            .await
    });
    tokio::time::sleep(Duration::from_millis(350)).await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert!(task.await.unwrap().unwrap().is_none());
    let fresh = f.code(false, true).await;
    let tokens = f
        .producer()
        .exchange(exchange(fresh.code(), false), end())
        .await
        .unwrap();
    let count = f.tokens();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        f.rotator()
            .rotate(
                refresh(tokens.refresh_token().unwrap(), false),
                Instant::now() + Duration::from_millis(100)
            )
            .await
            .unwrap_err(),
        Error::Control(ControlError::Deadline)
    );
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.tokens(), count);
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        f.producer()
            .exchange(exchange(code.code(), false), end())
            .await
            .unwrap_err(),
        Error::Control(ControlError::Closed)
    );
    f.engine.close().await;
}
