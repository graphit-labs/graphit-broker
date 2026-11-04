#[path = "support/sqlite_oidc_fixture.rs"]
pub mod fixture;
use fixture::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_token_http_code_refresh_and_reuse() {
    let f = Fixture::new().await;
    let server = Server::new(&f, Duration::from_secs(10)).await;
    let code = f.code(false, true).await;
    let result = server.form(&code_form(code.code())).await;
    result.policy();
    assert_eq!(result.status, StatusCode::OK);
    let json = result.json();
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(
        claims(&f.issuer, json["id_token"].as_str().unwrap(), "graphit-cli")["sub"],
        code.oidc_subject()
    );
    assert_eq!(
        claims(&f.issuer, json["access_token"].as_str().unwrap(), AUDIENCE)["client_id"],
        "graphit-cli"
    );
    server
        .form(&code_form(code.code()))
        .await
        .error(400, "invalid_grant");
    let raw = json["refresh_token"].as_str().unwrap();
    let next = server
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "graphit-cli"),
            ("refresh_token", raw),
            ("scope", "openid email"),
        ])
        .await;
    next.policy();
    assert_eq!(next.status, StatusCode::OK);
    let next = next.json();
    assert_eq!(next["scope"], "openid email");
    let id = claims(&f.issuer, next["id_token"].as_str().unwrap(), "graphit-cli");
    assert_eq!(id["amr"], serde_json::json!(["local-token"]));
    server
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "graphit-cli"),
            ("refresh_token", raw),
        ])
        .await
        .error(400, "invalid_grant");
    server
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "graphit-cli"),
            ("refresh_token", next["refresh_token"].as_str().unwrap()),
        ])
        .await
        .error(400, "invalid_grant");
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    server
        .form(&[
            ("grant_type", broker_control::DEVICE_GRANT_TYPE),
            ("client_id", "graphit-cli"),
            ("device_code", "synthetic-device"),
        ])
        .await
        .error(503, "temporarily_unavailable");
    server.close().await;
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_token_http_form_guards_and_configuration() {
    let f = Fixture::new().await;
    let server = Server::new(&f, Duration::from_secs(10)).await;
    for body in [
        b"code=a&code=b".as_slice(),
        b"code=%FF",
        b"grant_type=authorization_code&resource=a&resource=b",
        b"grant_type=authorization_code&client_secret=x",
    ] {
        server
            .send(
                "/oauth/token",
                body,
                None,
                "application/x-www-form-urlencoded",
            )
            .await
            .error(400, "invalid_request");
    }
    server
        .send(
            "/oauth/token",
            &vec![b'x'; 8193],
            None,
            "application/x-www-form-urlencoded",
        )
        .await
        .error(400, "invalid_request");
    server
        .send("/oauth/token", b"{}", None, "application/json")
        .await
        .error(400, "invalid_request");
    server
        .send(
            "/oauth/token",
            b"grant_type=authorization_code",
            Some("Basic !!!"),
            "application/x-www-form-urlencoded",
        )
        .await
        .error(401, "invalid_client");
    let code = f.code(false, false).await;
    let mut fields = code_form(code.code());
    fields.retain(|(k, _)| *k != "client_id");
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let response = server
        .send(
            "/oauth/token",
            body.as_bytes(),
            Some("Basic Z3JhcGhpdC1jbGk6c2VjcmV0"),
            "application/x-www-form-urlencoded",
        )
        .await;
    response.error(401, "invalid_client");
    assert!(response.headers.contains_key(header::WWW_AUTHENTICATE));
    assert_eq!(f.tokens(), 0);
    let code = f.code(false, false).await;
    let mut wrong = code_form(code.code());
    wrong.retain(|(k, _)| *k != "code_verifier");
    wrong.push((
        "code_verifier",
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    ));
    server.form(&wrong).await.error(400, "invalid_grant");
    assert_eq!(f.tokens(), 0);
    assert_eq!(
        server.form(&code_form(code.code())).await.status,
        StatusCode::OK
    );
    let device = Arc::new(
        broker_control::DeviceAuthorizationPolicy::new(
            Duration::from_secs(600),
            Duration::from_secs(5),
            Duration::from_secs(600),
        )
        .unwrap(),
    );
    assert!(
        sqlite_local_oidc_token_router(
            f.store.clone(),
            f.issuer.clone(),
            f.authorization.clone(),
            f.policy.clone(),
            OidcTokenHttpConfig::new(Duration::from_secs(10), n(8192))
                .unwrap()
                .with_device(device)
        )
        .is_ok()
    );
    let upstream =
        Arc::new(broker_control::UpstreamBearerVerifier::new(ISSUER, n(8192), Vec::new()).unwrap());
    assert!(
        sqlite_local_oidc_token_router(
            f.store.clone(),
            f.issuer.clone(),
            f.authorization.clone(),
            f.policy.clone(),
            OidcTokenHttpConfig::new(Duration::from_secs(10), n(8192))
                .unwrap()
                .with_upstream(upstream)
        )
        .is_err()
    );
    server.close().await;
    f.close().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_token_http_deadline_and_closed_owner() {
    let f = Fixture::new().await;
    let server = Server::new(&f, Duration::from_millis(100)).await;
    let code = f.code(false, false).await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    server
        .form(&code_form(code.code()))
        .await
        .error(504, "temporarily_unavailable");
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(f.tokens(), 0);
    f.store.shutdown(end()).await.unwrap();
    server
        .form(&code_form(code.code()))
        .await
        .error(503, "temporarily_unavailable");
    server.close().await;
    f.engine.close().await;
}
