#[path = "support/sqlite_oidc_fixture.rs"]
pub mod fixture;
use broker_presence::{
    OidcEndSessionHttpConfig, OidcIntrospectionHttpConfig, OidcRevocationHttpConfig,
    sqlite_oidc_end_session_router, sqlite_oidc_introspection_router,
    sqlite_oidc_revocation_router,
};
use fixture::*;

async fn server(f: &Fixture, timeout: Duration) -> Server {
    let verifier = f.verifier();
    let router = sqlite_local_oidc_token_router(
        f.store.clone(),
        f.issuer.clone(),
        f.authorization.clone(),
        f.policy.clone(),
        OidcTokenHttpConfig::new(timeout, n(8192)).unwrap(),
    )
    .unwrap()
    .merge(
        sqlite_oidc_introspection_router(
            f.store.clone(),
            verifier.clone(),
            f.authorization.clone(),
            OidcIntrospectionHttpConfig {
                request_timeout: timeout,
                body_bytes: n(8192),
            },
        )
        .unwrap(),
    )
    .merge(
        sqlite_oidc_revocation_router(
            f.store.clone(),
            verifier.clone(),
            f.authorization.clone(),
            OidcRevocationHttpConfig {
                request_timeout: timeout,
                body_bytes: n(8192),
            },
        )
        .unwrap(),
    )
    .merge(
        sqlite_oidc_end_session_router(
            f.store.clone(),
            verifier,
            f.authorization.clone(),
            OidcEndSessionHttpConfig {
                request_timeout: timeout,
                body_bytes: n(8192),
            },
        )
        .unwrap(),
    );
    Server::router(router).await
}
async fn form(
    server: &Server,
    path: &str,
    fields: &[(&str, &str)],
    authority: Option<&str>,
) -> Reply {
    let body = Zeroizing::new(
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish(),
    );
    let bearer = authority.map(|v| Zeroizing::new(format!("Bearer {v}")));
    server
        .send(
            path,
            body.as_bytes(),
            bearer.as_deref().map(String::as_str),
            "application/x-www-form-urlencoded",
        )
        .await
}
async fn issue(server: &Server, f: &Fixture, dynamic: bool, user: &str) -> Value {
    let code = f.code_for(dynamic, true, user).await;
    let mut fields = code_form(code.code());
    if dynamic {
        for (key, value) in &mut fields {
            if *key == "client_id" {
                *value = DYNAMIC;
            }
            if *key == "redirect_uri" {
                *value = "https://client.example/cb";
            }
        }
        fields.push(("resource", RESOURCE));
    }
    let result = form(server, "/oauth/token", &fields, None).await;
    result.policy();
    assert_eq!(result.status, StatusCode::OK);
    result.json()
}
fn raw<'a>(tokens: &'a Value, key: &str) -> &'a str {
    tokens[key].as_str().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real TCP, genuine LOCAL SQLite code exchange and lifecycle endpoints"]
async fn sqlite_lifecycle_http_authority_wire_and_disposal() {
    let f = Fixture::new().await;
    f.add_user("bob", "bob-subject").await;
    let server = server(&f, Duration::from_secs(10)).await;
    let a = issue(&server, &f, false, "alice").await;
    let b = issue(&server, &f, false, "alice").await;
    let d = issue(&server, &f, true, "alice").await;
    let bob = issue(&server, &f, false, "bob").await;
    let inspect = form(
        &server,
        "/oauth/introspect",
        &[("token", raw(&b, "access_token"))],
        Some(raw(&a, "access_token")),
    )
    .await;
    inspect.policy();
    assert_eq!(inspect.status, StatusCode::OK);
    assert_eq!(inspect.json()["active"], true);
    assert_eq!(inspect.json().as_object().unwrap().len(), 4);
    for target in [
        "",
        "invalid",
        raw(&a, "id_token"),
        raw(&a, "refresh_token"),
        raw(&d, "access_token"),
        raw(&bob, "access_token"),
    ] {
        let reply = form(
            &server,
            "/oauth/introspect",
            &[("token", target)],
            Some(raw(&a, "access_token")),
        )
        .await;
        reply.policy();
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json(), serde_json::json!({"active":false}));
    }
    for authority in [
        None,
        Some("invalid"),
        Some(raw(&a, "id_token")),
        Some(raw(&a, "refresh_token")),
    ] {
        let reply = form(
            &server,
            "/oauth/introspect",
            &[("client_id", "graphit-cli")],
            authority,
        )
        .await;
        reply.error(401, "invalid_token");
        assert!(reply.headers.contains_key(header::WWW_AUTHENTICATE));
    }
    server
        .send(
            "/oauth/introspect",
            b"token=invalid",
            Some("Basic Z3JhcGhpdC1jbGk6"),
            "application/x-www-form-urlencoded",
        )
        .await
        .error(401, "invalid_token");
    let bearer = Zeroizing::new(format!("Bearer {}", raw(&a, "access_token")));
    server
        .send_headers(
            "POST",
            "/oauth/introspect",
            b"token=invalid",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &bearer),
                ("authorization", &bearer),
            ],
        )
        .await
        .error(401, "invalid_token");
    server
        .send_headers(
            "POST",
            "/oauth/introspect",
            b"token=invalid",
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("authorization", &bearer),
            ],
        )
        .await
        .error(400, "invalid_request");
    for path in ["/oauth/introspect", "/oauth/revoke", "/oauth/end-session"] {
        let reply = server
            .send_method("PUT", path, b"", None, "application/x-www-form-urlencoded")
            .await;
        reply.policy();
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(reply.headers.contains_key(header::ALLOW));
    }
    for body in ["token=x&token=y", "token=%ff"] {
        let auth = Zeroizing::new(format!("Bearer {}", raw(&a, "access_token")));
        server
            .send(
                "/oauth/introspect",
                body.as_bytes(),
                Some(&auth),
                "application/x-www-form-urlencoded",
            )
            .await
            .error(400, "invalid_request");
    }
    form(
        &server,
        "/oauth/introspect?token=x",
        &[],
        Some(raw(&a, "access_token")),
    )
    .await
    .error(400, "invalid_request");
    let auth = Zeroizing::new(format!("Bearer {}", raw(&a, "access_token")));
    server
        .send(
            "/oauth/introspect",
            b"token=x",
            Some(&auth),
            "application/json",
        )
        .await
        .error(400, "invalid_request");
    form(
        &server,
        "/oauth/introspect",
        &[("token", &"x".repeat(8193))],
        Some(raw(&a, "access_token")),
    )
    .await
    .error(400, "invalid_request");
    form(
        &server,
        "/oauth/revoke",
        &[
            ("token", "unknown"),
            ("client_id", "graphit-cli"),
            ("client_secret", ""),
        ],
        None,
    )
    .await
    .error(401, "invalid_client");
    form(
        &server,
        "/oauth/revoke",
        &[
            ("token", "unknown"),
            ("client_id", "graphit-cli"),
            ("client_assertion", "x"),
        ],
        None,
    )
    .await
    .error(400, "invalid_request");
    for path in [
        "/oauth/end-session?post_logout_redirect_uri=",
        "/oauth/end-session?id_token_hint=invalid",
    ] {
        server
            .send_method("GET", path, b"", None, "application/x-www-form-urlencoded")
            .await
            .error(400, "invalid_request");
    }
    form(
        &server,
        "/oauth/end-session?id_token_hint=x",
        &[("id_token_hint", raw(&a, "id_token"))],
        None,
    )
    .await
    .error(400, "invalid_request");
    // Corruption is a server error, never an inactive credential oracle.
    let prior:String=f.db.query_row("SELECT principal_json FROM local_tokens WHERE token_kind='oidc_access' ORDER BY created_at LIMIT 1",[],|r|r.get(0)).unwrap();
    f.db.execute("UPDATE local_tokens SET principal_json='{}' WHERE token_kind='oidc_access' AND client_id='graphit-cli' AND subject='alice-subject'",[]).unwrap();
    form(
        &server,
        "/oauth/introspect",
        &[("token", raw(&b, "access_token"))],
        Some(raw(&a, "access_token")),
    )
    .await
    .error(500, "server_error");
    f.db.execute("UPDATE local_tokens SET principal_json=?1 WHERE token_kind='oidc_access' AND client_id='graphit-cli' AND subject='alice-subject'",[prior]).unwrap();
    f.db.execute(
        "UPDATE local_users SET enabled=0,revision=revision+1 WHERE username='alice'",
        [],
    )
    .unwrap();
    assert_eq!(
        form(
            &server,
            "/oauth/introspect",
            &[("token", raw(&b, "access_token"))],
            Some(raw(&a, "access_token"))
        )
        .await
        .json()["active"],
        true
    );
    let revoked = form(
        &server,
        "/oauth/revoke",
        &[
            ("client_id", "graphit-cli"),
            ("token", raw(&a, "access_token")),
            ("token_type_hint", "refresh_token"),
        ],
        None,
    )
    .await;
    revoked.policy();
    assert_eq!(revoked.status, StatusCode::OK);
    assert!(revoked.body.is_empty());
    f.verifier()
        .verify(raw(&a, "access_token"), &[], end())
        .unwrap();
    assert_eq!(
        form(
            &server,
            "/oauth/introspect",
            &[("token", raw(&a, "access_token"))],
            Some(raw(&b, "access_token"))
        )
        .await
        .json(),
        serde_json::json!({"active":false})
    );
    f.db.execute(
        "UPDATE local_users SET enabled=1,revision=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    let rotated = form(
        &server,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "graphit-cli"),
            ("refresh_token", raw(&a, "refresh_token")),
        ],
        None,
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let rotated = rotated.json();
    let family = form(
        &server,
        "/oauth/revoke",
        &[
            ("client_id", "graphit-cli"),
            ("token", raw(&a, "refresh_token")),
            ("token_type_hint", "access_token"),
        ],
        None,
    )
    .await;
    family.policy();
    assert_eq!(family.status, StatusCode::OK);
    assert!(family.body.is_empty());
    form(
        &server,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "graphit-cli"),
            ("refresh_token", raw(&rotated, "refresh_token")),
        ],
        None,
    )
    .await
    .error(400, "invalid_grant");
    assert_eq!(
        form(
            &server,
            "/oauth/introspect",
            &[("token", raw(&rotated, "access_token"))],
            Some(raw(&b, "access_token"))
        )
        .await
        .json(),
        serde_json::json!({"active":false})
    );
    f.db.execute(
        "DELETE FROM oauth_dynamic_clients WHERE client_id=?1",
        [DYNAMIC],
    )
    .unwrap();
    form(
        &server,
        "/oauth/revoke",
        &[("client_id", DYNAMIC), ("token", raw(&d, "refresh_token"))],
        None,
    )
    .await
    .error(401, "invalid_client");
    for tokens in [&d, &b] {
        let result = form(
            &server,
            "/oauth/end-session",
            &[("id_token_hint", raw(tokens, "id_token"))],
            None,
        )
        .await;
        result.policy();
        assert_eq!(result.status, StatusCode::NO_CONTENT);
        assert!(result.body.is_empty());
    }
    let repeated = form(
        &server,
        "/oauth/end-session",
        &[("id_token_hint", raw(&b, "id_token"))],
        None,
    )
    .await;
    repeated.policy();
    assert_eq!(repeated.status, StatusCode::NO_CONTENT);
    f.verifier()
        .verify(raw(&b, "access_token"), &[], end())
        .unwrap();
    assert_eq!(
        form(
            &server,
            "/oauth/introspect",
            &[("token", raw(&bob, "access_token"))],
            Some(raw(&bob, "access_token"))
        )
        .await
        .json()["active"],
        true
    );
    form(
        &server,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "graphit-cli"),
            ("refresh_token", raw(&b, "refresh_token")),
        ],
        None,
    )
    .await
    .error(400, "invalid_grant");
    f.store.shutdown(end()).await.unwrap();
    form(
        &server,
        "/oauth/revoke",
        &[("client_id", "graphit-cli"), ("token", "unknown")],
        None,
    )
    .await
    .error(503, "temporarily_unavailable");
    server.close().await;
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine SQLite expired ID hint over HTTP GET and physical lock deadline"]
async fn sqlite_lifecycle_http_expired_hint_and_original() {
    let mut f = Fixture::new().await;
    f.policy = Arc::new(
        OidcTokenExchangePolicy::new(Duration::from_secs(60), Duration::from_secs(120)).unwrap(),
    );
    let short = server(&f, Duration::from_secs(10)).await;
    let tokens = issue(&short, &f, true, "alice").await;
    let expiry = claims(&f.issuer, raw(&tokens, "id_token"), DYNAMIC)["exp"]
        .as_i64()
        .unwrap();
    short.close().await;
    while utc() / 1_000_000 <= expiry {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    f.db.execute(
        "DELETE FROM oauth_dynamic_clients WHERE client_id=?1",
        [DYNAMIC],
    )
    .unwrap();
    let server = server(&f, Duration::from_millis(100)).await;
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", raw(&tokens, "id_token"))
        .finish();
    let url = Zeroizing::new(format!("/oauth/end-session?{query}"));
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    server
        .send_method("GET", &url, b"", None, "application/x-www-form-urlencoded")
        .await
        .error(504, "temporarily_unavailable");
    f.db.execute_batch("ROLLBACK").unwrap();
    let result = server
        .send_method("GET", &url, b"", None, "application/x-www-form-urlencoded")
        .await;
    result.policy();
    assert_eq!(result.status, StatusCode::NO_CONTENT);
    assert!(result.body.is_empty());
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM local_tokens WHERE revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    server.close().await;
    f.close().await;
}
