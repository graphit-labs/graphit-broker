#[path = "../../broker-control/tests/support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine protocol fixtures cover both consumer targets"
)]
mod ingress;
#[path = "support/sqlite_oidc_fixture.rs"]
#[allow(
    dead_code,
    unused_imports,
    reason = "existing TCP transport supports the established OIDC journeys"
)]
mod transport;
use broker_control::FlowPurpose;
use broker_presence::{
    AdminCookieHttpConfig, AdminLocalBearerHttpConfig, AdminSessionHttpConfig,
    sqlite_admin_session_router_with_cookie,
};
use hyper::http::header;
use ingress as s;
use ingress::fixture::*;
use transport::{Reply, Server};
const SESSION: &str = "/admin/api/v1/session";
fn auth(v: &str) -> String {
    format!("Bearer {v}")
}
fn cookie(v: &str) -> String {
    format!("graphit_admin_session={v}")
}
fn config() -> AdminSessionHttpConfig {
    AdminSessionHttpConfig {
        limits: s::limits().authorization,
        request_timeout: Duration::from_secs(5),
    }
}
fn local() -> AdminLocalBearerHttpConfig {
    AdminLocalBearerHttpConfig {
        audience: "admin-api".into(),
        identity_json_bytes: n(8192),
        required_scopes: vec!["admin:session".into()],
    }
}
fn cookie_config() -> AdminCookieHttpConfig {
    AdminCookieHttpConfig {
        limits: s::limits(),
        policy: s::policy(),
        secure: true,
    }
}
fn policy(r: &Reply) {
    assert_eq!(r.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(r.headers[header::PRAGMA], "no-cache");
    assert!(r.headers.contains_key("x-request-id"));
}
fn denied(r: &Reply, status: u16) {
    assert_eq!(r.status.as_u16(), status);
    policy(r);
    assert!(!r.headers.contains_key(header::SET_COOKIE));
    assert!(r.json()["error"]["code"].is_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine LOCAL JWT and cookies, H1/H2 HTTPS, F1 signatures and native TCP SQLite"]
async fn sqlite_complete_session_dispatches_four_ingresses_and_preserves_cookie_priority() {
    let f = Fixture::new().await;
    s::allow_session(&f);
    let jwt = s::jwt(&f).await;
    let opaque = s::persisted_opaque(&f);
    let local_cookie = s::local_cookie(&f).await;
    let op = s::browser_op().await;
    let external = s::upstream::UpstreamFixture::new().await;
    let v = s::trust(vec![s::config(&op.issuer, &op.ca, true, Some("roles")), {
        let mut c = s::config(&external.issuer, &external.ca, false, None);
        c.id = "bearer".into();
        c
    }]);
    let h1 = s::h1(&f, &op, &v, FlowPurpose::Admin, end()).await;
    let federated = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(v.clone()))
        .unwrap()
        .issue_upstream(h1, end())
        .await
        .unwrap();
    let bearer = external.sign(&external.claims(), "upstream-key", "at+jwt");
    let server = Server::router(
        sqlite_admin_session_router_with_cookie(
            f.store.clone(),
            f.verifier(),
            config(),
            Some(local()),
            Some(v.clone()),
            Some(cookie_config()),
        )
        .unwrap(),
    )
    .await;
    let jwt_header = auth(&jwt);
    let opaque_header = auth(&opaque);
    let external_header = auth(&bearer);
    let local_header = cookie(local_cookie.secret());
    let fed_header = cookie(federated.secret());
    for (headers, source, name, has_csrf) in [
        (
            vec![("authorization", jwt_header.as_str())],
            "database",
            "Alice",
            false,
        ),
        (
            vec![("authorization", opaque_header.as_str())],
            "database",
            "Alice",
            false,
        ),
        (
            vec![("authorization", external_header.as_str())],
            "database",
            "Federated",
            false,
        ),
        (
            vec![("cookie", local_header.as_str())],
            "database",
            "Alice",
            true,
        ),
        (
            vec![("cookie", fed_header.as_str())],
            "claims",
            "ID Name",
            true,
        ),
    ] {
        let response = server.send_headers("GET", SESSION, b"", &headers).await;
        assert_eq!(response.status.as_u16(), 200);
        policy(&response);
        assert!(!response.headers.contains_key(header::SET_COOKIE));
        let body = response.json();
        assert_eq!(body["role_source"], source);
        assert_eq!(body["name"], name);
        assert_eq!(body["csrf_token"].as_str().unwrap().is_empty(), !has_csrf);
        let head = server.send_headers("HEAD", SESSION, b"", &headers).await;
        assert_eq!(head.status.as_u16(), 200);
        assert!(head.body.is_empty());
        policy(&head);
        assert!(!String::from_utf8_lossy(&response.body).contains(bearer.as_str()));
    }
    let before = (op.token_hits(), op.userinfo_hits(), op.jwks_hits());
    let response = server
        .send_headers(
            "GET",
            SESSION,
            b"",
            &[("cookie", &fed_header), ("authorization", "Bearer invalid")],
        )
        .await;
    assert_eq!(response.status.as_u16(), 200);
    assert_eq!(
        (op.token_hits(), op.userinfo_hits(), op.jwks_hits()),
        before
    );
    let csrf = response.json()["csrf_token"].as_str().unwrap().to_owned();
    for headers in [
        vec![
            ("cookie", "graphit_admin_session=invalid"),
            ("authorization", jwt_header.as_str()),
        ],
        vec![
            ("cookie", local_header.as_str()),
            ("cookie", fed_header.as_str()),
        ],
        vec![
            ("authorization", jwt_header.as_str()),
            ("authorization", jwt_header.as_str()),
        ],
    ] {
        denied(
            &server.send_headers("GET", SESSION, b"", &headers).await,
            401,
        );
    }
    let correlated = server
        .send_headers(
            "GET",
            SESSION,
            b"",
            &[
                ("authorization", jwt_header.as_str()),
                ("x-request-id", "correlation kept"),
            ],
        )
        .await;
    assert_eq!(correlated.status.as_u16(), 200);
    assert_eq!(correlated.headers["x-request-id"], "correlation kept");
    for empty in [
        "graphit_admin_session=",
        "graphit_admin_session=\"\"",
        "other_cookie=value",
    ] {
        assert_eq!(
            server
                .send_headers(
                    "GET",
                    SESSION,
                    b"",
                    &[("cookie", empty), ("authorization", jwt_header.as_str())]
                )
                .await
                .status
                .as_u16(),
            200
        );
    }
    denied(
        &server
            .send_headers(
                "GET",
                &format!("{SESSION}?access_token={}", jwt.as_str()),
                b"",
                &[],
            )
            .await,
        401,
    );
    let bad = server
        .send_headers(
            "POST",
            "/admin/auth/logout",
            b"",
            &[("cookie", &fed_header), ("x-csrf-token", "wrong")],
        )
        .await;
    denied(&bad, 403);
    let logout = server
        .send_headers(
            "POST",
            "/admin/auth/logout",
            b"",
            &[("cookie", &fed_header), ("x-csrf-token", &csrf)],
        )
        .await;
    assert_eq!(logout.status.as_u16(), 204);
    assert!(logout.body.is_empty());
    assert!(
        logout.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    denied(
        &server
            .send_headers(
                "GET",
                SESSION,
                b"",
                &[
                    ("cookie", &fed_header),
                    ("authorization", jwt_header.as_str()),
                ],
            )
            .await,
        401,
    );
    let local_read = server
        .send_headers("GET", SESSION, b"", &[("cookie", &local_header)])
        .await;
    let csrf = local_read.json()["csrf_token"].as_str().unwrap().to_owned();
    assert_eq!(
        server
            .send_headers(
                "POST",
                "/admin/auth/logout",
                b"",
                &[("cookie", &local_header), ("x-csrf-token", &csrf)]
            )
            .await
            .status
            .as_u16(),
        204
    );
    server.close().await;
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real native cookie, current trust removal, TCP errors and locked SQL"]
async fn sqlite_session_http_trust_removal_logout_deadline_and_closed_are_finite() {
    let f = Fixture::new().await;
    s::allow_session(&f);
    let op = s::browser_op().await;
    let v = s::trust(vec![s::config(&op.issuer, &op.ca, true, None)]);
    let proof = s::h1(&f, &op, &v, FlowPurpose::Admin, end()).await;
    let cookie_owner = f
        .store
        .admin_cookie_sessions(s::limits(), s::policy(), Some(v))
        .unwrap();
    let issued = cookie_owner.issue_upstream(proof, end()).await.unwrap();
    let read = cookie_owner.read(issued.secret(), end()).await.unwrap();
    let csrf = read.csrf_token().to_owned();
    let raw = cookie(issued.secret());
    let removed = Server::router(
        sqlite_admin_session_router_with_cookie(
            f.store.clone(),
            f.verifier(),
            config(),
            None,
            Some(s::trust(vec![])),
            Some(cookie_config()),
        )
        .unwrap(),
    )
    .await;
    denied(
        &removed
            .send_headers("GET", SESSION, b"", &[("cookie", &raw)])
            .await,
        401,
    );
    let logout = removed
        .send_headers(
            "POST",
            "/admin/auth/logout",
            b"",
            &[("cookie", &raw), ("x-csrf-token", &csrf)],
        )
        .await;
    assert_eq!(logout.status.as_u16(), 204);
    removed.close().await;
    let local = s::local_cookie(&f).await;
    let raw = cookie(local.secret());
    let mut short = config();
    short.request_timeout = Duration::from_millis(30);
    let server = Server::router(
        sqlite_admin_session_router_with_cookie(
            f.store.clone(),
            f.verifier(),
            short,
            None,
            None,
            Some(cookie_config()),
        )
        .unwrap(),
    )
    .await;
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let response = server
        .send_headers("GET", SESSION, b"", &[("cookie", &raw)])
        .await;
    f.db.execute_batch("ROLLBACK").unwrap();
    denied(&response, 504);
    f.store.shutdown(end()).await.unwrap();
    denied(
        &server
            .send_headers("GET", SESSION, b"", &[("cookie", &raw)])
            .await,
        503,
    );
    server.close().await;
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(
        SqliteControlStore::open(
            ingress::fixture::config(&root.path().join("private/db")),
            digester(),
            end(),
        )
        .await
        .unwrap(),
    );
    let server = Server::router(
        sqlite_admin_session_router_with_cookie(
            store.clone(),
            f.verifier(),
            config(),
            None,
            None,
            None,
        )
        .unwrap(),
    )
    .await;
    assert_eq!(
        server
            .send_headers("POST", "/admin/auth/logout", b"", &[])
            .await
            .status
            .as_u16(),
        404
    );
    server.close().await;
    store.shutdown(end()).await.unwrap();
}

#[tokio::test]
async fn agent_instruction_drafts_publish_for_authenticated_sync_and_survive_reopen() {
    use broker_presence::{InstructionHttpConfig, InstructionStore, instruction_overrides_router};
    use serde_json::json;

    const ADMIN: &str = "/admin/api/v1/agent-instructions";
    const SYNC: &str = "/v1/agent-instructions";
    const NAME: &str = "skills/ast/entry.md";
    let f = Fixture::new().await;
    s::allow_session(&f);
    let observer = s::local_cookie(&f).await;
    let key = s::persisted_opaque(&f);
    let bearer = auth(&key);
    let jwt = auth(&s::jwt(&f).await);
    let path = f._temp.path().join("instructions.json");
    let router = || {
        instruction_overrides_router(
            InstructionStore::Sqlite(f.store.clone()),
            f.verifier(),
            None,
            InstructionHttpConfig {
                file: path.clone(),
                timeout: Duration::from_secs(5),
                audience: "admin-api".into(),
                identity_json_bytes: n(8192),
                cookie: cookie_config(),
            },
        )
        .merge(
            sqlite_admin_session_router_with_cookie(
                f.store.clone(),
                f.verifier(),
                config(),
                Some(local()),
                None,
                Some(cookie_config()),
            )
            .unwrap(),
        )
    };
    let server = Server::router(router()).await;
    let observer_cookie = cookie(observer.secret());
    assert_eq!(
        server
            .send_headers(
                "PUT",
                ADMIN,
                b"{invalid",
                &[("content-type", "application/json")]
            )
            .await
            .status,
        401,
        "authenticate before consuming an unauthenticated JSON body"
    );
    assert_eq!(
        server
            .send_headers("GET", ADMIN, b"", &[("cookie", &observer_cookie)])
            .await
            .status,
        403
    );
    assert_eq!(server.send_headers("GET", SYNC, b"", &[]).await.status, 401);
    assert_eq!(
        server
            .send_headers(
                "PUT",
                ADMIN,
                b"{invalid",
                &[
                    ("cookie", &observer_cookie),
                    ("content-type", "application/json")
                ]
            )
            .await
            .status,
        403,
        "reject an unprivileged session before decoding JSON"
    );
    assert!(!path.exists());

    f.db.execute_batch("INSERT INTO role_assignments(subject,role,created_at) VALUES('local|alice-subject','admin',0)")
        .unwrap();
    let administrator = s::local_cookie(&f).await;
    let session = cookie(administrator.secret());
    let admin = [("cookie", session.as_str())];
    let read = server.send_headers("GET", ADMIN, b"", &admin).await;
    assert_eq!(read.json(), json!({"revision":0,"templates":{}}));
    let mut headers = vec![
        ("cookie", session.as_str()),
        ("content-type", "application/json"),
    ];
    let draft =
        json!({"revision":0,"templates":{NAME:{"enabled":false,"markdown":"Olá {{ brand }}."}}});
    let write = |document: &serde_json::Value| serde_json::to_vec(document).unwrap();
    assert_eq!(
        server
            .send_headers("PUT", ADMIN, &write(&draft), &headers)
            .await
            .status,
        403
    );
    let session_doc = server
        .send_headers("GET", SESSION, b"", &admin)
        .await
        .json();
    headers.push(("x-csrf-token", session_doc["csrf_token"].as_str().unwrap()));
    assert_eq!(
        server
            .send_headers("PUT", ADMIN, b"{invalid", &headers)
            .await
            .status,
        400
    );
    let mut repeated_csrf = headers.clone();
    repeated_csrf.push(("x-csrf-token", session_doc["csrf_token"].as_str().unwrap()));
    assert_eq!(
        server
            .send_headers("PUT", ADMIN, &write(&draft), &repeated_csrf)
            .await
            .status,
        403
    );
    assert_eq!(
        server
            .send_headers("PUT", ADMIN, &write(&draft), &headers)
            .await
            .json()["revision"],
        1
    );

    let synced = server
        .send_headers("GET", SYNC, b"", &[("authorization", &bearer)])
        .await;
    assert_eq!(synced.json(), json!({"version":1,"templates":{}}));
    assert_eq!(synced.headers[header::CACHE_CONTROL], "no-store");
    let mut active = draft;
    active["revision"] = 1.into();
    active["templates"][NAME]["enabled"] = true.into();
    let mut invalid = active.clone();
    invalid["templates"][NAME]["markdown"] = "{{".into();
    assert_eq!(
        server
            .send_headers("PUT", ADMIN, &write(&invalid), &headers)
            .await
            .json()["error"]["code"],
        "invalid_instruction_syntax"
    );
    let active_bytes = write(&active);
    let (first, second) = tokio::join!(
        server.send_headers("PUT", ADMIN, &active_bytes, &headers),
        server.send_headers("PUT", ADMIN, &active_bytes, &headers),
    );
    let mut statuses = [first.status.as_u16(), second.status.as_u16()];
    statuses.sort();
    assert_eq!(
        statuses,
        [200, 409],
        "one revision wins across concurrent writers"
    );
    assert_eq!(
        server
            .send_headers("PUT", ADMIN, &write(&active), &headers)
            .await
            .status,
        409
    );
    server.close().await;

    let reopened = Server::router(router()).await;
    let published = reopened
        .send_headers("GET", SYNC, b"", &[("authorization", &bearer)])
        .await;
    assert_eq!(
        published.json(),
        json!({"version":1,"templates":{NAME:"Olá {{ brand }}."}})
    );
    assert_eq!(
        reopened
            .send_headers("GET", SYNC, b"", &[("authorization", &jwt)])
            .await
            .json(),
        published.json()
    );
    for name in [
        "../entry.md",
        "defaults/entry.md",
        "a\\entry.md",
        "/entry.md",
        "a/../entry.md",
        "entry.txt",
    ] {
        let invalid = json!({"revision":2,"templates":{name:{"enabled":false,"markdown":"draft"}}});
        assert_eq!(
            reopened
                .send_headers("PUT", ADMIN, &write(&invalid), &headers)
                .await
                .status,
            400,
            "reject reserved or non-relative template path {name}"
        );
    }
    active["revision"] = 2.into();
    active["templates"][NAME]["enabled"] = false.into();
    assert_eq!(
        reopened
            .send_headers("PUT", ADMIN, &write(&active), &headers)
            .await
            .status,
        200
    );
    assert_eq!(
        reopened
            .send_headers("GET", SYNC, b"", &[("authorization", &bearer)])
            .await
            .json()["templates"],
        json!({})
    );
    let saved = std::fs::read(&path).unwrap();
    std::fs::write(&path, b"{corrupt").unwrap();
    assert_eq!(
        reopened
            .send_headers("GET", SYNC, b"", &[("authorization", &bearer)])
            .await
            .status,
        503,
        "corrupt persistence must not become an empty active bundle"
    );
    std::fs::write(&path, &saved).unwrap();
    f.db.execute_batch(
        "DELETE FROM role_assignments WHERE subject='local|alice-subject' AND role='admin'",
    )
    .unwrap();
    assert_eq!(
        reopened
            .send_headers("GET", ADMIN, b"", &admin)
            .await
            .status,
        403
    );
    assert_eq!(
        reopened
            .send_headers("PUT", ADMIN, &saved, &headers)
            .await
            .status,
        403
    );
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    reopened.close().await;
    f.store.shutdown(end()).await.unwrap();
}
