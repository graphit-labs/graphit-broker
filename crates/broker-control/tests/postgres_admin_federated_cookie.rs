#[path = "support/browser_upstream.rs"]
#[allow(
    dead_code,
    reason = "shared real issuer exercises additional key and protocol faults in H1/F1 contracts"
)]
mod browser;
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/browser_sql.rs"]
mod sql;
#[allow(
    dead_code,
    reason = "shared PostgreSQL fixture also serves the other SQL contracts"
)]
mod support;
use broker_control::{
    ADMIN_COOKIE_MAX_LIFETIME, AdminBrokerSessionLimits, AdminCookieSessionError as Error,
    AdminCookieSessionLimits, AdminCookieSessionPolicy, ControlError, FlowContinuation,
    FlowPurpose, IdentityReadLimits, IssuedAdminCookie, PostgresControlStore, SessionLimits,
    UpstreamAccessPolicy, UpstreamBearerVerifier, UpstreamBrowserClaimsSource,
    UpstreamBrowserClient, UpstreamClaimSelectors, UpstreamLoginCallback, UpstreamProviderConfig,
    UpstreamReadLimits, VerifiedUpstreamLogin,
};
use browser::{BrowserIssuer, ClientAuth, ClientRegistration, Fault};
use serde_json::json;
use sqlx_core::{connection::Connection, executor::Executor};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use support::{deadline, n};
use zeroize::Zeroizing;
fn client(
    id: &str,
    auth: ClientAuth,
    nonce: bool,
    source: UpstreamBrowserClaimsSource,
) -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: format!(" Browser {id} "),
        client_id: id.into(),
        client_secret: (auth != ClientAuth::Public).then(|| "fixture-secret".into()),
        redirect_url: "https://broker.example.invalid/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: nonce,
        claims_source: source,
        id_token_additional_audiences: vec![],
    }
}
fn configured(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
) -> UpstreamProviderConfig {
    let denied = vec!["public".to_owned()];
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec!["admin:session".into()],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: denied,
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "sub".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: Some("roles".into()),
            scope: "scope".into(),
        },
        limits: UpstreamReadLimits {
            token_bytes: n(16384),
            response_bytes: n(65536),
            keys: n(16),
            selector_bytes: n(512),
            claim_string_bytes: n(2048),
            profile_json_bytes: n(8192),
            teams: n(32),
        },
        request_timeout: Duration::from_secs(5),
        cache_max_age: Duration::from_secs(300),
        min_refresh_interval: Duration::from_millis(10),
        allow_loopback_http: false,
        trusted_ca_pem: Some(issuer.ca.clone()),
        browser_clients: clients,
    }
}
fn registration(id: &str, auth: ClientAuth) -> ClientRegistration {
    ClientRegistration {
        id: id.into(),
        secret: (auth != ClientAuth::Public).then(|| "fixture-secret".into()),
        redirect: "https://broker.example.invalid/oauth/oidc/callback".into(),
        auth,
    }
}
fn limits() -> AdminCookieSessionLimits {
    AdminCookieSessionLimits {
        authorization: AdminBrokerSessionLimits {
            identity: IdentityReadLimits {
                username_bytes: n(128),
                subject_bytes: n(512),
                role_bytes: n(128),
                roles: n(16),
                rows: n(128),
            },
            profile_json_bytes: n(8192),
        },
        metadata: SessionLimits {
            text_bytes: n(2048),
            csrf_bytes: n(43),
            team_bytes: n(512),
            role_bytes: n(128),
            max_teams: n(16),
            max_roles: n(16),
            teams_json_bytes: n(8192),
            roles_json_bytes: n(8192),
            max_lifetime: ADMIN_COOKIE_MAX_LIFETIME,
        },
    }
}
fn policy() -> AdminCookieSessionPolicy {
    AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(8 * 3600),
    }
}
fn owner(issuer: &BrowserIssuer, selector: Option<&str>, browser: bool) -> UpstreamBearerVerifier {
    let clients = if browser {
        vec![client(
            "public",
            ClientAuth::Public,
            true,
            UpstreamBrowserClaimsSource::IdToken,
        )]
    } else {
        vec![]
    };
    let mut config = configured(issuer, clients);
    config.claims.subject = "preferred_username".into();
    config.claims.roles = selector.map(str::to_owned);
    UpstreamBearerVerifier::new("https://broker.example.invalid", n(16384), vec![config]).unwrap()
}
fn no_issuer() -> UpstreamBearerVerifier {
    UpstreamBearerVerifier::new("https://broker.example.invalid", n(16384), vec![]).unwrap()
}
async fn proof_with_original(
    store: &PostgresControlStore,
    verifier: &UpstreamBearerVerifier,
    issuer: &BrowserIssuer,
    purpose: FlowPurpose,
    original: Instant,
) -> VerifiedUpstreamLogin {
    let id = verifier.browser_options(deadline()).unwrap()[0].id.clone();
    let continuation = match purpose {
        FlowPurpose::Admin => FlowContinuation::Admin { provider_id: id },
        FlowPurpose::OAuth => FlowContinuation::OAuth {
            provider_id: id,
            request_id: "genuine-oauth-request".into(),
        },
    };
    let login = store.upstream_logins(verifier);
    let issued = login.begin(continuation, original).await.unwrap();
    let code = issuer.authorize(&issued).await;
    login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            original,
        )
        .await
        .unwrap()
}
async fn proof(
    store: &PostgresControlStore,
    verifier: &UpstreamBearerVerifier,
    issuer: &BrowserIssuer,
    purpose: FlowPurpose,
) -> VerifiedUpstreamLogin {
    proof_with_original(store, verifier, issuer, purpose, deadline()).await
}
async fn issue(
    store: &PostgresControlStore,
    verifier: &UpstreamBearerVerifier,
    issuer: &BrowserIssuer,
) -> IssuedAdminCookie {
    let proof = proof(store, verifier, issuer, FlowPurpose::Admin).await;
    store
        .admin_cookie_sessions(limits(), policy(), Some(verifier))
        .unwrap()
        .issue_upstream(proof, deadline())
        .await
        .unwrap()
}
async fn count(admin: &mut sqlx_postgres::PgConnection) -> i64 {
    sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.admin_sessions")
        .fetch_one(admin)
        .await
        .unwrap()
}
fn hash(raw: &str) -> String {
    support::digester()
        .token(broker_security::TokenKind::AdminSession, raw.as_bytes())
        .unwrap()
        .to_sql_hex()
}
async fn seed(db: &mut sql::BrowserSql, issuer: &BrowserIssuer) {
    db.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user'")
        .await
        .unwrap();
    db.admin
        .execute(
            "INSERT INTO public.roles(name,created_at) VALUES('reader',0),('assigned',0) ON CONFLICT DO NOTHING",
        )
        .await
        .unwrap();
    db.admin.execute("INSERT INTO public.role_permissions(role,action) VALUES('reader','session.read'),('assigned','session.read') ON CONFLICT DO NOTHING").await.unwrap();
    sqlx_core::query::query(
        "INSERT INTO public.role_assignments(subject,role,created_at) VALUES($1,'assigned',0)",
    )
    .bind(format!("{}|id-user", issuer.issuer))
    .execute(&mut db.admin)
    .await
    .unwrap();
    // Only authorization state is seeded. All cookie rows and login proofs come from real H1.
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "genuine Rust HTTPS OIDC/PKCE and PostgreSQL NOSUPERUSER cookie lifecycle"]
async fn postgres_admin_federated_cookie_contract() {
    let mut db = sql::BrowserSql::new().await;
    let mut issuer = BrowserIssuer::new().await;
    issuer.register(registration("public", ClientAuth::Public));
    seed(&mut db, &issuer).await;
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader"]))].into(),
        ..Fault::default()
    });
    let verifier = owner(&issuer, Some("roles"), true);
    let view = db
        .store
        .admin_cookie_sessions(limits(), policy(), Some(&verifier))
        .unwrap();
    let foreign = owner(&issuer, Some("roles"), true);
    assert_eq!(
        view.issue_upstream(
            proof(&db.store, &foreign, &issuer, FlowPurpose::Admin).await,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(
        view.issue_upstream(
            proof(&db.store, &verifier, &issuer, FlowPurpose::OAuth).await,
            deadline()
        )
        .await
        .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(
        db.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_upstream(
                proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await,
                deadline()
            )
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(count(&mut db.admin).await, 0);
    let cookie = issue(&db.store, &verifier, &issuer).await;
    assert_eq!(cookie.secret().len(), 43);
    assert_eq!(format!("{cookie:?}"), "IssuedAdminCookie([REDACTED])");
    let session = view.read(cookie.secret(), deadline()).await.unwrap();
    assert_eq!(session.profile().subject, "id-user");
    assert_eq!(session.principal().issuer, issuer.issuer);
    assert_eq!(session.principal().local_user_revision, 0);
    assert_eq!(session.role_source(), "claims");
    assert_eq!(session.roles(), ["reader", "user"]);
    let csrf = Zeroizing::new(session.csrf_token().to_owned());
    assert_eq!(csrf.len(), 43);
    assert_ne!(csrf.as_str(), cookie.secret());
    let before: (i64, i64) = sqlx_core::query_as::query_as(
        "SELECT created_at,expires_at FROM public.admin_sessions WHERE token_hash=$1",
    )
    .bind(hash(cookie.secret()))
    .fetch_one(&mut db.admin)
    .await
    .unwrap();
    assert!(before.1 - before.0 > 7 * 3600 * 1_000_000);
    let stored: String = sqlx_core::query_scalar::query_scalar(
        "SELECT jsonb_agg(to_jsonb(s))::text FROM public.admin_sessions s",
    )
    .fetch_one(&mut db.admin)
    .await
    .unwrap();
    assert!(!stored.contains(cookie.secret()));
    assert!(stored.contains(&hash(cookie.secret())));
    let reduced = AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(300),
    };
    db.store
        .admin_cookie_sessions(limits(), reduced, Some(&verifier))
        .unwrap()
        .read(cookie.secret(), deadline())
        .await
        .unwrap();
    let after: (i64, i64) = sqlx_core::query_as::query_as(
        "SELECT created_at,expires_at FROM public.admin_sessions WHERE token_hash=$1",
    )
    .bind(hash(cookie.secret()))
    .fetch_one(&mut db.admin)
    .await
    .unwrap();
    assert_eq!(before, after, "GET never renews or shrinks stored TTL");
    let hits = (
        issuer.token_hits(),
        issuer.userinfo_hits(),
        issuer.jwks_hits(),
    );
    let removed_client = owner(&issuer, Some("roles"), false);
    db.store
        .admin_cookie_sessions(limits(), policy(), Some(&removed_client))
        .unwrap()
        .read(cookie.secret(), deadline())
        .await
        .unwrap();
    let changed = owner(&issuer, Some("$.roles[*]"), false);
    assert_eq!(
        db.store
            .admin_cookie_sessions(limits(), policy(), Some(&changed))
            .unwrap()
            .read(cookie.secret(), deadline())
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    let removed = owner(&issuer, None, false);
    let delegated = db
        .store
        .admin_cookie_sessions(limits(), policy(), Some(&removed))
        .unwrap()
        .read(cookie.secret(), deadline())
        .await
        .unwrap();
    assert_eq!(delegated.role_source(), "database");
    assert!(delegated.roles().iter().any(|r| r == "assigned"));
    assert!(!delegated.roles().iter().any(|r| r == "reader"));
    let absent = no_issuer();
    assert_eq!(
        db.store
            .admin_cookie_sessions(limits(), policy(), Some(&absent))
            .unwrap()
            .read(cookie.secret(), deadline())
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(
        db.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .read(cookie.secret(), deadline())
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    assert_eq!(
        hits,
        (
            issuer.token_hits(),
            issuer.userinfo_hits(),
            issuer.jwks_hits()
        ),
        "current cookie read has no discovery, refresh or UserInfo"
    );
    db.admin
        .execute("DELETE FROM public.role_permissions WHERE role='reader'")
        .await
        .unwrap();
    assert_eq!(
        view.read(cookie.secret(), deadline()).await.unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(
        view.logout(cookie.secret(), Some("malformed"), deadline())
            .await
            .unwrap_err(),
        Error::CsrfFailed
    );
    db.store
        .admin_cookie_sessions(limits(), policy(), Some(&absent))
        .unwrap()
        .logout(cookie.secret(), Some(&csrf), deadline())
        .await
        .unwrap();
    assert_eq!(count(&mut db.admin).await, 0);
    db.admin
        .execute("INSERT INTO public.role_permissions(role,action) VALUES('reader','session.read')")
        .await
        .unwrap();
    // Removing the selector ignores old claim-role authorization limits as well as authority.
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader", "old-a", "old-b"]))].into(),
        ..Fault::default()
    });
    let old = issue(&db.store, &verifier, &issuer).await;
    let mut constrained = limits();
    constrained.authorization.identity.roles = n(2);
    let current = db
        .store
        .admin_cookie_sessions(constrained, policy(), Some(&removed))
        .unwrap()
        .read(old.secret(), deadline())
        .await
        .unwrap();
    assert_eq!(current.roles(), ["assigned", "user"]);
    db.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .logout(old.secret(), Some(current.csrf_token()), deadline())
        .await
        .unwrap();
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader"]))].into(),
        ..Fault::default()
    });
    // Provenance preserves the literal compiled key; whitespace changes require a new login.
    issuer.fault(Fault {
        id_overrides: [
            (" roles ".into(), json!(["reader"])),
            ("roles".into(), json!([])),
        ]
        .into(),
        ..Fault::default()
    });
    let literal = owner(&issuer, Some(" roles "), true);
    let cookie = issue(&db.store, &literal, &issuer).await;
    let literal_view = db
        .store
        .admin_cookie_sessions(limits(), policy(), Some(&literal))
        .unwrap();
    let current = literal_view
        .read(cookie.secret(), deadline())
        .await
        .unwrap();
    assert_eq!(current.roles(), ["reader", "user"]);
    assert_eq!(
        view.read(cookie.secret(), deadline()).await.unwrap_err(),
        Error::Unauthorized
    );
    literal_view
        .logout(cookie.secret(), Some(current.csrf_token()), deadline())
        .await
        .unwrap();
    // Missing and empty claims retain only implicit user and its current SQL permissions.
    for selector in ["roles", "missing_roles"] {
        issuer.fault(Fault {
            id_overrides: [("roles".into(), json!([]))].into(),
            ..Fault::default()
        });
        db.admin.execute("INSERT INTO public.role_permissions(role,action) VALUES('user','session.read') ON CONFLICT DO NOTHING").await.unwrap();
        let empty = owner(&issuer, Some(selector), true);
        let cookie = issue(&db.store, &empty, &issuer).await;
        let empty_view = db
            .store
            .admin_cookie_sessions(limits(), policy(), Some(&empty))
            .unwrap();
        let current = empty_view.read(cookie.secret(), deadline()).await.unwrap();
        assert_eq!(current.roles(), ["user"]);
        assert_eq!(current.role_source(), "claims");
        db.admin
            .execute("DELETE FROM public.role_permissions WHERE role='user'")
            .await
            .unwrap();
        assert_eq!(
            empty_view
                .read(cookie.secret(), deadline())
                .await
                .unwrap_err(),
            Error::Forbidden
        );
        empty_view
            .logout(cookie.secret(), Some(current.csrf_token()), deadline())
            .await
            .unwrap();
    }
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader"]))].into(),
        ..Fault::default()
    });
    // A cookie issued without a role selector requires a fresh login if one is later added.
    let database_owner = owner(&issuer, None, true);
    let cookie = issue(&db.store, &database_owner, &issuer).await;
    assert_eq!(
        db.store
            .admin_cookie_sessions(limits(), policy(), Some(&verifier))
            .unwrap()
            .read(cookie.secret(), deadline())
            .await
            .unwrap_err(),
        Error::Unauthorized
    );
    let session = db
        .store
        .admin_cookie_sessions(limits(), policy(), Some(&database_owner))
        .unwrap()
        .read(cookie.secret(), deadline())
        .await
        .unwrap();
    assert_eq!(session.role_source(), "database");
    db.store
        .admin_cookie_sessions(limits(), policy(), None)
        .unwrap()
        .logout(cookie.secret(), Some(session.csrf_token()), deadline())
        .await
        .unwrap();
    // Proof must be live at issuance; the stored cookie thereafter has its own TTL.
    issuer.fault(Fault {
        id_overrides: [
            ("roles".into(), json!(["reader"])),
            ("exp".into(), json!(now() + 4)),
        ]
        .into(),
        ..Fault::default()
    });
    let cookie = issue(&db.store, &verifier, &issuer).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let session = view.read(cookie.secret(), deadline()).await.unwrap();
    assert!(
        session
            .authentication_expiry()
            .0
            .duration_since(SystemTime::now())
            .unwrap()
            > Duration::from_secs(7 * 3600)
    );
    view.logout(cookie.secret(), Some(session.csrf_token()), deadline())
        .await
        .unwrap();
    issuer.fault(Fault::default());
    // Same genuine flow/proof path cannot manufacture authority without current session.read.
    let denied = proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await;
    assert_eq!(
        view.issue_upstream(denied, deadline()).await.unwrap_err(),
        Error::Forbidden
    );
    assert_eq!(count(&mut db.admin).await, 0);
    let local_count: i64 =
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_users")
            .fetch_one(&mut db.admin)
            .await
            .unwrap();
    assert_eq!(local_count, 0);
    issuer.close().await;
    db.close().await;
}
async fn wait_lock(admin: &mut sqlx_postgres::PgConnection, pattern: &str) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='browser_login_owner' AND wait_event_type='Lock' AND query LIKE $1 LIMIT 1")
            .bind(pattern).fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "genuine cookie SQL must reach held lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual PostgreSQL cookie INSERT/read/revoke COMMIT ACK withholding, faults and cancellation"]
async fn postgres_admin_federated_cookie_uncertainty_contract() {
    let mut db = sql::BrowserSql::new().await;
    let mut issuer = BrowserIssuer::new().await;
    issuer.register(registration("public", ClientAuth::Public));
    seed(&mut db, &issuer).await;
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader"]))].into(),
        ..Fault::default()
    });
    let verifier = owner(&issuer, Some("roles"), true);
    let view = db
        .store
        .admin_cookie_sessions(limits(), policy(), Some(&verifier))
        .unwrap();
    for operation in ["issue", "read", "logout"] {
        let mut relay = commit::CommitRelay::new(db.fixture.port).await;
        let owner = PostgresControlStore::open(
            sql::config(&db.fixture, relay.port, Duration::from_secs(2)),
            support::digester(),
            deadline(),
        )
        .await
        .unwrap();
        let login = if operation == "issue" {
            Some(proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await)
        } else {
            None
        };
        let cookie = if operation != "issue" {
            Some(issue(&db.store, &verifier, &issuer).await)
        } else {
            None
        };
        let csrf = if let Some(c) = &cookie {
            Some(Zeroizing::new(
                view.read(c.secret(), deadline())
                    .await
                    .unwrap()
                    .csrf_token()
                    .to_owned(),
            ))
        } else {
            None
        };
        let token_hits = issuer.token_hits();
        let mut locker = db.fixture.connection().await;
        locker.execute("BEGIN").await.unwrap();
        let pattern = if operation == "logout" {
            sqlx_core::query::query(
                "SELECT token_hash FROM public.admin_sessions WHERE token_hash=$1 FOR UPDATE",
            )
            .bind(hash(cookie.as_ref().unwrap().secret()))
            .fetch_one(&mut locker)
            .await
            .unwrap();
            "%pg_catalog.octet_length(s.subject)%"
        } else {
            locker
                .execute("LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
                .await
                .unwrap();
            "%WITH selected AS%"
        };
        let cookie_owner = owner
            .admin_cookie_sessions(limits(), policy(), Some(&verifier))
            .unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        {
            let pending = async {
                match operation {
                    "issue" => cookie_owner
                        .issue_upstream(login.unwrap(), end)
                        .await
                        .map(|_| ()),
                    "read" => cookie_owner
                        .read(cookie.as_ref().unwrap().secret(), end)
                        .await
                        .map(|_| ()),
                    "logout" => cookie_owner
                        .logout(
                            cookie.as_ref().unwrap().secret(),
                            csrf.as_deref().map(|s| s.as_str()),
                            end,
                        )
                        .await
                        .map(|_| ()),
                    _ => unreachable!("finite fixture operation"),
                }
            };
            tokio::pin!(pending);
            let pid = tokio::select! {pid=wait_lock(&mut db.admin,pattern)=>pid,result=&mut pending=>panic!("actual operation must reach SQL lock: {:?}",result.err())};
            relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            locker.execute("ROLLBACK").await.unwrap();
            loop {
                let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("real COMMIT ACK must be withheld: {:?}",result.err())};
                let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                    "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
                )
                .bind(pid)
                .fetch_one(&mut db.admin)
                .await
                .unwrap();
                let expected = if operation == "logout" { 0 } else { 1 };
                if query == "COMMIT" && idle && count(&mut db.admin).await == expected {
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
        assert_eq!(
            issuer.token_hits(),
            token_hits,
            "unknown cookie commit never replays OIDC exchange"
        );
        assert_eq!(
            count(&mut db.admin).await,
            if operation == "logout" { 0 } else { 1 }
        );
        locker.close().await.unwrap();
        relay.close().await;
        owner.shutdown(deadline()).await.unwrap();
        db.admin
            .execute("DELETE FROM public.admin_sessions")
            .await
            .unwrap();
    }
    let bounded = proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await;
    let mut capped = limits();
    capped.authorization.profile_json_bytes = n(16);
    assert_eq!(
        db.store
            .admin_cookie_sessions(capped, policy(), Some(&verifier))
            .unwrap()
            .issue_upstream(bounded, deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::IdentityLimitExceeded)
    );
    assert_eq!(count(&mut db.admin).await, 0);
    // SQL INSERT fails after its parent statement: rollback never leaves partial authority.
    let login = proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await;
    db.admin
        .execute("REVOKE INSERT ON public.admin_session_principals FROM browser_login_owner")
        .await
        .unwrap();
    assert_eq!(
        view.issue_upstream(login, deadline()).await.unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    assert_eq!(count(&mut db.admin).await, 0);
    db.admin
        .execute("GRANT INSERT ON public.admin_session_principals TO browser_login_owner")
        .await
        .unwrap();
    let cookie = issue(&db.store, &verifier, &issuer).await;
    db.admin
        .execute("REVOKE SELECT ON public.role_permissions FROM browser_login_owner")
        .await
        .unwrap();
    assert_eq!(
        view.read(cookie.secret(), deadline()).await.unwrap_err(),
        Error::Control(ControlError::Storage)
    );
    db.admin
        .execute("GRANT SELECT ON public.role_permissions TO browser_login_owner")
        .await
        .unwrap();
    let session = view.read(cookie.secret(), deadline()).await.unwrap();
    let csrf = Zeroizing::new(session.csrf_token().to_owned());
    sqlx_core::query::query(
        "UPDATE public.admin_session_principals SET local_user_revision=1 WHERE token_hash=$1",
    )
    .bind(hash(cookie.secret()))
    .execute(&mut db.admin)
    .await
    .unwrap();
    assert_eq!(
        view.read(cookie.secret(), deadline()).await.unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(
        view.logout(cookie.secret(), Some(&csrf), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    sqlx_core::query::query(
        "UPDATE public.admin_session_principals SET local_user_revision=0 WHERE token_hash=$1",
    )
    .bind(hash(cookie.secret()))
    .execute(&mut db.admin)
    .await
    .unwrap();
    sqlx_core::query::query(
        "UPDATE public.admin_sessions SET csrf_token='invalid' WHERE token_hash=$1",
    )
    .bind(hash(cookie.secret()))
    .execute(&mut db.admin)
    .await
    .unwrap();
    assert_eq!(
        view.read(cookie.secret(), deadline()).await.unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    assert_eq!(
        view.logout(cookie.secret(), Some(&csrf), deadline())
            .await
            .unwrap_err(),
        Error::Control(ControlError::CorruptSession)
    );
    sqlx_core::query::query("UPDATE public.admin_sessions SET csrf_token=$1 WHERE token_hash=$2")
        .bind(csrf.as_str())
        .bind(hash(cookie.secret()))
        .execute(&mut db.admin)
        .await
        .unwrap();
    let (first, second) = tokio::join!(
        view.logout(cookie.secret(), Some(&csrf), deadline()),
        view.logout(cookie.secret(), Some(&csrf), deadline())
    );
    let a = first.unwrap().disposition();
    let b = second.unwrap().disposition();
    use broker_control::AdminCookieLogoutDisposition::{Absent, Revoked};
    assert!((a == Revoked && b == Absent) || (a == Absent && b == Revoked));
    assert_eq!(count(&mut db.admin).await, 0);
    // Expired known sessions clear without CSRF; corrupted metadata never becomes a guest proof.
    let cookie = issue(&db.store, &verifier, &issuer).await;
    let epoch = (now() as i64) * 1_000_000 - 1_000_000;
    sqlx_core::query::query(
        "UPDATE public.admin_sessions SET expires_at=$1,created_at=$1-1000000 WHERE token_hash=$2",
    )
    .bind(epoch)
    .bind(hash(cookie.secret()))
    .execute(&mut db.admin)
    .await
    .unwrap();
    assert_eq!(
        view.logout(cookie.secret(), None, deadline())
            .await
            .unwrap()
            .disposition(),
        broker_control::AdminCookieLogoutDisposition::Expired
    );
    let cookie = issue(&db.store, &verifier, &issuer).await;
    sqlx_core::query::query(
        "UPDATE public.admin_sessions SET expires_at=$1,created_at=$1-1000000 WHERE token_hash=$2",
    )
    .bind(epoch)
    .bind(hash(cookie.secret()))
    .execute(&mut db.admin)
    .await
    .unwrap();
    assert_eq!(
        view.read(cookie.secret(), deadline()).await.unwrap_err(),
        Error::Control(ControlError::SessionExpired)
    );
    assert_eq!(count(&mut db.admin).await, 0);
    // Dropping the real caller closes its physical waiting transaction and never emits a cookie.
    let login = proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await;
    let mut locker = db.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let pid = {
        let pending = view.issue_upstream(login, deadline());
        tokio::pin!(pending);
        tokio::select! {pid=wait_lock(&mut db.admin,"%WITH selected AS%")=>pid,result=&mut pending=>panic!("cancellation must reach held SQL: {:?}",result.err())}
    };
    let end = deadline();
    loop {
        let active: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut db.admin)
        .await
        .unwrap();
        if !active {
            break;
        }
        assert!(Instant::now() < end);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert_eq!(count(&mut db.admin).await, 0);
    // Expiry while actual SQL is blocked cannot produce a cookie or re-anchor the proof.
    issuer.fault(Fault {
        id_overrides: [
            ("roles".into(), json!(["reader"])),
            ("exp".into(), json!(now() + 4)),
        ]
        .into(),
        ..Fault::default()
    });
    let expiring = proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await;
    let mut locker = db.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let pending = view.issue_upstream(expiring, deadline());
        tokio::pin!(pending);
        tokio::select! { _=wait_lock(&mut db.admin,"%WITH selected AS%")=>{},result=&mut pending=>panic!("expiring proof must wait on actual SQL: {:?}",result.err()) };
        assert_eq!(
            pending.await.unwrap_err(),
            Error::Control(ControlError::Expired)
        );
    }
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert_eq!(count(&mut db.admin).await, 0);
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader"]))].into(),
        ..Fault::default()
    });
    let protected_original = Instant::now() + Duration::from_secs(3);
    let earlier = proof_with_original(
        &db.store,
        &verifier,
        &issuer,
        FlowPurpose::Admin,
        protected_original,
    )
    .await;
    let mut locker = db.fixture.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.role_permissions IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    {
        let pending = view.issue_upstream(earlier, Instant::now() + Duration::from_secs(15));
        tokio::pin!(pending);
        tokio::select! {_=wait_lock(&mut db.admin,"%WITH selected AS%")=>{},result=&mut pending=>panic!("Original proof must reach SQL lock: {:?}",result.err())};
        assert_eq!(
            tokio::time::timeout_at(
                (protected_original + Duration::from_secs(1)).into(),
                pending
            )
            .await
            .unwrap()
            .unwrap_err(),
            Error::Control(ControlError::Deadline)
        );
    }
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert_eq!(count(&mut db.admin).await, 0);
    // The consumer does not re-anchor an expired producer proof to its later own deadline.
    issuer.fault(Fault {
        id_overrides: [
            ("roles".into(), json!(["reader"])),
            ("exp".into(), json!(now() + 3)),
        ]
        .into(),
        ..Fault::default()
    });
    let expired = proof(&db.store, &verifier, &issuer, FlowPurpose::Admin).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(
        view.issue_upstream(expired, deadline()).await.unwrap_err(),
        Error::Control(ControlError::Expired)
    );
    assert_eq!(count(&mut db.admin).await, 0);
    issuer.fault(Fault {
        id_overrides: [("roles".into(), json!(["reader"]))].into(),
        ..Fault::default()
    });
    let healthy = issue(&db.store, &verifier, &issuer).await;
    let session = view.read(healthy.secret(), deadline()).await.unwrap();
    view.logout(healthy.secret(), Some(session.csrf_token()), deadline())
        .await
        .unwrap();
    issuer.close().await;
    db.close().await;
}
