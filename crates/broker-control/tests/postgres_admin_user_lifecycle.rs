//! PostgreSQL TLS and genuine native LOCAL login/MFA/OAuth/service consumers.
#[path = "support/browser_upstream.rs"]
#[allow(
    dead_code,
    reason = "shared genuine HTTPS issuer supports other protocol cases"
)]
mod browser;
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "genuine shared password/MFA fixture serves several contracts"
)]
mod cookie;
#[path = "support/admin_federated_read.rs"]
#[allow(
    dead_code,
    reason = "shared genuine federated fixture also renders native HTTP configuration"
)]
mod federated;
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture has other contract helpers"
)]
mod support;
use broker_control::{
    AdminBrokerSessionError, AdminReadAuthentication, AdminServiceCredentialInput, AdminUserInput,
    AdminUsersError as Error, AdminUsersLimits, AdminUsersRequest, AdminUsersResult,
    BrokerAccessIssuer, BrokerAccessVerifier, ControlError, LocalAuthStage, LocalAuthStep,
    OidcAuthorizationConfiguration, OidcAuthorizationInput, OidcAuthorizationLimits,
    OidcAuthorizationPolicy, OidcRefreshInput, OidcTokenExchangeInput, OidcTokenExchangePolicy,
    PostgresControlStore, PreparedAdminLogin, PreparedOidcLogin, SystemAction,
};
use broker_security::LocalAuthBinding;
use cookie::CookieFixture;
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU32,
    sync::Arc,
    time::{Duration, Instant},
};
use support::{deadline, n};
use zeroize::Zeroizing;
const PASSWORD: &str = "native administrative fixture password";
const CHANGED: &str = "native changed administrative password";
const AUDIENCE: &str = "explicit-admin-api";
const ISSUER: &str = "https://broker.example";
const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
fn limits() -> AdminUsersLimits {
    AdminUsersLimits {
        authorization: cookie::limits().authorization,
        response_json_bytes: n(65536),
        service_credential_audience: AUDIENCE.into(),
        service_credential_max_ttl: Duration::from_secs(365 * 86400),
    }
}
fn input(username: &str, subject: &str, kind: &str, password: &str) -> AdminUserInput {
    let mut input = AdminUserInput::default();
    input.username = username.to_owned();
    input.subject = subject.to_owned();
    input.kind = kind.to_owned();
    input.password = password.to_owned();
    input
}

fn observed(mut result: AdminUsersResult<'_>) -> Result<(u16, Zeroizing<Vec<u8>>), Error> {
    result.check()?;
    Ok((result.status(), Zeroizing::new(result.take_body())))
}
async fn cookie_action(
    f: &CookieFixture,
    raw: &str,
    csrf: Option<&str>,
    request: AdminUsersRequest<'_>,
) -> Result<(u16, Zeroizing<Vec<u8>>), Error> {
    let limits = limits();
    f.store
        .admin_users(&f.engine, &limits)
        .unwrap()
        .execute(
            AdminReadAuthentication::Cookie {
                raw,
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            request,
            csrf,
            deadline(),
        )
        .await
        .and_then(observed)
}
async fn service_action(
    f: &CookieFixture,
    raw: &str,
    request: AdminUsersRequest<'_>,
) -> Result<(u16, Zeroizing<Vec<u8>>), Error> {
    let limits = limits();
    let scopes = vec!["admin:session".to_owned()];
    f.store
        .admin_users(&f.engine, &limits)
        .unwrap()
        .execute(
            AdminReadAuthentication::Opaque {
                raw,
                audience: AUDIENCE,
                identity_json_bytes: n(8192),
                required_scopes: &scopes,
            },
            request,
            None,
            deadline(),
        )
        .await
        .and_then(observed)
}
async fn actions(f: &mut CookieFixture, actions: &[SystemAction]) {
    f.admin
        .execute("DELETE FROM public.role_permissions WHERE role='user'")
        .await
        .unwrap();
    for action in actions {
        sqlx_core::query::query(
            "INSERT INTO public.role_permissions(role,action) VALUES('user',$1)",
        )
        .bind(action.as_str())
        .execute(&mut f.admin)
        .await
        .unwrap();
    }
}
async fn scalar(admin: &mut sqlx_postgres::PgConnection, query: &'static str) -> i64 {
    sqlx_core::query_scalar::query_scalar(query)
        .fetch_one(admin)
        .await
        .unwrap()
}
fn pending(step: LocalAuthStep) -> broker_control::PendingLocalAuth {
    match step {
        LocalAuthStep::Pending(p) => p,
        _ => panic!("expected pending LOCAL stage"),
    }
}
fn complete(step: LocalAuthStep) -> broker_control::CompletedLocalLogin {
    match step {
        LocalAuthStep::Complete(p) => p,
        _ => panic!("expected genuine LOCAL completion"),
    }
}
fn limiter() -> broker_control::LocalMfaAttemptLimiter {
    broker_control::LocalMfaAttemptLimiter::new(
        broker_control::LocalMfaAttemptPolicy::new(
            NonZeroU32::new(10).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            n(4),
        )
        .unwrap(),
    )
}
async fn code(
    f: &CookieFixture,
    policy: &OidcAuthorizationPolicy,
    offline: bool,
) -> broker_control::AuthorizedOidcAuthorization {
    let service = f.store.oidc_authorization_service(&f.digester, policy);
    let request = service
        .create(
            OidcAuthorizationInput {
                client_id: "graphit-cli",
                redirect_uri: "http://localhost:49152/oauth/callback",
                response_type: "code",
                scope: if offline {
                    "openid profile email offline_access"
                } else {
                    "openid profile email"
                },
                state: "native-user-state",
                nonce: "native-user-nonce",
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some("query"),
                resources: &[],
                prompts: &[],
            },
            deadline(),
        )
        .await
        .unwrap();
    let login = f
        .login(LocalAuthBinding::OauthAuthorize(
            request.request().as_bytes(),
        ))
        .await;
    service
        .complete(
            request.request(),
            PreparedOidcLogin::try_from(login).unwrap(),
            deadline(),
        )
        .await
        .unwrap()
}
fn exchange_input(raw: &str) -> OidcTokenExchangeInput<'_> {
    OidcTokenExchangeInput {
        grant_type: Some("authorization_code"),
        client_id: Some("graphit-cli"),
        code: Some(raw),
        redirect_uri: Some("http://localhost:49152/oauth/callback"),
        code_verifier: Some(VERIFIER),
        resource: None,
        authorization: None,
    }
}
fn refresh_input(raw: &str) -> OidcRefreshInput<'_> {
    OidcRefreshInput {
        grant_type: Some("refresh_token"),
        client_id: Some("graphit-cli"),
        refresh_token: Some(raw),
        scope: None,
        resource: None,
        authorization: None,
    }
}
async fn blocked(admin: &mut sqlx_postgres::PgConnection, query: &str) -> i32 {
    let end = deadline();
    loop {
        let pid:Option<i32>=sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock' AND query LIKE $1 LIMIT 1").bind(query).fetch_optional(&mut *admin).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "operation must reach its actual SQL lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn closed(admin: &mut sqlx_postgres::PgConnection, pid: i32) {
    let end = deadline();
    loop {
        let live: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut *admin)
        .await
        .unwrap();
        if !live {
            return;
        }
        assert!(Instant::now() < end, "cancelled connection must close");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned TLS PostgreSQL NOSUPERUSER, native KDF/MFA/OAuth and actual COMMIT relay"]
async fn postgres_admin_user_lifecycle_contract() {
    let mut f = CookieFixture::new().await;
    let limits = limits();
    let cookie = f.cookie().await;
    let csrf = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .read(cookie.secret(), deadline())
        .await
        .unwrap()
        .csrf_token()
        .to_owned();
    let mut bob = input(" bob ", " bob-subject ", "human", PASSWORD);
    bob.name = "é".repeat(512);
    bob.teams = vec![" team ".into(), "team".into()];
    assert!(matches!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Create(&bob)
        )
        .await,
        Err(Error::Authorization(AdminBrokerSessionError::Forbidden))
    ));
    actions(&mut f, &[SystemAction::UsersWrite]).await;
    assert_eq!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Create(&bob)
        )
        .await
        .unwrap()
        .0,
        201
    );
    let state:(String,i64,i64,i64,String)=sqlx_core::query_as::query_as("SELECT subject,enabled::bigint,password_change_required::bigint,revision,teams_json FROM public.local_users WHERE username='bob'").fetch_one(&mut f.admin).await.unwrap();
    assert_eq!(state, ("bob-subject".into(), 1, 1, 1, "[\"team\"]".into()));
    let first_phc = Zeroizing::new(
        sqlx_core::query_scalar::query_scalar::<_, String>(
            "SELECT password_hash FROM public.local_users WHERE username='bob'",
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap(),
    );
    let mut update = input("robert", "bob-subject", "", "");
    update.enabled = None;
    assert_eq!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Update {
                username: "bob",
                user: &update
            }
        )
        .await
        .unwrap()
        .0,
        204
    );
    let state:(String,String,i64,i64)=sqlx_core::query_as::query_as("SELECT password_hash,teams_json,password_change_required::bigint,revision FROM public.local_users WHERE username='robert'").fetch_one(&mut f.admin).await.unwrap();
    assert!(state.0 == *first_phc);
    assert_eq!((state.1, state.2, state.3), ("[]".into(), 1, 2));
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("robert", PASSWORD, deadline())
        .await
        .unwrap();
    assert!(proof.password_change_required());
    update.subject = "different".into();
    assert!(matches!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Update {
                username: "robert",
                user: &update
            }
        )
        .await,
        Err(Error::UpdateFailed)
    ));
    update.subject = "bob-subject".into();
    update.kind = "service".into();
    assert!(matches!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Update {
                username: "robert",
                user: &update
            }
        )
        .await,
        Err(Error::UpdateFailed)
    ));
    let mut operator = input("operator", "operator-subject", "service", "");
    operator.roles = vec!["admin".into()];
    operator.password_change_required = true;
    assert_eq!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Create(&operator)
        )
        .await
        .unwrap()
        .0,
        201
    );
    assert_eq!(scalar(&mut f.admin,"SELECT password_change_required::bigint FROM public.local_users WHERE username='operator'").await,0);
    let request = AdminServiceCredentialInput {
        scopes: vec!["admin:session".into()],
        ..Default::default()
    };
    let delivered = cookie_action(
        &f,
        cookie.secret(),
        Some(&csrf),
        AdminUsersRequest::IssueCredential {
            username: "operator",
            input: &request,
        },
    )
    .await
    .unwrap();
    assert_eq!(delivered.0, 201);
    let value: Value = serde_json::from_slice(&delivered.1).unwrap();
    let operator_raw = Zeroizing::new(value["token"].as_str().unwrap().to_owned());
    assert!(operator_raw.starts_with("gb_sc_"));
    drop(value);
    drop(delivered);
    f.store
        .local_bearer_verifier(AUDIENCE, n(8192))
        .unwrap()
        .verify(&operator_raw, &["admin:session".into()], deadline())
        .await
        .unwrap();
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::Credentials {
                username: "operator"
            }
        )
        .await
        .unwrap()
        .0,
        200
    );
    assert!(matches!(
        cookie_action(
            &f,
            cookie.secret(),
            Some(&csrf),
            AdminUsersRequest::Credentials {
                username: "operator"
            }
        )
        .await,
        Err(Error::Authorization(AdminBrokerSessionError::Forbidden))
    ));
    // Mandatory change and enrollment use real LOCAL producers, not SQL-seeded factors.
    let auth = f
        .store
        .local_auth_service(&f.digester, &f.protector, &f.required);
    let change = pending(
        auth.begin(proof, LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap(),
    );
    assert_eq!(change.stage(), LocalAuthStage::PasswordChange);
    let enroll = pending(
        auth.complete_password_change(
            &f.engine,
            change.challenge(),
            LocalAuthBinding::AdminLogin,
            CHANGED,
            deadline(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(enroll.stage(), LocalAuthStage::Enrollment);
    let sdk = totp_rs::Totp::from_url(enroll.enrollment().unwrap().otpauth_uri()).unwrap();
    let otp = Zeroizing::new(
        sdk.generate((cookie::micros() / 1_000_000) as u64)
            .to_string(),
    );
    let mut login = complete(
        auth.complete_mfa(
            &limiter(),
            enroll.challenge(),
            LocalAuthBinding::AdminLogin,
            &otp,
            deadline(),
        )
        .await
        .unwrap(),
    );
    let recovery = login.take_recovery_codes().unwrap();
    let old_code = Zeroizing::new(recovery.iter().next().unwrap().to_owned());
    assert_eq!(
        scalar(
            &mut f.admin,
            "SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='bob-subject'"
        )
        .await,
        10
    );
    actions(
        &mut f,
        &[
            SystemAction::UsersWrite,
            SystemAction::UsersRead,
            SystemAction::SessionRead,
        ],
    )
    .await;
    let bob_cookie = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .issue_local(
            PreparedAdminLogin::try_from(login).unwrap(),
            &f.required,
            deadline(),
        )
        .await
        .unwrap();
    // Password administration keeps the existing factor/recovery and forces change.
    let factor_before=Zeroizing::new(sqlx_core::query_scalar::query_scalar::<_,String>("SELECT jsonb_build_array((SELECT to_jsonb(m) FROM public.local_mfa m WHERE subject='bob-subject'),(SELECT jsonb_agg(to_jsonb(c)) FROM public.local_mfa_recovery_codes c WHERE subject='bob-subject'))::text").fetch_one(&mut f.admin).await.unwrap());
    let reset_password = input("robert", "bob-subject", "human", PASSWORD);
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::Update {
                username: "robert",
                user: &reset_password
            }
        )
        .await
        .unwrap()
        .0,
        204
    );
    let factor_after=Zeroizing::new(sqlx_core::query_scalar::query_scalar::<_,String>("SELECT jsonb_build_array((SELECT to_jsonb(m) FROM public.local_mfa m WHERE subject='bob-subject'),(SELECT jsonb_agg(to_jsonb(c)) FROM public.local_mfa_recovery_codes c WHERE subject='bob-subject'))::text").fetch_one(&mut f.admin).await.unwrap());
    assert!(factor_before == factor_after);
    let mut disabled = input("robert", "bob-subject", "human", "");
    disabled.enabled = Some(false);
    service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Update {
            username: "robert",
            user: &disabled,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::ResetMfa { username: "robert" }
        )
        .await
        .unwrap()
        .0,
        204
    );
    assert_eq!(scalar(&mut f.admin,"SELECT (SELECT count(*) FROM public.local_mfa WHERE subject='bob-subject')+(SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='bob-subject')").await,0);
    assert!(
        f.store
            .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
            .unwrap()
            .read(bob_cookie.secret(), deadline())
            .await
            .is_err()
    );
    service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Update {
            username: "robert",
            user: &input("robert", "bob-subject", "human", ""),
        },
    )
    .await
    .unwrap();
    let auth = f
        .store
        .local_auth_service(&f.digester, &f.protector, &f.required);
    let password = f
        .store
        .local_password_verifier(&f.engine)
        .verify("robert", PASSWORD, deadline())
        .await
        .unwrap();
    let change = pending(
        auth.begin(password, LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap(),
    );
    assert_eq!(change.stage(), LocalAuthStage::PasswordChange);
    let reenroll = pending(
        auth.complete_password_change(
            &f.engine,
            change.challenge(),
            LocalAuthBinding::AdminLogin,
            CHANGED,
            deadline(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(reenroll.stage(), LocalAuthStage::Enrollment);
    let rejected = pending(
        auth.complete_mfa(
            &limiter(),
            reenroll.challenge(),
            LocalAuthBinding::AdminLogin,
            &old_code,
            deadline(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(rejected.stage(), LocalAuthStage::Enrollment);
    assert!(rejected.challenge() == reenroll.challenge());
    assert_eq!(scalar(&mut f.admin, "SELECT (SELECT count(*) FROM public.local_mfa WHERE subject='bob-subject')+(SELECT count(*) FROM public.local_mfa_recovery_codes WHERE subject='bob-subject')").await, 0);

    let sdk = totp_rs::Totp::from_url(reenroll.enrollment().unwrap().otpauth_uri()).unwrap();
    let otp = Zeroizing::new(
        sdk.generate((cookie::micros() / 1_000_000) as u64)
            .to_string(),
    );
    let mut fresh = complete(
        auth.complete_mfa(
            &limiter(),
            reenroll.challenge(),
            LocalAuthBinding::AdminLogin,
            &otp,
            deadline(),
        )
        .await
        .unwrap(),
    );
    assert!(fresh.take_recovery_codes().is_some());
    // Native emitter -> real verifier; inventory never exposes a raw token or hash.
    let service = input("worker", "worker-subject", "service", "");
    service_action(&f, &operator_raw, AdminUsersRequest::Create(&service))
        .await
        .unwrap();
    let scopes = AdminServiceCredentialInput {
        client_id: " worker-client ".into(),
        scopes: vec![
            " z ".into(),
            "a".into(),
            "z".into(),
            " ".into(),
            "admin:session".into(),
        ],
        expires_in: 3600,
    };
    let delivered = service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::IssueCredential {
            username: "worker",
            input: &scopes,
        },
    )
    .await
    .unwrap();
    let value: Value = serde_json::from_slice(&delivered.1).unwrap();
    let raw = Zeroizing::new(value["token"].as_str().unwrap().to_owned());
    let id = value["id"].as_str().unwrap().to_owned();
    assert_eq!(value["scopes"], json!(["a", "admin:session", "z"]));
    drop(value);
    drop(delivered);
    f.store
        .local_bearer_verifier(AUDIENCE, n(8192))
        .unwrap()
        .verify(&raw, &["a".into(), "z".into()], deadline())
        .await
        .unwrap();
    assert!(
        f.store
            .local_bearer_verifier(AUDIENCE, n(8192))
            .unwrap()
            .verify(&raw, &["missing".into()], deadline())
            .await
            .is_err()
    );
    let inventory = service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Credentials { username: "worker" },
    )
    .await
    .unwrap();
    let text = std::str::from_utf8(&inventory.1).unwrap();
    assert!(
        !text.contains(raw.as_str())
            && !text.contains("token_hash")
            && !text.contains("principal_json")
    );
    // Reciprocal inventory reads coexist with real shared LOCAL row observations.
    let mut read_locks = f.fixture.connection().await;
    read_locks.execute("BEGIN; SELECT username FROM public.local_users WHERE username IN ('operator','worker') ORDER BY username FOR SHARE").await.unwrap();
    let (operator_reads_worker, worker_reads_operator) = tokio::join!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::Credentials { username: "worker" }
        ),
        service_action(
            &f,
            &raw,
            AdminUsersRequest::Credentials {
                username: "operator"
            }
        )
    );
    assert_eq!(operator_reads_worker.unwrap().0, 200);
    assert_eq!(worker_reads_operator.unwrap().0, 200);
    read_locks.execute("ROLLBACK").await.unwrap();
    read_locks.close().await.unwrap();
    for expires_in in [-1, 3599, 365 * 86400 + 1] {
        assert!(matches!(
            service_action(
                &f,
                &operator_raw,
                AdminUsersRequest::IssueCredential {
                    username: "worker",
                    input: &AdminServiceCredentialInput {
                        expires_in,
                        ..Default::default()
                    }
                }
            )
            .await,
            Err(Error::InvalidCredential)
        ));
    }
    let mut disabled_service = input("worker", "worker-subject", "service", "");
    disabled_service.enabled = Some(false);
    service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Update {
            username: "worker",
            user: &disabled_service,
        },
    )
    .await
    .unwrap();
    assert!(
        f.store
            .local_bearer_verifier(AUDIENCE, n(8192))
            .unwrap()
            .verify(&raw, &[], deadline())
            .await
            .is_err()
    );
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::Credentials { username: "worker" }
        )
        .await
        .unwrap()
        .0,
        200
    );
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::RevokeCredential {
                username: "worker",
                id: &id
            }
        )
        .await
        .unwrap_err(),
        Error::CredentialRevokeFailed
    ); // lifecycle already revoked it
    assert!(matches!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::IssueCredential {
                username: "worker",
                input: &scopes
            }
        )
        .await,
        Err(Error::CredentialCreateFailed)
    ));
    service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Update {
            username: "worker",
            user: &service,
        },
    )
    .await
    .unwrap();
    let delivered = service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::IssueCredential {
            username: "worker",
            input: &scopes,
        },
    )
    .await
    .unwrap();
    let value: Value = serde_json::from_slice(&delivered.1).unwrap();
    let fresh_raw = Zeroizing::new(value["token"].as_str().unwrap().to_owned());
    let id = value["id"].as_str().unwrap().to_owned();
    drop(value);
    drop(delivered);
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::RevokeCredential {
                username: "worker",
                id: &id
            }
        )
        .await
        .unwrap()
        .0,
        204
    );
    assert!(
        f.store
            .local_bearer_verifier(AUDIENCE, n(8192))
            .unwrap()
            .verify(&fresh_raw, &[], deadline())
            .await
            .is_err()
    );
    assert!(matches!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::RevokeCredential {
                username: "worker",
                id: &id
            }
        )
        .await,
        Err(Error::CredentialRevokeFailed)
    ));
    // Authorization SQL/target failure rolls back actual mutation and recovers.
    f.admin
        .execute("REVOKE INSERT ON public.role_assignments FROM admin_cookie_owner")
        .await
        .unwrap();
    let mut denied = input("rollback", "rollback-subject", "service", "");
    denied.roles = vec!["admin".into()];
    assert!(matches!(
        service_action(&f, &operator_raw, AdminUsersRequest::Create(&denied)).await,
        Err(Error::CreateFailed)
    ));
    assert_eq!(
        scalar(
            &mut f.admin,
            "SELECT count(*) FROM public.local_users WHERE username='rollback'"
        )
        .await,
        0
    );
    f.admin
        .execute("GRANT INSERT ON public.role_assignments TO admin_cookie_owner")
        .await
        .unwrap();
    // Initial UsersWrite is checked before KDF; final UsersWrite is observed again.
    let mut locker = f.fixture.connection().await;
    locker
        .execute(
            "BEGIN; SELECT username FROM public.local_users WHERE username='robert' FOR UPDATE",
        )
        .await
        .unwrap();
    let store = Arc::clone(&f.store);
    let engine = Arc::clone(&f.engine);
    let writer = store.admin_users(&engine, &limits).unwrap();
    let request = input("robert", "bob-subject", "human", PASSWORD);
    {
        let pending = writer.execute(
            AdminReadAuthentication::Cookie {
                raw: cookie.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminUsersRequest::Update {
                username: "robert",
                user: &request,
            },
            Some(&csrf),
            deadline(),
        );
        tokio::pin!(pending);
        tokio::select! {_ = blocked(&mut f.admin,"%password_hash%FOR UPDATE")=>{},result=&mut pending=>panic!("pre-KDF target observation must block: {:?}",result.err())};
        actions(&mut f, &[SystemAction::UsersRead]).await;
        locker.execute("ROLLBACK").await.unwrap();
        assert!(matches!(
            pending.await,
            Err(Error::Authorization(AdminBrokerSessionError::Forbidden))
        ));
    }
    locker.close().await.unwrap();
    actions(
        &mut f,
        &[
            SystemAction::UsersWrite,
            SystemAction::UsersRead,
            SystemAction::SessionRead,
        ],
    )
    .await;
    // A genuine federated cookie with the same literal subject belongs to another issuer.
    let mut remote = browser::BrowserIssuer::new().await;
    remote.fault(browser::Fault {
        id_overrides: [("preferred_username".into(), json!("alice-subject"))].into(),
        ..browser::Fault::default()
    });
    let remote_verifier = broker_control::UpstreamBearerVerifier::new(
        ISSUER,
        n(16384),
        vec![federated::provider(&remote)],
    )
    .unwrap();
    let remote_cookie = federated::issue(&f.store, &remote_verifier, &remote).await;
    // P3/P4 families and unfinished LOCAL flows cannot survive a lifecycle edit.
    let authorization = OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: "storage-api".into(),
            accepted_resources: vec!["https://broker.example/v1".into()],
            dynamic_registration: true,
            authorization_ttl: Duration::from_secs(60),
        },
        OidcAuthorizationLimits::new(n(8192), n(8192)).unwrap(),
    )
    .unwrap();
    let token_policy =
        OidcTokenExchangePolicy::new(Duration::from_secs(600), Duration::from_secs(30 * 86400))
            .unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let signer = BrokerAccessIssuer::new(
        ISSUER,
        "storage-api",
        "user-lifecycle",
        &key.serialize_der(),
    )
    .unwrap();
    let first = code(&f, &authorization, true).await;
    let first = f
        .store
        .oidc_token_exchange(&authorization, &token_policy, &signer)
        .unwrap()
        .exchange(exchange_input(first.code()), deadline())
        .await
        .unwrap();
    let second = code(&f, &authorization, true).await;
    let second = f
        .store
        .oidc_token_exchange(&authorization, &token_policy, &signer)
        .unwrap()
        .exchange(exchange_input(second.code()), deadline())
        .await
        .unwrap();
    let unfinished = code(&f, &authorization, false).await;
    let native = f
        .store
        .local_password_verifier(&f.engine)
        .verify("alice", cookie::PASSWORD, deadline())
        .await
        .unwrap();
    let auth = f
        .store
        .local_auth_service(&f.digester, &f.protector, &f.required);
    let unfinished_login = pending(
        auth.begin(native, LocalAuthBinding::AdminLogin, deadline())
            .await
            .unwrap(),
    );
    let update_alice = input("alice", "alice-subject", "human", "");
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT username FROM public.local_users WHERE username='alice' FOR UPDATE")
        .await
        .unwrap();
    let store = Arc::clone(&f.store);
    let engine = Arc::clone(&f.engine);
    let writer = store.admin_users(&engine, &limits).unwrap();
    let scopes = vec!["admin:session".to_owned()];
    let refresher = store
        .oidc_refresh(&authorization, &token_policy, &signer)
        .unwrap();
    {
        let edit = writer.execute(
            AdminReadAuthentication::Opaque {
                raw: &operator_raw,
                audience: AUDIENCE,
                identity_json_bytes: n(8192),
                required_scopes: &scopes,
            },
            AdminUsersRequest::Update {
                username: "alice",
                user: &update_alice,
            },
            None,
            deadline(),
        );
        let refresh = refresher.rotate(refresh_input(first.refresh_token().unwrap()), deadline());
        tokio::pin!(edit);
        tokio::pin!(refresh);
        let waiting = async {
            let end = deadline();
            loop {
                let locks:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock'").fetch_one(&mut f.admin).await.unwrap();
                if locks >= 2 {
                    break;
                }
                assert!(
                    Instant::now() < end,
                    "both real operations must reach the current-user lock"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {_ = waiting=>{},result=&mut edit=>panic!("edit must wait on current user: {:?}",result.err()),result=&mut refresh=>panic!("refresh must wait on current user: {:?}",result.err())};
        locker.execute("ROLLBACK").await.unwrap();
        let (edited, refreshed) = tokio::join!(edit, refresh);
        assert_eq!(observed(edited.unwrap()).unwrap().0, 204);
        if let Ok(refreshed) = refreshed {
            assert!(refreshed.refresh_token().is_some());
        }
    }
    locker.close().await.unwrap();
    assert_eq!(scalar(&mut f.admin,"SELECT count(*) FROM public.local_tokens WHERE subject='alice-subject' AND local_user_revision>=1 AND created_at>(SELECT updated_at FROM public.local_users WHERE subject='alice-subject')").await,0,"a refresh cannot issue after the identity revision changes");

    assert_eq!(scalar(&mut f.admin,"SELECT count(*) FROM public.local_tokens WHERE subject='alice-subject' AND local_user_revision>=1 AND revoked_at IS NULL").await,0);
    assert_eq!(
        scalar(
            &mut f.admin,
            "SELECT count(*) FROM public.oidc_auth_requests WHERE identity_subject='alice-subject'"
        )
        .await,
        0
    );
    assert!(
        auth.load(
            unfinished_login.challenge(),
            LocalAuthBinding::AdminLogin,
            deadline()
        )
        .await
        .is_err()
    );
    assert!(
        f.store
            .oidc_token_exchange(&authorization, &token_policy, &signer)
            .unwrap()
            .exchange(exchange_input(unfinished.code()), deadline())
            .await
            .is_err()
    );
    for token in [&first, &second] {
        assert!(
            f.store
                .oidc_refresh(&authorization, &token_policy, &signer)
                .unwrap()
                .rotate(refresh_input(token.refresh_token().unwrap()), deadline())
                .await
                .is_err()
        );
    }
    let verifier =
        BrokerAccessVerifier::new(ISSUER, "storage-api", None, signer.jwks(), n(8192)).unwrap();
    let proof = verifier
        .verify(first.access_token(), &[], deadline())
        .unwrap(); // JWT remains cryptographically valid until exp
    assert_eq!(
        f.store
            .admin_users(&f.engine, &limits)
            .unwrap()
            .execute(
                AdminReadAuthentication::Broker {
                    verifier: &verifier,
                    proof
                },
                AdminUsersRequest::Credentials {
                    username: "operator"
                },
                None,
                deadline()
            )
            .await
            .and_then(observed)
            .unwrap()
            .0,
        200
    );
    assert!(
        f.store
            .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
            .unwrap()
            .read(cookie.secret(), deadline())
            .await
            .is_err()
    );
    // Delete/recreate removes old LOCAL credentials and cookies rather than reviving them.
    service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Delete { username: "alice" },
    )
    .await
    .unwrap();
    assert_eq!(scalar(&mut f.admin,"SELECT count(*) FROM public.local_tokens WHERE subject='alice-subject' AND local_user_revision>=1").await,0);
    assert_eq!(scalar(&mut f.admin,"SELECT count(*) FROM public.admin_sessions s JOIN public.admin_session_principals p USING(token_hash) WHERE subject='alice-subject' AND issuer='local'").await,0);
    let proof = verifier
        .verify(first.access_token(), &[], deadline())
        .unwrap();
    assert!(matches!(
        f.store
            .admin_users(&f.engine, &limits)
            .unwrap()
            .execute(
                AdminReadAuthentication::Broker {
                    verifier: &verifier,
                    proof
                },
                AdminUsersRequest::Credentials {
                    username: "operator"
                },
                None,
                deadline()
            )
            .await,
        Err(Error::Authorization(AdminBrokerSessionError::Forbidden))
    ));
    service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Create(&input("alice", "alice-subject", "human", cookie::PASSWORD)),
    )
    .await
    .unwrap();
    assert!(
        f.store
            .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
            .unwrap()
            .read(cookie.secret(), deadline())
            .await
            .is_err()
    );
    assert!(
        f.store
            .oidc_refresh(&authorization, &token_policy, &signer)
            .unwrap()
            .rotate(refresh_input(first.refresh_token().unwrap()), deadline())
            .await
            .is_err()
    );
    f.store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), Some(&remote_verifier))
        .unwrap()
        .read(remote_cookie.secret(), deadline())
        .await
        .unwrap();
    // Original/cancellation closes the actual blocked connection and leaves no user.
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    let scopes = vec!["admin:session".into()];
    let request = input("cancelled", "cancelled-subject", "service", "");
    let pid;
    {
        let pending = writer.execute(
            AdminReadAuthentication::Opaque {
                raw: &operator_raw,
                audience: AUDIENCE,
                identity_json_bytes: n(8192),
                required_scopes: &scopes,
            },
            AdminUsersRequest::Create(&request),
            None,
            deadline(),
        );
        tokio::pin!(pending);
        pid = tokio::select! {pid=blocked(&mut f.admin,"SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")=>pid,result=&mut pending=>panic!("must block at parent before cancellation: {:?}",result.err())};
    }
    closed(&mut f.admin, pid).await;
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert_eq!(
        scalar(
            &mut f.admin,
            "SELECT count(*) FROM public.local_users WHERE username='cancelled'"
        )
        .await,
        0
    );
    // Withhold a successful emission's actual COMMIT reply: never return its raw secret.
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let owner = PostgresControlStore::open(
        cookie::config(&f.fixture, relay.port),
        cookie::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let writer = owner.admin_users(&f.engine, &limits).unwrap();
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    let issue = AdminServiceCredentialInput {
        client_id: "unknown-commit".into(),
        expires_in: 3600,
        ..Default::default()
    };
    {
        let pending = writer.execute(
            AdminReadAuthentication::Opaque {
                raw: &operator_raw,
                audience: AUDIENCE,
                identity_json_bytes: n(8192),
                required_scopes: &scopes,
            },
            AdminUsersRequest::IssueCredential {
                username: "worker",
                input: &issue,
            },
            None,
            Instant::now() + Duration::from_secs(3),
        );
        tokio::pin!(pending);
        let pid = tokio::select! {pid=blocked(&mut f.admin,"SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")=>pid,result=&mut pending=>panic!("must block before COMMIT relay: {:?}",result.err())};
        relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        locker.execute("ROLLBACK").await.unwrap();
        loop {
            let decision = tokio::select! {decision=relay.replies.recv()=>decision.unwrap(),result=&mut pending=>panic!("COMMIT reply must be controlled: {:?}",result.err())};
            let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
                "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(pid)
            .fetch_one(&mut f.admin)
            .await
            .unwrap();
            let visible=scalar(&mut f.admin,"SELECT count(*) FROM public.local_tokens WHERE client_id='unknown-commit' AND token_kind='service'").await;
            if query == "COMMIT" && idle && visible == 1 {
                decision.send(false).unwrap();
                break;
            }
            decision.send(true).unwrap();
        }
        assert!(matches!(
            pending.await,
            Err(Error::Authorization(AdminBrokerSessionError::Control(
                ControlError::OutcomeUncertain
            )))
        ));
    }
    locker.close().await.unwrap();
    relay.close().await;
    owner.shutdown(deadline()).await.unwrap();
    assert_eq!(scalar(&mut f.admin,"SELECT count(*) FROM public.local_tokens WHERE client_id='unknown-commit' AND token_kind='service'").await,1);
    assert_eq!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::Credentials { username: "worker" }
        )
        .await
        .unwrap()
        .0,
        200
    );
    // Participating concurrent disables preserve one eligible explicit administrator.
    actions(&mut f, &[SystemAction::UsersWrite, SystemAction::UsersRead]).await;
    for name in ["last-a", "last-b"] {
        let mut user = input(name, &format!("{name}-subject"), "service", "");
        user.roles = vec!["admin".into()];
        service_action(&f, &operator_raw, AdminUsersRequest::Create(&user))
            .await
            .unwrap();
    }
    f.admin.execute("DELETE FROM public.role_assignments WHERE subject='local|operator-subject' AND role='admin'").await.unwrap();
    let mut a = input("last-a", "last-a-subject", "service", "");
    a.enabled = Some(false);
    a.roles = vec!["admin".into()];
    let mut b = input("last-b", "last-b-subject", "service", "");
    b.enabled = Some(false);
    b.roles = vec!["admin".into()];
    let first = service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Update {
            username: "last-a",
            user: &a,
        },
    );
    let second = service_action(
        &f,
        &operator_raw,
        AdminUsersRequest::Update {
            username: "last-b",
            user: &b,
        },
    );
    let (first, second) = tokio::join!(first, second);
    assert!(matches!(
        (&first, &second),
        (Ok(_), Err(Error::UpdateFailed)) | (Err(Error::UpdateFailed), Ok(_))
    ));
    assert_eq!(scalar(&mut f.admin,"SELECT count(*) FROM public.local_users u JOIN public.role_assignments a ON a.subject='local|'||u.subject WHERE a.role='admin' AND u.enabled=1").await,1);
    let last:String=sqlx_core::query_scalar::query_scalar("SELECT u.username FROM public.local_users u JOIN public.role_assignments a ON a.subject='local|'||u.subject WHERE a.role='admin' AND u.enabled=1").fetch_one(&mut f.admin).await.unwrap();
    assert!(matches!(
        service_action(
            &f,
            &operator_raw,
            AdminUsersRequest::Delete { username: &last }
        )
        .await,
        Err(Error::DeleteFailed)
    ));
    // Current actor denial precedes even an unavailable KDF owner.
    f.engine.close().await;
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='admin' AND action='*';DELETE FROM public.role_permissions WHERE role='user'").await.unwrap();
    let denied = input("no-hash", "no-hash-subject", "human", PASSWORD);
    assert!(matches!(
        service_action(&f, &operator_raw, AdminUsersRequest::Create(&denied)).await,
        Err(Error::Authorization(AdminBrokerSessionError::Forbidden))
    ));
    remote.close().await;
    f.close().await;
}
