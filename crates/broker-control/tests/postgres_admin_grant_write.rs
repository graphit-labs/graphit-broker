//! Grant CRUD against owned PostgreSQL TLS and a genuine LOCAL administrative cookie.
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "shared genuine password/MFA fixture serves other contracts"
)]
mod cookie;
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture serves other contracts"
)]
mod support;

use broker_control::{
    AdminBrokerSessionError, AdminGrantError, AdminGrantInput, AdminGrantRequest, AdminGrantRoutes,
    AdminReadAuthentication, AdminReadLimits, ControlError, PostgresControlStore,
    parse_grant_if_match,
};
use cookie::CookieFixture;
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use std::time::{Duration, Instant};
use support::{deadline, n};

const PROJECT: &str = "01M1YEAE1WYMWG9KJKV1XQC4T4";

fn limits() -> AdminReadLimits {
    AdminReadLimits {
        authorization: cookie::limits().authorization,
        grants_json_bytes: n(65536),
        response_json_bytes: n(65536),
    }
}
fn routes() -> AdminGrantRoutes {
    AdminGrantRoutes::new(["primary".to_owned()], "primary".to_owned()).unwrap()
}
fn authentication(raw: &str) -> AdminReadAuthentication<'_, '_> {
    AdminReadAuthentication::Cookie {
        raw,
        limits: cookie::limits(),
        policy: cookie::policy(),
        upstream: None,
    }
}
fn grant(id: &str) -> AdminGrantInput {
    AdminGrantInput {
        id: id.to_owned(),
        name: " Example ".to_owned(),
        access: " ORGANIZATION ".to_owned(),
        principal: " org* ".to_owned(),
        capabilities: vec![" s3 ".to_owned(), "hub".to_owned(), "hub".to_owned()],
        projects: vec![PROJECT.to_owned(), " * ".to_owned(), PROJECT.to_owned()],
        s3_operations: vec![" write ".to_owned(), "read".to_owned(), "read".to_owned()],
        s3_prefixes: vec![
            " v1/projects/{project}/registry ".to_owned(),
            "v1/projects/{project}/hub".to_owned(),
            "v1/projects/{project}/hub".to_owned(),
        ],
        s3_route: " primary ".to_owned(),
    }
}
async fn write(
    store: &PostgresControlStore,
    raw: &str,
    request: AdminGrantRequest<'_>,
    expected: u64,
    csrf: Option<&str>,
    original: Instant,
) -> Result<Value, AdminGrantError> {
    let routes = routes();
    let result = store
        .admin_grants(limits(), &routes)
        .unwrap()
        .write(authentication(raw), request, expected, csrf, original)
        .await?;
    result.check()?;
    let document: Value = serde_json::from_slice(result.body()).unwrap();
    assert_eq!(document["v"], 1);
    assert_eq!(document["revision"].as_i64(), Some(result.revision()));
    assert!(result.revision() > 0);
    assert!(document["updated_at"].as_str().unwrap().ends_with('Z'));
    assert!(document["rules"].is_array());
    result.check()?;
    Ok(document)
}
async fn revision(f: &mut CookieFixture) -> u64 {
    u64::try_from(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT revision FROM public.resource_acl_state WHERE id=1",
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap(),
    )
    .unwrap()
}
async fn exists(f: &mut CookieFixture, id: &str) -> bool {
    sqlx_core::query_scalar::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM public.resource_grants WHERE id=$1)",
    )
    .bind(id)
    .fetch_one(&mut f.admin)
    .await
    .unwrap()
}
async fn children(f: &mut CookieFixture, id: &str) -> Vec<(String, String)> {
    sqlx_core::query_as::query_as(
        "SELECT 'capability',value FROM public.grant_capabilities WHERE grant_id=$1
         UNION ALL SELECT 'project',value FROM public.grant_projects WHERE grant_id=$1
         UNION ALL SELECT 'operation',value FROM public.grant_s3_operations WHERE grant_id=$1
         UNION ALL SELECT 'prefix',value FROM public.grant_s3_prefixes WHERE grant_id=$1
         ORDER BY 1,2",
    )
    .bind(id)
    .fetch_all(&mut f.admin)
    .await
    .unwrap()
}
async fn blocked_pid(connection: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock' AND query=$1 LIMIT 1")
            .bind("SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
            .fetch_optional(&mut *connection).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "writer must reach the actual parent lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned Docker PostgreSQL TLS NOSUPERUSER"]
async fn postgres_admin_grant_write_contract() {
    let mut f = CookieFixture::new().await;
    let issued = f.cookie().await;
    let csrf = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .read(issued.secret(), deadline())
        .await
        .unwrap()
        .csrf_token()
        .to_owned();
    let expiring = f.cookie().await;
    let expiring_csrf = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .read(expiring.secret(), deadline())
        .await
        .unwrap()
        .csrf_token()
        .to_owned();
    let short = f.cookie().await;
    let initial = revision(&mut f).await;
    let input = grant(" grant-main ");
    assert!(matches!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&input),
            initial,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','roles.write')").await.unwrap();
    assert!(matches!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&input),
            initial,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','grants.write')").await.unwrap();
    assert!(matches!(
        f.store
            .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
            .unwrap()
            .read(issued.secret(), deadline())
            .await,
        Err(broker_control::AdminCookieSessionError::Forbidden)
    ));
    for supplied in [None, Some("bad-csrf")] {
        assert_eq!(
            write(
                &f.store,
                issued.secret(),
                AdminGrantRequest::Create(&input),
                initial,
                supplied,
                deadline()
            )
            .await,
            Err(AdminGrantError::CsrfFailed)
        );
    }
    for value in [
        None,
        Some("0"),
        Some("-1"),
        Some("\"1"),
        Some("18446744073709551616"),
    ] {
        assert_eq!(
            parse_grant_if_match(value),
            Err(AdminGrantError::PreconditionRequired)
        );
    }
    for value in ["1", "\"1\"", "W/\"1\""] {
        assert_eq!(parse_grant_if_match(Some(value)), Ok(1));
    }
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&input),
            0,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::PreconditionRequired)
    );
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&input),
            u64::MAX,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::RevisionConflict)
    );
    assert_eq!(revision(&mut f).await, initial);
    assert!(!exists(&mut f, "grant-main").await);

    let created = write(
        &f.store,
        issued.secret(),
        AdminGrantRequest::Create(&input),
        initial,
        Some(&csrf),
        deadline(),
    )
    .await
    .unwrap();
    let rule = created["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == "grant-main")
        .unwrap();
    assert_eq!(rule["name"], "Example");
    assert_eq!(rule["access"], "organization");
    assert_eq!(rule["principal"], "org*");
    assert_eq!(rule["s3_route"], "primary");
    assert_eq!(rule["capabilities"], json!(["hub", "s3"]));
    assert_eq!(
        children(&mut f, "grant-main").await,
        vec![
            ("capability".into(), "hub".into()),
            ("capability".into(), "s3".into()),
            ("operation".into(), "read".into()),
            ("operation".into(), "write".into()),
            ("prefix".into(), "v1/projects/{project}/hub".into()),
            ("prefix".into(), "v1/projects/{project}/registry".into()),
            ("project".into(), "*".into()),
            ("project".into(), PROJECT.into()),
        ]
    );
    let current = revision(&mut f).await;
    assert_eq!(current, initial + 1);
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&input),
            current,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::WriteFailed)
    );
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Delete { id: "absent" },
            current,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::WriteFailed)
    );
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Update {
                id: "absent",
                grant: &input
            },
            current,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::WriteFailed)
    );
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Delete { id: "grant-main" },
            initial,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::RevisionConflict)
    );

    let mut replacement = grant("body-id-is-ignored");
    replacement.name = "Replacement".into();
    replacement.capabilities = vec!["hub:read".into()];
    replacement.projects = vec![PROJECT.into()];
    replacement.s3_operations.clear();
    replacement.s3_prefixes.clear();
    replacement.s3_route.clear();
    write(
        &f.store,
        issued.secret(),
        AdminGrantRequest::Update {
            id: " grant-main ",
            grant: &replacement,
        },
        current,
        Some(&csrf),
        deadline(),
    )
    .await
    .unwrap();
    assert!(!exists(&mut f, "body-id-is-ignored").await);
    assert_eq!(
        children(&mut f, "grant-main").await,
        vec![
            ("capability".into(), "hub:read".into()),
            ("project".into(), PROJECT.into())
        ]
    );

    // Invalid policy input must not leave a parent, children, or a bumped revision.
    for case in 0..9 {
        let mut invalid = grant("invalid-grant");
        match case {
            0 => invalid.id = "bad id".into(),
            1 => invalid.principal.clear(),
            2 => invalid.access = "global".into(),
            3 => invalid.capabilities = vec!["[".into()],
            4 => invalid.projects = vec!["main".into()],
            5 => invalid.s3_route = "missing".into(),
            6 => invalid.s3_prefixes = vec!["../secret".into()],
            7 => invalid.capabilities.clear(),
            8 => invalid.name = " \n ".into(),
            _ => unreachable!(),
        }
        let current = revision(&mut f).await;
        assert_eq!(
            write(
                &f.store,
                issued.secret(),
                AdminGrantRequest::Create(&invalid),
                current,
                Some(&csrf),
                deadline()
            )
            .await,
            Err(AdminGrantError::InvalidGrant),
            "case {case}"
        );
        assert_eq!(revision(&mut f).await, current);
        assert!(!exists(&mut f, "invalid-grant").await);
        assert!(children(&mut f, "invalid-grant").await.is_empty());
    }
    let no_default = AdminGrantRoutes::new(["primary".to_owned()], String::new()).unwrap();
    let mut no_route = grant("no-route");
    no_route.s3_route.clear();
    let current = revision(&mut f).await;
    assert!(matches!(
        f.store
            .admin_grants(limits(), &no_default)
            .unwrap()
            .write(
                authentication(issued.secret()),
                AdminGrantRequest::Create(&no_route),
                current,
                Some(&csrf),
                deadline()
            )
            .await,
        Err(AdminGrantError::InvalidGrant)
    ));
    assert_eq!(revision(&mut f).await, current);

    let left = grant("concurrent-left");
    let right = grant("concurrent-right");
    let (a, b) = tokio::join!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&left),
            current,
            Some(&csrf),
            deadline()
        ),
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&right),
            current,
            Some(&csrf),
            deadline()
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(
        a == Err(AdminGrantError::RevisionConflict) || b == Err(AdminGrantError::RevisionConflict)
    );
    assert_eq!(revision(&mut f).await, current + 1);
    assert_ne!(
        exists(&mut f, "concurrent-left").await,
        exists(&mut f, "concurrent-right").await
    );

    let rollback = grant("rollback-grant");
    let current = revision(&mut f).await;
    f.admin
        .execute("REVOKE INSERT ON public.grant_s3_prefixes FROM admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Create(&rollback),
            current,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::WriteFailed)
    );
    f.admin
        .execute("GRANT INSERT ON public.grant_s3_prefixes TO admin_cookie_owner")
        .await
        .unwrap();
    assert!(!exists(&mut f, "rollback-grant").await);
    assert!(children(&mut f, "rollback-grant").await.is_empty());
    assert_eq!(revision(&mut f).await, current);
    let old_children = children(&mut f, "grant-main").await;
    f.admin
        .execute("REVOKE INSERT ON public.grant_s3_prefixes FROM admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Update {
                id: "grant-main",
                grant: &rollback
            },
            current,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::WriteFailed)
    );
    f.admin
        .execute("GRANT INSERT ON public.grant_s3_prefixes TO admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(children(&mut f, "grant-main").await, old_children);
    assert_eq!(revision(&mut f).await, current);
    write(
        &f.store,
        issued.secret(),
        AdminGrantRequest::Create(&rollback),
        current,
        Some(&csrf),
        deadline(),
    )
    .await
    .unwrap();
    let current = revision(&mut f).await;
    write(
        &f.store,
        issued.secret(),
        AdminGrantRequest::Delete {
            id: "rollback-grant",
        },
        current,
        Some(&csrf),
        deadline(),
    )
    .await
    .unwrap();
    assert!(!exists(&mut f, "rollback-grant").await);
    assert!(
        children(&mut f, "rollback-grant").await.is_empty(),
        "actual FK cascade removes all four child sets"
    );

    // Overflow is an error before mutation, never a signed cast or wraparound.
    let current = revision(&mut f).await;
    f.admin
        .execute("UPDATE public.resource_acl_state SET revision=9223372036854775807 WHERE id=1")
        .await
        .unwrap();
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Delete { id: "grant-main" },
            i64::MAX as u64,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::WriteFailed)
    );
    assert!(exists(&mut f, "grant-main").await);
    assert_eq!(revision(&mut f).await, i64::MAX as u64);
    sqlx_core::query::query("UPDATE public.resource_acl_state SET revision=$1 WHERE id=1")
        .bind(i64::try_from(current).unwrap())
        .execute(&mut f.admin)
        .await
        .unwrap();

    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    assert_eq!(
        write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Delete { id: "grant-main" },
            current,
            Some(&csrf),
            Instant::now() + Duration::from_millis(200)
        )
        .await,
        Err(AdminGrantError::Authorization(
            AdminBrokerSessionError::Control(ControlError::Deadline)
        ))
    );
    locker.execute("ROLLBACK").await.unwrap();
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    {
        let pending = write(
            &f.store,
            issued.secret(),
            AdminGrantRequest::Delete { id: "grant-main" },
            current,
            Some(&csrf),
            deadline(),
        );
        tokio::pin!(pending);
        tokio::select! { _ = blocked_pid(&mut f.admin) => (), result = &mut pending => panic!("must reach lock before cancellation: {result:?}") };
    }
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert!(exists(&mut f, "grant-main").await);
    assert_eq!(revision(&mut f).await, current);
    let hash = f
        .digester
        .token(
            broker_security::TokenKind::AdminSession,
            short.secret().as_bytes(),
        )
        .unwrap();
    sqlx_core::query::query("UPDATE public.admin_sessions SET expires_at=$1 WHERE token_hash=$2")
        .bind(cookie::micros() - 1)
        .bind(hash.to_sql_hex())
        .execute(&mut f.admin)
        .await
        .unwrap();
    assert!(matches!(
        write(
            &f.store,
            short.secret(),
            AdminGrantRequest::Delete { id: "grant-main" },
            current,
            Some(&csrf),
            deadline()
        )
        .await,
        Err(AdminGrantError::Authorization(
            AdminBrokerSessionError::Authentication(_)
        ))
    ));
    assert_eq!(revision(&mut f).await, current);

    // A real relay separates confirmed writes, missing COMMIT replies and failed DATA reads.
    for (id, withhold_read, fail_read, advance_read) in [
        ("uncertain-write", false, false, false),
        ("uncertain-read", true, false, false),
        ("committed-read-failed", false, true, false),
        ("committed-read-current", false, false, true),
    ] {
        let mut relay = commit::CommitRelay::new(f.fixture.port).await;
        let owner = PostgresControlStore::open(
            cookie::config(&f.fixture, relay.port),
            cookie::digester(),
            deadline(),
        )
        .await
        .unwrap();
        // Opening a store restores the official built-in role bundles. This
        // fixture intentionally grants only grants.write for the tested actor.
        f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','grants.write')").await.unwrap();
        let mut locker = f.fixture.connection().await;
        locker
            .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
            .await
            .unwrap();
        let input = grant(id);
        let current = revision(&mut f).await;
        {
            let pending = write(
                &owner,
                issued.secret(),
                AdminGrantRequest::Create(&input),
                current,
                Some(&csrf),
                Instant::now() + Duration::from_secs(3),
            );
            tokio::pin!(pending);
            tokio::select! { _ = blocked_pid(&mut f.admin) => (), result = &mut pending => panic!("must reach lock before relay: {result:?}") };
            relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            locker.execute("ROLLBACK").await.unwrap();
            let mut read_started = false;
            loop {
                let decision = tokio::select! { decision = relay.replies.recv() => decision.unwrap(), result = &mut pending => panic!("COMMIT response must be controlled: {result:?}") };
                let (query, idle): (String, bool) = sqlx_core::query_as::query_as("SELECT query,state='idle' FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' ORDER BY query_start DESC LIMIT 1")
                    .fetch_one(&mut f.admin).await.unwrap();
                read_started |= query == "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY";
                if query == "COMMIT" && idle && (!withhold_read || read_started) {
                    assert!(exists(&mut f, id).await);
                    if advance_read {
                        let later = grant("committed-read-current-later");
                        write(
                            &f.store,
                            issued.secret(),
                            AdminGrantRequest::Create(&later),
                            current + 1,
                            Some(&csrf),
                            deadline(),
                        )
                        .await
                        .unwrap();
                        relay
                            .armed
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        decision.send(true).unwrap();
                    } else if fail_read {
                        // The mutation has committed, but its reply is still held. Deny only
                        // the subsequent DATA read, then deliver the successful write ACK.
                        f.admin
                            .execute(
                                "REVOKE SELECT ON public.resource_grants FROM admin_cookie_owner",
                            )
                            .await
                            .unwrap();
                        relay
                            .armed
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        decision.send(true).unwrap();
                    } else {
                        decision.send(false).unwrap();
                    }
                    break;
                }
                decision.send(true).unwrap();
            }
            let outcome = pending.await;
            if advance_read {
                let document = outcome.unwrap();
                assert_eq!(document["revision"], current + 2);
                assert!(
                    document["rules"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|rule| rule["id"] == "committed-read-current-later")
                );
            } else {
                assert_eq!(
                    outcome,
                    Err(if fail_read {
                        AdminGrantError::ReadFailed
                    } else {
                        AdminGrantError::Authorization(AdminBrokerSessionError::Control(
                            ControlError::OutcomeUncertain,
                        ))
                    })
                );
            }
        }
        if fail_read {
            f.admin
                .execute("GRANT SELECT ON public.resource_grants TO admin_cookie_owner")
                .await
                .unwrap();
            // Recover with a fresh DATA read, without replaying the committed mutation.
            let fresh = owner
                .resource_grants(n(65536))
                .unwrap()
                .read(deadline())
                .await
                .unwrap();
            assert_eq!(u64::try_from(fresh.revision()).unwrap(), current + 1);
        }
        locker.close().await.unwrap();
        relay.close().await;
        owner.shutdown(deadline()).await.unwrap();
        assert!(
            exists(&mut f, id).await,
            "committed data must not be represented as rolled back"
        );
        assert_eq!(
            revision(&mut f).await,
            current + if advance_read { 2 } else { 1 }
        );
    }
    // Expiry also stops the fresh DATA read after a confirmed write. Hold only
    // its BEGIN reply: no COMMIT is uncertain and no mutation is retried.
    {
        let csrf = expiring_csrf.as_str();
        let hash = f
            .digester
            .token(
                broker_security::TokenKind::AdminSession,
                expiring.secret().as_bytes(),
            )
            .unwrap();
        let mut relay = commit::CommitRelay::new(f.fixture.port).await;
        let owner = PostgresControlStore::open(
            cookie::config(&f.fixture, relay.port),
            cookie::digester(),
            deadline(),
        )
        .await
        .unwrap();
        // Opening a store restores the official built-in role bundles. This
        // fixture intentionally grants only grants.write for the tested actor.
        f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','grants.write')").await.unwrap();
        let mut locker = f.fixture.connection().await;
        locker
            .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
            .await
            .unwrap();
        let expires = cookie::micros() + 3_000_000;
        sqlx_core::query::query(
            "UPDATE public.admin_sessions SET expires_at=$1 WHERE token_hash=$2",
        )
        .bind(expires)
        .bind(hash.to_sql_hex())
        .execute(&mut f.admin)
        .await
        .unwrap();
        let current = revision(&mut f).await;
        let input = grant("committed-read-expired");
        {
            let pending = write(
                &owner,
                expiring.secret(),
                AdminGrantRequest::Create(&input),
                current,
                Some(csrf),
                Instant::now() + Duration::from_secs(8),
            );
            tokio::pin!(pending);
            tokio::select! { _ = blocked_pid(&mut f.admin) => (), result = &mut pending => panic!("must reach writer lock: {result:?}") };
            relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            locker.execute("ROLLBACK").await.unwrap();
            let held_read = loop {
                let decision = tokio::select! { decision = relay.replies.recv() => decision.unwrap(), result = &mut pending => panic!("must reach fresh DATA read: {result:?}") };
                let query: String = sqlx_core::query_scalar::query_scalar("SELECT query FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' ORDER BY query_start DESC LIMIT 1")
                    .fetch_one(&mut f.admin).await.unwrap();
                if query == "BEGIN ISOLATION LEVEL READ COMMITTED READ ONLY" {
                    assert!(exists(&mut f, "committed-read-expired").await);
                    assert!(
                        cookie::micros() < expires,
                        "DATA read must start before factor expiry"
                    );
                    break decision;
                }
                decision.send(true).unwrap();
            };
            let outcome = tokio::time::timeout(Duration::from_secs(4), &mut pending)
                .await
                .expect("factor expiry must stop the DATA read before the longer Original");
            assert!(matches!(
                outcome,
                Err(AdminGrantError::Authorization(
                    AdminBrokerSessionError::Authentication(_)
                ))
            ));
            drop(held_read);
        }
        assert!(exists(&mut f, "committed-read-expired").await);
        assert_eq!(revision(&mut f).await, current + 1);
        locker.close().await.unwrap();
        relay.close().await;
        owner.shutdown(deadline()).await.unwrap();
    }
    f.close().await;
}
