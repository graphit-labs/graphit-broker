//! Real PostgreSQL, current authorization and genuine LOCAL administrative cookies.
#[path = "../../broker-server/tests/support/upstream_commit.rs"]
mod commit;
#[path = "support/admin_cookie.rs"]
#[allow(
    dead_code,
    reason = "genuine shared password/MFA fixture also serves other contracts"
)]
mod cookie;
#[allow(
    dead_code,
    reason = "shared owned PostgreSQL fixture includes other contract helpers"
)]
mod support;
use broker_control::{
    AdminBrokerSessionError, AdminRbacError, AdminRbacRequest, AdminReadAuthentication,
    ControlError, PostgresControlStore, SystemAction,
};
use cookie::CookieFixture;
use sqlx_core::{connection::Connection, executor::Executor};
use std::time::{Duration, Instant};
use support::deadline;

async fn write(
    f: &CookieFixture,
    raw: &str,
    command: AdminRbacRequest<'_>,
    csrf: Option<&str>,
) -> Result<(), AdminRbacError> {
    f.store
        .admin_rbac(cookie::limits().authorization)
        .unwrap()
        .write(
            AdminReadAuthentication::Cookie {
                raw,
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            command,
            csrf,
            deadline(),
        )
        .await
        .and_then(|result| result.check())
}
async fn roles_write(f: &mut CookieFixture) {
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','roles.write')").await.unwrap();
}
async fn exists(f: &mut CookieFixture, role: &str) -> bool {
    sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.roles WHERE name=$1)")
        .bind(role)
        .fetch_one(&mut f.admin)
        .await
        .unwrap()
}
async fn assignment_count(f: &mut CookieFixture, subject: &str, role: &str) -> i64 {
    sqlx_core::query_scalar::query_scalar(
        "SELECT count(*) FROM public.role_assignments WHERE subject=$1 AND role=$2",
    )
    .bind(subject)
    .bind(role)
    .fetch_one(&mut f.admin)
    .await
    .unwrap()
}
async fn blocked_pid(connection: &mut sqlx_postgres::PgConnection) -> i32 {
    let end = deadline();
    loop {
        let pid = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name='graphit-broker-rust-control' AND wait_event_type='Lock' AND query=$1 LIMIT 1")
            .bind("SELECT name FROM public.roles WHERE name='admin' FOR UPDATE").fetch_optional(&mut *connection).await.unwrap();
        if let Some(pid) = pid {
            return pid;
        }
        assert!(
            Instant::now() < end,
            "write must reach the actual admin parent lock"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn closed_pid(connection: &mut sqlx_postgres::PgConnection, pid: i32) {
    let end = deadline();
    loop {
        let present: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        if !present {
            return;
        }
        assert!(Instant::now() < end, "unconfirmed connection must close");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires owned Docker PostgreSQL TLS NOSUPERUSER"]
async fn postgres_admin_rbac_write_contract() {
    let mut f = CookieFixture::new().await;
    let issued = f.cookie().await;
    let csrf = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .read(issued.secret(), deadline())
        .await
        .unwrap();
    let csrf = csrf.csrf_token().to_owned();
    let short = f.cookie().await;
    let short_csrf = f
        .store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
        .unwrap()
        .read(short.secret(), deadline())
        .await
        .unwrap();
    let short_csrf = short_csrf.csrf_token().to_owned();
    let permissions = vec![
        "configuration.read".to_owned(),
        "*".to_owned(),
        "*".to_owned(),
    ];
    assert!(matches!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::SetRole {
                name: "auditor",
                permissions: &permissions
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    roles_write(&mut f).await;
    assert!(matches!(
        f.store
            .admin_cookie_sessions(cookie::limits(), cookie::policy(), None)
            .unwrap()
            .read(issued.secret(), deadline())
            .await,
        Err(broker_control::AdminCookieSessionError::Forbidden)
    ));
    for token in [None, Some("bad-csrf")] {
        assert_eq!(
            write(
                &f,
                issued.secret(),
                AdminRbacRequest::SetRole {
                    name: "auditor",
                    permissions: &permissions
                },
                token
            )
            .await,
            Err(AdminRbacError::CsrfFailed)
        );
        assert!(!exists(&mut f, "auditor").await);
    }
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::SetRole {
            name: " auditor ",
            permissions: &permissions,
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    let actions: Vec<String> = sqlx_core::query_scalar::query_scalar(
        "SELECT action FROM public.role_permissions WHERE role='auditor' ORDER BY action",
    )
    .fetch_all(&mut f.admin)
    .await
    .unwrap();
    assert_eq!(actions, ["*", "configuration.read"]);
    let created: i64 = sqlx_core::query_scalar::query_scalar(
        "SELECT created_at FROM public.roles WHERE name='auditor'",
    )
    .fetch_one(&mut f.admin)
    .await
    .unwrap();
    let replacement = vec!["roles.read".to_owned()];
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::SetRole {
            name: "auditor",
            permissions: &replacement,
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT created_at FROM public.roles WHERE name='auditor'"
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap(),
        created
    );
    for (name, values) in [
        ("admin", &permissions[..]),
        ("user", &permissions[..]),
        ("empty", &[][..]),
        ("invalid name", &permissions[..]),
    ] {
        assert_eq!(
            write(
                &f,
                issued.secret(),
                AdminRbacRequest::SetRole {
                    name,
                    permissions: values
                },
                Some(&csrf)
            )
            .await,
            Err(AdminRbacError::InvalidRole)
        );
    }
    assert_eq!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::SetRole {
                name: "unknown",
                permissions: &["unknown.action".into()]
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::InvalidRole)
    );
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::SetRole {
            name: "Admin",
            permissions: &replacement,
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::DeleteRole { name: "Admin" },
        Some(&csrf),
    )
    .await
    .unwrap();
    let unicode = "😀".repeat(512);
    for _ in 0..2 {
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::Assign {
                subject: &unicode,
                role: "auditor",
            },
            Some(&csrf),
        )
        .await
        .unwrap();
    }
    assert_eq!(assignment_count(&mut f, &unicode, "auditor").await, 1);
    let oversized = "😀".repeat(513);
    for subject in ["\0", "a\nb", oversized.as_str()] {
        assert_eq!(
            write(
                &f,
                issued.secret(),
                AdminRbacRequest::Assign {
                    subject,
                    role: "auditor"
                },
                Some(&csrf)
            )
            .await,
            Err(AdminRbacError::AssignmentFailed)
        );
    }
    assert_eq!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::Assign {
                subject: "external",
                role: "absent"
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::AssignmentFailed)
    );
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::Revoke {
            subject: "absent",
            role: "auditor",
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::DeleteRole { name: "auditor" },
        Some(&csrf),
    )
    .await
    .unwrap();
    assert_eq!(
        assignment_count(&mut f, &unicode, "auditor").await,
        0,
        "foreign-key cascade is the actual removal mechanism"
    );
    for name in ["admin", "user", "absent", "invalid name"] {
        assert_eq!(
            write(
                &f,
                issued.secret(),
                AdminRbacRequest::DeleteRole { name },
                Some(&csrf)
            )
            .await,
            Err(AdminRbacError::RoleDeleteFailed)
        );
    }

    // The parent guard serializes two simultaneous removals of the last two admins.
    f.admin.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('external-a','admin',0),('external-b','admin',0)").await.unwrap();
    let (a, b) = tokio::join!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::Revoke {
                subject: "external-a",
                role: "admin"
            },
            Some(&csrf)
        ),
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::Revoke {
                subject: "external-b",
                role: "admin"
            },
            Some(&csrf)
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(
        a == Err(AdminRbacError::AssignmentFailed) || b == Err(AdminRbacError::AssignmentFailed)
    );
    assert_eq!(
        sqlx_core::query_scalar::query_scalar::<_, i64>(
            "SELECT count(*) FROM public.role_assignments WHERE role='admin'"
        )
        .fetch_one(&mut f.admin)
        .await
        .unwrap(),
        1
    );
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::Revoke {
            subject: "absent",
            role: "admin",
        },
        Some(&csrf),
    )
    .await
    .unwrap();

    // A disabled/missing LOCAL assignment is not an eligible replacement admin.
    f.admin.execute("DELETE FROM public.role_assignments WHERE role='admin'; INSERT INTO public.role_assignments(subject,role,created_at) VALUES('external-target','admin',0),('local|missing','admin',0)").await.unwrap();
    assert_eq!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::Revoke {
                subject: "external-target",
                role: "admin"
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::AssignmentFailed)
    );
    f.admin.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('bob','missing','service','','','','','[]',0,0,1,0,0)").await.unwrap();
    assert_eq!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::Revoke {
                subject: "external-target",
                role: "admin"
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::AssignmentFailed)
    );
    f.admin
        .execute("UPDATE public.local_users SET enabled=1 WHERE username='bob'")
        .await
        .unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::Revoke {
            subject: "external-target",
            role: "admin",
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    f.admin.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('external-target','admin',0)").await.unwrap();
    for username in ["bad name".to_owned(), "é".repeat(65)] {
        sqlx_core::query::query(
            "UPDATE public.local_users SET username=$1 WHERE subject='missing'",
        )
        .bind(username)
        .execute(&mut f.admin)
        .await
        .unwrap();
        assert!(matches!(
            write(
                &f,
                issued.secret(),
                AdminRbacRequest::Revoke {
                    subject: "external-target",
                    role: "admin"
                },
                Some(&csrf)
            )
            .await,
            Err(AdminRbacError::Authorization(
                AdminBrokerSessionError::Control(ControlError::CorruptIdentity)
            ))
        ));
        assert_eq!(
            assignment_count(&mut f, "external-target", "admin").await,
            1
        );
    }
    f.admin.execute("INSERT INTO public.role_assignments(subject,role,created_at) VALUES('other-external','admin',0)").await.unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::Revoke {
            subject: "external-target",
            role: "admin",
        },
        Some(&csrf),
    )
    .await
    .unwrap();

    // Authorization SQL failure is distinct from a mutation-domain failure.
    f.admin
        .execute("REVOKE SELECT ON public.role_permissions FROM admin_cookie_owner")
        .await
        .unwrap();
    assert!(matches!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::SetRole {
                name: "authorization-denied",
                permissions: &replacement
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::Authorization(
            AdminBrokerSessionError::Control(ControlError::Storage)
        ))
    ));
    assert!(!exists(&mut f, "authorization-denied").await);
    f.admin
        .execute("GRANT SELECT ON public.role_permissions TO admin_cookie_owner")
        .await
        .unwrap();

    // A real SQL permission failure rolls back the newly inserted parent too.
    f.admin
        .execute("REVOKE INSERT ON public.role_permissions FROM admin_cookie_owner")
        .await
        .unwrap();
    assert_eq!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::SetRole {
                name: "rollback-role",
                permissions: &replacement
            },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::InvalidRole)
    );
    assert!(!exists(&mut f, "rollback-role").await);
    f.admin
        .execute("GRANT INSERT ON public.role_permissions TO admin_cookie_owner")
        .await
        .unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::SetRole {
            name: "healthy",
            permissions: &replacement,
        },
        Some(&csrf),
    )
    .await
    .unwrap();

    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    let expired = f
        .store
        .admin_rbac(cookie::limits().authorization)
        .unwrap()
        .write(
            AdminReadAuthentication::Cookie {
                raw: issued.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminRbacRequest::DeleteRole { name: "healthy" },
            Some(&csrf),
            Instant::now() + Duration::from_millis(200),
        )
        .await;
    assert!(matches!(
        expired,
        Err(AdminRbacError::Authorization(
            AdminBrokerSessionError::Control(ControlError::Deadline)
        ))
    ));
    locker.execute("ROLLBACK").await.unwrap();
    assert!(exists(&mut f, "healthy").await);

    // Cancel a known blocked operation; the exact unconfirmed connection is discarded.
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    let pid;
    {
        let writer = f.store.admin_rbac(cookie::limits().authorization).unwrap();
        let pending = writer.write(
            AdminReadAuthentication::Cookie {
                raw: issued.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminRbacRequest::DeleteRole { name: "healthy" },
            Some(&csrf),
            deadline(),
        );
        tokio::pin!(pending);
        pid = tokio::select! {pid=blocked_pid(&mut f.admin)=>pid,result=&mut pending=>panic!("write must block before cancellation: {:?}",result.err())};
    }
    closed_pid(&mut f.admin, pid).await;
    locker.execute("ROLLBACK").await.unwrap();
    locker.close().await.unwrap();
    assert!(exists(&mut f, "healthy").await);

    // Cookie expiry after waiting for the parent lock denies the write, not a stale lease.
    let hash = f
        .digester
        .token(
            broker_security::TokenKind::AdminSession,
            short.secret().as_bytes(),
        )
        .unwrap();
    sqlx_core::query::query("UPDATE public.admin_sessions SET expires_at=$1 WHERE token_hash=$2")
        .bind(cookie::micros() + 1_000_000)
        .bind(hash.to_sql_hex())
        .execute(&mut f.admin)
        .await
        .unwrap();
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    {
        let writer = f.store.admin_rbac(cookie::limits().authorization).unwrap();
        let pending = writer.write(
            AdminReadAuthentication::Cookie {
                raw: short.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminRbacRequest::DeleteRole { name: "healthy" },
            Some(&short_csrf),
            Instant::now() + Duration::from_secs(3),
        );
        tokio::pin!(pending);
        tokio::select! { _ = blocked_pid(&mut f.admin) => {}, result = &mut pending => panic!("write must reach lock before expiry: {:?}", result.err()) }
        tokio::time::sleep(Duration::from_millis(1100)).await;
        locker.execute("ROLLBACK").await.unwrap();
        assert!(matches!(
            pending.await,
            Err(AdminRbacError::Authorization(
                AdminBrokerSessionError::Authentication(_)
            ))
        ));
    }
    locker.close().await.unwrap();
    assert!(exists(&mut f, "healthy").await);

    // Self-demotion succeeds after known COMMIT, then the next action is denied.
    let role_write = vec![SystemAction::RolesWrite.as_str().to_owned()];
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::SetRole {
            name: "writer",
            permissions: &role_write,
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::Assign {
            subject: "local|alice-subject",
            role: "writer",
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    f.admin.execute("DELETE FROM public.role_permissions WHERE role='user'; INSERT INTO public.role_permissions(role,action) VALUES('user','session.read')").await.unwrap();
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::Revoke {
            subject: "local|alice-subject",
            role: "writer",
        },
        Some(&csrf),
    )
    .await
    .unwrap();
    assert!(matches!(
        write(
            &f,
            issued.secret(),
            AdminRbacRequest::DeleteRole { name: "healthy" },
            Some(&csrf)
        )
        .await,
        Err(AdminRbacError::Authorization(
            AdminBrokerSessionError::Forbidden
        ))
    ));
    roles_write(&mut f).await;

    // Withhold the real successful COMMIT reply; no uncertain write is reported successful.
    let mut relay = commit::CommitRelay::new(f.fixture.port).await;
    let owner = PostgresControlStore::open(
        cookie::config(&f.fixture, relay.port),
        cookie::digester(),
        deadline(),
    )
    .await
    .unwrap();
    roles_write(&mut f).await;
    let mut locker = f.fixture.connection().await;
    locker
        .execute("BEGIN; SELECT name FROM public.roles WHERE name='admin' FOR UPDATE")
        .await
        .unwrap();
    let writer = owner.admin_rbac(cookie::limits().authorization).unwrap();
    {
        let pending = writer.write(
            AdminReadAuthentication::Cookie {
                raw: issued.secret(),
                limits: cookie::limits(),
                policy: cookie::policy(),
                upstream: None,
            },
            AdminRbacRequest::SetRole {
                name: "committed-uncertain",
                permissions: &replacement,
            },
            Some(&csrf),
            Instant::now() + Duration::from_secs(3),
        );
        tokio::pin!(pending);
        let pid = tokio::select! {pid=blocked_pid(&mut f.admin)=>pid,result=&mut pending=>panic!("write must reach lock before COMMIT relay: {:?}",result.err())};
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
            if query == "COMMIT" && idle && exists(&mut f, "committed-uncertain").await {
                decision.send(false).unwrap();
                break;
            }
            decision.send(true).unwrap();
        }
        assert!(matches!(
            pending.await,
            Err(AdminRbacError::Authorization(
                AdminBrokerSessionError::Control(ControlError::OutcomeUncertain)
            ))
        ));
    }
    locker.close().await.unwrap();
    relay.close().await;
    owner.shutdown(deadline()).await.unwrap();
    assert!(exists(&mut f, "committed-uncertain").await);
    write(
        &f,
        issued.secret(),
        AdminRbacRequest::DeleteRole { name: "healthy" },
        Some(&csrf),
    )
    .await
    .unwrap();
    f.close().await;
}
