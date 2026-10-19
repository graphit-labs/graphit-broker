#[path = "support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine fixtures serve independent native ingress targets"
)]
mod ingress;
use broker_control::{
    AdminBrokerSessionError as AuthError, AdminBrokerSessionLimits, AdminRbacError as Error,
    AdminRbacRequest as Request, AdminRbacResult, AdminReadAuthentication as A, BrokerAccessError,
    ControlError, FlowPurpose, SqliteControlStore,
};
use ingress::fixture::{Arc, Duration, Fixture, Instant, SystemTime, Zeroizing, end, json, n};
use rusqlite::{Connection, params};
fn limits() -> AdminBrokerSessionLimits {
    ingress::limits().authorization
}
fn action(db: &Connection, value: &str) {
    db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    db.execute(
        "INSERT INTO role_permissions(role,action)VALUES('user',?1)",
        [value],
    )
    .unwrap();
}
fn revision(db: &Connection) -> i64 {
    db.query_row(
        "SELECT revision FROM resource_acl_state WHERE id=1",
        [],
        |row| row.get(0),
    )
    .unwrap()
}
fn roles(db: &Connection, name: &str) -> i64 {
    db.query_row("SELECT count(*) FROM roles WHERE name=?1", [name], |row| {
        row.get(0)
    })
    .unwrap()
}
fn assignments(db: &Connection, subject: &str, role: &str) -> i64 {
    db.query_row(
        "SELECT count(*) FROM role_assignments WHERE subject=?1 AND role=?2",
        params![subject, role],
        |row| row.get(0),
    )
    .unwrap()
}
async fn opaque(
    store: &SqliteControlStore,
    raw: &str,
    request: Request<'_>,
    original: Instant,
) -> Result<AdminRbacResult<'static>, Error> {
    store
        .admin_rbac(limits())
        .unwrap()
        .write(
            A::Opaque {
                raw,
                audience: "admin-api",
                identity_json_bytes: n(8192),
                required_scopes: &["admin:session".into()],
            },
            request,
            None,
            original,
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine JWT opaque HTTPS F1 and LOCAL/federated cookies with current roles.write"]
async fn sqlite_rbac_four_ingresses_current_action_and_cookie_csrf() {
    let f = Fixture::new().await;
    ingress::allow_session(&f);
    let jwt = ingress::jwt(&f).await;
    let opaque_raw = ingress::persisted_opaque(&f);
    let local = ingress::local_cookie(&f).await;
    let verifier = f.verifier();
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let mut op = ingress::browser_op().await;
    let mut bearer_config = ingress::config(&bearer.issuer, &bearer.ca, false, Some("roles"));
    bearer_config.id = "bearer".into();
    let trust = ingress::trust(vec![
        ingress::config(&op.issuer, &op.ca, true, Some("roles")),
        bearer_config,
    ]);
    let raw = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    let login = ingress::h1(&f, &op, &trust, FlowPurpose::Admin, end()).await;
    let federated = f
        .store
        .admin_cookie_sessions(ingress::limits(), ingress::policy(), Some(trust.clone()))
        .unwrap()
        .issue_upstream(login, end())
        .await
        .unwrap();
    // CSRF is session DATA obtained during issuance setup; all read authority is then removed.
    let sessions = f
        .store
        .admin_cookie_sessions(ingress::limits(), ingress::policy(), Some(trust.clone()))
        .unwrap();
    let local_csrf = Zeroizing::new(
        sessions
            .read(local.secret(), end())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    let external_csrf = Zeroizing::new(
        sessions
            .read(federated.secret(), end())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    let scopes = vec!["admin:session".into()];
    let auth = |kind| match kind {
        0 => A::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        1 => A::Opaque {
            raw: &opaque_raw,
            audience: "admin-api",
            identity_json_bytes: n(8192),
            required_scopes: &scopes,
        },
        2 => A::Upstream {
            raw: &raw,
            verifier: &trust,
        },
        3 => A::Cookie {
            raw: local.secret(),
            limits: ingress::limits(),
            policy: ingress::policy(),
            upstream: Some(trust.clone()),
        },
        4 => A::Cookie {
            raw: federated.secret(),
            limits: ingress::limits(),
            policy: ingress::policy(),
            upstream: Some(trust.clone()),
        },
        _ => panic!("unknown fixture ingress"),
    };

    let writer = f.store.admin_rbac(limits()).unwrap();
    let initial = revision(&f.db);
    action(&f.db, "roles.write");
    for kind in 0..5 {
        let role = format!("genuine-{kind}");
        let subject = format!("external|{kind}");
        let permissions = vec!["roles.read".into()];
        let csrf = match kind {
            3 => Some(local_csrf.as_str()),
            4 => Some(external_csrf.as_str()),
            _ => None,
        };
        for request in [
            Request::SetRole {
                name: &role,
                permissions: &permissions,
            },
            Request::Assign {
                subject: &subject,
                role: &role,
            },
            Request::Revoke {
                subject: &subject,
                role: &role,
            },
            Request::DeleteRole { name: &role },
        ] {
            let committed = writer
                .write(auth(kind), request, csrf, end())
                .await
                .unwrap();
            committed.check().unwrap();
            assert_eq!(format!("{committed:?}"), "AdminRbacResult([REDACTED])");
            assert_eq!(revision(&f.db), initial);
        }
        assert_eq!(roles(&f.db, &role), 0);
        assert_eq!(assignments(&f.db, &subject, &role), 0);
    }
    let denied_permissions = vec!["roles.read".into()];
    let expected = revision(&f.db);
    action(&f.db, "session.read");
    for kind in 0..5 {
        let csrf = match kind {
            3 => Some(local_csrf.as_str()),
            4 => Some(external_csrf.as_str()),
            _ => None,
        };
        assert_eq!(
            writer
                .write(
                    auth(kind),
                    Request::SetRole {
                        name: "denied",
                        permissions: &denied_permissions
                    },
                    csrf,
                    end()
                )
                .await
                .unwrap_err(),
            Error::Authorization(AuthError::Forbidden)
        );
        assert_eq!(revision(&f.db), expected);
    }
    action(&f.db, "roles.write");
    let other_verifier = f.verifier();
    assert_eq!(
        writer
            .write(
                A::Broker {
                    verifier: &other_verifier,
                    proof: verifier.verify(&jwt, &[], end()).unwrap()
                },
                Request::SetRole {
                    name: "denied",
                    permissions: &denied_permissions
                },
                None,
                end()
            )
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::InvalidToken))
    );
    for (kind, csrf) in [(3, local_csrf.as_str()), (4, external_csrf.as_str())] {
        let changed = if let Some(suffix) = csrf.strip_prefix('A') {
            format!("B{suffix}")
        } else {
            format!("A{}", &csrf[1..])
        };
        let noncanonical = format!("{}B", "A".repeat(42));
        for supplied in [
            None,
            Some("invalid"),
            Some("noncanonical="),
            Some(noncanonical.as_str()),
            Some(changed.as_str()),
        ] {
            assert_eq!(
                writer
                    .write(
                        auth(kind),
                        Request::SetRole {
                            name: "denied",
                            permissions: &denied_permissions
                        },
                        supplied,
                        end()
                    )
                    .await
                    .unwrap_err(),
                Error::CsrfFailed
            );
            assert_eq!(revision(&f.db), expected);
        }
    }
    for trust in [
        ingress::trust(vec![]),
        ingress::trust(vec![ingress::config(
            &op.issuer,
            &op.ca,
            true,
            Some("other_roles"),
        )]),
    ] {
        assert!(
            writer
                .write(
                    A::Cookie {
                        raw: federated.secret(),
                        limits: ingress::limits(),
                        policy: ingress::policy(),
                        upstream: Some(trust)
                    },
                    Request::SetRole {
                        name: "denied",
                        permissions: &denied_permissions
                    },
                    Some(&external_csrf),
                    end()
                )
                .await
                .is_err()
        );
        assert_eq!(revision(&f.db), expected);
    }
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    for kind in [0, 1, 3] {
        assert!(
            writer
                .write(
                    auth(kind),
                    Request::SetRole {
                        name: "denied",
                        permissions: &denied_permissions
                    },
                    Some(&local_csrf),
                    end()
                )
                .await
                .is_err()
        );
        assert_eq!(revision(&f.db), expected);
    }
    f.db.execute(
        "UPDATE local_users SET enabled=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='user';INSERT INTO roles(name,created_at)VALUES('assigned-write',0);INSERT INTO role_permissions(role,action)VALUES('assigned-write','roles.write')").unwrap();
    let mut claims = bearer.claims();
    claims["sub"] = json!("rbac-subject");
    claims["roles"] = json!([]);
    let assigned = format!("{}|rbac-subject", bearer.issuer);
    f.db.execute(
        "INSERT INTO role_assignments(subject,role,created_at)VALUES(?1,'assigned-write',0)",
        [assigned],
    )
    .unwrap();
    let empty = bearer.sign(&claims, "upstream-key", "at+jwt");
    let no_selector = ingress::trust(vec![ingress::config(
        &bearer.issuer,
        &bearer.ca,
        false,
        None,
    )]);
    for request in [
        Request::SetRole {
            name: "assigned-permitted",
            permissions: &denied_permissions,
        },
        Request::DeleteRole {
            name: "assigned-permitted",
        },
    ] {
        writer
            .write(
                A::Upstream {
                    raw: &empty,
                    verifier: &no_selector,
                },
                request,
                None,
                end(),
            )
            .await
            .unwrap()
            .check()
            .unwrap();
    }
    assert_eq!(
        writer
            .write(
                A::Upstream {
                    raw: &empty,
                    verifier: &trust
                },
                Request::SetRole {
                    name: "denied",
                    permissions: &denied_permissions
                },
                None,
                end()
            )
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    claims["roles"] = json!(["unknown-write"]);
    let unknown = bearer.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        writer
            .write(
                A::Upstream {
                    raw: &unknown,
                    verifier: &trust
                },
                Request::SetRole {
                    name: "denied",
                    permissions: &denied_permissions
                },
                None,
                end()
            )
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    assert_eq!(revision(&f.db), expected);
    assert_eq!(roles(&f.db, "denied"), 0);
    f.store.shutdown(end()).await.unwrap();
    op.close().await;
    bearer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real role definitions, Unicode assignment, cascade and SQLite shared role transaction"]
async fn sqlite_rbac_definitions_assignments_and_no_acl_revision() {
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    action(&f.db, "roles.write");
    let initial = revision(&f.db);
    let permissions = vec![
        "roles.read".into(),
        "roles.read".into(),
        "session.read".into(),
    ];
    opaque(
        &f.store,
        &raw,
        Request::SetRole {
            name: " Auditors ",
            permissions: &permissions,
        },
        end(),
    )
    .await
    .unwrap()
    .check()
    .unwrap();
    let created: i64 =
        f.db.query_row(
            "SELECT created_at FROM roles WHERE name='Auditors'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let actions: Vec<String> =
        f.db.prepare("SELECT action FROM role_permissions WHERE role='Auditors' ORDER BY action")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    assert_eq!(actions, vec!["roles.read", "session.read"]);
    let replacement = vec!["*".into()];
    opaque(
        &f.store,
        &raw,
        Request::SetRole {
            name: "Auditors",
            permissions: &replacement,
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.db.query_row(
            "SELECT created_at FROM roles WHERE name='Auditors'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        created
    );
    assert_eq!(
        f.db.query_row(
            "SELECT action FROM role_permissions WHERE role='Auditors'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "*"
    );
    for name in ["admin", "user", " bad name ", "é", "-bad", &"a".repeat(129)] {
        assert_eq!(
            opaque(
                &f.store,
                &raw,
                Request::SetRole {
                    name,
                    permissions: &permissions
                },
                end()
            )
            .await
            .unwrap_err(),
            Error::InvalidRole
        );
        assert_eq!(
            opaque(&f.store, &raw, Request::DeleteRole { name }, end())
                .await
                .unwrap_err(),
            Error::RoleDeleteFailed
        );
    }
    for invalid in [
        vec![],
        vec!["roles.read".into(), "unknown".into()],
        vec![" roles.read ".into()],
    ] {
        assert_eq!(
            opaque(
                &f.store,
                &raw,
                Request::SetRole {
                    name: "invalid",
                    permissions: &invalid
                },
                end()
            )
            .await
            .unwrap_err(),
            Error::InvalidRole
        );
        assert_eq!(roles(&f.db, "invalid"), 0);
    }
    opaque(
        &f.store,
        &raw,
        Request::SetRole {
            name: "Admin",
            permissions: &permissions,
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(roles(&f.db, "Admin"), 1);
    let at_limit = "界".repeat(512);
    let trimmed = format!("  {at_limit}  ");
    opaque(
        &f.store,
        &raw,
        Request::Assign {
            subject: &trimmed,
            role: " Auditors ",
        },
        end(),
    )
    .await
    .unwrap();
    let assigned_at: i64 =
        f.db.query_row(
            "SELECT created_at FROM role_assignments WHERE subject=?1 AND role='Auditors'",
            [&at_limit],
            |r| r.get(0),
        )
        .unwrap();
    opaque(
        &f.store,
        &raw,
        Request::Assign {
            subject: &at_limit,
            role: "Auditors",
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.db.query_row(
            "SELECT created_at FROM role_assignments WHERE subject=?1 AND role='Auditors'",
            [&at_limit],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        assigned_at
    );
    for subject in [
        "".to_owned(),
        "
	"
        .to_owned(),
        "bad
subject"
            .to_owned(),
        "界".repeat(513),
    ] {
        for request in [
            Request::Assign {
                subject: &subject,
                role: "Auditors",
            },
            Request::Revoke {
                subject: &subject,
                role: "Auditors",
            },
        ] {
            assert_eq!(
                opaque(&f.store, &raw, request, end()).await.unwrap_err(),
                Error::AssignmentFailed
            );
        }
    }
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Assign {
                subject: "external|notlocal",
                role: "missing"
            },
            end()
        )
        .await
        .unwrap_err(),
        Error::AssignmentFailed
    );
    opaque(
        &f.store,
        &raw,
        Request::Revoke {
            subject: "absent",
            role: "missing",
        },
        end(),
    )
    .await
    .unwrap();
    opaque(
        &f.store,
        &raw,
        Request::DeleteRole { name: "Auditors" },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(assignments(&f.db, &at_limit, "Auditors"), 0);
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM role_permissions WHERE role='Auditors'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::DeleteRole { name: "Auditors" },
            end()
        )
        .await
        .unwrap_err(),
        Error::RoleDeleteFailed
    );
    assert_eq!(revision(&f.db), initial);
    // The authenticated self-demotion commits; retained factor remains usable for ACK only.
    opaque(
        &f.store,
        &raw,
        Request::SetRole {
            name: "operators",
            permissions: &["roles.write".into()],
        },
        end(),
    )
    .await
    .unwrap();
    f.db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    f.db.execute("INSERT INTO role_assignments(subject,role,created_at)SELECT 'local|'||subject,'operators',0 FROM local_users WHERE username='alice'",[]).unwrap();
    let demotion = opaque(
        &f.store,
        &raw,
        Request::SetRole {
            name: "operators",
            permissions: &["roles.read".into()],
        },
        end(),
    )
    .await
    .unwrap();
    demotion.check().unwrap();
    assert_eq!(
        opaque(&f.store, &raw, Request::DeleteRole { name: "Admin" }, end())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    action(&f.db, "roles.write");
    f.db.execute("DELETE FROM roles WHERE name='admin'", [])
        .unwrap();
    assert_eq!(
        opaque(&f.store, &raw, Request::DeleteRole { name: "Admin" }, end())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::CorruptRbac))
    );
    f.store.shutdown(end()).await.unwrap();
}

async fn upstream<'a>(
    store: &SqliteControlStore,
    raw: &str,
    trust: &'a broker_control::UpstreamBearerVerifier,
    request: Request<'_>,
    original: Instant,
) -> Result<AdminRbacResult<'a>, Error> {
    store
        .admin_rbac(limits())
        .unwrap()
        .write(
            A::Upstream {
                raw,
                verifier: trust,
            },
            request,
            None,
            original,
        )
        .await
}
fn admin_pair(db: &Connection, subject: &str) {
    db.execute(
        "INSERT INTO role_assignments(subject,role,created_at)VALUES(?1,'admin',0)",
        [subject],
    )
    .unwrap();
}
fn reset_admins(db: &Connection) {
    db.execute("DELETE FROM role_assignments WHERE role='admin'", [])
        .unwrap();
    admin_pair(db, "external|target");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real explicit last-admin candidates and two independent SQLite physical owners"]
async fn sqlite_rbac_last_eligible_admin_and_two_physical_owners() {
    let f = Fixture::new().await;
    action(&f.db, "roles.write");
    let mut issuer = ingress::upstream::UpstreamFixture::new().await;
    let trust = ingress::trust(vec![ingress::config(
        &issuer.issuer,
        &issuer.ca,
        false,
        Some("roles"),
    )]);
    let raw = issuer.sign(&issuer.claims(), "upstream-key", "at+jwt");
    let revoke = || Request::Revoke {
        subject: "external|target",
        role: "admin",
    };
    reset_admins(&f.db);
    assert_eq!(
        upstream(&f.store, &raw, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::AssignmentFailed
    );
    assert_eq!(assignments(&f.db, "external|target", "admin"), 1);

    // Neither a wildcard custom assignment nor an IdP admin claim is another explicit admin.
    upstream(
        &f.store,
        &raw,
        &trust,
        Request::SetRole {
            name: "wildcard",
            permissions: &["*".into()],
        },
        end(),
    )
    .await
    .unwrap();
    upstream(
        &f.store,
        &raw,
        &trust,
        Request::Assign {
            subject: "external|custom",
            role: "wildcard",
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        upstream(&f.store, &raw, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::AssignmentFailed
    );
    let mut claimed = issuer.claims();
    claimed["roles"] = json!(["admin"]);
    let claimed = issuer.sign(&claimed, "upstream-key", "at+jwt");
    assert_eq!(
        upstream(&f.store, &claimed, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::AssignmentFailed
    );
    admin_pair(&f.db, "external|other");
    upstream(&f.store, &raw, &trust, revoke(), end())
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(assignments(&f.db, "external|target", "admin"), 0);

    let (subject, kind, identity_revision): (String, String, i64) =
        f.db.query_row(
            "SELECT subject,identity_kind,revision FROM local_users WHERE username='alice'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let assigned = format!("local|{subject}");
    reset_admins(&f.db);
    admin_pair(&f.db, &assigned);
    upstream(&f.store, &raw, &trust, revoke(), end())
        .await
        .unwrap();
    reset_admins(&f.db);
    admin_pair(&f.db, &assigned);
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        [],
    )
    .unwrap();
    assert_eq!(
        upstream(&f.store, &raw, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::AssignmentFailed
    );
    assert_eq!(assignments(&f.db, "external|target", "admin"), 1);
    // A disabled target still cannot be revoked when no eligible other assignment exists.
    f.db.execute("DELETE FROM role_assignments WHERE role='admin'", [])
        .unwrap();
    admin_pair(&f.db, &assigned);
    assert_eq!(
        upstream(
            &f.store,
            &raw,
            &trust,
            Request::Revoke {
                subject: &assigned,
                role: "admin"
            },
            end()
        )
        .await
        .unwrap_err(),
        Error::AssignmentFailed
    );
    f.db.execute(
        "UPDATE local_users SET enabled=1 WHERE username='alice'",
        [],
    )
    .unwrap();
    reset_admins(&f.db);
    admin_pair(&f.db, "local|missing-local");
    assert_eq!(
        upstream(&f.store, &raw, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::AssignmentFailed
    );

    // Corrupt candidate fixtures do not weaken the observer's exact types or pre-copy caps.
    f.db.execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    reset_admins(&f.db);
    admin_pair(&f.db, &assigned);
    for invalid in ["broken", ""] {
        f.db.execute(
            "UPDATE local_users SET identity_kind=?1 WHERE username='alice'",
            [invalid],
        )
        .unwrap();
        assert_eq!(
            upstream(&f.store, &raw, &trust, revoke(), end())
                .await
                .unwrap_err(),
            Error::Authorization(AuthError::Control(ControlError::CorruptIdentity))
        );
        assert_eq!(assignments(&f.db, "external|target", "admin"), 1);
    }
    f.db.execute(
        "UPDATE local_users SET identity_kind=zeroblob(4096) WHERE username='alice'",
        [],
    )
    .unwrap();
    assert_eq!(
        upstream(&f.store, &raw, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::CorruptIdentity))
    );
    f.db.execute(
        "UPDATE local_users SET identity_kind=?1 WHERE username='alice'",
        [&kind],
    )
    .unwrap();
    for value in ["0", "'text-revision'"] {
        f.db.execute_batch(&format!(
            "UPDATE local_users SET revision={value} WHERE username='alice'"
        ))
        .unwrap();
        assert_eq!(
            upstream(&f.store, &raw, &trust, revoke(), end())
                .await
                .unwrap_err(),
            Error::Authorization(AuthError::Control(ControlError::CorruptIdentity))
        );
    }
    f.db.execute(
        "UPDATE local_users SET revision=?1 WHERE username='alice'",
        [identity_revision],
    )
    .unwrap();
    let huge = "界".repeat(200);
    f.db.execute(
        "UPDATE local_users SET subject=?1 WHERE username='alice'",
        [&huge],
    )
    .unwrap();
    reset_admins(&f.db);
    admin_pair(&f.db, &format!("local|{huge}"));
    assert_eq!(
        upstream(&f.store, &raw, &trust, revoke(), end())
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::CorruptIdentity))
    );
    f.db.execute(
        "UPDATE local_users SET subject=?1 WHERE username='alice'",
        [&subject],
    )
    .unwrap();
    f.db.execute_batch("PRAGMA ignore_check_constraints=OFF")
        .unwrap();

    let second = SqliteControlStore::open(
        ingress::fixture::config(&f.path),
        ingress::fixture::digester(),
        end(),
    )
    .await
    .unwrap();
    // Opening another owner reseeds the official built-ins; reapply this fixture-only action.
    action(&f.db, "roles.write");
    f.db.execute("DELETE FROM role_assignments WHERE role='admin'", [])
        .unwrap();
    admin_pair(&f.db, "external|one");
    admin_pair(&f.db, "external|two");
    let (one, two) = tokio::join!(
        upstream(
            &f.store,
            &raw,
            &trust,
            Request::Revoke {
                subject: "external|one",
                role: "admin"
            },
            end()
        ),
        upstream(
            &second,
            &raw,
            &trust,
            Request::Revoke {
                subject: "external|two",
                role: "admin"
            },
            end()
        )
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    let failed = if let Err(e) = one {
        e
    } else {
        two.unwrap_err()
    };
    assert_eq!(failed, Error::AssignmentFailed);
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM role_assignments WHERE role='admin'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(revision(&f.db), 1);
    // Missing revocation is still an idempotent no-op when exactly one admin remains.
    upstream(
        &f.store,
        &raw,
        &trust,
        Request::Revoke {
            subject: "absent",
            role: "admin",
        },
        end(),
    )
    .await
    .unwrap();
    second.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
    issuer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native SQL barriers, known ACK then elapsed Original, cancellation and signed F1 expiry"]
async fn sqlite_rbac_native_ack_original_cancel_and_factor_expiry() {
    use std::{
        future::Future,
        task::{Context, Poll, Wake, Waker},
    };
    struct JobReady(tokio::sync::Notify);
    impl Wake for JobReady {
        fn wake(self: Arc<Self>) {
            self.0.notify_one();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.notify_one();
        }
    }
    let f = Fixture::new().await;
    let jwt = ingress::jwt(&f).await;
    let verifier = f.verifier();
    let raw = ingress::persisted_opaque(&f);
    action(&f.db, "roles.write");
    let writer = f.store.admin_rbac(limits()).unwrap();
    let permissions = vec!["roles.read".into()];
    let ready = Arc::new(JobReady(tokio::sync::Notify::new()));
    let waker = Waker::from(ready.clone());
    let mut context = Context::from_waker(&waker);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let original = Instant::now() + Duration::from_secs(2);
    let mut pending = Box::pin(writer.write(
        A::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        Request::SetRole {
            name: "known-ack",
            permissions: &permissions,
        },
        None,
        original,
    ));
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
    f.db.execute_batch("ROLLBACK").unwrap();
    tokio::time::timeout(Duration::from_secs(10), ready.0.notified())
        .await
        .unwrap();
    assert_eq!(roles(&f.db, "known-ack"), 1);
    tokio::time::sleep_until((original + Duration::from_millis(10)).into()).await;
    assert_eq!(
        pending.await.unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    assert_eq!(roles(&f.db, "known-ack"), 1);

    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = writer
        .write(
            A::Broker {
                verifier: &verifier,
                proof: verifier.verify(&jwt, &[], end()).unwrap(),
            },
            Request::SetRole {
                name: "deadline",
                permissions: &permissions,
            },
            None,
            Instant::now() + Duration::from_millis(150),
        )
        .await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    assert_eq!(roles(&f.db, "deadline"), 0);

    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut pending = Box::pin(writer.write(
        A::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        Request::SetRole {
            name: "cancelled",
            permissions: &permissions,
        },
        None,
        end(),
    ));
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
    drop(pending);
    f.db.execute_batch("ROLLBACK").unwrap();
    f.store
        .resource_grants(n(65536))
        .unwrap()
        .read(end())
        .await
        .unwrap();
    assert_eq!(roles(&f.db, "cancelled"), 0);

    let mut issuer = ingress::upstream::UpstreamFixture::new().await;
    let trust = ingress::trust(vec![ingress::config(
        &issuer.issuer,
        &issuer.ca,
        false,
        None,
    )]);
    let warm = issuer.sign(&issuer.claims(), "upstream-key", "at+jwt");
    assert_eq!(
        upstream(
            &f.store,
            &warm,
            &trust,
            Request::DeleteRole { name: "absent" },
            end()
        )
        .await
        .unwrap_err(),
        Error::RoleDeleteFailed
    );
    // Acquire the physical barrier before creating the short UTC proof window.
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut claims = issuer.claims();
    let expires = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    claims["exp"] = json!(expires);
    let expiring = issuer.sign(&claims, "upstream-key", "at+jwt");
    let mut pending = Box::pin(writer.write(
        A::Upstream {
            raw: &expiring,
            verifier: &trust,
        },
        Request::SetRole {
            name: "expired",
            permissions: &permissions,
        },
        None,
        end(),
    ));
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
    assert!(SystemTime::now() < std::time::UNIX_EPOCH + Duration::from_secs(expires));
    let release = async {
        let until =
            std::time::UNIX_EPOCH + Duration::from_secs(expires) + Duration::from_millis(100);
        tokio::time::sleep(until.duration_since(SystemTime::now()).unwrap_or_default()).await;
        f.db.execute_batch("ROLLBACK").unwrap();
    };
    let (result, ()) = tokio::join!(pending, release);
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::Expired))
    );
    assert_eq!(roles(&f.db, "expired"), 0);
    let second = SqliteControlStore::open(
        ingress::fixture::config(&f.path),
        ingress::fixture::digester(),
        end(),
    )
    .await
    .unwrap();
    // Opening another owner reseeds the official built-ins; reapply this fixture-only action.
    action(&f.db, "roles.write");
    opaque(
        &second,
        &raw,
        Request::SetRole {
            name: "recovered",
            permissions: &permissions,
        },
        end(),
    )
    .await
    .unwrap()
    .check()
    .unwrap();
    assert_eq!(roles(&f.db, "recovered"), 1);
    assert_eq!(revision(&f.db), 1);
    issuer.close().await;
    second.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}
