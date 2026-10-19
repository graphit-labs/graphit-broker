#[path = "support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine fixtures serve independent ingress targets"
)]
mod ingress;

use broker_control::{
    AdminBrokerSessionError as AuthError, AdminGrantError as Error, AdminGrantInput,
    AdminGrantRequest as Request, AdminGrantResult, AdminGrantRoutes, AdminReadAuthentication as A,
    AdminReadLimits, BrokerAccessError, ControlError, FlowPurpose, SqliteControlStore,
};
use ingress::fixture::{Arc, Duration, Fixture, Instant, SystemTime, Zeroizing, end, json, n};
use rusqlite::Connection;
use serde_json::Value;

fn limits() -> AdminReadLimits {
    AdminReadLimits {
        authorization: ingress::limits().authorization,
        grants_json_bytes: n(65536),
        response_json_bytes: n(65536),
    }
}
fn routes() -> Arc<AdminGrantRoutes> {
    Arc::new(AdminGrantRoutes::new(vec!["primary".into()], "primary".into()).unwrap())
}
fn input(id: &str) -> AdminGrantInput {
    let operation = "read";
    serde_json::from_value(json!({
        "id":id,"name":" Grant ","access":" AUTHENTICATED ","principal":"",
        "capabilities":[" hub ","hub",format!("s3:{operation}")],
        "projects":[" 01M1YEAE1WYMWG9KJKV1XQC4T4 ","01M1YEAE1WYMWG9KJKV1XQC4T4"],
        "s3_operations":[operation,format!(" {operation} ")],
        "s3_prefixes":[" prefix/ ","prefix/"],"s3_route":" primary "
    }))
    .unwrap()
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
fn revision(db: &Connection) -> u64 {
    let revision: i64 = db
        .query_row(
            "SELECT revision FROM resource_acl_state WHERE id=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    u64::try_from(revision).unwrap()
}
fn value(result: &AdminGrantResult<'_>) -> Value {
    result.check().unwrap();
    serde_json::from_slice(result.body()).unwrap()
}
async fn opaque(
    store: &SqliteControlStore,
    raw: &str,
    request: Request<'_>,
    expected: u64,
    read_limits: AdminReadLimits,
    original: Instant,
) -> Result<AdminGrantResult<'static>, Error> {
    store
        .admin_grants(read_limits, routes())
        .unwrap()
        .write(
            A::Opaque {
                raw,
                audience: "admin-api",
                identity_json_bytes: n(8192),
                required_scopes: &["admin:session".into()],
            },
            request,
            expected,
            None,
            original,
        )
        .await
}
fn row_count(db: &Connection, id: &str) -> i64 {
    db.query_row(
        "SELECT count(*) FROM resource_grants WHERE id=?1",
        [id],
        |row| row.get(0),
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "genuine signed JWT, opaque possession, HTTPS F1 and LOCAL/federated cookies"]
async fn sqlite_grants_four_ingresses_current_write_action_and_cookie_csrf() {
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
    let writer = f.store.admin_grants(limits(), routes()).unwrap();
    action(&f.db, "grants.write");
    for kind in 0..5 {
        let id = format!("genuine-{kind}");
        let mut grant = input(&id);
        let csrf = match kind {
            3 => Some(local_csrf.as_str()),
            4 => Some(external_csrf.as_str()),
            _ => None,
        };
        let mut expected = revision(&f.db);
        let created = writer
            .write(auth(kind), Request::Create(&grant), expected, csrf, end())
            .await
            .unwrap();
        expected += 1;
        assert_eq!(created.revision() as u64, expected);
        assert_eq!(value(&created)["rules"][0]["id"], id);
        grant.name = "Updated".into();
        let updated = writer
            .write(
                auth(kind),
                Request::Update {
                    id: &id,
                    grant: &grant,
                },
                expected,
                csrf,
                end(),
            )
            .await
            .unwrap();
        expected += 1;
        assert_eq!(updated.revision() as u64, expected);
        let deleted = writer
            .write(
                auth(kind),
                Request::Delete { id: &id },
                expected,
                csrf,
                end(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.revision() as u64, expected + 1);
        assert_eq!(value(&deleted)["rules"], json!([]));
        assert_eq!(format!("{deleted:?}"), "AdminGrantResult([REDACTED])");
    }
    let grant = input("denied");
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
                .write(auth(kind), Request::Create(&grant), expected, csrf, end())
                .await
                .unwrap_err(),
            Error::Authorization(AuthError::Forbidden)
        );
        assert_eq!(revision(&f.db), expected);
    }
    action(&f.db, "grants.write");
    let other_verifier = f.verifier();
    assert_eq!(
        writer
            .write(
                A::Broker {
                    verifier: &other_verifier,
                    proof: verifier.verify(&jwt, &[], end()).unwrap()
                },
                Request::Create(&grant),
                expected,
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
                        Request::Create(&grant),
                        expected,
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
                    Request::Create(&grant),
                    expected,
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
                    Request::Create(&grant),
                    expected,
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
    f.db.execute_batch("DELETE FROM role_permissions WHERE role='user';INSERT INTO roles(name,created_at)VALUES('assigned-write',0);INSERT INTO role_permissions(role,action)VALUES('assigned-write','grants.write')").unwrap();
    let mut claims = bearer.claims();
    claims["sub"] = json!("grants-subject");
    claims["roles"] = json!([]);
    let assigned = format!("{}|grants-subject", bearer.issuer);
    f.db.execute(
        "INSERT INTO role_assignments(subject,role,created_at)VALUES(?1,'assigned-write',0)",
        [assigned],
    )
    .unwrap();
    let empty = bearer.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        writer
            .write(
                A::Upstream {
                    raw: &empty,
                    verifier: &trust
                },
                Request::Create(&grant),
                expected,
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
                Request::Create(&grant),
                expected,
                None,
                end()
            )
            .await
            .unwrap_err(),
        Error::Authorization(AuthError::Forbidden)
    );
    assert_eq!(revision(&f.db), expected);
    f.store.shutdown(end()).await.unwrap();
    op.close().await;
    bearer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real private SQLite CAS, policy rollback and concurrent physical owners"]
async fn sqlite_grants_cas_four_sets_normalization_and_rollback() {
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    action(&f.db, "grants.write");
    let grant = input(" first ");
    let created = opaque(&f.store, &raw, Request::Create(&grant), 1, limits(), end())
        .await
        .unwrap();
    assert_eq!(created.revision(), 2);
    let rule = &value(&created)["rules"][0];
    assert_eq!(rule["id"], "first");
    assert_eq!(rule["name"], "Grant");
    assert_eq!(rule["access"], "authenticated");
    assert_eq!(rule["projects"], json!(["01M1YEAE1WYMWG9KJKV1XQC4T4"]));
    assert_eq!(rule["s3_prefixes"], json!(["prefix/"]));
    for table in ["grant_projects", "grant_s3_operations", "grant_s3_prefixes"] {
        assert_eq!(
            f.db.query_row(
                &format!("SELECT count(*) FROM {table} WHERE grant_id='first'"),
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM grant_capabilities WHERE grant_id='first'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    let born =
        f.db.query_row(
            "SELECT created_at FROM resource_grants WHERE id='first'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap();
    let mut updated = input("body-must-not-win");
    updated.name = " Changed ".into();
    updated.projects.clear();
    updated.s3_operations.clear();
    updated.s3_prefixes.clear();
    updated.capabilities = vec!["hub".into()];
    let changed = opaque(
        &f.store,
        &raw,
        Request::Update {
            id: " first ",
            grant: &updated,
        },
        2,
        limits(),
        end(),
    )
    .await
    .unwrap();
    assert_eq!(changed.revision(), 3);
    assert_eq!(row_count(&f.db, "body-must-not-win"), 0);
    assert_eq!(
        f.db.query_row(
            "SELECT created_at FROM resource_grants WHERE id='first'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        born
    );
    for table in ["grant_projects", "grant_s3_operations", "grant_s3_prefixes"] {
        assert_eq!(
            f.db.query_row(
                &format!("SELECT count(*) FROM {table} WHERE grant_id='first'"),
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM grant_capabilities WHERE grant_id='first' AND value='hub'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        f.db.query_row(
            "SELECT count(*) FROM grant_capabilities WHERE grant_id='first'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    f.db.execute(
        "UPDATE grant_capabilities SET value=?1 WHERE grant_id='first'",
        [vec![0xffu8]],
    )
    .unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&input("malformed-snapshot")),
            3,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::ReadFailed
    );
    assert_eq!(row_count(&f.db, "malformed-snapshot"), 0);
    assert_eq!(revision(&f.db), 3);
    f.db.execute(
        "UPDATE grant_capabilities SET value='hub' WHERE grant_id='first'",
        [],
    )
    .unwrap();
    f.db.execute(
        "UPDATE resource_grants SET s3_route='missing' WHERE id='first'",
        [],
    )
    .unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&input("other-rule-invalid")),
            3,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(row_count(&f.db, "other-rule-invalid"), 0);
    assert_eq!(revision(&f.db), 3);
    f.db.execute(
        "UPDATE resource_grants SET s3_route='primary' WHERE id='first'",
        [],
    )
    .unwrap();
    let mut invalid = input("bad");
    invalid.s3_route = "missing".into();
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&invalid),
            2,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::RevisionConflict
    );
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&invalid),
            3,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::InvalidGrant
    );
    assert_eq!(row_count(&f.db, "bad"), 0);
    assert_eq!(revision(&f.db), 3);
    assert_eq!(
        opaque(&f.store, &raw, Request::Create(&grant), 3, limits(), end())
            .await
            .unwrap_err(),
        Error::WriteFailed
    );
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Delete { id: "absent" },
            3,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::WriteFailed
    );
    let second = SqliteControlStore::open(
        ingress::fixture::config(&f.path),
        ingress::fixture::digester(),
        end(),
    )
    .await
    .unwrap();
    action(&f.db, "grants.write");
    let left = input("left");
    let right = input("right");
    let (left, right) = tokio::join!(
        opaque(&f.store, &raw, Request::Create(&left), 3, limits(), end()),
        opaque(&second, &raw, Request::Create(&right), 3, limits(), end()),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert_eq!(left.err().or(right.err()), Some(Error::RevisionConflict));
    assert_eq!(revision(&f.db), 4);
    assert_eq!(row_count(&f.db, "left") + row_count(&f.db, "right"), 1);
    f.db.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    for bad in ["0", "'not-an-integer'"] {
        f.db.execute_batch(&format!("UPDATE resource_acl_state SET revision={bad}"))
            .unwrap();
        assert_eq!(
            opaque(
                &f.store,
                &raw,
                Request::Create(&input("bad-revision")),
                4,
                limits(),
                end()
            )
            .await
            .unwrap_err(),
            Error::WriteFailed
        );
        assert_eq!(row_count(&f.db, "bad-revision"), 0);
    }
    f.db.execute("UPDATE resource_acl_state SET revision=4", [])
        .unwrap();
    f.db.pragma_update(None, "ignore_check_constraints", false)
        .unwrap();
    f.db.execute("UPDATE resource_acl_state SET revision=?1", [i64::MAX])
        .unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&input("overflow")),
            i64::MAX as u64,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::WriteFailed
    );
    assert_eq!(row_count(&f.db, "overflow"), 0);
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&input("unsigned")),
            u64::MAX,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::RevisionConflict
    );
    f.db.execute("UPDATE resource_acl_state SET revision=4", [])
        .unwrap();
    f.db.execute("DELETE FROM roles WHERE name='admin'", [])
        .unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &raw,
            Request::Create(&input("missing-parent")),
            4,
            limits(),
            end()
        )
        .await
        .unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::CorruptRbac))
    );
    assert_eq!(revision(&f.db), 4);
    second.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "known SQLite ACK, later concurrent DATA, cancellation and signed proof expiry"]
async fn sqlite_grants_post_ack_data_and_original_are_causal() {
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
    let raw = ingress::persisted_opaque(&f);
    let jwt = ingress::jwt(&f).await;
    let verifier = f.verifier();
    action(&f.db, "grants.write");
    let mut tiny = limits();
    tiny.response_json_bytes = n(2);
    let grant = input("post-ack-error");
    assert_eq!(
        opaque(&f.store, &raw, Request::Create(&grant), 1, tiny, end())
            .await
            .unwrap_err(),
        Error::ReadFailed
    );
    assert_eq!(revision(&f.db), 2);
    assert_eq!(row_count(&f.db, "post-ack-error"), 1);
    assert_eq!(
        opaque(&f.store, &raw, Request::Create(&grant), 1, limits(), end())
            .await
            .unwrap_err(),
        Error::RevisionConflict
    );
    assert_eq!(revision(&f.db), 2);

    let second = SqliteControlStore::open(
        ingress::fixture::config(&f.path),
        ingress::fixture::digester(),
        end(),
    )
    .await
    .unwrap();
    action(&f.db, "grants.write");
    let writer = f.store.admin_grants(limits(), routes()).unwrap();
    let first = input("first-before-ack");
    let later = input("later-before-data");
    let ready = Arc::new(JobReady(tokio::sync::Notify::new()));
    let waker = Waker::from(ready.clone());
    let mut context = Context::from_waker(&waker);
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut pending = Box::pin(writer.write(
        A::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        Request::Create(&first),
        2,
        None,
        end(),
    ));
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
    f.db.execute_batch("ROLLBACK").unwrap();
    tokio::time::timeout(Duration::from_secs(10), ready.0.notified())
        .await
        .unwrap();
    // Do not poll the first caller yet: its real COMMIT completed, but ACK is pending.
    let later_result = opaque(&second, &raw, Request::Create(&later), 3, limits(), end())
        .await
        .unwrap();
    assert_eq!(later_result.revision(), 4);
    let first_result = pending.await.unwrap();
    assert_eq!(first_result.revision(), 4);
    let rules = value(&first_result)["rules"].as_array().unwrap().clone();
    assert!(rules.iter().any(|r| r["id"] == "first-before-ack"));
    assert!(rules.iter().any(|r| r["id"] == "later-before-data"));

    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let deadline = input("deadline-must-not-apply");
    let result = writer
        .write(
            A::Broker {
                verifier: &verifier,
                proof: verifier.verify(&jwt, &[], end()).unwrap(),
            },
            Request::Create(&deadline),
            4,
            None,
            Instant::now() + Duration::from_millis(150),
        )
        .await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AuthError::Control(ControlError::Deadline))
    );
    assert_eq!(row_count(&f.db, "deadline-must-not-apply"), 0);
    assert_eq!(revision(&f.db), 4);

    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let cancelled = input("cancelled-must-not-apply");
    let mut pending = Box::pin(writer.write(
        A::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        Request::Create(&cancelled),
        4,
        None,
        end(),
    ));
    assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
    drop(pending);
    f.db.execute_batch("ROLLBACK").unwrap();
    // This real owner operation waits for the cancelled native job to finish.
    assert_eq!(
        f.store
            .resource_grants(n(65536))
            .unwrap()
            .read(end())
            .await
            .unwrap()
            .revision(),
        4
    );
    assert_eq!(row_count(&f.db, "cancelled-must-not-apply"), 0);

    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let trust = ingress::trust(vec![ingress::config(
        &bearer.issuer,
        &bearer.ca,
        false,
        None,
    )]);
    let mut claims = bearer.claims();
    claims["exp"] = json!(
        SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 2
    );
    let expiring = bearer.sign(&claims, "upstream-key", "at+jwt");
    assert_eq!(
        writer
            .write(
                A::Upstream {
                    raw: &expiring,
                    verifier: &trust
                },
                Request::Delete { id: "absent" },
                4,
                None,
                end()
            )
            .await
            .unwrap_err(),
        Error::WriteFailed
    );
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let expires = input("expired-must-not-apply");
    let pending = writer.write(
        A::Upstream {
            raw: &expiring,
            verifier: &trust,
        },
        Request::Create(&expires),
        4,
        None,
        end(),
    );
    let release = async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        f.db.execute_batch("ROLLBACK").unwrap();
    };
    let (result, ()) = tokio::join!(pending, release);
    assert_eq!(
        result.unwrap_err(),
        Error::Authorization(AuthError::Authentication(BrokerAccessError::Expired))
    );
    assert_eq!(row_count(&f.db, "expired-must-not-apply"), 0);
    assert_eq!(revision(&f.db), 4);
    bearer.close().await;
    second.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}
