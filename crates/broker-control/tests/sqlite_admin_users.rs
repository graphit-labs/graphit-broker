#[path = "support/sqlite_admin_ingress_fixture.rs"]
#[allow(
    dead_code,
    reason = "genuine shared protocol fixtures serve separate contracts"
)]
mod ingress;
use broker_control::*;
use broker_security::{LocalAuthBinding, LocalMfaProtector};
use ingress::fixture::{Arc, Duration, Fixture, Instant, PASSWORD, Zeroizing, end, json, n, utc};
use rusqlite::Connection;
use serde_json::Value;
use std::{
    num::NonZeroU32,
    sync::{
        Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tracing::instrument::WithSubscriber;
use tracing_subscriber::{Layer, Registry, layer::Context, prelude::*};
fn limits() -> AdminUsersLimits {
    AdminUsersLimits {
        authorization: ingress::limits().authorization,
        response_json_bytes: n(65536),
        service_credential_audience: "admin-api".into(),
        service_credential_max_ttl: Duration::from_secs(365 * 86400),
    }
}
fn input(username: &str, subject: &str, kind: &str, password: &str) -> AdminUserInput {
    let mut u = AdminUserInput::default();
    u.username = username.into();
    u.subject = subject.into();
    u.kind = kind.into();
    u.password = password.into();
    u
}
fn actions(db: &Connection, values: &[&str]) {
    db.execute("DELETE FROM role_permissions WHERE role='user'", [])
        .unwrap();
    for action in values {
        db.execute(
            "INSERT INTO role_permissions(role,action)VALUES('user',?1)",
            [action],
        )
        .unwrap();
    }
}
fn count(db: &Connection, query: &str) -> i64 {
    db.query_row(query, [], |r| r.get(0)).unwrap()
}
fn observed(mut r: AdminUsersResult<'_>) -> Result<(u16, Zeroizing<Vec<u8>>), AdminUsersError> {
    r.check()?;
    Ok((r.status(), Zeroizing::new(r.take_body())))
}
async fn opaque(
    store: &SqliteControlStore,
    engine: &LocalPasswordEngine,
    raw: &str,
    request: AdminUsersRequest<'_>,
    original: Instant,
) -> Result<(u16, Zeroizing<Vec<u8>>), AdminUsersError> {
    store
        .admin_users(engine, &limits())
        .unwrap()
        .execute(
            AdminReadAuthentication::Opaque {
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
        .and_then(observed)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real SQLite CRUD, five genuine factors, current action and cookie CSRF"]
async fn sqlite_users_four_ingresses_crud_and_current_action() {
    let f = Fixture::new().await;
    ingress::allow_session(&f);
    let jwt = ingress::jwt(&f).await;
    let raw = ingress::persisted_opaque(&f);
    let local = ingress::local_cookie(&f).await;
    let verifier = f.verifier();
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let mut op = ingress::browser_op().await;
    let mut bc = ingress::config(&bearer.issuer, &bearer.ca, false, Some("roles"));
    bc.id = "bearer".into();
    let trust = ingress::trust(vec![
        ingress::config(&op.issuer, &op.ca, true, Some("roles")),
        bc,
    ]);
    let upstream = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    let login = ingress::h1(&f, &op, &trust, FlowPurpose::Admin, end()).await;
    let sessions = f
        .store
        .admin_cookie_sessions(ingress::limits(), ingress::policy(), Some(trust.clone()))
        .unwrap();
    let federated = sessions.issue_upstream(login, end()).await.unwrap();
    let local_csrf = Zeroizing::new(
        sessions
            .read(local.secret(), end())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    let federated_csrf = Zeroizing::new(
        sessions
            .read(federated.secret(), end())
            .await
            .unwrap()
            .csrf_token()
            .to_owned(),
    );
    let scopes = vec!["admin:session".into()];
    let auth = |kind| match kind {
        0 => AdminReadAuthentication::Broker {
            verifier: &verifier,
            proof: verifier.verify(&jwt, &[], end()).unwrap(),
        },
        1 => AdminReadAuthentication::Opaque {
            raw: &raw,
            audience: "admin-api",
            identity_json_bytes: n(8192),
            required_scopes: &scopes,
        },
        2 => AdminReadAuthentication::Upstream {
            raw: &upstream,
            verifier: &trust,
        },
        3 => AdminReadAuthentication::Cookie {
            raw: local.secret(),
            limits: ingress::limits(),
            policy: ingress::policy(),
            upstream: Some(trust.clone()),
        },
        4 => AdminReadAuthentication::Cookie {
            raw: federated.secret(),
            limits: ingress::limits(),
            policy: ingress::policy(),
            upstream: Some(trust.clone()),
        },
        _ => panic!("fixture factor"),
    };
    let l = limits();
    let service = f.store.admin_users(&f.engine, &l).unwrap();
    actions(&f.db, &["users.write"]);
    for kind in 0..5 {
        let name = format!("factor-{kind}");
        let subject = format!("factor-subject-{kind}");
        let mut u = input(&name, &subject, "service", "");
        u.name = "  Service  ".into();
        u.teams = vec![" b ".into(), "a".into(), "a".into()];
        let csrf = match kind {
            3 => Some(local_csrf.as_str()),
            4 => Some(federated_csrf.as_str()),
            _ => None,
        };
        if kind >= 3 {
            assert_eq!(
                service
                    .execute(auth(kind), AdminUsersRequest::Create(&u), None, end())
                    .await
                    .unwrap_err(),
                AdminUsersError::CsrfFailed
            );
        }
        let r = service
            .execute(auth(kind), AdminUsersRequest::Create(&u), csrf, end())
            .await
            .unwrap();
        r.check().unwrap();
        assert_eq!(r.status(), 201);
        assert!(r.body().is_empty());
        assert_eq!(
            count(
                &f.db,
                "SELECT count(*) FROM local_users WHERE name='Service' AND teams_json='[\"a\",\"b\"]' AND identity_kind='service' AND password_change_required=0"
            ),
            1
        );
        assert_eq!(
            service
                .execute(auth(kind), AdminUsersRequest::Create(&u), csrf, end())
                .await
                .unwrap_err(),
            AdminUsersError::CreateFailed
        );
        u.username = format!("renamed-{kind}");
        u.name = "Updated".into();
        u.enabled = Some(false);
        let renamed = u.username.clone();
        service
            .execute(
                auth(kind),
                AdminUsersRequest::Update {
                    username: &name,
                    user: &u,
                },
                csrf,
                end(),
            )
            .await
            .unwrap()
            .check()
            .unwrap();
        let row: (String, String, i64, i64) =
            f.db.query_row(
                "SELECT subject,identity_kind,revision,enabled FROM local_users WHERE username=?1",
                [&renamed],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, (subject.clone(), "service".into(), 2, 0));
        u.subject = "changed-subject".into();
        assert_eq!(
            service
                .execute(
                    auth(kind),
                    AdminUsersRequest::Update {
                        username: &renamed,
                        user: &u
                    },
                    csrf,
                    end()
                )
                .await
                .unwrap_err(),
            AdminUsersError::UpdateFailed
        );
        u.subject = subject;
        actions(&f.db, &["users.read"]);
        let inventory = service
            .execute(
                auth(kind),
                AdminUsersRequest::Credentials { username: &renamed },
                None,
                end(),
            )
            .await
            .unwrap();
        inventory.check().unwrap();
        let v: Value = serde_json::from_slice(inventory.body()).unwrap();
        assert_eq!(v, json!({"credentials":[]}));
        assert_eq!(
            service
                .execute(
                    auth(kind),
                    AdminUsersRequest::Delete { username: &renamed },
                    csrf,
                    end()
                )
                .await
                .unwrap_err(),
            AdminUsersError::Authorization(AdminBrokerSessionError::Forbidden)
        );
        actions(&f.db, &["users.write"]);
        service
            .execute(
                auth(kind),
                AdminUsersRequest::Delete { username: &renamed },
                csrf,
                end(),
            )
            .await
            .unwrap()
            .check()
            .unwrap();
    }
    actions(&f.db, &["users.write"]);
    let human = input("new-human", "human-subject", "", PASSWORD);
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Create(&human),
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_users WHERE username='new-human' AND identity_kind='human' AND password_change_required=1"
        ),
        1
    );
    for bad in [
        input("bad-user", "bad", "human", "short"),
        input("bad-user", "bad", "service", PASSWORD),
        input("bad user", "bad", "service", ""),
    ] {
        assert_eq!(
            opaque(
                &f.store,
                &f.engine,
                &raw,
                AdminUsersRequest::Create(&bad),
                end()
            )
            .await
            .unwrap_err(),
            AdminUsersError::CreateFailed
        );
    }
    bearer.close().await;
    op.close().await;
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_users_service_credential_issuance_verification_and_revocation() {
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    actions(&f.db, &["users.write", "users.read"]);
    let u = input("robot", "robot-subject", "service", "");
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Create(&u),
        end(),
    )
    .await
    .unwrap();
    let request = AdminServiceCredentialInput {
        client_id: String::new(),
        scopes: vec![" beta ".into(), "alpha".into(), "alpha".into()],
        expires_in: 0,
    };
    let (status, body) = opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::IssueCredential {
            username: "robot",
            input: &request,
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(status, 201);
    let v: Value = serde_json::from_slice(&body).unwrap();
    let token = Zeroizing::new(v["token"].as_str().unwrap().to_owned());
    let id = v["id"].as_str().unwrap();
    assert!(token.starts_with("gb_sc_"));
    assert_ne!(id, token.as_str());
    assert_eq!(v["scopes"], json!(["alpha", "beta"]));
    assert_eq!(v["token_type"], "Bearer");
    let verifier = f.store.local_bearer_verifier("admin-api", n(8192)).unwrap();
    let proof = verifier
        .verify(&token, &["alpha".into()], end())
        .await
        .unwrap();
    assert_eq!(proof.current_local_user().username(), "robot");
    // Isolate current-user predicates while this credential is still valid and unrevoked.
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='robot'",
        [],
    )
    .unwrap();
    assert!(verifier.verify(&token, &[], end()).await.is_err());
    f.db.execute(
        "UPDATE local_users SET enabled=1 WHERE username='robot'",
        [],
    )
    .unwrap();
    assert!(verifier.verify(&token, &[], end()).await.is_ok());
    f.db.execute(
        "UPDATE local_users SET revision=revision+1 WHERE username='robot'",
        [],
    )
    .unwrap();
    assert!(verifier.verify(&token, &[], end()).await.is_err());
    f.db.execute(
        "UPDATE local_users SET revision=revision-1 WHERE username='robot'",
        [],
    )
    .unwrap();
    assert!(verifier.verify(&token, &[], end()).await.is_ok());
    assert!(
        f.store
            .local_bearer_verifier("other-audience", n(8192))
            .unwrap()
            .verify(&token, &[], end())
            .await
            .is_err()
    );
    assert!(
        verifier
            .verify(&token, &["absent".into()], end())
            .await
            .is_err()
    );
    let stored: (String, String, String) =
        f.db.query_row(
            "SELECT token_hash,principal_json,client_id FROM local_tokens WHERE token_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(!stored.0.contains(token.as_str()));
    assert_eq!(stored.0.len(), 64);
    assert!(!stored.1.contains(token.as_str()));
    assert_eq!(stored.2, "robot");
    let (_, inventory) = opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Credentials { username: "robot" },
        end(),
    )
    .await
    .unwrap();
    let inv: Value = serde_json::from_slice(&inventory).unwrap();
    assert_eq!(inv["credentials"][0]["id"], id);
    assert!(inv["credentials"][0].get("revoked_at").is_none());
    assert!(!String::from_utf8_lossy(&inventory).contains(token.as_str()));
    for expires_in in [1, 3599, -1, 366 * 86400] {
        let bad = AdminServiceCredentialInput {
            expires_in,
            ..Default::default()
        };
        assert_eq!(
            opaque(
                &f.store,
                &f.engine,
                &raw,
                AdminUsersRequest::IssueCredential {
                    username: "robot",
                    input: &bad
                },
                end()
            )
            .await
            .unwrap_err(),
            AdminUsersError::InvalidCredential
        );
    }
    let mut small = limits();
    small.response_json_bytes = n(1);
    assert!(
        f.store
            .admin_users(&f.engine, &small)
            .unwrap()
            .execute(
                AdminReadAuthentication::Opaque {
                    raw: &raw,
                    audience: "admin-api",
                    identity_json_bytes: n(8192),
                    required_scopes: &[]
                },
                AdminUsersRequest::Credentials { username: "robot" },
                None,
                end()
            )
            .await
            .is_err()
    );
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::RevokeCredential {
            username: "robot",
            id,
        },
        end(),
    )
    .await
    .unwrap();
    assert!(verifier.verify(&token, &[], end()).await.is_err());
    let (_, inventory) = opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Credentials { username: "robot" },
        end(),
    )
    .await
    .unwrap();
    let inv: Value = serde_json::from_slice(&inventory).unwrap();
    assert!(inv["credentials"][0]["revoked_at"].is_string());
    assert_eq!(
        opaque(
            &f.store,
            &f.engine,
            &raw,
            AdminUsersRequest::RevokeCredential {
                username: "robot",
                id
            },
            end()
        )
        .await
        .unwrap_err(),
        AdminUsersError::CredentialRevokeFailed
    );
    let (_, expired_body) = opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::IssueCredential {
            username: "robot",
            input: &request,
        },
        end(),
    )
    .await
    .unwrap();
    let expired_json: Value = serde_json::from_slice(&expired_body).unwrap();
    let expired_token = Zeroizing::new(expired_json["token"].as_str().unwrap().to_owned());
    let expired_id = expired_json["id"].as_str().unwrap();
    f.db.execute(
        "UPDATE local_tokens SET expires_at=created_at+1 WHERE token_id=?1",
        [expired_id],
    )
    .unwrap();
    assert!(verifier.verify(&expired_token, &[], end()).await.is_err());
    let (_, inventory) = opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Credentials { username: "robot" },
        end(),
    )
    .await
    .unwrap();
    let inventory: Value = serde_json::from_slice(&inventory).unwrap();
    assert_eq!(inventory["credentials"].as_array().unwrap().len(), 2);
    assert!(
        inventory["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == expired_id && v.get("revoked_at").is_none())
    );
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='robot'",
        [],
    )
    .unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &f.engine,
            &raw,
            AdminUsersRequest::IssueCredential {
                username: "robot",
                input: &request
            },
            end()
        )
        .await
        .unwrap_err(),
        AdminUsersError::CredentialCreateFailed
    );
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Credentials { username: "robot" },
        end(),
    )
    .await
    .unwrap();
    let other = SqliteControlStore::open(
        ingress::fixture::config(&f.path),
        ingress::fixture::digester(),
        end(),
    )
    .await
    .unwrap();
    assert!(
        other
            .local_bearer_verifier("admin-api", n(8192))
            .unwrap()
            .verify(&token, &[], end())
            .await
            .is_err()
    );
    other.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}

struct Gate {
    target: &'static str,
    count: AtomicUsize,
    needed: usize,
    notify: tokio::sync::Notify,
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn new(target: &'static str, needed: usize) -> Arc<Self> {
        Arc::new(Self {
            target,
            count: AtomicUsize::new(0),
            needed,
            notify: tokio::sync::Notify::new(),
            released: Mutex::new(false),
            changed: Condvar::new(),
        })
    }
    async fn wait(&self) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let notified = self.notify.notified();
                if self.count.load(Ordering::SeqCst) >= self.needed {
                    break;
                }
                notified.await;
            }
        })
        .await
        .unwrap();
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
struct GateLayer(Arc<Gate>);
impl Layer<Registry> for GateLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, Registry>) {
        if event.metadata().target() != self.0.target {
            return;
        }
        assert_eq!(event.metadata().fields().len(), 1);
        if self.0.count.fetch_add(1, Ordering::SeqCst) >= self.0.needed {
            return;
        }
        self.0.notify.notify_waiters();
        let released = self.0.released.lock().unwrap();
        let (_released, timed) = self
            .0
            .changed
            .wait_timeout_while(released, Duration::from_secs(25), |v| !*v)
            .unwrap();
        assert!(
            !timed.timed_out(),
            "owned test observation was not released"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real KDF preflight SQL release, fresh authorization and factor expiry with longer Original"]
async fn sqlite_users_kdf_reobserves_authority_and_retains_factor_expiry() {
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    actions(&f.db, &["users.write"]);
    f.add_user("kdf-existing", "kdf-existing-subject").await;
    let engine = Arc::new(f.engine);
    for (i, mutation) in [
        "DELETE FROM role_permissions WHERE role='user'",
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
    ]
    .into_iter()
    .enumerate()
    {
        let gate = Gate::new("broker_control::sqlite::admin_users_before_hash", 1);
        let job = tokio::spawn({
            let s = f.store.clone();
            let e = engine.clone();
            let raw = Zeroizing::new(raw.to_string());
            let gate = gate.clone();
            async move {
                let u = input("kdf-target", "kdf-subject", "human", PASSWORD);
                opaque(&s, &e, &raw, AdminUsersRequest::Create(&u), end()).await
            }
            .with_subscriber(Registry::default().with(GateLayer(gate)))
        });
        gate.wait().await;
        f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
        f.db.execute(
            "INSERT INTO roles(name,created_at)VALUES(?1,0)",
            [format!("sql-free-{i}")],
        )
        .unwrap();
        f.db.execute_batch(mutation).unwrap();
        f.db.execute_batch("COMMIT").unwrap();
        gate.release();
        assert!(matches!(
            job.await.unwrap(),
            Err(AdminUsersError::Authorization(_))
        ));
        assert_eq!(
            count(
                &f.db,
                "SELECT count(*) FROM local_users WHERE username='kdf-target'"
            ),
            0
        );
        f.db.execute(
            "UPDATE local_users SET enabled=1 WHERE username='alice'",
            [],
        )
        .unwrap();
        actions(&f.db, &["users.write"]);
    }
    let original_hash: Zeroizing<String> = Zeroizing::new(
        f.db.query_row(
            "SELECT password_hash FROM local_users WHERE username='kdf-existing'",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    );
    let gate = Gate::new("broker_control::sqlite::admin_users_before_hash", 1);
    let job = tokio::spawn({
        let store = f.store.clone();
        let e = engine.clone();
        let raw = Zeroizing::new(raw.to_string());
        let gate = gate.clone();
        async move {
            let u = input(
                "kdf-existing",
                "kdf-existing-subject",
                "human",
                "a genuinely different administrative password",
            );
            opaque(
                &store,
                &e,
                &raw,
                AdminUsersRequest::Update {
                    username: "kdf-existing",
                    user: &u,
                },
                end(),
            )
            .await
        }
        .with_subscriber(Registry::default().with(GateLayer(gate)))
    });
    gate.wait().await;
    f.db.execute(
        "UPDATE local_users SET subject='recreated-subject' WHERE username='kdf-existing'",
        [],
    )
    .unwrap();
    gate.release();
    assert_eq!(
        job.await.unwrap().unwrap_err(),
        AdminUsersError::UpdateFailed
    );
    let unchanged: Zeroizing<String> = Zeroizing::new(
        f.db.query_row(
            "SELECT password_hash FROM local_users WHERE username='kdf-existing'",
            [],
            |r| r.get(0),
        )
        .unwrap(),
    );
    assert!(original_hash.as_str() == unchanged.as_str());
    f.db.execute(
        "UPDATE local_tokens SET expires_at=?1 WHERE token_id='persisted-opaque'",
        [utc() + 600_000],
    )
    .unwrap();
    let gate = Gate::new("broker_control::sqlite::admin_users_before_hash", 1);
    let job = tokio::spawn({
        let s = f.store.clone();
        let e = engine.clone();
        let raw = Zeroizing::new(raw.to_string());
        let gate = gate.clone();
        async move {
            let u = input("expired-kdf", "expired-kdf-subject", "human", PASSWORD);
            opaque(&s, &e, &raw, AdminUsersRequest::Create(&u), end()).await
        }
        .with_subscriber(Registry::default().with(GateLayer(gate)))
    });
    gate.wait().await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    gate.release();
    let error = job.await.unwrap().unwrap_err();
    assert!(
        matches!(
            error,
            AdminUsersError::Authorization(AdminBrokerSessionError::Authentication(_))
        ),
        "factor must take authentication category: {error:?}"
    );
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_users WHERE username='expired-kdf'"
        ),
        0
    );
    f.store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_users_commit_uncertainty_and_cancellation_do_not_release_secret() {
    use std::{future::Future, task::Poll};
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    actions(&f.db, &["users.write"]);
    let engine = Arc::new(f.engine);
    let u = input("ack-robot", "ack-subject", "service", "");
    opaque(
        &f.store,
        &engine,
        &raw,
        AdminUsersRequest::Create(&u),
        end(),
    )
    .await
    .unwrap();
    let gate = Gate::new("broker_control::sqlite::admin_users_commit_ack", 1);
    let mut job = tokio::spawn({
        let s = f.store.clone();
        let e = engine.clone();
        let raw = Zeroizing::new(raw.to_string());
        let gate = gate.clone();
        async move {
            let r = AdminServiceCredentialInput::default();
            opaque(
                &s,
                &e,
                &raw,
                AdminUsersRequest::IssueCredential {
                    username: "ack-robot",
                    input: &r,
                },
                Instant::now() + Duration::from_secs(3),
            )
            .await
        }
        .with_subscriber(Registry::default().with(GateLayer(gate)))
    });
    tokio::select! {
        biased;
        () = gate.wait() => {},
        result = &mut job => {
            gate.release();
            match result {
                Ok(Err(error)) => panic!("credential issuance failed before the commit was observed: {error:?}"),
                Ok(Ok(_)) => panic!("credential issuance returned before the commit was observed"),
                Err(error) => panic!("credential issuance task failed before the commit was observed: {error}"),
            }
        }
    }
    let committed = count(
        &f.db,
        "SELECT count(*) FROM local_tokens WHERE subject='ack-subject'",
    );
    let outcome = job.await;
    gate.release();
    assert_eq!(committed, 1);
    let error = outcome
        .unwrap()
        .expect_err("credential secret must remain withheld without acknowledgement");
    assert_eq!(
        error,
        AdminUsersError::Authorization(AdminBrokerSessionError::Control(
            ControlError::OutcomeUncertain
        ))
    );
    // A known independent read joins the actual owner before the next operation.
    f.store
        .resource_grants(n(65536))
        .unwrap()
        .read(end())
        .await
        .unwrap();
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let cancelled = input("cancelled-user", "cancelled-subject", "service", "");
    let mut pending = Box::pin(opaque(
        &f.store,
        &engine,
        &raw,
        AdminUsersRequest::Create(&cancelled),
        end(),
    ));
    std::future::poll_fn(|cx| {
        assert!(matches!(pending.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    drop(pending);
    f.db.execute_batch("ROLLBACK").unwrap();
    f.store
        .resource_grants(n(65536))
        .unwrap()
        .read(end())
        .await
        .unwrap();
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_users WHERE username='cancelled-user'"
        ),
        0
    );
    f.db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let deadline = opaque(
        &f.store,
        &engine,
        &raw,
        AdminUsersRequest::Create(&cancelled),
        Instant::now() + Duration::from_millis(100),
    )
    .await;
    f.db.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        deadline.unwrap_err(),
        AdminUsersError::Authorization(AdminBrokerSessionError::Control(ControlError::Deadline))
    );
    f.store.shutdown(end()).await.unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &engine,
            &raw,
            AdminUsersRequest::Create(&cancelled),
            end()
        )
        .await
        .unwrap_err(),
        AdminUsersError::Authorization(AdminBrokerSessionError::Control(ControlError::Closed))
    );
}
fn limiter() -> Arc<LocalMfaAttemptLimiter> {
    Arc::new(LocalMfaAttemptLimiter::new(
        LocalMfaAttemptPolicy::new(
            NonZeroU32::new(10).unwrap(),
            Duration::from_secs(60),
            Duration::from_secs(60),
            n(16),
        )
        .unwrap(),
    ))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real enrollment, disabled-user administrative reset and mandatory re-enrollment"]
async fn sqlite_users_mfa_reset_invalidates_local_and_requires_real_reenrollment() {
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    actions(&f.db, &["users.write"]);
    f.add_user("mfa-human", "mfa-subject").await;
    let p = Arc::new(
        LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(120)).unwrap(),
    );
    let auth = f.store.local_auth_service(
        Arc::new(ingress::fixture::digester()),
        Arc::new(LocalMfaProtector::new(Zeroizing::new(vec![47; 32].into_boxed_slice())).unwrap()),
        p,
    );
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("mfa-human", PASSWORD, end())
        .await
        .unwrap();
    let LocalAuthStep::Pending(enrollment) = auth
        .begin(proof, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    else {
        panic!("enrollment")
    };
    assert_eq!(enrollment.stage(), LocalAuthStage::Enrollment);
    let sdk = totp_rs::Totp::from_url(enrollment.enrollment().unwrap().otpauth_uri()).unwrap();
    let code = Zeroizing::new(sdk.generate(utc() as u64 / 1_000_000).to_string());
    let LocalAuthStep::Complete(mut completed) = auth
        .complete_mfa(
            limiter(),
            enrollment.challenge(),
            LocalAuthBinding::AdminLogin,
            &code,
            end(),
        )
        .await
        .unwrap()
    else {
        panic!("genuine MFA completion")
    };
    let recovery = completed.take_recovery_codes().unwrap();
    assert_eq!(recovery.iter().count(), 10);
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_mfa WHERE subject='mfa-subject'"
        ),
        1
    );
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("mfa-human", PASSWORD, end())
        .await
        .unwrap();
    let LocalAuthStep::Pending(old) = auth
        .begin(proof, LocalAuthBinding::DeviceApprove(b"RESET123"), end())
        .await
        .unwrap()
    else {
        panic!("MFA challenge")
    };
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username='mfa-human'",
        [],
    )
    .unwrap();
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::ResetMfa {
            username: "mfa-human",
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_mfa WHERE subject='mfa-subject'"
        ),
        0
    );
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_mfa_recovery_codes WHERE subject='mfa-subject'"
        ),
        0
    );
    assert!(
        auth.load(
            old.challenge(),
            LocalAuthBinding::DeviceApprove(b"RESET123"),
            end()
        )
        .await
        .is_err()
    );
    f.db.execute(
        "UPDATE local_users SET enabled=1 WHERE username='mfa-human'",
        [],
    )
    .unwrap();
    let proof = f
        .store
        .local_password_verifier(&f.engine)
        .verify("mfa-human", PASSWORD, end())
        .await
        .unwrap();
    let LocalAuthStep::Pending(next) = auth
        .begin(proof, LocalAuthBinding::AdminLogin, end())
        .await
        .unwrap()
    else {
        panic!("fresh enrollment")
    };
    assert_eq!(next.stage(), LocalAuthStage::Enrollment);
    assert_ne!(
        next.enrollment().unwrap().otpauth_uri(),
        enrollment.enrollment().unwrap().otpauth_uri()
    );
    let before = count(
        &f.db,
        "SELECT revision FROM local_users WHERE username='mfa-human'",
    );
    let mut update = input("renamed-human", "mfa-subject", "human", "");
    update.password_change_required = false;
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Update {
            username: "mfa-human",
            user: &update,
        },
        end(),
    )
    .await
    .unwrap();
    assert_eq!(
        count(
            &f.db,
            "SELECT revision FROM local_users WHERE username='renamed-human'"
        ),
        before + 1
    );
    assert!(
        f.store
            .local_password_verifier(&f.engine)
            .verify("renamed-human", PASSWORD, end())
            .await
            .is_ok()
    );
    assert!(
        auth.load(next.challenge(), LocalAuthBinding::AdminLogin, end())
            .await
            .is_err()
    );
    f.store.shutdown(end()).await.unwrap();
}

pub fn client(id: &str) -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: id.into(),
        client_id: id.into(),
        client_secret: None,
        redirect_url: "https://broker.example/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: true,
        claims_source: UpstreamBrowserClaimsSource::IdToken,
        id_token_additional_audiences: vec![],
    }
}
pub fn register(issuer: &BrowserIssuer, id: &str) {
    issuer.register(ClientRegistration {
        id: id.into(),
        secret: None,
        redirect: client(id).redirect_url.clone(),
        auth: ClientAuth::Public,
    });
}
pub fn configured(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamProviderConfig {
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec![],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["public".into(), "other".into()],
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "mapped_subject".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: selector.map(str::to_owned),
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
pub fn verifier(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamBearerVerifier {
    UpstreamBearerVerifier::new(
        ingress::fixture::ISSUER,
        n(16384),
        vec![configured(issuer, clients, selector)],
    )
    .unwrap()
}

async fn new_op() -> BrowserIssuer {
    let op = BrowserIssuer::new().await;
    let mut fault = ingress::browser::Fault::default();
    fault
        .id_overrides
        .insert("mapped_subject".into(), json!("alice-subject"));
    fault.id_overrides.insert("roles".into(), json!(["editor"]));
    op.fault(fault);
    op
}
async fn proof(
    f: &Fixture,
    op: &BrowserIssuer,
    verifier: &UpstreamBearerVerifier,
    request: &str,
    original: Instant,
) -> VerifiedUpstreamLogin {
    let login = f.store.upstream_logins(verifier);
    let issued = login
        .begin(
            FlowContinuation::OAuth {
                provider_id: verifier.browser_options(end()).unwrap()[0].id.clone(),
                request_id: request.into(),
            },
            original,
        )
        .await
        .unwrap();
    let code = op.authorize(&issued).await;
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
async fn code(
    f: &Fixture,
    op: &BrowserIssuer,
    verifier: Arc<UpstreamBearerVerifier>,
    dynamic: bool,
) -> AuthorizedOidcAuthorization {
    let auth = f.store.browser_oidc_authorizations(f.authorization.clone());
    let mut input = ingress::fixture::request(dynamic, true);
    input.state = "literal-state\0kept";
    input.nonce = "literal-nonce\0kept";
    let pending = auth.create(input, end()).await.unwrap();
    let login = proof(f, op, &verifier, pending.request(), end()).await;
    auth.complete_upstream(login, verifier, end())
        .await
        .unwrap()
}

use ingress::browser::{BrowserIssuer, ClientAuth, ClientRegistration};
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real LOCAL and federated same-subject OAuth grants, corrupt codec rollback and administrative invalidation"]
async fn sqlite_users_update_delete_preserve_federated_same_subject_and_atomicity() {
    let f = Fixture::new().await;
    let mut op = new_op().await;
    register(&op, "public");
    let trust = Arc::new(verifier(&op, vec![client("public")], Some("roles")));
    let fed = code(&f, &op, trust.clone(), false).await;
    let issued = f
        .producer()
        .with_upstream(trust.clone())
        .exchange(ingress::fixture::exchange(fed.code(), false), end())
        .await
        .unwrap();
    let pending_fed = code(&f, &op, trust.clone(), false).await;
    let local = f.code(false, true).await;
    let local_tokens = f
        .producer()
        .exchange(ingress::fixture::exchange(local.code(), false), end())
        .await
        .unwrap();
    let pending_local = f.code(false, false).await;
    let raw = ingress::persisted_opaque(&f);
    actions(&f.db, &["users.write"]);
    let before = count(
        &f.db,
        "SELECT revision FROM local_users WHERE username='alice'",
    );
    let code_hash = ingress::fixture::digester()
        .token(
            ingress::fixture::TokenKind::OidcAuthorizationCode,
            pending_fed.code().as_bytes(),
        )
        .unwrap()
        .to_sql_hex();
    let original: String =
        f.db.query_row(
            "SELECT request_json FROM oidc_auth_requests WHERE code_hash=?1",
            [&code_hash],
            |r| r.get(0),
        )
        .unwrap();
    f.db.execute("UPDATE oidc_auth_requests SET request_json='{' WHERE identity_subject='alice-subject' AND request_json=?1",[&original]).unwrap();
    let mut update = input("alice-renamed", "alice-subject", "human", "");
    update.name = "Current profile".into();
    assert!(
        opaque(
            &f.store,
            &f.engine,
            &raw,
            AdminUsersRequest::Update {
                username: "alice",
                user: &update
            },
            end()
        )
        .await
        .is_err()
    );
    assert_eq!(
        count(
            &f.db,
            "SELECT revision FROM local_users WHERE username='alice'"
        ),
        before
    );
    assert!(f.code_exists(pending_local.code()));
    f.db.execute(
        "UPDATE oidc_auth_requests SET request_json=?1 WHERE request_json='{'",
        [&original],
    )
    .unwrap();
    // Known self-edit ACK must survive the same transaction invalidating this actual opaque proof.
    opaque(
        &f.store,
        &f.engine,
        &raw,
        AdminUsersRequest::Update {
            username: "alice",
            user: &update,
        },
        end(),
    )
    .await
    .unwrap();
    assert!(!f.code_exists(pending_local.code()));
    assert!(f.code_exists(pending_fed.code()));
    assert!(
        f.store
            .local_bearer_verifier("admin-api", n(8192))
            .unwrap()
            .verify(&raw, &[], end())
            .await
            .is_err()
    );
    assert!(
        f.store
            .oidc_userinfo(f.authorization.clone(), f.verifier())
            .unwrap()
            .profile(local_tokens.access_token(), end())
            .await
            .is_err()
    );
    assert!(
        f.rotator()
            .rotate(
                ingress::fixture::refresh(local_tokens.refresh_token().unwrap(), false),
                end()
            )
            .await
            .is_err()
    );
    f.store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(trust.clone())
        .profile(issued.access_token(), end())
        .await
        .unwrap();
    let mut bearer = ingress::upstream::UpstreamFixture::new().await;
    let upstream = ingress::trust(vec![ingress::config(
        &bearer.issuer,
        &bearer.ca,
        false,
        Some("roles"),
    )]);
    let token = bearer.sign(&bearer.claims(), "upstream-key", "at+jwt");
    f.store
        .admin_users(&f.engine, &limits())
        .unwrap()
        .execute(
            AdminReadAuthentication::Upstream {
                raw: &token,
                verifier: &upstream,
            },
            AdminUsersRequest::Delete {
                username: "alice-renamed",
            },
            None,
            end(),
        )
        .await
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_users WHERE subject='alice-subject'"
        ),
        0
    );
    assert!(f.code_exists(pending_fed.code()));
    f.store
        .oidc_userinfo(f.authorization.clone(), f.verifier())
        .unwrap()
        .with_upstream(trust)
        .profile(issued.access_token(), end())
        .await
        .unwrap();
    bearer.close().await;
    op.close().await;
    f.store.shutdown(end()).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_users_last_admin_concurrent_owners_and_disabled_target() {
    let f = Fixture::new().await;
    let raw = ingress::persisted_opaque(&f);
    f.add_user("admin-b", "subject-b").await;
    f.add_user("admin-c", "subject-c").await;
    f.db.execute("INSERT INTO role_assignments(subject,role,created_at)VALUES('local|subject-b','admin',0),('local|subject-c','admin',0)",[]).unwrap();
    let second = SqliteControlStore::open(
        ingress::fixture::config(&f.path),
        ingress::fixture::digester(),
        end(),
    )
    .await
    .unwrap();
    actions(&f.db, &["users.write"]);
    let (b, c) = tokio::join!(
        opaque(
            &f.store,
            &f.engine,
            &raw,
            AdminUsersRequest::Delete {
                username: "admin-b"
            },
            end()
        ),
        opaque(
            &second,
            &f.engine,
            &raw,
            AdminUsersRequest::Delete {
                username: "admin-c"
            },
            end()
        )
    );
    assert_eq!(usize::from(b.is_ok()) + usize::from(c.is_ok()), 1);
    let error = if let Err(e) = b { e } else { c.unwrap_err() };
    assert_eq!(error, AdminUsersError::DeleteFailed);
    assert_eq!(
        count(
            &f.db,
            "SELECT count(*) FROM local_users WHERE username IN ('admin-b','admin-c')"
        ),
        1
    );
    let remaining: String =
        f.db.query_row(
            "SELECT username FROM local_users WHERE username IN ('admin-b','admin-c')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    f.db.execute(
        "UPDATE local_users SET enabled=0 WHERE username=?1",
        [&remaining],
    )
    .unwrap();
    assert_eq!(
        opaque(
            &f.store,
            &f.engine,
            &raw,
            AdminUsersRequest::Delete {
                username: &remaining
            },
            end()
        )
        .await
        .unwrap_err(),
        AdminUsersError::DeleteFailed
    );
    let subject: String =
        f.db.query_row(
            "SELECT subject FROM local_users WHERE username=?1",
            [&remaining],
            |r| r.get(0),
        )
        .unwrap();
    let mut demote = input(&remaining, &subject, "human", "");
    demote.enabled = Some(false);
    assert_eq!(
        opaque(
            &f.store,
            &f.engine,
            &raw,
            AdminUsersRequest::Update {
                username: &remaining,
                user: &demote
            },
            end()
        )
        .await
        .unwrap_err(),
        AdminUsersError::UpdateFailed
    );
    second.shutdown(end()).await.unwrap();
    f.store.shutdown(end()).await.unwrap();
}
