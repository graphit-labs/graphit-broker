#[path = "support/sqlite_storage_admission_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared physical fixtures serve independent SQL and HTTP targets"
)]
mod fixture;
use broker_control::{
    BrokerAccessError, ControlError, LocalBearerVerificationError, ResourceGrantReadError,
    StorageAdmissionError as Error, StorageModule, StorageScope,
};
use fixture::*;
use serde_json::json;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real private SQLite, Ed25519 verification and controlled human/service opaque possession"]
async fn sqlite_storage_admits_seven_scopes_and_current_possession() {
    let f = Fixture::new().await;
    let raw = f.signer.sign(&f.signer.claims());
    f.grant("all", &Rule::all());
    for scope in scopes() {
        let jwt = native(&f, &raw, &scope).await.unwrap();
        let human = opaque(&f, &f.access, &scope).await.unwrap();
        let service = opaque(&f, &f.service, &scope).await.unwrap();
        for observed in [&jwt, &human, &service] {
            assert_eq!(observed.route, "configured");
            assert_eq!(observed.revision, f.revision());
            assert!(observed.original > Instant::now());
            assert!(observed.access.iter().all(|prefixes| !prefixes.is_empty()));
            assert_eq!(observed.access[0], observed.access[1]);
            assert_eq!(observed.access[1], observed.access[2]);
            assert_eq!(observed.access[2], observed.access[3]);
        }
        assert_eq!(jwt.subject, format!("{ISSUER}|native-subject"));
        assert_eq!(human.subject, "local|alice-subject");
        assert_eq!(service.subject, "local|bot-subject");
        if let Some(project) = scope.project_id() {
            if scope.module() == StorageModule::Hub {
                let mut roots = ["registry", "artifacts", "hub/metadata", "hub/events"]
                    .map(|part| format!("v1/projects/{project}/{part}"));
                roots.sort();
                assert_eq!(jwt.access[0], roots);
            } else {
                assert_eq!(
                    jwt.access[0],
                    vec![format!(
                        "v1/projects/{project}/corpora/{}",
                        scope.module().as_str()
                    )]
                );
            }
            assert_eq!(jwt.access, human.access);
            assert_eq!(jwt.access, service.access);
        } else if scope.installation_id().is_some() {
            for prefix in [
                &jwt.access[0][0],
                &human.access[0][0],
                &service.access[0][0],
            ] {
                assert!(prefix.starts_with("v1/installations/Install-A/users/"));
                assert!(prefix.ends_with("/corpora/memory"));
                let key = prefix.split('/').nth(4).unwrap();
                assert_eq!(key.len(), 64);
                assert!(
                    key.bytes()
                        .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
                );
            }
            assert_ne!(jwt.access, human.access);
            assert_ne!(human.access, service.access);
        } else {
            assert_eq!(
                jwt.access[0],
                vec!["v1/hub/global/registry", "v1/hub/global/rules"]
            );
            assert_eq!(jwt.access, human.access);
        }
    }
    let user = StorageScope::user_memory("Install-A").unwrap();
    let prior = opaque(&f, &f.access, &user).await.unwrap();
    f.db.execute("UPDATE local_users SET name='Changed',organization='changed-org',teams_json='[]' WHERE username='alice'",[]).unwrap();
    assert_eq!(
        opaque(&f, &f.access, &user).await.unwrap().access,
        prior.access
    );
    f.clear();
    f.grant(
        "literal",
        &Rule {
            kind: "user",
            principal: "alice*",
            ..Rule::all()
        },
    );
    assert!(matches!(
        opaque(&f, &f.access, &user).await,
        Err(Error::Forbidden)
    ));
    f.clear();
    f.grant(
        "literal",
        &Rule {
            kind: "user",
            principal: "alice",
            ..Rule::all()
        },
    );
    opaque(&f, &f.access, &user).await.unwrap();
    assert!(matches!(
        opaque(&f, &f.service, &user).await,
        Err(Error::Forbidden)
    ));
    f.clear();
    f.grant("all", &Rule::all());
    for statement in [
        "UPDATE local_users SET enabled=0 WHERE username='alice'",
        "UPDATE local_users SET revision=2 WHERE username='alice'",
        "UPDATE local_tokens SET revoked_at=0 WHERE token_kind='access'",
    ] {
        f.db.execute_batch(statement).unwrap();
        assert!(matches!(
            opaque(&f, &f.access, &user).await,
            Err(Error::Local(LocalBearerVerificationError::Unauthenticated))
        ));
        f.db.execute_batch("UPDATE local_users SET enabled=1,revision=1 WHERE username='alice';UPDATE local_tokens SET revoked_at=NULL WHERE token_kind='access'").unwrap();
    }
    f.db.execute(
        "UPDATE local_tokens SET revoked_at=0 WHERE token_kind='service'",
        [],
    )
    .unwrap();
    assert!(matches!(
        opaque(&f, &f.service, &user).await,
        Err(Error::Local(LocalBearerVerificationError::Unauthenticated))
    ));
    f.db.execute(
        "UPDATE local_tokens SET revoked_at=NULL WHERE token_kind='service'",
        [],
    )
    .unwrap();
    let reopened = f.reopen().await;
    let verifier = f.signer.verifier();
    let factory = reopened
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    let grant = factory
        .authorize(&raw, &["storage".into()], &user, end())
        .await
        .unwrap();
    assert_eq!(
        observe(&grant).access,
        native(&f, &raw, &user).await.unwrap().access
    );
    reopened.shutdown(end()).await.unwrap();
    f.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "factory identity, fresh ACL ACK, exact policy contributors and route confinement"]
async fn sqlite_storage_factory_binding_and_policy_are_current() {
    let f = Fixture::new().await;
    f.grant("all", &Rule::all());
    let raw = f.signer.sign(&f.signer.claims());
    let verifier = f.signer.verifier();
    let other_verifier = f.signer.verifier();
    let one = f
        .store
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    let two = f
        .store
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    let wrong_verifier = f
        .store
        .broker_storage_authorizer(&other_verifier, n(65536), "configured")
        .unwrap();
    let local = f
        .store
        .local_storage_authorizer(AUDIENCE, n(8192), n(65536), "configured")
        .unwrap();
    let local_again = f
        .store
        .local_storage_authorizer(AUDIENCE, n(8192), n(65536), "configured")
        .unwrap();
    let local_other_audience = f
        .store
        .local_storage_authorizer("another-audience", n(8192), n(65536), "configured")
        .unwrap();
    let scope = StorageScope::project(A, StorageModule::Memory).unwrap();
    // Invalid binding is rejected before attempting to decode this deliberately corrupt ACL.
    f.db.execute(
        "UPDATE resource_grants SET principal=zeroblob(1) WHERE id='all'",
        [],
    )
    .unwrap();
    for target in [&two, &wrong_verifier] {
        let caller = one.authenticate(&raw, &["storage".into()], end()).unwrap();
        assert_eq!(
            target
                .authorize_authenticated(caller, &scope)
                .await
                .unwrap_err(),
            Error::InvalidConfiguration
        );
    }
    let caller = one.authenticate(&raw, &[], end()).unwrap();
    assert_eq!(
        local
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    for target in [&local_again, &local_other_audience] {
        let caller = local
            .authenticate(&f.access, &["storage".into()], end())
            .await
            .unwrap();
        assert_eq!(
            target
                .authorize_authenticated(caller, &scope)
                .await
                .unwrap_err(),
            Error::InvalidConfiguration
        );
    }
    let caller = local.authenticate(&f.access, &[], end()).await.unwrap();
    assert_eq!(
        one.authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert!(matches!(
        one.authorize(&raw, &[], &scope, end()).await,
        Err(Error::Grants(ResourceGrantReadError::MalformedStored))
    ));
    f.db.execute("UPDATE resource_grants SET principal='' WHERE id='all'", [])
        .unwrap();
    let second = f.reopen().await;
    let foreign = second
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    assert_eq!(
        foreign
            .authorize_authenticated(one.authenticate(&raw, &[], end()).unwrap(), &scope)
            .await
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        f.store
            .broker_storage_authorizer(&verifier, n(65536), "   ")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    assert_eq!(
        f.store
            .broker_storage_authorizer(&verifier, n(usize::MAX), "configured")
            .unwrap_err(),
        Error::InvalidConfiguration
    );
    let empty_audience = f
        .store
        .local_storage_authorizer(" ", n(8192), n(65536), "configured")
        .unwrap();
    assert!(matches!(
        empty_audience.authenticate(&f.access, &[], end()).await,
        Err(Error::Local(LocalBearerVerificationError::Unauthenticated))
    ));
    let tiny = f
        .store
        .broker_storage_authorizer(&verifier, n(2), "configured")
        .unwrap();
    assert!(matches!(
        tiny.authorize(&raw, &[], &scope, end()).await,
        Err(Error::Grants(ResourceGrantReadError::ReadLimitExceeded))
    ));
    let caller = one.authenticate(&raw, &[], end()).unwrap();
    f.db.execute(
        "UPDATE resource_acl_state SET revision=revision+1 WHERE id=1",
        [],
    )
    .unwrap();
    f.db.execute(
        "UPDATE resource_grants SET s3_route='updated-route' WHERE id='all'",
        [],
    )
    .unwrap();
    let grant = one.authorize_authenticated(caller, &scope).await.unwrap();
    assert_eq!(grant.route(), "updated-route");
    assert_eq!(grant.revision(), f.revision());
    f.clear();
    grant.check().unwrap();
    assert!(matches!(
        one.authorize(&raw, &[], &scope, end()).await,
        Err(Error::Forbidden)
    ));

    // Operation capability and operation mask must match within the same contributing rule.
    f.grant(
        "read-wrong-mask",
        &Rule {
            caps: &["s3:read"],
            operations: &["write"],
            ..Rule::all()
        },
    );
    f.grant(
        "write-wrong-mask",
        &Rule {
            caps: &["s3:write"],
            operations: &["read"],
            ..Rule::all()
        },
    );
    assert!(matches!(
        native(&f, &raw, &scope).await,
        Err(Error::Forbidden)
    ));
    f.clear();
    f.grant(
        "bounded",
        &Rule {
            caps: &["s3:r*"],
            projects: &[A],
            operations: &["r*", "write"],
            prefixes: &[&format!("v1/projects/{A}/corpora/memory/inside")],
            route: "bounded",
            ..Rule::all()
        },
    );
    let bounded = native(&f, &raw, &scope).await.unwrap();
    assert_eq!(
        bounded.access[0],
        vec![format!("v1/projects/{A}/corpora/memory/inside")]
    );
    assert!(bounded.access[1..].iter().all(Vec::is_empty));
    assert!(matches!(
        native(
            &f,
            &raw,
            &StorageScope::project(B, StorageModule::Memory).unwrap()
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        native(
            &f,
            &raw,
            &StorageScope::project(A, StorageModule::Task).unwrap()
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        native(&f, &raw, &StorageScope::user_memory("Install-A").unwrap()).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        native(&f, &raw, &StorageScope::global_hub()).await,
        Err(Error::Forbidden)
    ));
    f.clear();
    f.grant(
        "hub-only",
        &Rule {
            caps: &["hub"],
            route: "does-not-contribute",
            ..Rule::all()
        },
    );
    f.grant(
        "s3",
        &Rule {
            caps: &["s3"],
            route: "selected",
            ..Rule::all()
        },
    );
    assert_eq!(
        native(&f, &raw, &StorageScope::global_hub())
            .await
            .unwrap()
            .route,
        "selected"
    );
    f.grant(
        "other",
        &Rule {
            caps: &["s3:read"],
            route: "conflict",
            ..Rule::all()
        },
    );
    assert!(matches!(
        native(&f, &raw, &StorageScope::global_hub()).await,
        Err(Error::ConflictingRoutes)
    ));
    f.clear();
    f.grant(
        "hub-lookalike",
        &Rule {
            caps: &["hub:admin", "s3"],
            ..Rule::all()
        },
    );
    assert!(matches!(
        native(&f, &raw, &StorageScope::global_hub()).await,
        Err(Error::Forbidden)
    ));
    f.clear();
    f.grant(
        "hub",
        &Rule {
            caps: &["hub*", "s3"],
            ..Rule::all()
        },
    );
    assert!(native(&f, &raw, &StorageScope::global_hub()).await.is_ok());
    f.clear();
    f.grant(
        "hub-only",
        &Rule {
            caps: &["hub"],
            ..Rule::all()
        },
    );
    f.grant(
        "template-without-project",
        &Rule {
            caps: &["s3"],
            prefixes: &["v1/projects/{project}"],
            route: "irrelevant",
            ..Rule::all()
        },
    );
    assert!(matches!(
        native(&f, &raw, &StorageScope::global_hub()).await,
        Err(Error::Forbidden)
    ));
    f.clear();
    f.grant("all", &Rule::all());
    f.grant(
        "irrelevant-invalid",
        &Rule {
            kind: "user",
            principal: "nobody",
            prefixes: &["../escape"],
            ..Rule::all()
        },
    );
    assert!(matches!(
        native(&f, &raw, &scope).await,
        Err(Error::InvalidPolicy)
    ));
    second.shutdown(end()).await.unwrap();
    f.close().await;
}

#[tokio::test]
#[ignore = "native SQLite snapshot, expiring proof before corrupt ACL error, Original, closed and recovery"]
async fn sqlite_storage_negative_acl_errors_keep_factor_and_original_causality() {
    let f = Fixture::new().await;
    f.grant("all", &Rule::all());
    let verifier = f.signer.verifier();
    let factory = f
        .store
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    let scope = StorageScope::project(A, StorageModule::Task).unwrap();
    f.db.execute(
        "UPDATE resource_grants SET principal=zeroblob(1) WHERE id='all'",
        [],
    )
    .unwrap();
    let mut claims = f.signer.claims();
    let expires = seconds() + 2;
    claims["exp"] = json!(expires);
    let raw = f.signer.sign(&claims);
    let caller = factory
        .authenticate(&raw, &["storage".into()], end())
        .unwrap();
    caller.check().unwrap();
    let until = UNIX_EPOCH + Duration::from_secs(expires);
    tokio::time::sleep(until.duration_since(SystemTime::now()).unwrap_or_default()).await;
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::Native(BrokerAccessError::Expired)
    );
    f.db.execute("UPDATE resource_grants SET principal='' WHERE id='all'", [])
        .unwrap();
    let fresh = f.signer.sign(&f.signer.claims());
    let deadline = Instant::now() + Duration::from_millis(150);
    let caller = factory.authenticate(&fresh, &[], deadline).unwrap();
    tokio::time::sleep_until(deadline.into()).await;
    assert_eq!(
        factory
            .authorize_authenticated(caller, &scope)
            .await
            .unwrap_err(),
        Error::Deadline
    );
    f.store
        .resource_grants(n(65536))
        .unwrap()
        .read(end())
        .await
        .unwrap();
    let recovered = f.reopen().await;
    let recovering = recovered
        .broker_storage_authorizer(&verifier, n(65536), "configured")
        .unwrap();
    recovering
        .authorize(&fresh, &[], &scope, end())
        .await
        .unwrap()
        .check()
        .unwrap();
    f.store.shutdown(end()).await.unwrap();
    assert!(matches!(
        factory.authorize(&fresh, &[], &scope, end()).await,
        Err(Error::Grants(ResourceGrantReadError::Control(
            ControlError::Closed
        )))
    ));
    let local = f
        .store
        .local_storage_authorizer(AUDIENCE, n(8192), n(65536), "configured")
        .unwrap();
    assert!(matches!(
        local.authenticate(&f.access, &[], end()).await,
        Err(Error::Local(_))
    ));
    recovered.shutdown(end()).await.unwrap();
}
