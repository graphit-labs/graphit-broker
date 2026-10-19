#[path = "support/sqlite_oidc_fixture.rs"]
#[allow(
    dead_code,
    unused_imports,
    reason = "shared issuer fixture provides a real configured Broker verifier"
)]
mod issuer;
#[path = "support/sqlite_admin_fixture.rs"]
#[allow(
    dead_code,
    reason = "shared genuine LOCAL human/service fixtures also serve administration"
)]
mod opaque;
#[allow(
    dead_code,
    reason = "shared PostgreSQL support also serves other SQL tests"
)]
mod support;

use broker_control::{
    ControlError, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
    RerankAdmissionError, RerankAdmissionLimits,
};
use opaque::{Fixture, end, n};
use rusqlite::params;
use sqlx_core::{connection::Connection, executor::Executor};
use std::{
    num::NonZeroU16,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn limits() -> RerankAdmissionLimits {
    RerankAdmissionLimits {
        identity_json_bytes: n(8192),
        grants_json_bytes: n(16384),
    }
}
fn grants(f: &Fixture, access: &str, capability: &str) {
    let db = f.db();
    db.execute_batch("DELETE FROM grant_capabilities;DELETE FROM grant_projects;DELETE FROM grant_s3_operations;DELETE FROM grant_s3_prefixes;DELETE FROM resource_grants;").unwrap();
    db.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('rerank-fixture','fixture',?1,'','',0,0)",params![access]).unwrap();
    db.execute(
        "INSERT INTO grant_capabilities(grant_id,value)VALUES('rerank-fixture',?1)",
        params![capability],
    )
    .unwrap();
    db.execute("INSERT INTO resource_acl_state(id,revision,updated_at)VALUES(1,1,0) ON CONFLICT(id) DO UPDATE SET revision=revision+1",[]).unwrap();
}

#[tokio::test]
async fn sqlite_rerank_is_separate_from_embeddings_and_scoped_to_current_identity() {
    let f = Fixture::new().await;
    let issuer = issuer::Fixture::new().await;
    let verifier = issuer.verifier();
    let scopes = Vec::new();
    let admissions = f
        .store
        .rerank_admissions(&verifier, None, "admin-api", &scopes, limits())
        .unwrap();
    grants(&f, "authenticated", "embeddings");
    assert!(matches!(
        admissions.authorize(Some(&f.access), end()).await,
        Err(RerankAdmissionError::Forbidden)
    ));
    assert!(
        f.store
            .embedding_admissions(
                &verifier,
                None,
                "admin-api",
                &scopes,
                broker_control::EmbeddingAdmissionLimits {
                    identity_json_bytes: n(8192),
                    grants_json_bytes: n(16384)
                }
            )
            .unwrap()
            .authorize(Some(&f.access), end())
            .await
            .is_ok()
    );
    grants(&f, "authenticated", "rerank");
    let mut human = admissions.authorize(Some(&f.access), end()).await.unwrap();
    let service = admissions.authorize(Some(&f.service), end()).await.unwrap();
    assert_ne!(human.cache_scope(), service.cache_scope());
    human.check().unwrap();
    assert!(matches!(
        admissions.authorize(None, end()).await,
        Err(RerankAdmissionError::Forbidden)
    ));
    let before = human.authorization_revision();
    grants(&f, "authenticated", "rerank*");
    let current = admissions.authorize(Some(&f.access), end()).await.unwrap();
    assert!(current.authorization_revision() > before);
    assert_eq!(human.cache_scope(), current.cache_scope());
    grants(&f, "authenticated", "embeddings");
    assert!(matches!(
        admissions.authorize(Some(&f.access), end()).await,
        Err(RerankAdmissionError::Forbidden)
    ));
    grants(&f, "authenticated", "rerank");
    f.db()
        .execute(
            "UPDATE local_users SET enabled=0,revision=revision+1 WHERE username='alice'",
            [],
        )
        .unwrap();
    assert!(matches!(
        admissions.authorize(Some(&f.access), end()).await,
        Err(RerankAdmissionError::LocalAuthentication(_))
    ));
    drop((human, service, current, admissions));
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(issuer::end()).await.unwrap();
}

#[tokio::test]
async fn sqlite_rerank_preserves_deadline_and_sql_failure_without_fabricating_denial() {
    let f = Fixture::new().await;
    let issuer = issuer::Fixture::new().await;
    let verifier = issuer.verifier();
    let scopes = Vec::new();
    let admissions = f
        .store
        .rerank_admissions(&verifier, None, "admin-api", &scopes, limits())
        .unwrap();
    grants(&f, "global", "rerank");
    let original = Instant::now() + Duration::from_secs(1);
    let mut proof = admissions.authorize(None, original).await.unwrap();
    assert_eq!(proof.deadline(), original);
    tokio::time::sleep_until((original + Duration::from_millis(5)).into()).await;
    assert!(matches!(
        proof.check(),
        Err(RerankAdmissionError::Control(ControlError::Deadline))
    ));
    f.db()
        .execute_batch("DROP TABLE grant_capabilities;")
        .unwrap();
    assert!(matches!(
        admissions.authorize(None, end()).await,
        Err(RerankAdmissionError::Grants(_))
    ));
    drop((proof, admissions));
    f.store.shutdown(end()).await.unwrap();
    issuer.store.shutdown(issuer::end()).await.unwrap();
}

fn pg_config(f: &support::Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "rerank_owner".into(),
            Zeroizing::new("ephemeral-fixture-owner".into()),
        ),
        f.ca.clone(),
        broker_control::ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER rerank grant snapshots and physical shutdown"]
async fn postgres_rerank_requires_its_own_current_capability_and_preserves_sql_failure() {
    let pg = support::Fixture::new(true).await;
    let mut admin = pg.connection().await;
    admin.execute("CREATE ROLE rerank_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD 'ephemeral-fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION rerank_owner").await.unwrap();
    let store =
        PostgresControlStore::open(pg_config(&pg), support::digester(), support::deadline())
            .await
            .unwrap();
    let issuer = issuer::Fixture::new().await;
    let verifier = issuer.verifier();
    let scopes = Vec::new();
    let admissions = store
        .rerank_admissions(&verifier, None, "admin-api", &scopes, limits())
        .unwrap();
    admin.execute("INSERT INTO resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at)VALUES('rerank-fixture','fixture','global','','',0,0);INSERT INTO grant_capabilities(grant_id,value)VALUES('rerank-fixture','embeddings');").await.unwrap();
    assert!(matches!(
        admissions.authorize(None, support::deadline()).await,
        Err(RerankAdmissionError::Forbidden)
    ));
    admin
        .execute("UPDATE grant_capabilities SET value='rerank' WHERE grant_id='rerank-fixture'")
        .await
        .unwrap();
    let mut proof = admissions
        .authorize(None, support::deadline())
        .await
        .unwrap();
    proof.check().unwrap();
    admin
        .execute("UPDATE grant_capabilities SET value='embeddings' WHERE grant_id='rerank-fixture'")
        .await
        .unwrap();
    assert!(matches!(
        admissions.authorize(None, support::deadline()).await,
        Err(RerankAdmissionError::Forbidden)
    ));
    admin
        .execute("ALTER TABLE grant_capabilities RENAME TO unavailable_grant_capabilities")
        .await
        .unwrap();
    assert!(matches!(
        admissions.authorize(None, support::deadline()).await,
        Err(RerankAdmissionError::Grants(_))
    ));
    drop((proof, admissions));
    store.shutdown(support::deadline()).await.unwrap();
    admin.close().await.unwrap();
    pg.shutdown().unwrap();
    issuer.store.shutdown(issuer::end()).await.unwrap();
}
