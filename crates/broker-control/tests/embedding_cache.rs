#[path = "../../broker-server/tests/support/admin_read_commit.rs"]
mod commit;
#[allow(
    dead_code,
    reason = "the shared PostgreSQL fixture also serves other native SQL targets"
)]
mod support;
use broker_control::{
    ConnectionLimits, EmbeddingCacheEntry, EmbeddingCacheError, EmbeddingCacheKey,
    EmbeddingCacheLimits, EmbeddingCacheProvenance, EmbeddingCacheWrite, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use sqlx_core::{connection::Connection, executor::Executor};
use std::num::NonZeroU16;
use support::{deadline, n};
use zeroize::Zeroizing;
fn limits() -> EmbeddingCacheLimits {
    EmbeddingCacheLimits {
        dimensions: n(2),
        max_entries: n(256),
        vector_json_bytes: n(64),
        metadata_bytes: n(256),
    }
}
fn key() -> EmbeddingCacheKey {
    EmbeddingCacheKey::new([0x12; 32], [0x34; 32])
}
fn provenance() -> EmbeddingCacheProvenance<'static> {
    EmbeddingCacheProvenance {
        provider: "cohere",
        revision: "fixture-r1",
        model: "fixture-model",
        input_type: "query",
    }
}
fn config(f: &support::Fixture) -> PostgresConfig {
    config_at(f, f.port, 2)
}
fn config_at(f: &support::Fixture, port: u16, connections: u32) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "embedding_owner".into(),
            Zeroizing::new("ephemeral-fixture-owner".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(connections),
        support::limits(),
    )
    .unwrap()
}
#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER physical cache and reopen"]
async fn postgres_tls_non_superuser_cache_is_persistent_bounded_and_no_overwrite() {
    let f = support::Fixture::new(true).await;
    let mut admin = f.connection().await;
    admin.execute("CREATE ROLE embedding_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD 'ephemeral-fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION embedding_owner").await.expect("owned role/schema setup");
    let store = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    {
        let cache = store.embedding_cache(limits()).unwrap();
        assert_eq!(cache.read(&[key()], deadline()).await.unwrap(), vec![None]);
        assert_eq!(
            cache
                .insert(
                    &[EmbeddingCacheEntry {
                        key: key(),
                        provenance: provenance(),
                        vector: &[1., 2.]
                    }],
                    deadline()
                )
                .await
                .unwrap(),
            EmbeddingCacheWrite {
                inserted: 1,
                unchanged: 0
            }
        );
        assert_eq!(
            cache
                .insert(
                    &[EmbeddingCacheEntry {
                        key: key(),
                        provenance: provenance(),
                        vector: &[3., 4.]
                    }],
                    deadline()
                )
                .await
                .unwrap(),
            EmbeddingCacheWrite {
                inserted: 0,
                unchanged: 1
            }
        );
        assert_eq!(
            cache.read(&[key()], deadline()).await.unwrap(),
            vec![Some(vec![1., 2.])]
        );
        for json in ["[1]", "[1,2,3]", "[1e39,0]", "[1,2] trailing", "null"] {
            sqlx_core::query::query("UPDATE public.embedding_cache SET embedding_json=$1")
                .bind(json)
                .execute(&mut admin)
                .await
                .unwrap();
            assert_eq!(
                cache.read(&[key()], deadline()).await.unwrap_err(),
                EmbeddingCacheError::MalformedStored
            );
        }
        sqlx_core::query::query("UPDATE public.embedding_cache SET embedding_json=$1")
            .bind(" ".repeat(65))
            .execute(&mut admin)
            .await
            .unwrap();
        assert_eq!(
            cache.read(&[key()], deadline()).await.unwrap_err(),
            EmbeddingCacheError::ReadLimitExceeded
        );
        admin
            .execute("UPDATE public.embedding_cache SET embedding_json='[1,2]'")
            .await
            .unwrap();
    }
    store.shutdown(deadline()).await.unwrap();
    drop(store);
    let reopened = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert_eq!(
        reopened
            .embedding_cache(limits())
            .unwrap()
            .read(&[key()], deadline())
            .await
            .unwrap(),
        vec![Some(vec![1., 2.])]
    );
    let is_super: bool = sqlx_core::query_scalar::query_scalar(
        "SELECT rolsuper FROM pg_roles WHERE rolname='embedding_owner'",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert!(!is_super);
    reopened.shutdown(deadline()).await.unwrap();
    admin.close().await.unwrap();
}

#[tokio::test]
#[ignore = "actual PostgreSQL TLS concurrent owners, unique-lock deadline and dropped-operation rollback"]
async fn postgres_cache_concurrency_and_physical_cancel_do_not_overwrite_or_replay() {
    use std::time::{Duration, Instant};
    let f = support::Fixture::new(true).await;
    let mut admin = f.connection().await;
    admin.execute("CREATE ROLE embedding_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD 'ephemeral-fixture-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION embedding_owner").await.unwrap();
    let first = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    let second = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    let a = first.embedding_cache(limits()).unwrap();
    let b = second.embedding_cache(limits()).unwrap();
    let concurrent = EmbeddingCacheKey::new([5; 32], [6; 32]);
    let left = [EmbeddingCacheEntry {
        key: concurrent,
        provenance: provenance(),
        vector: &[1., 2.],
    }];
    let right = [EmbeddingCacheEntry {
        key: concurrent,
        provenance: provenance(),
        vector: &[3., 4.],
    }];
    let (left, right) = tokio::join!(a.insert(&left, deadline()), b.insert(&right, deadline()));
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.inserted + right.inserted, 1);
    assert_eq!(left.unchanged + right.unchanged, 1);
    let value = a
        .read(&[concurrent], deadline())
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert!(value == vec![1., 2.] || value == vec![3., 4.]);
    second.shutdown(deadline()).await.unwrap();
    assert_eq!(
        a.read(&[concurrent], deadline()).await.unwrap(),
        vec![Some(value)]
    );
    for (byte, drop_operation) in [(0x77u8, false), (0x88, true)] {
        let compatibility = format!("{byte:02x}").repeat(32);
        let input = "99".repeat(32);
        let key = EmbeddingCacheKey::new([byte; 32], [0x99; 32]);
        admin.execute("BEGIN").await.unwrap();
        sqlx_core::query::query("INSERT INTO embedding_cache(compatibility_hash,input_hash,provider,revision,model,input_type,embedding_json)VALUES($1,$2,'cohere','fixture-r1','fixture-model','query','[9,9]')").bind(&compatibility).bind(&input).execute(&mut admin).await.unwrap();
        let abandoned = [EmbeddingCacheEntry {
            key,
            provenance: provenance(),
            vector: &[1., 2.],
        }];
        if drop_operation {
            {
                let operation = a.insert(&abandoned, deadline());
                tokio::pin!(operation);
                let physical_wait = async {
                    let end = Instant::now() + Duration::from_secs(2);
                    loop {
                        let waiting:i64=sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE usename='embedding_owner' AND wait_event_type='Lock'").fetch_one(&mut admin).await.unwrap();
                        if waiting > 0 {
                            break;
                        }
                        assert!(
                            Instant::now() < end,
                            "cache insert did not reach the actual PostgreSQL unique lock"
                        );
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                };
                tokio::select! { result=&mut operation=>panic!("insert escaped the held unique lock: {result:?}"),_=physical_wait=>{} }
            }
        } else {
            let started = Instant::now();
            let result = a
                .insert(&abandoned, started + Duration::from_millis(50))
                .await;
            assert_eq!(
                result,
                Err(EmbeddingCacheError::Control(
                    broker_control::ControlError::Deadline
                ))
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        }
        admin.execute("ROLLBACK").await.unwrap();
        assert_eq!(a.read(&[key], deadline()).await.unwrap(), vec![None]);
        assert_eq!(
            a.insert(
                &[EmbeddingCacheEntry {
                    key,
                    provenance: provenance(),
                    vector: &[5., 6.]
                }],
                deadline()
            )
            .await
            .unwrap()
            .inserted,
            1
        );
        assert_eq!(
            a.read(&[key], deadline()).await.unwrap(),
            vec![Some(vec![5., 6.])]
        );
    }
    first.shutdown(deadline()).await.unwrap();
    admin.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual PostgreSQL TLS COMMIT ACK withholding and physical connection disposal"]
async fn postgres_cache_commit_ack_loss_is_uncertain_without_replay() {
    use std::time::{Duration, Instant};
    let f = support::Fixture::new(true).await;
    let mut admin = f.connection().await;
    admin.execute("CREATE ROLE embedding_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD 'ephemeral-fixture-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION embedding_owner").await.unwrap();
    let mut relay = commit::CommitRelay::new(f.port).await;
    let owner = PostgresControlStore::open(
        config_at(&f, relay.port, 1),
        support::digester(),
        deadline(),
    )
    .await
    .unwrap();
    let cache = owner.embedding_cache(limits()).unwrap();
    let mut locker = f.connection().await;
    locker
        .execute("BEGIN; LOCK TABLE public.embedding_cache IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let entries = [EmbeddingCacheEntry {
        key: key(),
        provenance: provenance(),
        vector: &[1., 2.],
    }];
    let operation = cache.insert(&entries, Instant::now() + Duration::from_secs(4));
    tokio::pin!(operation);
    let blocked = async {
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            let pid: Option<i32> = sqlx_core::query_scalar::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='embedding_owner' AND wait_event_type='Lock' LIMIT 1").fetch_optional(&mut admin).await.unwrap();
            if let Some(pid) = pid {
                break pid;
            }
            assert!(
                Instant::now() < end,
                "cache insert must reach the real table lock"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    let pid = tokio::select! { pid=blocked=>pid, result=&mut operation=>panic!("insert must wait for the table lock: {result:?}") };
    relay.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    locker.execute("ROLLBACK").await.unwrap();
    loop {
        let decision = tokio::select! { decision=relay.replies.recv()=>decision.unwrap(), result=&mut operation=>panic!("actual COMMIT acknowledgement was not withheld: {result:?}") };
        let (query, idle): (String, bool) = sqlx_core::query_as::query_as(
            "SELECT query,state='idle' FROM pg_stat_activity WHERE pid=$1",
        )
        .bind(pid)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        let visible: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM embedding_cache WHERE compatibility_hash=$1 AND input_hash=$2 AND embedding_json='[1.0,2.0]'").bind("12".repeat(32)).bind("34".repeat(32)).fetch_one(&mut admin).await.unwrap();
        if query == "COMMIT" && idle && visible == 1 {
            decision.send(false).unwrap();
            break;
        }
        decision.send(true).unwrap();
    }
    assert_eq!(
        operation.await,
        Err(EmbeddingCacheError::Control(
            broker_control::ControlError::OutcomeUncertain
        ))
    );
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        let exists: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)",
        )
        .bind(pid)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        if !exists {
            break;
        }
        assert!(
            Instant::now() < end,
            "uncertain connection must close physically"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let rows: i64 = sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM embedding_cache")
        .fetch_one(&mut admin)
        .await
        .unwrap();
    assert_eq!(rows, 1, "the real committed write remains durable");
    relay
        .armed
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        cache.read(&[key()], deadline()).await.unwrap(),
        vec![Some(vec![1., 2.])]
    );
    owner.shutdown(deadline()).await.unwrap();
    relay.close().await;
    locker.close().await.unwrap();
    admin.close().await.unwrap();
}
