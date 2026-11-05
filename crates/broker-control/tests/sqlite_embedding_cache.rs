use broker_control::{
    ControlError, EmbeddingCacheEntry, EmbeddingCacheError, EmbeddingCacheKey,
    EmbeddingCacheLimits, EmbeddingCacheProvenance, EmbeddingCacheWrite, FlowLimits,
    SqliteControlConfig, SqliteControlStore,
};
use broker_security::{CredentialDigester, DigestLimits};
use rusqlite::{Connection, params};
use std::{
    num::NonZeroUsize,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
fn n(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap()
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
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

#[tokio::test]
async fn one_batch_preserves_mixed_hits_order_and_preflights_every_entry() {
    let temp = tempfile::tempdir().unwrap();
    let store = open(&temp.path().join("private/cache.db")).await;
    let cache = store.embedding_cache(limits()).unwrap();
    let second = EmbeddingCacheKey::new([0x12; 32], [0x56; 32]);
    let missing = EmbeddingCacheKey::new([0x12; 32], [0x78; 32]);
    let entries = [
        EmbeddingCacheEntry {
            key: key(),
            provenance: provenance(),
            vector: &[1., 2.],
        },
        EmbeddingCacheEntry {
            key: second,
            provenance: provenance(),
            vector: &[3., 4.],
        },
    ];
    assert_eq!(
        cache.insert(&entries, end()).await.unwrap(),
        EmbeddingCacheWrite {
            inserted: 2,
            unchanged: 0
        }
    );
    assert_eq!(
        cache
            .read(&[second, missing, key(), second], end())
            .await
            .unwrap(),
        vec![
            Some(vec![3., 4.]),
            None,
            Some(vec![1., 2.]),
            Some(vec![3., 4.])
        ]
    );
    let invalid = [
        EmbeddingCacheEntry {
            key: missing,
            provenance: provenance(),
            vector: &[8., 9.],
        },
        EmbeddingCacheEntry {
            key: second,
            provenance: provenance(),
            vector: &[f32::NAN, 0.],
        },
    ];
    assert_eq!(
        cache.insert(&invalid, end()).await.unwrap_err(),
        EmbeddingCacheError::InvalidInput
    );
    assert_eq!(cache.read(&[missing], end()).await.unwrap(), vec![None]);
    let mut small = limits();
    small.max_entries = n(1);
    assert_eq!(
        store
            .embedding_cache(small)
            .unwrap()
            .read(&[key(), second], end())
            .await
            .unwrap_err(),
        EmbeddingCacheError::InvalidInput
    );
    store.shutdown(end()).await.unwrap();
}
fn provenance() -> EmbeddingCacheProvenance<'static> {
    EmbeddingCacheProvenance {
        provider: "openai",
        revision: "fixture-r1",
        model: "fixture-model",
        input_type: "document",
    }
}
async fn open(path: &Path) -> SqliteControlStore {
    let config = SqliteControlConfig::new(
        path.into(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        FlowLimits {
            provider_bytes: n(128),
            request_bytes: n(256),
            continuation_bytes: n(1024),
        },
    )
    .unwrap();
    let digester = CredentialDigester::new(
        Zeroizing::new(vec![0x93; 32].into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap();
    SqliteControlStore::open(config, digester, end())
        .await
        .unwrap()
}
#[tokio::test]
async fn persistent_no_overwrite_reopen_and_public_provenance() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private/cache.db");
    let store = open(&path).await;
    {
        let cache = store.embedding_cache(limits()).unwrap();
        assert_eq!(cache.read(&[key()], end()).await.unwrap(), vec![None]);
        assert_eq!(
            cache
                .insert(
                    &[EmbeddingCacheEntry {
                        key: key(),
                        provenance: provenance(),
                        vector: &[0.25, -0.5]
                    }],
                    end()
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
                        vector: &[8., 9.]
                    }],
                    end()
                )
                .await
                .unwrap(),
            EmbeddingCacheWrite {
                inserted: 0,
                unchanged: 1
            }
        );
        assert_eq!(
            cache.read(&[key()], end()).await.unwrap(),
            vec![Some(vec![0.25, -0.5])]
        );
    }
    store.shutdown(end()).await.unwrap();
    drop(store);
    let reopened = open(&path).await;
    assert_eq!(
        reopened
            .embedding_cache(limits())
            .unwrap()
            .read(&[key()], end())
            .await
            .unwrap(),
        vec![Some(vec![0.25, -0.5])]
    );
    let db = Connection::open(&path).unwrap();
    let row:(String,String,String,String,String,String) = db.query_row("SELECT compatibility_hash,input_hash,provider,revision,model,input_type FROM embedding_cache",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).unwrap();
    assert_eq!(row.0, "12".repeat(32));
    assert_eq!(row.1, "34".repeat(32));
    assert_eq!(
        (row.2, row.3, row.4, row.5),
        (
            "openai".into(),
            "fixture-r1".into(),
            "fixture-model".into(),
            "document".into()
        )
    );
    let columns: Vec<String> = db
        .prepare("PRAGMA table_info(embedding_cache)")
        .unwrap()
        .query_map([], |r| r.get(1))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        columns,
        [
            "compatibility_hash",
            "input_hash",
            "provider",
            "revision",
            "model",
            "input_type",
            "embedding_json"
        ]
    );
    reopened.shutdown(end()).await.unwrap();
}
#[tokio::test]
async fn invalid_vectors_and_corrupt_rows_never_become_misses_or_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private/cache.db");
    let store = open(&path).await;
    let cache = store.embedding_cache(limits()).unwrap();
    for value in [
        &[1.][..],
        &[1., 2., 3.][..],
        &[f32::NAN, 0.][..],
        &[f32::INFINITY, 0.][..],
    ] {
        assert_eq!(
            cache
                .insert(
                    &[EmbeddingCacheEntry {
                        key: key(),
                        provenance: provenance(),
                        vector: value
                    }],
                    end()
                )
                .await
                .unwrap_err(),
            EmbeddingCacheError::InvalidInput
        );
    }
    cache
        .insert(
            &[EmbeddingCacheEntry {
                key: key(),
                provenance: provenance(),
                vector: &[1., 2.],
            }],
            end(),
        )
        .await
        .unwrap();
    let db = Connection::open(&path).unwrap();
    for json in [
        "[1]",
        "[1,2,3]",
        "[1e39,0]",
        "[1,2] trailing",
        "null",
        "[\"secret-fixture-text\",0]",
    ] {
        db.execute("UPDATE embedding_cache SET embedding_json=?1", [json])
            .unwrap();
        assert_eq!(
            cache.read(&[key()], end()).await.unwrap_err(),
            EmbeddingCacheError::MalformedStored
        );
    }
    db.execute(
        "UPDATE embedding_cache SET embedding_json=?1",
        [" ".repeat(65)],
    )
    .unwrap();
    assert_eq!(
        cache.read(&[key()], end()).await.unwrap_err(),
        EmbeddingCacheError::ReadLimitExceeded
    );
    db.execute(
        "UPDATE embedding_cache SET embedding_json=?1",
        params![vec![1u8, 2, 3]],
    )
    .unwrap();
    assert_eq!(
        cache.read(&[key()], end()).await.unwrap_err(),
        EmbeddingCacheError::MalformedStored
    );
    db.execute(
        "UPDATE embedding_cache SET embedding_json='[1,2]',input_type='wrong'",
        [],
    )
    .unwrap();
    assert_eq!(
        cache.read(&[key()], end()).await.unwrap_err(),
        EmbeddingCacheError::MalformedStored
    );
    store.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_same_key_known_results_and_independent_owners() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private/cache.db");
    let store = Arc::new(open(&path).await);
    let a = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .embedding_cache(limits())
                .unwrap()
                .insert(
                    &[EmbeddingCacheEntry {
                        key: key(),
                        provenance: provenance(),
                        vector: &[1., 2.],
                    }],
                    end(),
                )
                .await
                .unwrap()
        })
    };
    let b = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .embedding_cache(limits())
                .unwrap()
                .insert(
                    &[EmbeddingCacheEntry {
                        key: key(),
                        provenance: provenance(),
                        vector: &[3., 4.],
                    }],
                    end(),
                )
                .await
                .unwrap()
        })
    };
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    assert!(matches!(
        (a, b),
        (
            EmbeddingCacheWrite {
                inserted: 1,
                unchanged: 0
            },
            EmbeddingCacheWrite {
                inserted: 0,
                unchanged: 1
            }
        ) | (
            EmbeddingCacheWrite {
                inserted: 0,
                unchanged: 1
            },
            EmbeddingCacheWrite {
                inserted: 1,
                unchanged: 0
            }
        )
    ));
    let vector = store
        .embedding_cache(limits())
        .unwrap()
        .read(&[key()], end())
        .await
        .unwrap()
        .remove(0)
        .unwrap();
    assert!(vector == [1., 2.] || vector == [3., 4.]);
    let other = open(&temp.path().join("other/cache.db")).await;
    assert_eq!(
        other
            .embedding_cache(limits())
            .unwrap()
            .read(&[key()], end())
            .await
            .unwrap(),
        vec![None]
    );
    store.shutdown(end()).await.unwrap();
    other.shutdown(end()).await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_and_dropped_locked_work_cannot_insert_and_store_remains_usable() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private/cache.db");
    let store = Arc::new(open(&path).await);
    let cache = store.embedding_cache(limits()).unwrap();
    assert_eq!(
        cache
            .read(&[key()], Instant::now() - Duration::from_millis(1))
            .await
            .unwrap_err(),
        EmbeddingCacheError::Control(ControlError::Deadline)
    );
    let locker = Connection::open(&path).unwrap();
    locker.execute_batch("BEGIN IMMEDIATE").unwrap();
    {
        let entries = [EmbeddingCacheEntry {
            key: key(),
            provenance: provenance(),
            vector: &[1., 2.],
        }];
        let mut pending = std::pin::pin!(cache.insert(&entries, end()));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        // Cancel the real submitted request while SQLite is still locked.
    }
    locker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(cache.read(&[key()], end()).await.unwrap(), vec![None]);
    assert_eq!(
        cache
            .insert(
                &[EmbeddingCacheEntry {
                    key: key(),
                    provenance: provenance(),
                    vector: &[3., 4.]
                }],
                end()
            )
            .await
            .unwrap(),
        EmbeddingCacheWrite {
            inserted: 1,
            unchanged: 0
        }
    );
    store.shutdown(end()).await.unwrap();
    assert_eq!(
        cache.read(&[key()], end()).await.unwrap_err(),
        EmbeddingCacheError::Control(ControlError::Closed)
    );
}
