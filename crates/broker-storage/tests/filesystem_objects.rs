#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves multiple suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, StorageModule, StorageScope,
};
use broker_storage::{
    FilesystemConditions, FilesystemPutOptions, FilesystemRequest, FilesystemSessionError,
    FilesystemStorageIssuer, FilesystemStorageRoute, FilesystemStorageRouteConfig, FilesystemStore,
    FilesystemStoreConfig, FilesystemStoreError,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use sqlx_postgres::PgConnection;
use std::{
    io::{Cursor, Read},
    num::{NonZeroU16, NonZeroU64},
    sync::{Arc, Barrier},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
struct Signer {
    key: EncodingKey,
    keys: jsonwebtoken::jwk::JwkSet,
}
impl Signer {
    fn new() -> Self {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        Self { key: EncodingKey::from_ed_der(&pair.serialize_der()), keys: serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"hub-key","x":URL_SAFE_NO_PAD.encode(pair.public_key_raw())}]})).unwrap() }
    }
    fn verifier(&self, resource: Option<&str>) -> BrokerAccessVerifier {
        BrokerAccessVerifier::new(ISSUER, "hub-api", resource, &self.keys, n(8192)).unwrap()
    }
    fn claims(&self) -> Value {
        let now = seconds();
        json!({"iss":ISSUER,"sub":"hub-subject","aud":["hub-api",RESOURCE],"iat":now-1,"exp":now+600,"token_use":"access","client_id":"explicit-client","jti":"hub-token","scope":"","preferred_username":"alice","organization":"engineering","groups":["dev"],"roles":["admin"]})
    }
    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("hub-key".into());
        encode(&header, claims, &self.key).unwrap()
    }
}
fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "object_owner".into(),
            Zeroizing::new("ephemeral-owner".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap()
}
struct Rule<'a> {
    kind: &'a str,
    principal: &'a str,
    caps: &'a [&'a str],
    projects: &'a [&'a str],
    operations: &'a [&'a str],
    prefixes: &'a [&'a str],
    route: &'a str,
}
async fn grant(c: &mut PgConnection, id: &str, r: &Rule<'_>) {
    sqlx_core::query::query("INSERT INTO public.resource_grants(id,name,access_kind,principal,s3_route,created_at,updated_at) VALUES($1,'fixture',$2,$3,$4,0,0)")
        .bind(id).bind(r.kind).bind(r.principal).bind(r.route).execute(&mut *c).await.unwrap();
    for (query, values) in [
        (
            "INSERT INTO public.grant_capabilities(grant_id,value) VALUES($1,$2)",
            r.caps,
        ),
        (
            "INSERT INTO public.grant_projects(grant_id,value) VALUES($1,$2)",
            r.projects,
        ),
        (
            "INSERT INTO public.grant_s3_operations(grant_id,value) VALUES($1,$2)",
            r.operations,
        ),
        (
            "INSERT INTO public.grant_s3_prefixes(grant_id,value) VALUES($1,$2)",
            r.prefixes,
        ),
    ] {
        for value in values {
            sqlx_core::query::query(query)
                .bind(id)
                .bind(*value)
                .execute(&mut *c)
                .await
                .unwrap();
        }
    }
}
fn issuer(pepper: u8, name: &str, budget: usize) -> FilesystemStorageIssuer {
    FilesystemStorageIssuer::new(
        vec![
            FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                name: name.into(),
                bucket: "graphit-local".into(),
                region: "us-east-1".into(),
                base_prefix: "tenant".into(),
                endpoint: "http://127.0.0.1:9000".into(),
                session_duration: Duration::from_secs(900),
                token_bytes: n(budget),
            })
            .unwrap(),
        ],
        Zeroizing::new(vec![pepper; 32]),
    )
    .unwrap()
}
fn storage(directory: &std::path::Path) -> FilesystemStoreConfig {
    FilesystemStoreConfig {
        directory: directory.to_path_buf(),
        bucket: "graphit-local".into(),
        max_object_bytes: NonZeroU64::new(32).unwrap(),
        metadata_bytes: n(8192),
    }
}
fn request() -> FilesystemRequest {
    FilesystemRequest {
        deadline: deadline(),
        cancellation: CancellationToken::new(),
    }
}
#[tokio::test]
#[ignore = "actual PostgreSQL TLS admission, MAC session and filesystem volume/threads/permissions"]
async fn filesystem_objects_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE object_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION object_owner;GRANT CONNECT,TEMP ON DATABASE postgres TO object_owner").await.unwrap();
    let sql = PostgresControlStore::open(config(&f), support::digester(), deadline())
        .await
        .unwrap();
    assert!(
        !sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT rolsuper FROM pg_roles WHERE rolname='object_owner'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    grant(
        &mut c,
        "objects",
        &Rule {
            kind: "authenticated",
            principal: "",
            caps: &["s3"],
            projects: &[A],
            operations: &["publish"],
            prefixes: &[],
            route: "primary",
        },
    )
    .await;
    let signer = Signer::new();
    let verifier = signer.verifier(Some(RESOURCE));
    let raw = signer.sign(&signer.claims());
    let factory = sql
        .broker_storage_authorizer(&verifier, n(65536), "primary")
        .unwrap();
    let grant = factory
        .authorize(
            &raw,
            &[],
            &StorageScope::project(A, StorageModule::Hub).unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    let issuer = issuer(0x71, "primary", 65536);
    let keys = issuer.issue(&grant).await.unwrap();
    let proof = Arc::new(
        issuer
            .verify_session("primary", keys.access_key_id(), keys.session_token())
            .unwrap(),
    );
    let folder = tempfile::tempdir().unwrap();
    let store = Arc::new(FilesystemStore::open(storage(folder.path())).unwrap());
    assert!(matches!(
        FilesystemStore::open(storage(folder.path())),
        Err(FilesystemStoreError::VolumeBusy)
    ));
    let root = format!("tenant/v1/projects/{A}/artifacts");
    let key = format!("{root}/file.json");
    let unconditional = FilesystemConditions::default();
    let first = store
        .put(
            &proof,
            &key,
            Cursor::new(b"first"),
            FilesystemPutOptions {
                content_type: Some("application/x-graphit"),
                expected_digest: None,
                conditions: &unconditional,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(first.size, 5);
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&key)).unwrap(),
        b"first"
    );
    let head = store.head(&proof, &key, &request()).unwrap();
    assert_eq!(head.etag, first.etag);
    assert_eq!(head.content_type, "application/x-graphit");
    let mut read = store
        .open_range(&proof, &key, Some(1..4), &request())
        .unwrap();
    let mut range = Vec::new();
    Read::by_ref(&mut read.file)
        .take(read.length)
        .read_to_end(&mut range)
        .unwrap();
    assert_eq!(range, b"irs");
    assert_eq!(read.offset, 1);
    assert!(matches!(
        store.open_range(&proof, &key, Some(5..6), &request()),
        Err(FilesystemStoreError::InvalidRange)
    ));
    assert!(matches!(
        store.put(
            &proof,
            &key,
            Cursor::new(b"second"),
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &FilesystemConditions {
                    if_match: Some("\"stale\"".into()),
                    if_none_match: None
                }
            },
            &request()
        ),
        Err(FilesystemStoreError::Precondition)
    ));
    assert!(matches!(
        store.put(
            &proof,
            &key,
            Cursor::new(b"second"),
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &FilesystemConditions {
                    if_match: None,
                    if_none_match: Some("*".into())
                }
            },
            &request()
        ),
        Err(FilesystemStoreError::Precondition)
    ));
    let updated = store
        .put(
            &proof,
            &key,
            Cursor::new(b"second"),
            FilesystemPutOptions {
                content_type: Some("application/x-graphit"),
                expected_digest: None,
                conditions: &FilesystemConditions {
                    if_match: Some(first.etag.clone()),
                    if_none_match: None,
                },
            },
            &request(),
        )
        .unwrap();
    assert_ne!(updated.etag, first.etag);
    // Conditional deletion and PUT publication share the same per-key lock.
    let conditional = format!("{root}/conditional-delete");
    let put_delete_fixture = |key: &str, bytes: &[u8]| {
        store
            .put(
                &proof,
                key,
                Cursor::new(bytes),
                FilesystemPutOptions {
                    content_type: Some("application/x-delete-contract"),
                    expected_digest: None,
                    conditions: &unconditional,
                },
                &request(),
            )
            .unwrap()
    };
    let original = put_delete_fixture(&conditional, b"delete-a");
    let data_path = folder.path().join("data").join(&conditional);
    let meta_path = folder.path().join("meta").join(&conditional);
    let metadata = std::fs::read(&meta_path).unwrap();
    assert!(matches!(
        store.delete_if_match(&proof, &conditional, &first.etag, &request()),
        Err(FilesystemStoreError::Precondition)
    ));
    assert_eq!(std::fs::read(&data_path).unwrap(), b"delete-a");
    assert_eq!(std::fs::read(&meta_path).unwrap(), metadata);
    let replacement = put_delete_fixture(&conditional, b"delete-b");
    let metadata = std::fs::read(&meta_path).unwrap();
    assert!(matches!(
        store.delete_if_match(&proof, &conditional, &original.etag, &request()),
        Err(FilesystemStoreError::Precondition)
    ));
    assert_eq!(std::fs::read(&data_path).unwrap(), b"delete-b");
    assert_eq!(std::fs::read(&meta_path).unwrap(), metadata);
    let expired = FilesystemRequest {
        deadline: Instant::now(),
        cancellation: CancellationToken::new(),
    };
    assert!(matches!(
        store.delete_if_match(&proof, &conditional, &replacement.etag, &expired),
        Err(FilesystemStoreError::Session(
            FilesystemSessionError::Deadline
        ))
    ));
    assert_eq!(std::fs::read(&data_path).unwrap(), b"delete-b");
    assert_eq!(std::fs::read(&meta_path).unwrap(), metadata);
    let cancelled = request();
    cancelled.cancellation.cancel();
    assert!(matches!(
        store.delete_if_match(&proof, &conditional, &replacement.etag, &cancelled),
        Err(FilesystemStoreError::Cancelled)
    ));
    assert_eq!(std::fs::read(&data_path).unwrap(), b"delete-b");
    assert_eq!(std::fs::read(&meta_path).unwrap(), metadata);
    store
        .delete_if_match(&proof, &conditional, &replacement.etag, &request())
        .unwrap();
    assert!(!data_path.exists() && !meta_path.exists());
    for absent in [original.etag.as_str(), "*"] {
        assert!(matches!(
            store.delete_if_match(&proof, &conditional, absent, &request()),
            Err(FilesystemStoreError::Precondition)
        ));
    }
    store.delete(&proof, &conditional, &request()).unwrap();
    put_delete_fixture(&conditional, b"wildcard");
    store
        .delete_if_match(&proof, &conditional, "*", &request())
        .unwrap();
    assert!(!data_path.exists() && !meta_path.exists());
    put_delete_fixture(&conditional, b"invalid-metadata");
    std::fs::write(&meta_path, b"invalid authored metadata").unwrap();
    assert!(matches!(
        store.delete_if_match(&proof, &conditional, "*", &request()),
        Err(FilesystemStoreError::InvalidMetadata)
    ));
    assert_eq!(std::fs::read(&data_path).unwrap(), b"invalid-metadata");
    assert_eq!(
        std::fs::read(&meta_path).unwrap(),
        b"invalid authored metadata"
    );
    // Unconditional deletion must not start validating authored metadata.
    store.delete(&proof, &conditional, &request()).unwrap();
    assert!(!data_path.exists() && !meta_path.exists());
    let delete_race = format!("{root}/delete-put-race");
    let before = put_delete_fixture(&delete_race, b"race-a");
    let barrier = Arc::new(Barrier::new(3));
    let deleting = {
        let store = Arc::clone(&store);
        let proof = Arc::clone(&proof);
        let barrier = Arc::clone(&barrier);
        let key = delete_race.clone();
        std::thread::spawn(move || {
            barrier.wait();
            store.delete_if_match(&proof, &key, &before.etag, &request())
        })
    };
    let replacing = {
        let store = Arc::clone(&store);
        let proof = Arc::clone(&proof);
        let barrier = Arc::clone(&barrier);
        let key = delete_race.clone();
        std::thread::spawn(move || {
            barrier.wait();
            store.put(
                &proof,
                &key,
                Cursor::new(b"race-b"),
                FilesystemPutOptions {
                    content_type: Some("application/x-delete-race"),
                    expected_digest: None,
                    conditions: &FilesystemConditions::default(),
                },
                &request(),
            )
        })
    };
    // This releases contenders; it does not force compare/remove interleaving.
    barrier.wait();
    let deleted = deleting.join().unwrap();
    let replaced = replacing.join().unwrap().unwrap();
    assert!(matches!(
        deleted,
        Ok(()) | Err(FilesystemStoreError::Precondition)
    ));
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&delete_race)).unwrap(),
        b"race-b"
    );
    let current = store.head(&proof, &delete_race, &request()).unwrap();
    assert_eq!(current.etag, replaced.etag);
    assert_eq!(current.content_type, "application/x-delete-race");
    let limit = format!("{root}/limit");
    store
        .put(
            &proof,
            &limit,
            Cursor::new([7u8; 32]),
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &unconditional,
            },
            &request(),
        )
        .unwrap();
    let oversized = format!("{root}/oversized");
    assert!(matches!(
        store.put(
            &proof,
            &oversized,
            Cursor::new([7u8; 33]),
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::TooLarge)
    ));
    assert!(matches!(
        store.head(&proof, &oversized, &request()),
        Err(FilesystemStoreError::NotFound)
    ));
    let digest = format!("{root}/digest");
    assert!(matches!(
        store.put(
            &proof,
            &digest,
            Cursor::new(b"bad"),
            FilesystemPutOptions {
                content_type: None,
                expected_digest: Some(&"0".repeat(64)),
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::BadDigest)
    ));
    assert!(!folder.path().join("data").join(&digest).exists());
    for invalid in [
        "",
        "/leading",
        "trailing/",
        "a//b",
        "../escape",
        "a/../../escape",
    ] {
        assert!(matches!(
            store.put(
                &proof,
                invalid,
                Cursor::new(b"x"),
                FilesystemPutOptions {
                    content_type: None,
                    expected_digest: None,
                    conditions: &unconditional
                },
                &request()
            ),
            Err(FilesystemStoreError::InvalidKey)
        ));
    }
    assert!(matches!(
        store.head(
            &proof,
            &format!("tenant/v1/projects/{B}/artifacts/file"),
            &request()
        ),
        Err(FilesystemStoreError::Forbidden)
    ));
    let foreignissuer = FilesystemStorageIssuer::new(
        vec![
            FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                name: "primary".into(),
                bucket: "foreign-bucket".into(),
                region: "us-east-1".into(),
                base_prefix: "tenant".into(),
                endpoint: "http://127.0.0.1:9000".into(),
                session_duration: Duration::from_secs(900),
                token_bytes: n(65536),
            })
            .unwrap(),
        ],
        Zeroizing::new(vec![0x71; 32]),
    )
    .unwrap();
    let foreignkeys = foreignissuer.issue(&grant).await.unwrap();
    let foreign = foreignissuer
        .verify_session(
            "primary",
            foreignkeys.access_key_id(),
            foreignkeys.session_token(),
        )
        .unwrap();
    assert!(matches!(
        store.head(&foreign, &key, &request()),
        Err(FilesystemStoreError::Forbidden)
    ));
    assert!(matches!(
        store.delete_if_match(&foreign, &key, "*", &request()),
        Err(FilesystemStoreError::Forbidden)
    ));
    assert!(matches!(
        store.delete_if_match(
            &proof,
            &format!("tenant/v1/projects/{B}/artifacts/file"),
            "*",
            &request(),
        ),
        Err(FilesystemStoreError::Forbidden)
    ));
    let rawkey = format!("{root}/raw.json");
    let rawpath = folder.path().join("data").join(&rawkey);
    std::fs::write(&rawpath, b"{\"raw\":true}").unwrap();
    let info = store.head(&proof, &rawkey, &request()).unwrap();
    assert_eq!(info.size, 12);
    assert_eq!(info.content_type, "application/json");
    assert_eq!(std::fs::read(&rawpath).unwrap(), b"{\"raw\":true}");
    #[cfg(unix)]
    {
        let old_time = UNIX_EPOCH - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&rawpath)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        let past = store.head(&proof, &rawkey, &request()).unwrap();
        assert_eq!(past.modified, old_time);
        assert_eq!(past.etag, info.etag);
        assert_eq!(past.content_type, "application/json");
        assert_eq!(std::fs::read(&rawpath).unwrap(), b"{\"raw\":true}");
        let authored_path = folder.path().join("data").join(&key);
        std::fs::File::options()
            .write(true)
            .open(authored_path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        let past_authored = store.head(&proof, &key, &request()).unwrap();
        assert_eq!(past_authored.modified, old_time);
        assert_eq!(past_authored.etag, updated.etag);
        assert_eq!(past_authored.content_type, "application/x-graphit");
    }
    let metapath = folder.path().join("meta").join(&key);
    let mut meta: Value = serde_json::from_slice(&std::fs::read(&metapath).unwrap()).unwrap();
    meta["derived"] = json!({"etag":"broken","size":0});
    std::fs::write(&metapath, serde_json::to_vec(&meta).unwrap()).unwrap();
    let rebuilt = store.head(&proof, &key, &request()).unwrap();
    assert_eq!(rebuilt.etag, updated.etag);
    assert_eq!(rebuilt.content_type, "application/x-graphit");
    std::fs::write(folder.path().join("data").join(&key), b"external-bytes").unwrap();
    let changed = store.head(&proof, &key, &request()).unwrap();
    assert_ne!(changed.etag, updated.etag);
    assert_eq!(changed.size, 14);
    assert_eq!(changed.content_type, "application/x-graphit");
    meta["content_type"] = json!(42);
    std::fs::write(&metapath, serde_json::to_vec(&meta).unwrap()).unwrap();
    assert!(matches!(
        store.head(&proof, &key, &request()),
        Err(FilesystemStoreError::InvalidMetadata)
    ));
    store
        .put(
            &proof,
            &key,
            Cursor::new(b"replaced"),
            FilesystemPutOptions {
                content_type: Some("application/x-restored"),
                expected_digest: None,
                conditions: &unconditional,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(
        store.head(&proof, &key, &request()).unwrap().content_type,
        "application/x-restored"
    );
    let race = format!("{root}/race");
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for body in [b"left".to_vec(), b"right".to_vec()] {
        let store = store.clone();
        let proof = proof.clone();
        let barrier = barrier.clone();
        let key = race.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.put(
                &proof,
                &key,
                Cursor::new(body),
                FilesystemPutOptions {
                    content_type: None,
                    expected_digest: None,
                    conditions: &FilesystemConditions {
                        if_match: None,
                        if_none_match: Some("*".into()),
                    },
                },
                &request(),
            )
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(FilesystemStoreError::Precondition)))
            .count(),
        1
    );
    let current = store.head(&proof, &race, &request()).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for body in [b"replacement-a".to_vec(), b"replacement-b".to_vec()] {
        let store = store.clone();
        let proof = proof.clone();
        let barrier = barrier.clone();
        let key = race.clone();
        let old = current.etag.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            store.put(
                &proof,
                &key,
                Cursor::new(body),
                FilesystemPutOptions {
                    content_type: None,
                    expected_digest: None,
                    conditions: &FilesystemConditions {
                        if_match: Some(old),
                        if_none_match: None,
                    },
                },
                &request(),
            )
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(FilesystemStoreError::Precondition)))
            .count(),
        1
    );
    struct Cancelling {
        cancel: CancellationToken,
        read: bool,
    }
    impl Read for Cancelling {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.read {
                return Ok(0);
            }
            self.read = true;
            buf[0] = 1;
            self.cancel.cancel();
            Ok(1)
        }
    }
    let cancel = request();
    let cancelled = format!("{root}/cancelled");
    assert!(matches!(
        store.put(
            &proof,
            &cancelled,
            Cancelling {
                cancel: cancel.cancellation.clone(),
                read: false
            },
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &unconditional
            },
            &cancel
        ),
        Err(FilesystemStoreError::Cancelled)
    ));
    assert!(!folder.path().join("data").join(&cancelled).exists());
    let timed = FilesystemRequest {
        deadline: Instant::now() - Duration::from_secs(1),
        cancellation: CancellationToken::new(),
    };
    assert!(
        store
            .put(
                &proof,
                &cancelled,
                Cursor::new(b"x"),
                FilesystemPutOptions {
                    content_type: None,
                    expected_digest: None,
                    conditions: &unconditional
                },
                &timed
            )
            .is_err()
    );
    struct ObservedReader<'a> {
        calls: &'a std::cell::Cell<usize>,
        until: Option<Instant>,
    }
    impl Read for ObservedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.calls.set(self.calls.get() + 1);
            if let Some(until) = self.until {
                std::thread::sleep(
                    until.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
                );
            }
            buf[0] = 1;
            Ok(1)
        }
    }
    let reads = std::cell::Cell::new(0);
    let late = FilesystemRequest {
        deadline: Instant::now() + Duration::from_millis(100),
        cancellation: CancellationToken::new(),
    };
    let delayed_key = format!("{root}/delayed");
    assert!(matches!(
        store.put(
            &proof,
            &delayed_key,
            ObservedReader {
                calls: &reads,
                until: Some(late.deadline)
            },
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &unconditional
            },
            &late
        ),
        Err(FilesystemStoreError::Session(
            FilesystemSessionError::Deadline
        ))
    ));
    assert_eq!(reads.get(), 1, "Original is crossed during the actual Read");
    assert!(!folder.path().join("data").join(&delayed_key).exists());
    assert_eq!(
        std::fs::read_dir(folder.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
    reads.set(0);
    let author_key = format!("{root}/author-budget");
    let author = "a".repeat(storage(folder.path()).metadata_bytes.get());
    assert!(matches!(
        store.put(
            &proof,
            &author_key,
            ObservedReader {
                calls: &reads,
                until: None
            },
            FilesystemPutOptions {
                content_type: Some(&author),
                expected_digest: None,
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidMetadata)
    ));
    assert_eq!(
        reads.get(),
        0,
        "authored JSON budget is checked before streaming"
    );
    assert!(!folder.path().join("data").join(&author_key).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("private"), b"outside").unwrap();
        let link = format!("{root}/link");
        symlink(
            outside.path().join("private"),
            folder.path().join("data").join(&link),
        )
        .unwrap();
        assert!(store.head(&proof, &link, &request()).is_err());
        assert!(
            store
                .put(
                    &proof,
                    &link,
                    Cursor::new(b"attempt"),
                    FilesystemPutOptions {
                        content_type: None,
                        expected_digest: None,
                        conditions: &unconditional
                    },
                    &request()
                )
                .is_err()
        );
        assert!(store.delete(&proof, &link, &request()).is_err());
        assert!(
            store
                .delete_if_match(&proof, &link, "*", &request())
                .is_err()
        );
        assert_eq!(
            std::fs::read(outside.path().join("private")).unwrap(),
            b"outside"
        );
        let parent = format!("{root}/linked-dir");
        symlink(outside.path(), folder.path().join("data").join(&parent)).unwrap();
        assert!(
            store
                .put(
                    &proof,
                    &format!("{parent}/private"),
                    Cursor::new(b"attempt"),
                    FilesystemPutOptions {
                        content_type: None,
                        expected_digest: None,
                        conditions: &unconditional
                    },
                    &request()
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(outside.path().join("private")).unwrap(),
            b"outside"
        );
        let uncertain = format!("{root}/uncertain");
        let metadir = folder.path().join("meta").join(&root);
        std::fs::set_permissions(&metadir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = store.put(
            &proof,
            &uncertain,
            Cursor::new(b"published"),
            FilesystemPutOptions {
                content_type: Some("application/x-uncertain"),
                expected_digest: None,
                conditions: &unconditional,
            },
            &request(),
        );
        std::fs::set_permissions(&metadir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            outcome,
            Err(FilesystemStoreError::CommitUncertain(_))
        ));
        assert_eq!(
            std::fs::read(folder.path().join("data").join(&uncertain)).unwrap(),
            b"published"
        );
        let deleting = format!("{root}/uncertain-delete");
        let object = put_delete_fixture(&deleting, b"remove-data");
        let metapath = folder.path().join("meta").join(&deleting);
        let metadata = std::fs::read(&metapath).unwrap();
        std::fs::set_permissions(&metadir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = store.delete_if_match(&proof, &deleting, &object.etag, &request());
        std::fs::set_permissions(&metadir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            outcome,
            Err(FilesystemStoreError::CommitUncertain(cause))
                if matches!(*cause, FilesystemStoreError::Io(ref error)
                    if error.kind() == std::io::ErrorKind::PermissionDenied)
        ));
        assert!(!folder.path().join("data").join(&deleting).exists());
        assert_eq!(std::fs::read(&metapath).unwrap(), metadata);
    }
    store.delete(&proof, &race, &request()).unwrap();
    store.delete(&proof, &race, &request()).unwrap();
    assert!(matches!(
        store.head(&proof, &race, &request()),
        Err(FilesystemStoreError::NotFound)
    ));
    assert_eq!(
        std::fs::read_dir(folder.path().join("tmp"))
            .unwrap()
            .count(),
        0,
        "owned staging has no unjoined operation"
    );
    let delete_only_key = format!("{root}/delete-only");
    let delete_only_object = put_delete_fixture(&delete_only_key, b"delete-without-read");
    c.execute("DELETE FROM public.grant_s3_operations WHERE grant_id='objects'; INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('objects','delete')").await.unwrap();
    let delete_grant = factory
        .authorize(
            &raw,
            &[],
            &StorageScope::project(A, StorageModule::Hub).unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    let delete_keys = issuer.issue(&delete_grant).await.unwrap();
    let delete_only = issuer
        .verify_session(
            "primary",
            delete_keys.access_key_id(),
            delete_keys.session_token(),
        )
        .unwrap();
    assert!(matches!(
        store.head(&delete_only, &delete_only_key, &request()),
        Err(FilesystemStoreError::Forbidden)
    ));
    store
        .delete_if_match(
            &delete_only,
            &delete_only_key,
            &delete_only_object.etag,
            &request(),
        )
        .unwrap();
    assert!(!folder.path().join("data").join(&delete_only_key).exists());
    assert!(!folder.path().join("meta").join(&delete_only_key).exists());
    drop(store);
    let reopened = FilesystemStore::open(storage(folder.path())).unwrap();
    assert_eq!(
        reopened
            .head(&proof, &key, &request())
            .unwrap()
            .content_type,
        "application/x-restored"
    );
    drop(reopened);
    drop(grant);
    drop(factory);
    sql.shutdown(deadline()).await.unwrap();
    drop(c);
    f.shutdown().unwrap();
}

#[test]
fn volume_startup_and_owner_release() {
    let folder = tempfile::tempdir().unwrap();
    let store = FilesystemStore::open(storage(folder.path())).unwrap_or_else(|e| {
        use std::error::Error;
        let code = e
            .source()
            .and_then(|s| s.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error);
        panic!("volume startup must succeed; native IO errno={code:?}");
    });
    assert!(matches!(
        FilesystemStore::open(storage(folder.path())),
        Err(FilesystemStoreError::VolumeBusy)
    ));
    drop(store);
    FilesystemStore::open(storage(folder.path())).unwrap();
}

#[test]
fn metadata_read_sentinel_is_checked_before_opening_volume() {
    if usize::BITS != 64 {
        return;
    }
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("not-created");
    let mut config = storage(&path);
    config.metadata_bytes = std::num::NonZeroUsize::new(usize::MAX).unwrap();
    assert!(matches!(
        FilesystemStore::open(config),
        Err(FilesystemStoreError::InvalidConfiguration)
    ));
    assert!(!path.exists());
}
