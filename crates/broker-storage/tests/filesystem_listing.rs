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
    FilesystemConditions, FilesystemCopyOptions, FilesystemListEncoding, FilesystemListRequest,
    FilesystemPutOptions, FilesystemRequest, FilesystemStorageIssuer, FilesystemStorageRoute,
    FilesystemStorageRouteConfig, FilesystemStore, FilesystemStoreConfig, FilesystemStoreError,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use sqlx_postgres::PgConnection;
use std::{
    io::Cursor,
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
fn list<'a>(
    prefix: &'a str,
    token: Option<&'a str>,
    max_keys: Option<i32>,
) -> FilesystemListRequest<'a> {
    FilesystemListRequest {
        prefix,
        delimiter: None,
        start_after: None,
        continuation_token: token,
        max_keys,
        encoding: FilesystemListEncoding::Plain,
    }
}
#[tokio::test]
#[ignore = "actual PostgreSQL TLS admission, MAC session and filesystem volume/threads/permissions"]
async fn filesystem_listing_postgres_contract() {
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
    let prefix = format!("{root}/");
    let unconditional = FilesystemConditions::default();
    for name in [
        "zeta",
        "dir/b",
        "beta",
        "space name%.json",
        "alpha",
        "dir/a",
    ] {
        store
            .put(
                &proof,
                &format!("{prefix}{name}"),
                Cursor::new(name.as_bytes()),
                FilesystemPutOptions {
                    content_type: Some("application/x-original"),
                    expected_digest: None,
                    conditions: &unconditional,
                },
                &request(),
            )
            .unwrap();
    }
    let sibling = format!("tenant/v1/projects/{B}/artifacts/private");
    let sibling_path = folder.path().join("data").join(&sibling);
    std::fs::create_dir_all(sibling_path.parent().unwrap()).unwrap();
    std::fs::write(&sibling_path, b"private").unwrap();
    let adjacent = format!("{root}2/private");
    let adjacent_path = folder.path().join("data").join(&adjacent);
    std::fs::create_dir_all(adjacent_path.parent().unwrap()).unwrap();
    std::fs::write(&adjacent_path, b"adjacent private").unwrap();
    let exact_root = store
        .list(&proof, list(&root, None, None), &request())
        .unwrap();
    assert_eq!(
        exact_root.key_count, 6,
        "exact root prunes adjacent out-of-scope siblings"
    );
    assert!(
        exact_root
            .objects
            .iter()
            .all(|o| o.key.starts_with(&prefix))
    );
    let all = store
        .list(&proof, list(&prefix, None, None), &request())
        .unwrap();
    let expected: Vec<_> = [
        "alpha",
        "beta",
        "dir/a",
        "dir/b",
        "space name%.json",
        "zeta",
    ]
    .into_iter()
    .map(|name| format!("{prefix}{name}"))
    .collect();
    assert_eq!(
        all.objects.iter().map(|o| &o.key).collect::<Vec<_>>(),
        expected.iter().collect::<Vec<_>>()
    );
    assert_eq!(all.key_count, 6);
    assert!(!all.is_truncated);
    assert!(all.next_token.is_none());
    assert_eq!(
        store
            .list(&proof, list(&prefix, None, Some(0)), &request())
            .unwrap()
            .key_count,
        6
    );
    for max in [-1, 1001] {
        assert!(matches!(
            store.list(&proof, list(&prefix, None, Some(max)), &request()),
            Err(FilesystemStoreError::InvalidArgument)
        ));
    }
    let mut paged = Vec::new();
    let mut token = None;
    loop {
        let page = store
            .list(&proof, list(&prefix, token.as_deref(), Some(2)), &request())
            .unwrap();
        assert_eq!(page.key_count, 2);
        paged.extend(page.objects.into_iter().map(|o| o.key));
        assert_eq!(page.is_truncated, page.next_token.is_some());
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    assert_eq!(paged, expected);
    let start = format!("{prefix}beta");
    let after = store
        .list(
            &proof,
            FilesystemListRequest {
                start_after: Some(&start),
                ..list(&prefix, None, None)
            },
            &request(),
        )
        .unwrap();
    assert_eq!(
        after.objects.iter().map(|o| &o.key).collect::<Vec<_>>(),
        expected[2..].iter().collect::<Vec<_>>()
    );
    let empty = format!("{prefix}missing/");
    assert_eq!(
        store
            .list(
                &proof,
                FilesystemListRequest {
                    prefix: &empty,
                    ..list(&prefix, None, None)
                },
                &request()
            )
            .unwrap()
            .key_count,
        0
    );
    for denied in [
        "tenant",
        "",
        "../outside",
        "tenant/v1/projects/01D39ZY06FGSCTVN4T2V9PKHG0/artifacts/",
    ] {
        assert!(
            store
                .list(
                    &proof,
                    FilesystemListRequest {
                        prefix: denied,
                        ..list(&prefix, None, None)
                    },
                    &request()
                )
                .is_err()
        );
    }
    assert!(matches!(
        store.list(
            &proof,
            FilesystemListRequest {
                delimiter: Some("-"),
                ..list(&prefix, None, None)
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidArgument)
    ));
    let mut grouped = Vec::new();
    let mut token = None;
    loop {
        let page = store
            .list(
                &proof,
                FilesystemListRequest {
                    delimiter: Some("/"),
                    ..list(&prefix, token.as_deref(), Some(2))
                },
                &request(),
            )
            .unwrap();
        grouped.extend(page.objects.into_iter().map(|o| o.key));
        grouped.extend(page.common_prefixes);
        token = page.next_token;
        if token.is_none() {
            break;
        }
    }
    grouped.sort();
    assert_eq!(
        grouped,
        ["alpha", "beta", "dir/", "space name%.json", "zeta"]
            .into_iter()
            .map(|name| format!("{prefix}{name}"))
            .collect::<Vec<_>>()
    );
    let first_page = store
        .list(&proof, list(&prefix, None, Some(2)), &request())
        .unwrap();
    let token = first_page.next_token.unwrap();
    assert!(matches!(
        store.list(
            &proof,
            FilesystemListRequest {
                delimiter: Some("/"),
                ..list(&prefix, Some(&token), None)
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidArgument)
    ));
    let different_prefix = format!("{prefix}dir/");
    assert!(matches!(
        store.list(
            &proof,
            list(&different_prefix, Some(&token), None),
            &request()
        ),
        Err(FilesystemStoreError::InvalidArgument)
    ));
    assert!(matches!(
        store.list(
            &proof,
            list(&prefix, Some(&"a".repeat(8192)), None),
            &request()
        ),
        Err(FilesystemStoreError::InvalidArgument)
    ));
    let ignored_start = format!("{prefix}zeta");
    let continued = store
        .list(
            &proof,
            FilesystemListRequest {
                start_after: Some(&ignored_start),
                ..list(&prefix, Some(&token), None)
            },
            &request(),
        )
        .unwrap();
    assert_eq!(
        continued.key_count, 4,
        "continuation takes precedence over start-after"
    );
    let mut cursor: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&token).unwrap()).unwrap();
    cursor["marker"] = json!(sibling);
    let altered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cursor).unwrap());
    assert!(matches!(
        store.list(&proof, list(&prefix, Some(&altered), None), &request()),
        Err(FilesystemStoreError::InvalidArgument)
    ));
    assert!(matches!(
        store.list(
            &proof,
            list(&prefix, Some("invalid-token"), None),
            &request()
        ),
        Err(FilesystemStoreError::InvalidArgument)
    ));
    let encoded = store
        .list(
            &proof,
            FilesystemListRequest {
                encoding: FilesystemListEncoding::Url,
                ..list(&prefix, None, None)
            },
            &request(),
        )
        .unwrap();
    assert!(
        encoded
            .objects
            .iter()
            .any(|o| o.key == format!("{prefix}space%20name%25.json"))
    );
    assert_eq!(
        std::fs::read(
            folder
                .path()
                .join("data")
                .join(format!("{prefix}space name%.json"))
        )
        .unwrap(),
        b"space name%.json"
    );
    let partial = format!("{prefix}d");
    let selected = store
        .list(
            &proof,
            FilesystemListRequest {
                prefix: &partial,
                ..list(&prefix, None, None)
            },
            &request(),
        )
        .unwrap();
    assert_eq!(selected.objects.len(), 2);
    let invalid_selected = folder
        .path()
        .join("data")
        .join(format!("{prefix}noncanonicalé"));
    std::fs::write(&invalid_selected, b"invalid key").unwrap();
    assert!(matches!(
        store.list(&proof, list(&prefix, None, None), &request()),
        Err(FilesystemStoreError::InvalidKey)
    ));
    std::fs::remove_file(invalid_selected).unwrap();
    let source = format!("{prefix}alpha");
    let target = format!("{prefix}copied");
    let original = store.head(&proof, &source, &request()).unwrap();
    let require = FilesystemConditions {
        if_match: Some(original.etag.clone()),
        if_none_match: None,
    };
    let create = FilesystemConditions {
        if_match: None,
        if_none_match: Some("*".into()),
    };
    let copied = store
        .copy(
            &proof,
            &source,
            &target,
            FilesystemCopyOptions {
                source_conditions: &require,
                target_conditions: &create,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(copied.etag, original.etag);
    assert_eq!(copied.content_type, "application/x-original");
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&target)).unwrap(),
        b"alpha"
    );
    assert!(matches!(
        store.copy(
            &proof,
            &source,
            &target,
            FilesystemCopyOptions {
                source_conditions: &require,
                target_conditions: &create
            },
            &request()
        ),
        Err(FilesystemStoreError::Precondition)
    ));
    let stale = FilesystemConditions {
        if_match: Some(format!("\"{}\"", "0".repeat(64))),
        if_none_match: None,
    };
    assert!(matches!(
        store.copy(
            &proof,
            &source,
            &format!("{prefix}not-copied"),
            FilesystemCopyOptions {
                source_conditions: &stale,
                target_conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::Precondition)
    ));
    assert!(matches!(
        store.copy(
            &proof,
            &sibling,
            &target,
            FilesystemCopyOptions {
                source_conditions: &unconditional,
                target_conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::Forbidden)
    ));
    assert!(matches!(
        store.copy(
            &proof,
            &source,
            &sibling,
            FilesystemCopyOptions {
                source_conditions: &unconditional,
                target_conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::Forbidden)
    ));
    let self_copy = store
        .copy(
            &proof,
            &source,
            &source,
            FilesystemCopyOptions {
                source_conditions: &require,
                target_conditions: &require,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(self_copy.etag, original.etag);
    let barrier = Arc::new(Barrier::new(3));
    let (send, receive) = std::sync::mpsc::sync_channel(2);
    let mut workers = Vec::new();
    for (from, to) in [
        (source.clone(), format!("{prefix}beta")),
        (format!("{prefix}beta"), source.clone()),
    ] {
        let store = store.clone();
        let proof = proof.clone();
        let barrier = barrier.clone();
        let send = send.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let conditions = FilesystemConditions::default();
            send.send(store.copy(
                &proof,
                &from,
                &to,
                FilesystemCopyOptions {
                    source_conditions: &conditions,
                    target_conditions: &conditions,
                },
                &request(),
            ))
            .unwrap();
        }));
    }
    barrier.wait();
    for _ in 0..2 {
        assert!(
            receive
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_ok()
        );
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let left = std::fs::read(folder.path().join("data").join(&source)).unwrap();
    let right = std::fs::read(folder.path().join("data").join(format!("{prefix}beta"))).unwrap();
    assert_eq!(left, right);
    assert!(left == b"alpha" || left == b"beta");
    let race_key = format!("{prefix}copy-race");
    let barrier = Arc::new(Barrier::new(3));
    let (send, receive) = std::sync::mpsc::sync_channel(2);
    let mut workers = Vec::new();
    for from in [source.clone(), format!("{prefix}zeta")] {
        let store = store.clone();
        let proof = proof.clone();
        let barrier = barrier.clone();
        let to = race_key.clone();
        let send = send.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let source_conditions = FilesystemConditions::default();
            let target_conditions = FilesystemConditions {
                if_match: None,
                if_none_match: Some("*".into()),
            };
            send.send(store.copy(
                &proof,
                &from,
                &to,
                FilesystemCopyOptions {
                    source_conditions: &source_conditions,
                    target_conditions: &target_conditions,
                },
                &request(),
            ))
            .unwrap();
        }));
    }
    barrier.wait();
    let outcomes = [
        receive.recv_timeout(Duration::from_secs(5)).unwrap(),
        receive.recv_timeout(Duration::from_secs(5)).unwrap(),
    ];
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|r| matches!(r, Err(FilesystemStoreError::Precondition)))
            .count(),
        1
    );
    for worker in workers {
        worker.join().unwrap();
    }
    let absent = format!("{prefix}absent");
    let batch = store
        .delete_batch(
            &proof,
            &[
                target.clone(),
                sibling.clone(),
                "../escape".into(),
                absent.clone(),
            ],
            false,
            &request(),
        )
        .unwrap();
    assert_eq!(batch.len(), 4);
    assert!(batch[0].result.is_ok());
    assert!(matches!(
        batch[1].result,
        Err(FilesystemStoreError::Forbidden)
    ));
    assert!(matches!(
        batch[2].result,
        Err(FilesystemStoreError::InvalidKey)
    ));
    assert!(batch[3].result.is_ok());
    assert_eq!(std::fs::read(&sibling_path).unwrap(), b"private");
    let quiet = store
        .delete_batch(&proof, &[absent, sibling.clone()], true, &request())
        .unwrap();
    assert_eq!(quiet.len(), 1);
    assert_eq!(quiet[0].key, sibling);
    assert!(matches!(
        quiet[0].result,
        Err(FilesystemStoreError::Forbidden)
    ));
    let expired = FilesystemRequest {
        deadline: Instant::now() - Duration::from_secs(1),
        cancellation: CancellationToken::new(),
    };
    assert!(
        store
            .delete_batch(&proof, std::slice::from_ref(&source), false, &expired)
            .is_err()
    );
    assert!(folder.path().join("data").join(&source).exists());
    let no_effect_request = request();
    let no_effect_token = no_effect_request.cancellation.clone();
    let denied_keys = vec!["..".to_owned(); 16384];
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(1));
        no_effect_token.cancel();
    });
    let no_effect = store.delete_batch(&proof, &denied_keys, false, &no_effect_request);
    canceller.join().unwrap();
    assert!(
        matches!(no_effect, Err(FilesystemStoreError::Cancelled)),
        "denials followed by cancellation have no uncertain mutation"
    );
    assert_eq!(std::fs::read(&adjacent_path).unwrap(), b"adjacent private");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let interrupted_key = format!("{prefix}interrupted-batch");
        store
            .put(
                &proof,
                &interrupted_key,
                Cursor::new(b"delete me"),
                FilesystemPutOptions {
                    content_type: None,
                    expected_digest: None,
                    conditions: &unconditional,
                },
                &request(),
            )
            .unwrap();
        let interrupted_path = folder.path().join("data").join(&interrupted_key);
        let author_dir = folder.path().join("meta").join(&root);
        std::fs::set_permissions(&author_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let cancelled = request();
        let cancellation = cancelled.cancellation.clone();
        let observe = interrupted_path.clone();
        let watcher = std::thread::spawn(move || {
            let bound = Instant::now() + Duration::from_secs(5);
            while observe.exists() && Instant::now() < bound {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                !observe.exists(),
                "cancellation follows an actual data removal"
            );
            cancellation.cancel();
        });
        let mut keys = vec![format!("{prefix}absent-batch"); 4096];
        keys[0] = interrupted_key;
        let outcome = store.delete_batch(&proof, &keys, false, &cancelled);
        watcher.join().unwrap();
        std::fs::set_permissions(&author_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        match outcome {
            Err(FilesystemStoreError::CommitUncertain(cause)) => assert!(
                matches!(*cause, FilesystemStoreError::Io(_)),
                "retain actual post-removal IO instead of masking it with cancellation"
            ),
            _ => panic!("interrupted batch must retain uncertain actual removal"),
        }
        assert!(!interrupted_path.exists());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("private"), b"outside").unwrap();
        let link = folder.path().join("data").join(format!("{prefix}linked"));
        symlink(outside.path(), &link).unwrap();
        assert!(
            store
                .list(&proof, list(&prefix, None, None), &request())
                .is_err()
        );
        assert_eq!(
            std::fs::read(outside.path().join("private")).unwrap(),
            b"outside"
        );
        std::fs::remove_file(link).unwrap();
    }
    assert_eq!(
        std::fs::read_dir(folder.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
    drop(store);
    drop(grant);
    drop(factory);
    sql.shutdown(deadline()).await.unwrap();
    drop(c);
    f.shutdown().unwrap();
}
