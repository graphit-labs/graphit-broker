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
    FilesystemCompleteUpload, FilesystemCompletedPart, FilesystemConditions,
    FilesystemPartsRequest, FilesystemPutOptions, FilesystemRequest, FilesystemSessionError,
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
async fn filesystem_multipart_postgres_contract() {
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
            operations: &["read"],
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
    let read_grant = factory
        .authorize(
            &raw,
            &[],
            &StorageScope::project(A, StorageModule::Hub).unwrap(),
            deadline(),
        )
        .await
        .unwrap();
    let issuer = issuer(0x71, "primary", 65536);
    let keys = issuer.issue(&read_grant).await.unwrap();
    let readonly = Arc::new(
        issuer
            .verify_session("primary", keys.access_key_id(), keys.session_token())
            .unwrap(),
    );
    c.execute("DELETE FROM public.grant_s3_operations WHERE grant_id='objects'; INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('objects','publish')").await.unwrap();
    let grant = factory
        .authorize(
            &raw,
            &[],
            &StorageScope::project(A, StorageModule::Hub).unwrap(),
            deadline(),
        )
        .await
        .unwrap();
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
    assert!(matches!(
        store.create_upload(
            &proof,
            &format!("tenant/v1/projects/{B}/artifacts/denied"),
            None,
            &request()
        ),
        Err(FilesystemStoreError::Forbidden)
    ));
    assert!(matches!(
        store.create_upload(&readonly, &key, None, &request()),
        Err(FilesystemStoreError::Forbidden)
    ));
    let id = store
        .create_upload(&proof, &key, Some("application/x-native"), &request())
        .unwrap();
    assert_eq!(id.len(), 43);
    let part1 = store
        .upload_part(
            &proof,
            &key,
            &id,
            1,
            Cursor::new(b"hello part1"),
            &request(),
        )
        .unwrap();
    let part3 = store
        .upload_part(
            &proof,
            &key,
            &id,
            3,
            Cursor::new(b"hello part3"),
            &request(),
        )
        .unwrap();
    assert_eq!(part1.size, 11);
    assert_eq!(part3.size, 11);
    assert!(matches!(
        store.list_parts(
            &readonly,
            &key,
            FilesystemPartsRequest {
                upload_id: &id,
                marker: None,
                max_parts: None
            },
            &request()
        ),
        Err(FilesystemStoreError::Forbidden)
    ));
    let page = store
        .list_parts(
            &proof,
            &key,
            FilesystemPartsRequest {
                upload_id: &id,
                marker: None,
                max_parts: Some(1),
            },
            &request(),
        )
        .unwrap();
    assert_eq!(page.parts.len(), 1);
    assert_eq!(page.parts[0].number, 1);
    assert!(page.is_truncated);
    assert_eq!(page.next_marker, Some(1));
    let tail = store
        .list_parts(
            &proof,
            &key,
            FilesystemPartsRequest {
                upload_id: &id,
                marker: page.next_marker,
                max_parts: Some(0),
            },
            &request(),
        )
        .unwrap();
    assert_eq!(tail.parts.len(), 1);
    assert_eq!(tail.parts[0].number, 3);
    assert!(!tail.is_truncated);
    for number in [0, 10001] {
        assert!(matches!(
            store.upload_part(&proof, &key, &id, number, Cursor::new(b"no"), &request()),
            Err(FilesystemStoreError::InvalidArgument)
        ));
    }
    for max in [-1, 1001] {
        assert!(matches!(
            store.list_parts(
                &proof,
                &key,
                FilesystemPartsRequest {
                    upload_id: &id,
                    marker: None,
                    max_parts: Some(max)
                },
                &request()
            ),
            Err(FilesystemStoreError::InvalidArgument)
        ));
    }
    assert!(matches!(
        store.upload_part(&proof, &key, "../escape", 1, Cursor::new(b"no"), &request()),
        Err(FilesystemStoreError::NoSuchUpload)
    ));
    let another = format!("{root}/another");
    assert!(matches!(
        store.upload_part(&proof, &another, &id, 1, Cursor::new(b"no"), &request()),
        Err(FilesystemStoreError::NoSuchUpload)
    ));
    assert!(matches!(
        store.abort_upload(&proof, &another, &id, &request()),
        Err(FilesystemStoreError::NoSuchUpload)
    ));
    let foreign_issuer = FilesystemStorageIssuer::new(
        vec![
            FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                name: "primary".into(),
                bucket: "graphit-foreign".into(),
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
    let foreign_keys = foreign_issuer.issue(&grant).await.unwrap();
    let foreign = foreign_issuer
        .verify_session(
            "primary",
            foreign_keys.access_key_id(),
            foreign_keys.session_token(),
        )
        .unwrap();
    assert!(matches!(
        store.abort_upload(&foreign, &key, &id, &request()),
        Err(FilesystemStoreError::Forbidden)
    ));
    let completed = |first: &str, third: &str| {
        vec![
            FilesystemCompletedPart {
                number: 1,
                etag: first.into(),
            },
            FilesystemCompletedPart {
                number: 3,
                etag: third.into(),
            },
        ]
    };
    for wrong in ["", "unquoted", &format!("\"{}\"", "0".repeat(64))] {
        assert!(matches!(
            store.complete_upload(
                &proof,
                &key,
                FilesystemCompleteUpload {
                    upload_id: &id,
                    parts: &completed(wrong, &part3.etag),
                    conditions: &unconditional
                },
                &request()
            ),
            Err(FilesystemStoreError::InvalidPart)
        ));
    }
    let reversed = vec![
        FilesystemCompletedPart {
            number: 3,
            etag: part3.etag.clone(),
        },
        FilesystemCompletedPart {
            number: 1,
            etag: part1.etag.clone(),
        },
    ];
    assert!(matches!(
        store.complete_upload(
            &proof,
            &key,
            FilesystemCompleteUpload {
                upload_id: &id,
                parts: &reversed,
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidPartOrder)
    ));
    let missing = vec![FilesystemCompletedPart {
        number: 2,
        etag: part1.etag.clone(),
    }];
    assert!(matches!(
        store.complete_upload(
            &proof,
            &key,
            FilesystemCompleteUpload {
                upload_id: &id,
                parts: &missing,
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidPart)
    ));
    assert_eq!(
        std::fs::read_dir(folder.path().join("multipart").join(&id).join("parts"))
            .unwrap()
            .count(),
        2
    );
    assert!(!folder.path().join("data").join(&key).exists());
    let replacement = store
        .upload_part(
            &proof,
            &key,
            &id,
            1,
            Cursor::new(b"new partone"),
            &request(),
        )
        .unwrap();
    assert_ne!(replacement.etag, part1.etag);
    assert!(matches!(
        store.complete_upload(
            &proof,
            &key,
            FilesystemCompleteUpload {
                upload_id: &id,
                parts: &completed(&part1.etag, &part3.etag),
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidPart)
    ));
    let renewed_keys = issuer.issue(&grant).await.unwrap();
    assert_ne!(renewed_keys.access_key_id(), keys.access_key_id());
    let renewed = Arc::new(
        issuer
            .verify_session(
                "primary",
                renewed_keys.access_key_id(),
                renewed_keys.session_token(),
            )
            .unwrap(),
    );
    let result = store
        .complete_upload(
            &renewed,
            &key,
            FilesystemCompleteUpload {
                upload_id: &id,
                parts: &completed(&replacement.etag, &part3.etag),
                conditions: &unconditional,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(result.size, 22);
    assert_eq!(result.content_type, "application/x-native");
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&key)).unwrap(),
        b"new partonehello part3"
    );
    assert!(!folder.path().join("multipart").join(&id).exists());
    let cap_key = format!("{root}/cap");
    let cap_id = store
        .create_upload(&proof, &cap_key, None, &request())
        .unwrap();
    let a = store
        .upload_part(
            &proof,
            &cap_key,
            &cap_id,
            1,
            Cursor::new([1u8; 20]),
            &request(),
        )
        .unwrap();
    let b = store
        .upload_part(
            &proof,
            &cap_key,
            &cap_id,
            3,
            Cursor::new([2u8; 20]),
            &request(),
        )
        .unwrap();
    assert!(matches!(
        store.complete_upload(
            &proof,
            &cap_key,
            FilesystemCompleteUpload {
                upload_id: &cap_id,
                parts: &completed(&a.etag, &b.etag),
                conditions: &unconditional
            },
            &request()
        ),
        Err(FilesystemStoreError::TooLarge)
    ));
    assert!(!folder.path().join("data").join(&cap_key).exists());
    assert_eq!(
        std::fs::read_dir(folder.path().join("multipart").join(&cap_id).join("parts"))
            .unwrap()
            .count(),
        2
    );
    store
        .abort_upload(&proof, &cap_key, &cap_id, &request())
        .unwrap();
    assert!(!folder.path().join("multipart").join(&cap_id).exists());
    for (tail, total) in [(16usize, 32u64), (17usize, 33u64)] {
        let boundary_key = format!("{root}/boundary-{total}");
        let boundary_id = store
            .create_upload(&proof, &boundary_key, None, &request())
            .unwrap();
        let first = store
            .upload_part(
                &proof,
                &boundary_key,
                &boundary_id,
                1,
                Cursor::new([0x11u8; 16]),
                &request(),
            )
            .unwrap();
        let third = store
            .upload_part(
                &proof,
                &boundary_key,
                &boundary_id,
                3,
                Cursor::new(vec![0x22u8; tail]),
                &request(),
            )
            .unwrap();
        let assembled = store.complete_upload(
            &proof,
            &boundary_key,
            FilesystemCompleteUpload {
                upload_id: &boundary_id,
                parts: &completed(&first.etag, &third.etag),
                conditions: &unconditional,
            },
            &request(),
        );
        if total == 32 {
            assert_eq!(assembled.unwrap().size, 32);
            assert_eq!(
                std::fs::read(folder.path().join("data").join(&boundary_key)).unwrap(),
                [vec![0x11u8; 16], vec![0x22u8; 16]].concat()
            );
            assert!(!folder.path().join("multipart").join(&boundary_id).exists());
        } else {
            assert!(matches!(assembled, Err(FilesystemStoreError::TooLarge)));
            assert!(!folder.path().join("data").join(&boundary_key).exists());
            assert_eq!(
                std::fs::read_dir(
                    folder
                        .path()
                        .join("multipart")
                        .join(&boundary_id)
                        .join("parts")
                )
                .unwrap()
                .count(),
                2
            );
            store
                .abort_upload(&proof, &boundary_key, &boundary_id, &request())
                .unwrap();
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let uncertain_key = format!("{root}/uncertain-part");
        let uncertain_id = store
            .create_upload(&proof, &uncertain_key, None, &request())
            .unwrap();
        let upload = folder.path().join("multipart").join(&uncertain_id);
        let before = std::fs::read(upload.join("manifest")).unwrap();
        std::fs::set_permissions(&upload, std::fs::Permissions::from_mode(0o500)).unwrap();
        let part_result = store.upload_part(
            &proof,
            &uncertain_key,
            &uncertain_id,
            1,
            Cursor::new(b"uncertain"),
            &request(),
        );
        std::fs::set_permissions(&upload, std::fs::Permissions::from_mode(0o700)).unwrap();
        match part_result {
            Err(FilesystemStoreError::CommitUncertain(cause)) => {
                assert!(matches!(*cause, FilesystemStoreError::Io(_)))
            }
            _ => panic!("published part with failed progress must retain actual uncertain IO"),
        }
        assert_eq!(std::fs::read(upload.join("parts/1")).unwrap(), b"uncertain");
        assert_eq!(std::fs::read(upload.join("manifest")).unwrap(), before);
        let part = store
            .list_parts(
                &proof,
                &uncertain_key,
                FilesystemPartsRequest {
                    upload_id: &uncertain_id,
                    marker: None,
                    max_parts: None,
                },
                &request(),
            )
            .unwrap()
            .parts
            .pop()
            .unwrap();
        let multipart_dir = folder.path().join("multipart");
        std::fs::set_permissions(&multipart_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let complete_result = store.complete_upload(
            &proof,
            &uncertain_key,
            FilesystemCompleteUpload {
                upload_id: &uncertain_id,
                parts: &[FilesystemCompletedPart {
                    number: 1,
                    etag: part.etag,
                }],
                conditions: &unconditional,
            },
            &request(),
        );
        std::fs::set_permissions(&multipart_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        match complete_result {
            Err(FilesystemStoreError::CommitUncertain(cause)) => {
                assert!(matches!(*cause, FilesystemStoreError::Io(_)))
            }
            _ => panic!(
                "published object with failed upload cleanup must retain actual uncertain IO"
            ),
        }
        assert_eq!(
            std::fs::read(folder.path().join("data").join(&uncertain_key)).unwrap(),
            b"uncertain"
        );
        let cleanup_trigger = store
            .create_upload(&proof, &uncertain_key, None, &request())
            .unwrap();
        assert!(
            !upload.exists(),
            "a slot left without an active manifest is reclaimed"
        );
        store
            .abort_upload(&proof, &uncertain_key, &cleanup_trigger, &request())
            .unwrap();
    }
    let retry_key = format!("{root}/retry");
    store
        .put(
            &proof,
            &retry_key,
            Cursor::new(b"existing"),
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &unconditional,
            },
            &request(),
        )
        .unwrap();
    let retry_id = store
        .create_upload(&proof, &retry_key, None, &request())
        .unwrap();
    let retry = store
        .upload_part(
            &proof,
            &retry_key,
            &retry_id,
            1,
            Cursor::new(b"replacement"),
            &request(),
        )
        .unwrap();
    let parts = vec![FilesystemCompletedPart {
        number: 1,
        etag: retry.etag,
    }];
    let create = FilesystemConditions {
        if_match: None,
        if_none_match: Some("*".into()),
    };
    assert!(matches!(
        store.complete_upload(
            &proof,
            &retry_key,
            FilesystemCompleteUpload {
                upload_id: &retry_id,
                parts: &parts,
                conditions: &create
            },
            &request()
        ),
        Err(FilesystemStoreError::Precondition)
    ));
    assert!(folder.path().join("multipart").join(&retry_id).exists());
    let known = FilesystemConditions {
        if_match: Some(store.head(&proof, &retry_key, &request()).unwrap().etag),
        if_none_match: None,
    };
    store
        .complete_upload(
            &proof,
            &retry_key,
            FilesystemCompleteUpload {
                upload_id: &retry_id,
                parts: &parts,
                conditions: &known,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&retry_key)).unwrap(),
        b"replacement"
    );
    let race_key = format!("{root}/complete-race");
    let mut uploads = Vec::new();
    for body in [b"left", b"right".as_slice()] {
        let id = store
            .create_upload(&proof, &race_key, None, &request())
            .unwrap();
        let part = store
            .upload_part(&proof, &race_key, &id, 1, Cursor::new(body), &request())
            .unwrap();
        uploads.push((id, part.etag));
    }
    let barrier = Arc::new(Barrier::new(3));
    let (send, receive) = std::sync::mpsc::sync_channel(2);
    let mut workers = Vec::new();
    for (id, etag) in &uploads {
        let store = store.clone();
        let proof = proof.clone();
        let barrier = barrier.clone();
        let key = race_key.clone();
        let id = id.clone();
        let etag = etag.clone();
        let send = send.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let condition = FilesystemConditions {
                if_match: None,
                if_none_match: Some("*".into()),
            };
            let parts = [FilesystemCompletedPart { number: 1, etag }];
            send.send(store.complete_upload(
                &proof,
                &key,
                FilesystemCompleteUpload {
                    upload_id: &id,
                    parts: &parts,
                    conditions: &condition,
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
    assert_eq!(
        uploads
            .iter()
            .filter(|(id, _)| folder.path().join("multipart").join(id).exists())
            .count(),
        1
    );
    for (id, _) in uploads {
        if folder.path().join("multipart").join(&id).exists() {
            store
                .abort_upload(&proof, &race_key, &id, &request())
                .unwrap();
        }
    }
    struct Cancelling {
        cancellation: CancellationToken,
    }
    impl Read for Cancelling {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.cancellation.cancel();
            buf[0] = 1;
            Ok(1)
        }
    }
    let cancel_key = format!("{root}/cancel");
    let cancel_id = store
        .create_upload(&proof, &cancel_key, None, &request())
        .unwrap();
    let manifest_path = folder
        .path()
        .join("multipart")
        .join(&cancel_id)
        .join("manifest");
    let before = std::fs::read(&manifest_path).unwrap();
    let cancel = request();
    assert!(matches!(
        store.upload_part(
            &proof,
            &cancel_key,
            &cancel_id,
            1,
            Cancelling {
                cancellation: cancel.cancellation.clone()
            },
            &cancel
        ),
        Err(FilesystemStoreError::Cancelled)
    ));
    assert_eq!(std::fs::read(&manifest_path).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(
            folder
                .path()
                .join("multipart")
                .join(&cancel_id)
                .join("parts")
        )
        .unwrap()
        .count(),
        0
    );
    struct Delayed {
        until: Instant,
    }
    impl Read for Delayed {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(
                self.until.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
            );
            buf[0] = 1;
            Ok(1)
        }
    }
    let timed = FilesystemRequest {
        deadline: Instant::now() + Duration::from_millis(100),
        cancellation: CancellationToken::new(),
    };
    assert!(matches!(
        store.upload_part(
            &proof,
            &cancel_key,
            &cancel_id,
            1,
            Delayed {
                until: timed.deadline
            },
            &timed
        ),
        Err(FilesystemStoreError::Session(
            FilesystemSessionError::Deadline
        ))
    ));
    assert_eq!(std::fs::read(&manifest_path).unwrap(), before);
    assert_eq!(
        std::fs::read_dir(
            folder
                .path()
                .join("multipart")
                .join(&cancel_id)
                .join("parts")
        )
        .unwrap()
        .count(),
        0
    );
    let bad_key = format!("{root}/bad-author");
    let bad_id = store
        .create_upload(&proof, &bad_key, Some("application/x-good"), &request())
        .unwrap();
    let bad_path = folder
        .path()
        .join("multipart")
        .join(&bad_id)
        .join("manifest");
    let good = std::fs::read(&bad_path).unwrap();
    let mut malformed: Value = serde_json::from_slice(&good).unwrap();
    malformed["content_type"] = json!(42);
    std::fs::write(&bad_path, serde_json::to_vec(&malformed).unwrap()).unwrap();
    assert!(matches!(
        store.list_parts(
            &proof,
            &bad_key,
            FilesystemPartsRequest {
                upload_id: &bad_id,
                marker: None,
                max_parts: None
            },
            &request()
        ),
        Err(FilesystemStoreError::InvalidMetadata)
    ));
    std::fs::write(&bad_path, good).unwrap();
    store
        .abort_upload(&proof, &bad_key, &bad_id, &request())
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("private"), b"outside").unwrap();
        symlink(
            outside.path().join("private"),
            folder
                .path()
                .join("multipart")
                .join(&cancel_id)
                .join("parts/1"),
        )
        .unwrap();
        assert!(
            store
                .upload_part(
                    &proof,
                    &cancel_key,
                    &cancel_id,
                    1,
                    Cursor::new(b"no"),
                    &request()
                )
                .is_err()
        );
        assert!(
            store
                .list_parts(
                    &proof,
                    &cancel_key,
                    FilesystemPartsRequest {
                        upload_id: &cancel_id,
                        marker: None,
                        max_parts: None
                    },
                    &request()
                )
                .is_err()
        );
        store
            .abort_upload(&proof, &cancel_key, &cancel_id, &request())
            .unwrap();
        assert_eq!(
            std::fs::read(outside.path().join("private")).unwrap(),
            b"outside"
        );
    }
    #[cfg(not(unix))]
    store
        .abort_upload(&proof, &cancel_key, &cancel_id, &request())
        .unwrap();
    let stale_key = format!("{root}/stale");
    let stale_id = store
        .create_upload(&proof, &stale_key, None, &request())
        .unwrap();
    store
        .upload_part(
            &proof,
            &stale_key,
            &stale_id,
            1,
            Cursor::new(b"stale"),
            &request(),
        )
        .unwrap();
    age_upload(folder.path(), &stale_id);
    let trigger = store
        .create_upload(&proof, &another, None, &request())
        .unwrap();
    assert!(!folder.path().join("multipart").join(&stale_id).exists());
    store
        .abort_upload(&proof, &another, &trigger, &request())
        .unwrap();
    let resume_key = format!("{root}/resume");
    let resume_id = store
        .create_upload(&proof, &resume_key, None, &request())
        .unwrap();
    let resume = store
        .upload_part(
            &proof,
            &resume_key,
            &resume_id,
            1,
            Cursor::new(b"resume"),
            &request(),
        )
        .unwrap();
    let startup_id = store
        .create_upload(&proof, &stale_key, None, &request())
        .unwrap();
    age_upload(folder.path(), &startup_id);
    assert_eq!(
        std::fs::read_dir(folder.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
    drop(store);
    let store = FilesystemStore::open(storage(folder.path())).unwrap();
    assert!(!folder.path().join("multipart").join(&startup_id).exists());
    let preserved = store
        .list_parts(
            &renewed,
            &resume_key,
            FilesystemPartsRequest {
                upload_id: &resume_id,
                marker: None,
                max_parts: None,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(preserved.parts.len(), 1);
    assert_eq!(preserved.parts[0].etag, resume.etag);
    store
        .complete_upload(
            &renewed,
            &resume_key,
            FilesystemCompleteUpload {
                upload_id: &resume_id,
                parts: &[FilesystemCompletedPart {
                    number: 1,
                    etag: resume.etag,
                }],
                conditions: &unconditional,
            },
            &request(),
        )
        .unwrap();
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&resume_key)).unwrap(),
        b"resume"
    );
    drop(store);
    drop(read_grant);
    drop(grant);
    drop(factory);
    sql.shutdown(deadline()).await.unwrap();
    drop(c);
    f.shutdown().unwrap();
}
fn age_upload(folder: &std::path::Path, id: &str) {
    let path = folder.join("multipart").join(id).join("manifest");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let old = seconds() - 25 * 60 * 60;
    manifest["created"] = json!(old);
    manifest["last_progress"] = json!(old);
    std::fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}
