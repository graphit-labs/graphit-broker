#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves other suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
mod support_aws;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, StorageAdmissionError, StorageModule, StorageScope,
};
use broker_security::TokenKind;
use broker_storage::{
    AwsCredentialSource, AwsEndpointTransport, AwsStorageIssuer, AwsStorageRoute,
    AwsStorageRouteConfig, IssuedStorageCredentials, PrivateStaticCredentials, StorageIssueError,
};
use futures_util::TryStreamExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use object_store::{
    ClientOptions, ObjectStore, ObjectStoreExt, PutMode, PutOptions,
    aws::{AmazonS3, AmazonS3Builder, S3ConditionalPut},
    path::Path as ObjectPath,
};
use serde_json::{Value, json};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use support_aws::Minio;
use zeroize::Zeroizing;
const A: &str = "01D39ZY06FGSCTVN4T2V9PKHFZ";
const B: &str = "01D39ZY06FGSCTVN4T2V9PKHG0";
const ISSUER: &str = "https://broker.example.test";
const RESOURCE: &str = "https://broker.example.test/v1";
const RAW: &str = "gb_at_ephemeral-hub-access";
const SERVICE: &str = "gb_sc_ephemeral-hub-service";
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
fn micros() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}
fn config(f: &Fixture) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(f.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new("hub_owner".into(), Zeroizing::new("ephemeral-owner".into())),
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
async fn clear(c: &mut PgConnection) {
    c.execute("DELETE FROM public.resource_grants; UPDATE public.resource_acl_state SET revision=revision+1,updated_at=0 WHERE id=1").await.unwrap();
}
async fn seed_local(c: &mut PgConnection) {
    c.execute("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human','','current-name','current-email','current-org','[\"current-team\"]',1,0,1,0,0),('bot','bot-subject','service','','Bot','','Automation','[]',1,0,1,0,0)").await.unwrap();
    for (raw, id, kind, token_kind, subject) in [
        (
            RAW,
            "hub-access",
            "access",
            TokenKind::LocalAccess,
            "alice-subject",
        ),
        (
            SERVICE,
            "hub-service",
            "service",
            TokenKind::ServiceCredential,
            "bot-subject",
        ),
    ] {
        let digest = support::digester()
            .token(token_kind, raw.as_bytes())
            .unwrap();
        let principal = json!({"issuer":"local","subject":subject,"username":"stale-name","auth_method":"local-token","organization":"stale-org","teams":["stale-team"],"local_user_revision":1}).to_string();
        sqlx_core::query::query("INSERT INTO public.local_tokens(token_hash,token_id,token_kind,subject,oidc_subject,principal_json,client_id,audience,resource,scopes_json,local_user_revision,family_id,auth_time,expires_at,created_at) VALUES($1,$2,$3,$4,'pseudonymous-other',$5,'explicit-client','explicit-audience','','[]',1,'',0,$6,0)").bind(digest.to_sql_hex()).bind(id).bind(kind).bind(subject).bind(principal).bind(micros()+600_000_000).execute(&mut *c).await.unwrap();
    }
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
fn ok<T, E>(result: Result<T, E>, label: &str) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("{label}"),
    }
}
fn route(service: &Minio, key: &str, secret: &str) -> AwsStorageRoute {
    route_with_conditional_delete(service, key, secret, false)
}
fn route_with_conditional_delete(
    service: &Minio,
    key: &str,
    secret: &str,
    conditional_delete: bool,
) -> AwsStorageRoute {
    ok(
        AwsStorageRoute::new(AwsStorageRouteConfig {
            name: "primary".into(),
            region: "us-east-1".into(),
            bucket: service.bucket.clone(),
            base_prefix: "tenant".into(),
            conditional_delete,
            s3_endpoint: Some(service.endpoint.clone()),
            sts_endpoint: None,
            role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
            session_name: "  graphit-broker  ".into(),
            session_duration: Duration::from_secs(900),
            endpoint_transport: AwsEndpointTransport::LoopbackHttp,
            credential_source: AwsCredentialSource::StaticPair(ok(
                PrivateStaticCredentials::new(
                    Zeroizing::new(key.into()),
                    Zeroizing::new(secret.into()),
                ),
                "static pair",
            )),
        }),
        "explicit route",
    )
}
fn objects(keys: &IssuedStorageCredentials) -> AmazonS3 {
    ok(
        AmazonS3Builder::new()
            .with_bucket_name(keys.bucket())
            .with_region(keys.region())
            .with_endpoint(keys.endpoint().unwrap())
            .with_virtual_hosted_style_request(false)
            .with_access_key_id(keys.access_key_id())
            .with_secret_access_key(keys.secret_access_key())
            .with_token(keys.session_token())
            .with_conditional_put(S3ConditionalPut::ETagMatch)
            .with_client_options(
                ClientOptions::new()
                    .with_allow_http(true)
                    .with_timeout(Duration::from_secs(5))
                    .with_connect_timeout(Duration::from_secs(2)),
            )
            .with_retry(object_store::RetryConfig {
                max_retries: 0,
                retry_timeout: Duration::from_secs(5),
                ..Default::default()
            })
            .build(),
        "issued S3 configuration",
    )
}
fn denied<T>(result: object_store::Result<T>) {
    match result {
        Err(object_store::Error::PermissionDenied { .. }) => {}
        Err(object_store::Error::Generic { source, .. }) => {
            let text = Zeroizing::new(source.to_string());
            assert!(
                text.contains("403 Forbidden") || text.ends_with("(code: AccessDenied)"),
                "actual service denial required"
            );
        }
        _ => panic!("actual permission denial required"),
    }
}
async fn restricted(c: &mut PgConnection, operation: &str) {
    clear(c).await;
    grant(
        c,
        "current",
        &Rule {
            kind: "authenticated",
            principal: "",
            caps: &["s3"],
            projects: &[A],
            operations: &[operation],
            prefixes: &["v1/projects/{project}/artifacts"],
            route: "primary",
        },
    )
    .await;
}
#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER, private Native/opaque grants, SDK STS and owned MinIO S3"]
async fn aws_hub_storage_sts_s3_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION hub_owner;GRANT CONNECT,TEMP ON DATABASE postgres TO hub_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    assert!(
        !sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT rolsuper FROM pg_roles WHERE rolname='hub_owner'"
        )
        .fetch_one(&mut c)
        .await
        .unwrap()
    );
    seed_local(&mut c).await;
    let signer = Signer::new();
    let verifier = signer.verifier(Some(RESOURCE));
    let claims = signer.claims();
    let raw = signer.sign(&claims);
    let scope = StorageScope::project(A, StorageModule::Hub).unwrap();
    let mut service = Minio::start().await;
    let root = format!("tenant/v1/projects/{A}/artifacts");
    let seed = format!("{root}/seed");
    let sibling = format!("tenant/v1/projects/{B}/artifacts/seed");
    let boundary = format!("tenant/v1/projects/{A}/artifacts2/seed");
    for key in [&seed, &sibling, &boundary] {
        service.seed(key, b"seed-data");
    }
    let issuer = AwsStorageIssuer::new(
        vec![route(&service, &service.caller_key, &service.caller_secret)],
        Duration::from_secs(5),
    )
    .unwrap();
    restricted(&mut c, "read").await;
    provider_child(&service, &f, "environment").await;
    provider_child(&service, &f, "profile").await;
    provider_child(&service, &f, "missing").await;
    provider_child(&service, &f, "static-isolation").await;
    let mut issued = Vec::new();
    for operation in ["read", "write", "publish", "delete"] {
        restricted(&mut c, operation).await;
        let factory = store
            .broker_storage_authorizer(&verifier, n(65536), "primary")
            .unwrap();
        let grant = factory
            .authorize(&raw, &[], &scope, deadline())
            .await
            .unwrap();
        let keys = ok(issuer.issue(&grant).await, "actual STS issuance");
        assert_ne!(keys.access_key_id(), service.caller_key.as_str());
        assert!(!keys.session_token().is_empty() && !keys.secret_access_key().is_empty());
        assert_eq!(keys.project_id(), A);
        assert_eq!(keys.bucket(), service.bucket);
        assert_eq!(keys.base_prefix(), "tenant");
        assert!(!keys.supports_conditional_delete());
        assert!(
            keys.expiry() > UNIX_EPOCH + Duration::from_secs(claims["exp"].as_u64().unwrap()),
            "actual STS900s is independent of JWT600s"
        );
        assert_eq!(format!("{keys:?}"), "IssuedStorageCredentials([REDACTED])");
        issued.push(objects(&keys));
    }
    let read = &issued[0];
    let write = &issued[1];
    let publish = &issued[2];
    let delete = &issued[3];
    let seed_path = ObjectPath::from(seed.clone());
    let bytes = ok(
        ok(read.get(&seed_path).await, "allowed read").bytes().await,
        "read body",
    );
    assert_eq!(bytes.as_ref(), b"seed-data");
    denied(read.get(&ObjectPath::from(sibling.clone())).await);
    denied(read.get(&ObjectPath::from(boundary.clone())).await);
    denied(
        read.put(&ObjectPath::from(format!("{root}/read-write")), "x".into())
            .await,
    );
    denied(read.delete(&seed_path).await);
    assert!(service.exists(&seed));
    let listing = ok(
        read.list(Some(&ObjectPath::from(root.clone())))
            .try_collect::<Vec<_>>()
            .await,
        "allowed list",
    );
    assert!(listing.iter().any(|m| m.location == seed_path));
    denied(read.list(None).try_collect::<Vec<_>>().await);
    let created = ObjectPath::from(format!("{root}/conditional"));
    let first = ok(
        write
            .put_opts(
                &created,
                "first".into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await,
        "conditional create",
    );
    assert!(matches!(
        write
            .put_opts(
                &created,
                "duplicate".into(),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                }
            )
            .await,
        Err(object_store::Error::AlreadyExists { .. })
    ));
    let version = object_store::UpdateVersion::from(first);
    ok(
        write
            .put_opts(
                &created,
                "updated".into(),
                PutOptions {
                    mode: PutMode::Update(version.clone()),
                    ..Default::default()
                },
            )
            .await,
        "conditional update",
    );
    assert!(matches!(
        write
            .put_opts(
                &created,
                "stale".into(),
                PutOptions {
                    mode: PutMode::Update(version),
                    ..Default::default()
                }
            )
            .await,
        Err(object_store::Error::Precondition { .. })
    ));
    denied(write.delete(&created).await);
    assert!(service.exists(created.as_ref()));
    denied(
        write
            .put(&ObjectPath::from(sibling.clone()), "escape".into())
            .await,
    );
    let large = ObjectPath::from(format!("{root}/multipart"));
    let mut upload = ok(write.put_multipart(&large).await, "multipart start");
    ok(
        upload.put_part(vec![42u8; 5 * 1024 * 1024].into()).await,
        "multipart part1",
    );
    ok(
        upload.put_part(vec![43u8; 1024].into()).await,
        "multipart part2",
    );
    ok(upload.complete().await, "multipart complete");
    let content = ok(
        ok(read.get(&large).await, "multipart read").bytes().await,
        "multipart body",
    );
    assert_eq!(content.len(), 5 * 1024 * 1024 + 1024);
    assert_eq!(content[0], 42);
    let aborted = ObjectPath::from(format!("{root}/aborted"));
    let mut upload = ok(write.put_multipart(&aborted).await, "abort start");
    ok(
        upload.put_part(vec![44u8; 5 * 1024 * 1024].into()).await,
        "abort part",
    );
    ok(upload.abort().await, "actual abort");
    assert!(!service.exists(aborted.as_ref()));
    ok(publish.delete(&created).await, "publish delete");
    assert!(!service.exists(created.as_ref()));
    let delete_only = format!("{root}/delete-only");
    service.seed(&delete_only, b"delete");
    ok(
        delete.delete(&ObjectPath::from(delete_only.clone())).await,
        "delete allowed",
    );
    assert!(!service.exists(&delete_only));
    denied(delete.get(&seed_path).await);
    denied(delete.delete(&ObjectPath::from(sibling.clone())).await);
    assert!(service.exists(&sibling));
    // Issued AWS sessions retain their service policy after a new SQL denial.
    clear(&mut c).await;
    let factory = store
        .broker_storage_authorizer(&verifier, n(65536), "primary")
        .unwrap();
    assert!(matches!(
        factory.authorize(&raw, &[], &scope, deadline()).await,
        Err(StorageAdmissionError::Forbidden)
    ));
    ok(
        read.get(&seed_path).await,
        "issued session remains active after grant withdrawal",
    );
    // Current opaque access and service credentials produce actual private grants and STS sessions.
    restricted(&mut c, "read").await;
    for token in [RAW, SERVICE] {
        let factory = store
            .local_storage_authorizer("explicit-audience", n(8192), n(65536), "primary")
            .unwrap();
        let grant = factory
            .authorize(token, &[], &scope, deadline())
            .await
            .unwrap();
        let keys = ok(issuer.issue(&grant).await, "opaque actual STS");
        ok(
            objects(&keys).get(&seed_path).await,
            "opaque actual S3 read",
        );
    }
    let wrong = AwsStorageIssuer::new(
        vec![route(
            &service,
            &service.caller_key,
            "wrong-synthetic-secret",
        )],
        Duration::from_secs(2),
    )
    .unwrap();
    let factory = store
        .broker_storage_authorizer(&verifier, n(65536), "primary")
        .unwrap();
    let grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    assert!(matches!(
        wrong.issue(&grant).await,
        Err(StorageIssueError::Forbidden | StorageIssueError::Sdk)
    ));
    // Original/fresh proof gates bound real service waits, without claiming session rollback.
    let end = Instant::now() + Duration::from_millis(500);
    let grant = factory.authorize(&raw, &[], &scope, end).await.unwrap();
    service.pause();
    let timed = issuer.issue(&grant).await;
    assert!(
        matches!(
            timed,
            Err(StorageIssueError::Deadline)
                | Err(StorageIssueError::Admission(
                    StorageAdmissionError::Deadline
                ))
        ),
        "finite timeout origin: {timed:?}"
    );
    service.resume();
    let grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    ok(
        issuer.issue(&grant).await,
        "real service recovers after Original",
    );
    let grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    service.pause();
    let mut future = Box::pin(issuer.issue(&grant));
    tokio::select! {_=&mut future=>panic!("paused service must wait"),_=tokio::time::sleep(Duration::from_millis(150))=>{}}
    drop(future);
    service.resume();
    let grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    ok(
        issuer.issue(&grant).await,
        "real session after cancelled future",
    );
    let mut short_claims = signer.claims();
    short_claims["exp"] = json!(seconds() + 2);
    let short_raw = signer.sign(&short_claims);
    let auth_original = deadline();
    let grant = factory
        .authorize(&short_raw, &[], &scope, auth_original)
        .await
        .unwrap();
    service.pause();
    let mut pending = Box::pin(issuer.issue(&grant));
    tokio::select! {_=&mut pending=>panic!("paused service must stay pending"),_=tokio::time::sleep(Duration::from_millis(2250))=>{}}
    service.resume();
    assert!(matches!(
        pending.await,
        Err(StorageIssueError::Admission(StorageAdmissionError::Native(
            broker_control::BrokerAccessError::Expired
        )))
    ));
    assert!(
        Instant::now() < auth_original,
        "authentication expiry is independent of Original"
    );
    drop(issued);
    drop(issuer);
    drop(wrong);
    drop(service);
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
    drop(store);
    drop(f);
}

#[tokio::test]
#[ignore = "actual PostgreSQL TLS NOSUPERUSER, private Native grant and owned MinIO STS/S3"]
async fn aws_conditional_delete_capability_is_explicit_and_does_not_grant_delete() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION hub_owner;GRANT CONNECT,TEMP ON DATABASE postgres TO hub_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    restricted(&mut c, "read").await;
    let signer = Signer::new();
    let verifier = signer.verifier(Some(RESOURCE));
    let raw = signer.sign(&signer.claims());
    let scope = StorageScope::project(A, StorageModule::Hub).unwrap();
    let service = Minio::start().await;
    let key = format!("tenant/v1/projects/{A}/artifacts/capability");
    service.seed(&key, b"capability does not grant delete");
    let object = ObjectPath::from(key);
    let factory = store
        .broker_storage_authorizer(&verifier, n(65536), "primary")
        .unwrap();
    for capability in [false, true] {
        // This verifies configured DATA propagation, not atomic DELETE support in MinIO.
        let issuer = AwsStorageIssuer::new(
            vec![route_with_conditional_delete(
                &service,
                &service.caller_key,
                &service.caller_secret,
                capability,
            )],
            Duration::from_secs(5),
        )
        .unwrap();
        let grant = factory
            .authorize(&raw, &[], &scope, deadline())
            .await
            .unwrap();
        let keys = issuer.issue(&grant).await.unwrap();
        assert_eq!(keys.supports_conditional_delete(), capability);
        assert_eq!(
            keys.copy_if_not_exists(),
            broker_storage::StorageCopyIfNotExists::Multipart
        );
        let client = objects(&keys);
        assert_eq!(
            client
                .get(&object)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"capability does not grant delete"
        );
        denied(client.delete(&object).await);
        assert_eq!(
            client
                .get(&object)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            b"capability does not grant delete"
        );
    }
    drop(factory);
    drop(service);
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildInput {
    endpoint: String,
    bucket: String,
    port: u16,
    ca: Vec<u8>,
}
async fn provider_child(service: &Minio, f: &Fixture, mode: &str) {
    use std::io::Write;
    let folder = tempfile::tempdir().unwrap();
    let credentials = folder.path().join("credentials");
    let config_file = folder.path().join("config");
    let config_text = "[default]\nendpoint_url = http://198.51.100.9:9999\n";
    std::fs::write(&config_file, config_text).unwrap();
    if mode == "profile" {
        std::fs::write(
            &credentials,
            format!(
                "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
                service.caller_key.as_str(),
                service.caller_secret.as_str()
            ),
        )
        .unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if credentials.exists() {
            std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "aws_default_chain_child",
            "--test-threads=1",
        ])
        .env("BROKER_STS_PROVIDER_CHILD", mode)
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_CONFIG_FILE", config_file)
        .env("AWS_SHARED_CREDENTIALS_FILE", credentials)
        .env("AWS_ENDPOINT_URL_STS", "http://198.51.100.9:9999");
    for name in [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_ENDPOINT_URL",
    ] {
        command.env_remove(name);
    }
    if matches!(mode, "environment" | "static-isolation") {
        command
            .env("AWS_ACCESS_KEY_ID", service.caller_key.as_str())
            .env("AWS_SECRET_ACCESS_KEY", service.caller_secret.as_str());
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let body = Zeroizing::new(
        json!({"endpoint":service.endpoint,"bucket":service.bucket,"port":f.port,"ca":f.ca})
            .to_string(),
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "isolated real provider child failed");
            break;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated provider child timeout");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[tokio::test]
#[ignore = "isolated child only, actual parent-owned PostgreSQL TLS and MinIO"]
async fn aws_default_chain_child() {
    let Ok(mode) = std::env::var("BROKER_STS_PROVIDER_CHILD") else {
        return;
    };
    use std::io::Read;
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut input).unwrap();
    let data: ChildInput = serde_json::from_str(&input).unwrap();
    let config = PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(data.port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new("hub_owner".into(), Zeroizing::new("ephemeral-owner".into())),
        data.ca,
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        support::pool(2),
        support::limits(),
    )
    .unwrap();
    let store = PostgresControlStore::open(config, support::digester(), deadline())
        .await
        .unwrap();
    let signer = Signer::new();
    let verifier = signer.verifier(Some(RESOURCE));
    let raw = signer.sign(&signer.claims());
    let scope = StorageScope::project(A, StorageModule::Hub).unwrap();
    let factory = store
        .broker_storage_authorizer(&verifier, n(65536), "primary")
        .unwrap();
    let grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    let route = AwsStorageRoute::new(AwsStorageRouteConfig {
        name: "primary".into(),
        region: "us-east-1".into(),
        bucket: data.bucket,
        base_prefix: "tenant".into(),
        conditional_delete: false,
        s3_endpoint: Some(data.endpoint),
        sts_endpoint: None,
        role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
        session_name: "graphit-broker".into(),
        session_duration: Duration::from_secs(900),
        credential_source: if mode == "static-isolation" {
            AwsCredentialSource::StaticPair(
                PrivateStaticCredentials::new(
                    Zeroizing::new("synthetic-invalid-caller".into()),
                    Zeroizing::new("synthetic-invalid-secret".into()),
                )
                .unwrap(),
            )
        } else {
            AwsCredentialSource::DefaultChain
        },
        endpoint_transport: AwsEndpointTransport::LoopbackHttp,
    })
    .unwrap();
    let issuer = AwsStorageIssuer::new(vec![route], Duration::from_secs(5)).unwrap();
    if mode == "missing" {
        assert!(matches!(
            issuer.issue(&grant).await,
            Err(StorageIssueError::Provider)
        ));
        store.shutdown(deadline()).await.unwrap();
        return;
    }
    if mode == "static-isolation" {
        assert!(matches!(
            issuer.issue(&grant).await,
            Err(StorageIssueError::Forbidden | StorageIssueError::Sdk)
        ));
        store.shutdown(deadline()).await.unwrap();
        return;
    }
    let keys = ok(
        issuer.issue(&grant).await,
        "isolated DefaultChain actual STS",
    );
    ok(
        objects(&keys)
            .get(&ObjectPath::from(format!(
                "tenant/v1/projects/{A}/artifacts/seed"
            )))
            .await,
        "isolated DefaultChain actual S3",
    );
    store.shutdown(deadline()).await.unwrap();
}
