#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture is used by multiple suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, StorageAdmissionError, StorageModule, StorageOperation,
    StorageScope,
};
use broker_security::TokenKind;
use broker_storage::{
    FilesystemSessionError, FilesystemStorageIssuer, FilesystemStorageRoute,
    FilesystemStorageRouteConfig, StorageIssueError,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
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
        PostgresCredentials::new("fs_owner".into(), Zeroizing::new("ephemeral-owner".into())),
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
#[tokio::test]
#[ignore = "actual PostgreSQL TLS, NOSUPERUSER SQL admission and native filesystem session cryptography"]
async fn filesystem_sessions_postgres_contract() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE fs_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner';DROP SCHEMA public CASCADE;CREATE SCHEMA public AUTHORIZATION fs_owner;GRANT CONNECT,TEMP ON DATABASE postgres TO fs_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    assert!(
        !sqlx_core::query_scalar::query_scalar::<_, bool>(
            "SELECT rolsuper FROM pg_roles WHERE rolname='fs_owner'"
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
    let fs = issuer(0x71, "primary", 65536);
    let restarted = issuer(0x71, "primary", 65536);
    let rotated = issuer(0x72, "primary", 65536);
    let mut scopes: Vec<_> = [
        StorageModule::Hub,
        StorageModule::Task,
        StorageModule::Memory,
        StorageModule::Knowledge,
        StorageModule::Ast,
    ]
    .into_iter()
    .map(|m| StorageScope::project(A, m).unwrap())
    .collect();
    scopes.push(StorageScope::user_memory("Install-A").unwrap());
    scopes.push(StorageScope::global_hub());
    for operation in ["read", "write", "publish", "delete"] {
        clear(&mut c).await;
        grant(
            &mut c,
            "project",
            &Rule {
                kind: "authenticated",
                principal: "",
                caps: &["s3"],
                projects: &[A],
                operations: &[operation],
                prefixes: &[],
                route: "primary",
            },
        )
        .await;
        grant(
            &mut c,
            "nonproject",
            &Rule {
                kind: "authenticated",
                principal: "",
                caps: &["hub", "s3"],
                projects: &[],
                operations: &[operation],
                prefixes: &[],
                route: "primary",
            },
        )
        .await;
        for scope in &scopes {
            for ingress in 0..3 {
                let native = store
                    .broker_storage_authorizer(&verifier, n(65536), "primary")
                    .unwrap();
                let local = store
                    .local_storage_authorizer("explicit-audience", n(8192), n(65536), "primary")
                    .unwrap();
                let grant = if ingress == 0 {
                    native
                        .authorize(&raw, &[], scope, deadline())
                        .await
                        .unwrap()
                } else {
                    local
                        .authorize(
                            if ingress == 1 { RAW } else { SERVICE },
                            &[],
                            scope,
                            deadline(),
                        )
                        .await
                        .unwrap()
                };
                let keys = ok(fs.issue(&grant).await, "actual filesystem session issuance");
                let session = fs
                    .verify_session("primary", keys.access_key_id(), keys.session_token())
                    .unwrap();
                assert_eq!(session.canonical_subject(), grant.canonical_subject());
                assert_eq!(session.authorization_revision(), grant.revision());
                assert_eq!(session.scope().project_id(), scope.project_id());
                assert_eq!(session.scope().installation_id(), scope.installation_id());
                assert_eq!(session.scope().module(), scope.module());
                assert_eq!(keys.project_id(), scope.project_id().unwrap_or_default());
                assert_eq!(keys.bucket(), "graphit-local");
                assert_eq!(keys.base_prefix(), "tenant");
                assert_eq!(session.secret_access_key(), keys.secret_access_key());
                assert!(
                    keys.expiry()
                        > UNIX_EPOCH + Duration::from_secs(claims["exp"].as_u64().unwrap()),
                    "storage900s independent of JWT600s"
                );
                assert_eq!(format!("{keys:?}"), "IssuedStorageCredentials([REDACTED])");
                let op = match operation {
                    "read" => StorageOperation::Read,
                    "write" => StorageOperation::Write,
                    "publish" => StorageOperation::Publish,
                    "delete" => StorageOperation::Delete,
                    _ => unreachable!(),
                };
                assert!(!grant.prefixes(op).is_empty());
                for prefix in grant.prefixes(op) {
                    let root = format!("tenant/{prefix}");
                    assert!(session.allows(op, &root));
                    assert!(session.allows(op, &format!("{root}/object")));
                    assert!(!session.allows(op, &format!("{root}2/object")));
                    assert_eq!(
                        session.allows_list(&format!("{root}/")),
                        operation != "delete"
                    );
                }
                assert!(!session.allows(
                    StorageOperation::Read,
                    &format!("tenant/v1/projects/{B}/artifacts/object")
                ));
                assert!(!session.allows_list("tenant"));
                assert_eq!(
                    restarted
                        .verify_session("primary", keys.access_key_id(), keys.session_token())
                        .unwrap()
                        .secret_access_key(),
                    keys.secret_access_key()
                );
                assert!(
                    rotated
                        .verify_session("primary", keys.access_key_id(), keys.session_token())
                        .is_err()
                );
                assert!(
                    fs.verify_session("primary", "foreign-access-key", keys.session_token())
                        .is_err()
                );
                assert_eq!(
                    session.check(Instant::now() - Duration::from_secs(1)),
                    Err(FilesystemSessionError::Deadline)
                );
                if ingress == 0
                    && operation == "publish"
                    && scope.project_id() == Some(A)
                    && scope.module() == StorageModule::Hub
                {
                    cross_process(
                        keys.access_key_id(),
                        keys.session_token(),
                        &format!("tenant/v1/projects/{A}/artifacts/object"),
                    )
                    .await;
                }

                assert!(matches!(
                    issuer(0x71, "other-route", 65536).issue(&grant).await,
                    Err(StorageIssueError::RouteUnavailable)
                ));
                assert!(matches!(
                    issuer(0x71, "primary", 16).issue(&grant).await,
                    Err(StorageIssueError::PolicyTooLarge)
                ));
            }
        }
    }
    clear(&mut c).await;
    let factory = store
        .broker_storage_authorizer(&verifier, n(65536), "primary")
        .unwrap();
    assert!(matches!(
        factory.authorize(&raw, &[], &scopes[0], deadline()).await,
        Err(StorageAdmissionError::Forbidden)
    ));
    assert!(
        factory
            .authorize(
                &raw,
                &[],
                &scopes[0],
                Instant::now() - Duration::from_secs(1)
            )
            .await
            .is_err()
    );
    drop(factory);
    store.shutdown(deadline()).await.unwrap();
    drop(store);
    drop(c);
    f.shutdown().unwrap();
}
async fn cross_process(access_key: &str, token: &str, key: &str) {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "filesystem_session_child",
            "--test-threads=1",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let bytes = Zeroizing::new(
        serde_json::to_vec(&json!({"access_key":access_key,"token":token,"key":key})).unwrap(),
    );
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&bytes).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "independent process must verify the native session"
    );
}
#[test]
#[ignore = "only the parent-owned SQL fixture supplies the native session on stdin"]
fn filesystem_session_child() {
    use std::io::Read;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        access_key: String,
        token: String,
        key: String,
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(131072)
        .read_to_end(&mut bytes)
        .unwrap();
    let input: Input = serde_json::from_slice(&bytes).unwrap();
    let access_key = Zeroizing::new(input.access_key);
    let token = Zeroizing::new(input.token);
    let verifier = issuer(0x71, "primary", 65536);
    let session = verifier
        .verify_session("primary", &access_key, &token)
        .unwrap();
    assert!(session.allows(StorageOperation::Write, &input.key));
    assert!(session.check(deadline()).is_ok());
    assert!(!session.secret_access_key().is_empty());
}
