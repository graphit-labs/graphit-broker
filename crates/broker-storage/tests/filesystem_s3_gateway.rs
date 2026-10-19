#[allow(
    dead_code,
    reason = "shared PostgreSQL TLS fixture serves multiple suites"
)]
#[path = "../../broker-control/tests/support/mod.rs"]
mod support;
use aws_sdk_sts::config::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use broker_control::{
    BrokerAccessVerifier, ConnectionLimits, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, StorageModule, StorageScope,
};
use broker_storage::{
    FilesystemGateway, FilesystemGatewayConfig, FilesystemStorageIssuer, FilesystemStorageRoute,
    FilesystemStorageRouteConfig, FilesystemStore, FilesystemStoreConfig, IssuedStorageCredentials,
};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use s3s::xml::{Serialize, Serializer};
use serde_json::{Value, json};
use sqlx_core::executor::Executor;
use sqlx_postgres::PgConnection;
use std::{
    num::{NonZeroU16, NonZeroU64},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::{Fixture, deadline, n};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
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
struct Server {
    endpoint: String,
    gateway: Arc<FilesystemGateway>,
    cancel: CancellationToken,
    worker: JoinHandle<()>,
}
impl Server {
    async fn start(issuer: Arc<FilesystemStorageIssuer>, store: Arc<FilesystemStore>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let gateway = Arc::new(
            FilesystemGateway::new(
                issuer,
                vec![store],
                FilesystemGatewayConfig {
                    request_timeout: Duration::from_secs(2),
                    request_head_bytes: n(70000),
                },
            )
            .unwrap(),
        );
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let shared = gateway.clone();
        let worker = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased; _=stop.cancelled()=>break,
                    Some(r)=connections.join_next(),if !connections.is_empty()=>{r.unwrap();},
                    accepted=listener.accept()=>{let (tcp,_)=accepted.unwrap();let gateway=shared.clone();let stop=stop.clone();connections.spawn(async move {
                        let service=hyper::service::service_fn(move|request:hyper::Request<hyper::body::Incoming>|{let gateway=gateway.clone();async move { gateway.handle(request.map(s3s::Body::http_body_unsync),Instant::now()+Duration::from_secs(5)).await }});
                        let connection=hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tcp),service);
                        tokio::select! { _=stop.cancelled()=>{}, result=connection=>{if let Err(e)=result { assert!(e.is_incomplete_message()||e.is_canceled()||e.is_closed()||e.is_body_write_aborted() || e.is_user(),"{e}"); }} }
                    });}
                }
            }
            while let Some(r) = connections.join_next().await {
                r.unwrap();
            }
        });
        Self {
            endpoint,
            gateway,
            cancel,
            worker,
        }
    }
    async fn stop(self) {
        self.cancel.cancel();
        self.gateway
            .shutdown(Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
        self.worker.await.unwrap();
    }
}
fn signed(
    keys: &IssuedStorageCredentials,
    method: Method,
    url: &str,
    body: Bytes,
    headers: HeaderMap,
    scope: (&str, &str),
    payload: SignableBody<'_>,
) -> Request<Bytes> {
    let (region, service) = scope;
    let credentials = Credentials::new(
        keys.access_key_id(),
        keys.secret_access_key(),
        Some(keys.session_token().into()),
        None,
        "native-fixture",
    );
    let identity = credentials.into();
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let mut r = Request::builder()
        .method(method)
        .uri(url)
        .body(body)
        .unwrap();
    *r.headers_mut() = headers;
    let uri: r#http::Uri = url.parse().unwrap();
    r.headers_mut()
        .insert("host", uri.authority().unwrap().as_str().parse().unwrap());
    let signable = SignableRequest::new(
        r.method().as_str(),
        url,
        r.headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap())),
        payload,
    )
    .unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    instructions.apply_to_request_http1x(&mut r);
    r
}
async fn send(client: &reqwest::Client, r: Request<Bytes>) -> (StatusCode, HeaderMap, Bytes) {
    let (parts, body) = r.into_parts();
    let response = client
        .request(parts.method, parts.uri.to_string())
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap();
    (status, headers, body)
}
async fn call(
    client: &reqwest::Client,
    keys: &IssuedStorageCredentials,
    method: Method,
    url: &str,
    body: &[u8],
    headers: HeaderMap,
) -> (StatusCode, HeaderMap, Bytes) {
    let r = signed(
        keys,
        method,
        url,
        Bytes::copy_from_slice(body),
        headers,
        ("us-east-1", "s3"),
        SignableBody::Bytes(body),
    );
    send(client, r).await
}
fn h(items: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in items {
        h.insert(
            http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    h
}
fn xml<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize(&mut Serializer::new(&mut bytes)).unwrap();
    bytes
}
fn upload_id(body: &[u8]) -> String {
    let mut d = s3s::xml::Deserializer::new(body);
    let mut id = None;
    d.named_element("InitiateMultipartUploadResult", |d| {
        d.for_each_element(|d, name| {
            let value = d.text(|s| Ok(s.to_owned()))?;
            if name == b"UploadId" {
                assert!(id.replace(value).is_none());
            }
            Ok(())
        })
    })
    .unwrap();
    d.expect_eof().unwrap();
    id.unwrap()
}

fn chunk_request(
    keys: &IssuedStorageCredentials,
    url: &str,
    payload: &[u8],
    signed_chunks: bool,
    checksum: &str,
) -> Request<Bytes> {
    chunk_request_algorithm(keys, url, payload, signed_chunks, "sha256", checksum)
}
fn chunk_request_algorithm(
    keys: &IssuedStorageCredentials,
    url: &str,
    payload: &[u8],
    signed_chunks: bool,
    algorithm: &str,
    checksum: &str,
) -> Request<Bytes> {
    chunk_request_method(
        keys,
        url,
        payload,
        signed_chunks,
        algorithm,
        checksum,
        Method::PUT,
    )
}
fn chunk_request_method(
    keys: &IssuedStorageCredentials,
    url: &str,
    payload: &[u8],
    signed_chunks: bool,
    algorithm: &str,
    checksum: &str,
    method: Method,
) -> Request<Bytes> {
    let headers = h(&[
        ("content-encoding", "aws-chunked"),
        ("x-amz-decoded-content-length", &payload.len().to_string()),
        ("x-amz-trailer", &format!("x-amz-checksum-{algorithm}")),
    ]);
    let mode = if signed_chunks {
        SignableBody::StreamingSignedPayloadTrailer
    } else {
        SignableBody::StreamingUnsignedPayloadTrailer
    };
    let mut request = signed(
        keys,
        method,
        url,
        Bytes::new(),
        headers,
        ("us-east-1", "s3"),
        mode,
    );
    let date =
        s3s_sigv4::AmzDate::parse(request.headers()["x-amz-date"].to_str().unwrap()).unwrap();
    let auth =
        s3s_sigv4::AuthorizationV4::parse(request.headers()["authorization"].to_str().unwrap())
            .unwrap();
    let trailers = format!("x-amz-checksum-{algorithm}:{checksum}");
    let body = if signed_chunks {
        let text = s3s_sigv4::create_chunk_string_to_sign(
            &date,
            "us-east-1",
            "s3",
            auth.signature,
            &[payload],
        );
        let part = s3s_sigv4::calculate_signature(
            &text,
            keys.secret_access_key(),
            &date,
            "us-east-1",
            "s3",
        );
        let text = s3s_sigv4::create_chunk_string_to_sign(
            &date,
            "us-east-1",
            "s3",
            &part,
            &[b"".as_slice()],
        );
        let end = s3s_sigv4::calculate_signature(
            &text,
            keys.secret_access_key(),
            &date,
            "us-east-1",
            "s3",
        );
        let canonical = format!("{trailers}\n");
        let text = s3s_sigv4::create_trailer_string_to_sign(
            &date,
            "us-east-1",
            "s3",
            &end,
            canonical.as_bytes(),
        );
        let trailer = s3s_sigv4::calculate_signature(
            &text,
            keys.secret_access_key(),
            &date,
            "us-east-1",
            "s3",
        );
        format!(
            "{:x};chunk-signature={part}\r\n{}\r\n0;chunk-signature={end}\r\n\r\n{trailers}\r\nx-amz-trailer-signature:{trailer}\r\n\r\n",
            payload.len(),
            std::str::from_utf8(payload).unwrap()
        )
    } else {
        format!(
            "{:x}\r\n{}\r\n0\r\n\r\n{trailers}\r\n\r\n",
            payload.len(),
            std::str::from_utf8(payload).unwrap()
        )
    };
    *request.body_mut() = Bytes::from(body);
    request
}
fn expired_token(keys: &IssuedStorageCredentials) -> String {
    use hmac::{KeyInit, Mac};
    let parts: Vec<_> = keys.session_token().split('.').collect();
    let mut payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    payload["issued_at"] = json!(seconds() - 901);
    payload["expires_at"] = json!(seconds() - 1);
    let bytes = serde_json::to_vec(&payload).unwrap();
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&[0x71; 32]).unwrap();
    mac.update(b"graphit-broker/rust-filesystem-session/v1\0");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    format!(
        "rust-fs1.{}.{}",
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
#[tokio::test]
#[ignore = "real PostgreSQL TLS admission, Hyper TCP and official AWS SigV4 signer"]
async fn filesystem_s3_gateway_postgres_contract() {
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
    let scope = StorageScope::project(A, StorageModule::Hub).unwrap();
    let issuer = Arc::new(
        FilesystemStorageIssuer::new(
            vec![
                FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                    name: "primary".into(),
                    bucket: "graphit-local".into(),
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
        .unwrap(),
    );
    let read = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    let readonly = issuer.issue(&read).await.unwrap();
    c.execute("DELETE FROM public.grant_s3_operations WHERE grant_id='objects'; INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('objects','publish')").await.unwrap();
    let grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    let keys = issuer.issue(&grant).await.unwrap();
    assert!(keys.supports_conditional_delete());
    assert_eq!(
        keys.copy_if_not_exists(),
        broker_storage::StorageCopyIfNotExists::IfNoneMatch
    );
    assert!(readonly.supports_conditional_delete());
    let folder = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FilesystemStore::open(FilesystemStoreConfig {
            directory: folder.path().into(),
            bucket: "graphit-local".into(),
            max_object_bytes: NonZeroU64::new(32).unwrap(),
            metadata_bytes: n(8192),
        })
        .unwrap(),
    );
    let server = Server::start(issuer.clone(), store).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let root = format!("tenant/v1/projects/{A}/artifacts");
    let path = format!("{}/graphit-local/{root}", server.endpoint);
    let object = format!("{path}/file.json");
    let payload = b"hello-world";
    let (status, headers, body) = call(
        &client,
        &keys,
        Method::PUT,
        &object,
        payload,
        h(&[("content-type", "application/json")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let etag = headers.get("etag").unwrap().to_str().unwrap().to_owned();
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&root).join("file.json")).unwrap(),
        payload
    );
    let (status, headers, body) = call(&client, &keys, Method::GET, &object, b"", h(&[])).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body.as_ref(), payload);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["etag"], etag);
    let (status, headers, body) = call(&client, &keys, Method::HEAD, &object, b"", h(&[])).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    assert_eq!(headers["content-length"], "11");
    for (range, expected) in [("bytes=1-3", &payload[1..4]), ("bytes=-5", &payload[6..])] {
        let (status, headers, body) = call(
            &client,
            &keys,
            Method::GET,
            &object,
            b"",
            h(&[("range", range)]),
        )
        .await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body.as_ref(), expected);
        assert!(headers.contains_key("content-range"));
    }
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &object,
            b"",
            h(&[("range", "bytes=99-")])
        )
        .await
        .0,
        StatusCode::RANGE_NOT_SATISFIABLE
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &object,
            b"",
            h(&[("if-none-match", &etag)])
        )
        .await
        .0,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &object,
            b"",
            h(&[("if-match", "\"wrong\"")])
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::PUT,
            &object,
            b"changed",
            h(&[("if-none-match", "*")])
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        call(&client, &readonly, Method::GET, &object, b"", h(&[]))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&client, &readonly, Method::PUT, &object, b"denied", h(&[]))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let copied = format!("{path}/copy.json");
    let source = format!("/graphit-local/{root}/file.json");
    assert_eq!(
        call(
            &client,
            &keys,
            Method::PUT,
            &copied,
            b"",
            h(&[("x-amz-copy-source", &source)])
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&client, &keys, Method::GET, &copied, b"", h(&[]))
            .await
            .2
            .as_ref(),
        payload
    );
    let denied = format!("/graphit-local/tenant/v1/projects/{B}/artifacts/file.json");
    assert_eq!(
        call(
            &client,
            &keys,
            Method::PUT,
            &copied,
            b"",
            h(&[("x-amz-copy-source", &denied)])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut list = url::Url::parse(&format!("{}/graphit-local", server.endpoint)).unwrap();
    list.query_pairs_mut()
        .append_pair("list-type", "2")
        .append_pair("prefix", &root)
        .append_pair("max-keys", "1");
    let (status, _, body) = call(&client, &keys, Method::GET, list.as_str(), b"", h(&[])).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert!(
        body.windows(b"<IsTruncated>true".len())
            .any(|w| w == b"<IsTruncated>true")
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &format!("{}/graphit-local?location", server.endpoint),
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::OK
    );
    let multipart = format!("{path}/multipart");
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{multipart}?uploads"),
        b"",
        h(&[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let id = upload_id(&body);
    let mut parts = Vec::new();
    for number in [1, 3] {
        let (status, headers, body) = call(
            &client,
            &keys,
            Method::PUT,
            &format!("{multipart}?partNumber={number}&uploadId={id}"),
            payload,
            h(&[]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        parts.push(s3s::dto::CompletedPart {
            part_number: Some(number),
            e_tag: Some(s3s::dto::ETag::parse_http_header(headers["etag"].as_bytes()).unwrap()),
            ..Default::default()
        });
    }
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &format!("{multipart}?uploadId={id}&max-parts=1"),
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::OK
    );
    let mut bad_parts = parts.clone();
    bad_parts[0].e_tag = Some(s3s::dto::ETag::Strong("0".repeat(64)));
    let bad = xml(&s3s::dto::CompletedMultipartUpload {
        parts: Some(bad_parts),
    });
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{multipart}?uploadId={id}"),
        &bad,
        h(&[("content-type", "application/xml")]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("multipart")
            .exists()
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &format!("{multipart}?uploadId={id}"),
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::OK
    );
    let complete = xml(&s3s::dto::CompletedMultipartUpload { parts: Some(parts) });
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{multipart}?uploadId={id}"),
        &complete,
        h(&[("content-type", "application/xml")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        call(&client, &keys, Method::GET, &multipart, b"", h(&[]))
            .await
            .2
            .as_ref(),
        payload.repeat(2)
    );
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{multipart}?uploads"),
        b"",
        h(&[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = upload_id(&body);
    assert_eq!(
        call(
            &client,
            &keys,
            Method::DELETE,
            &format!("{multipart}?uploadId={id}"),
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let batch = xml(&s3s::dto::Delete {
        quiet: Some(false),
        objects: vec![
            s3s::dto::ObjectIdentifier {
                key: format!("{root}/copy.json"),
                ..Default::default()
            },
            s3s::dto::ObjectIdentifier {
                key: format!("tenant/v1/projects/{B}/artifacts/denied"),
                ..Default::default()
            },
        ],
    });
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{}/graphit-local?delete", server.endpoint),
        &batch,
        h(&[("content-type", "application/xml")]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert!(String::from_utf8_lossy(&body).contains("AccessDenied"));
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("copy.json")
            .exists()
    );
    // Real signed body integrity and unchanged object oracles.
    let bad_checksum = format!("{path}/bad-checksum");
    let (status, _, _) = call(
        &client,
        &keys,
        Method::PUT,
        &bad_checksum,
        payload,
        h(&[(
            "x-amz-checksum-sha256",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("bad-checksum")
            .exists()
    );
    let bad_hash = format!("{path}/bad-hash");
    let r = signed(
        &keys,
        Method::PUT,
        &bad_hash,
        Bytes::copy_from_slice(payload),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::Precomputed("0".repeat(64)),
    );
    assert!(send(&client, r).await.0.is_client_error());
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("bad-hash")
            .exists()
    );
    let unsigned = signed(
        &keys,
        Method::PUT,
        &format!("{path}/unsigned-payload"),
        Bytes::copy_from_slice(payload),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::UnsignedPayload,
    );
    assert_eq!(send(&client, unsigned).await.0, StatusCode::OK);
    let (status, _, _) = call(
        &client,
        &keys,
        Method::PUT,
        &format!("{path}/too-large"),
        &[7; 33],
        h(&[]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("too-large")
            .exists()
    );
    for (region, service) in [("eu-west-1", "s3"), ("us-east-1", "sts")] {
        let r = signed(
            &keys,
            Method::GET,
            &object,
            Bytes::new(),
            h(&[]),
            (region, service),
            SignableBody::empty(),
        );
        let (status, _, body) = send(&client, r).await;
        assert!(
            status
                == if service == "s3" {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::NOT_IMPLEMENTED
                },
            "wrong region/service {region}/{service}: {status}, {body:?}"
        );
    }
    let mut tampered = signed(
        &keys,
        Method::PUT,
        &object,
        Bytes::from_static(b"denied"),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::Bytes(b"denied"),
    );
    tampered
        .headers_mut()
        .insert("x-amz-security-token", "tampered".parse().unwrap());
    assert!(send(&client, tampered).await.0.is_client_error());
    let mut duplicate = signed(
        &keys,
        Method::PUT,
        &object,
        Bytes::from_static(b"denied"),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::Bytes(b"denied"),
    );
    duplicate.headers_mut().append(
        "x-amz-security-token",
        keys.session_token().parse().unwrap(),
    );
    assert!(send(&client, duplicate).await.0.is_client_error());
    assert!(
        client
            .get(&object)
            .send()
            .await
            .unwrap()
            .status()
            .is_client_error()
    );
    assert_eq!(
        std::fs::read(folder.path().join("data").join(&root).join("file.json")).unwrap(),
        payload
    );
    // Signed conditional DELETE reaches the same native key lock as PUT.
    let conditional = format!("{path}/conditional-delete");
    let (status, headers, _) = call(
        &client,
        &keys,
        Method::PUT,
        &conditional,
        b"delete-a",
        h(&[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tag_a = headers["etag"].to_str().unwrap().to_owned();
    let data_path = folder
        .path()
        .join("data")
        .join(&root)
        .join("conditional-delete");
    let meta_path = folder
        .path()
        .join("meta")
        .join(&root)
        .join("conditional-delete");
    let metadata = std::fs::read(&meta_path).unwrap();
    assert_eq!(
        call(
            &client,
            &readonly,
            Method::DELETE,
            &conditional,
            b"",
            h(&[("if-match", &tag_a)])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(std::fs::read(&data_path).unwrap(), b"delete-a");
    assert_eq!(std::fs::read(&meta_path).unwrap(), metadata);
    let (status, headers, _) = call(
        &client,
        &keys,
        Method::PUT,
        &conditional,
        b"delete-b",
        h(&[]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let tag_b = headers["etag"].to_str().unwrap().to_owned();
    let metadata = std::fs::read(&meta_path).unwrap();
    let (status, _, body) = call(
        &client,
        &keys,
        Method::DELETE,
        &conditional,
        b"",
        h(&[("if-match", &tag_a)]),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(String::from_utf8_lossy(&body).contains("<Code>PreconditionFailed</Code>"));
    for (url, headers) in [
        (
            format!("{conditional}?versionId=unsupported"),
            h(&[("if-match", &tag_b)]),
        ),
        (
            conditional.clone(),
            h(&[("if-match", &tag_b), ("x-amz-if-match-size", "8")]),
        ),
        (
            conditional.clone(),
            h(&[
                ("if-match", &tag_b),
                (
                    "x-amz-if-match-last-modified-time",
                    "Mon, 01 Jan 2024 00:00:00 GMT",
                ),
            ]),
        ),
    ] {
        assert_eq!(
            call(&client, &keys, Method::DELETE, &url, b"", headers)
                .await
                .0,
            StatusCode::NOT_IMPLEMENTED
        );
    }
    for poison_token in [false, true] {
        let mut denied = signed(
            &keys,
            Method::DELETE,
            &conditional,
            Bytes::new(),
            h(&[("if-match", &tag_b)]),
            ("us-east-1", "s3"),
            SignableBody::empty(),
        );
        if poison_token {
            denied
                .headers_mut()
                .insert("x-amz-security-token", "tampered".parse().unwrap());
        } else {
            assert!(
                denied.headers()["authorization"]
                    .to_str()
                    .unwrap()
                    .contains("if-match")
            );
            denied
                .headers_mut()
                .insert("if-match", "*".parse().unwrap());
        }
        assert!(send(&client, denied).await.0.is_client_error());
    }
    assert_eq!(std::fs::read(&data_path).unwrap(), b"delete-b");
    assert_eq!(std::fs::read(&meta_path).unwrap(), metadata);
    c.execute("DELETE FROM public.grant_s3_operations WHERE grant_id='objects'; INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('objects','delete')").await.unwrap();
    let delete_grant = factory
        .authorize(&raw, &[], &scope, deadline())
        .await
        .unwrap();
    let delete_only = issuer.issue(&delete_grant).await.unwrap();
    c.execute("DELETE FROM public.grant_s3_operations WHERE grant_id='objects'; INSERT INTO public.grant_s3_operations(grant_id,value) VALUES('objects','publish')").await.unwrap();
    assert_eq!(
        call(
            &client,
            &delete_only,
            Method::GET,
            &conditional,
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &client,
            &delete_only,
            Method::DELETE,
            &conditional,
            b"",
            h(&[("if-match", &tag_b)])
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(!data_path.exists() && !meta_path.exists());
    for absent in [tag_b.as_str(), "*"] {
        let (status, _, body) = call(
            &client,
            &delete_only,
            Method::DELETE,
            &conditional,
            b"",
            h(&[("if-match", absent)]),
        )
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert!(String::from_utf8_lossy(&body).contains("<Code>PreconditionFailed</Code>"));
    }
    assert_eq!(
        call(
            &client,
            &delete_only,
            Method::DELETE,
            &conditional,
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::PUT,
            &conditional,
            b"wildcard",
            h(&[])
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &client,
            &delete_only,
            Method::DELETE,
            &conditional,
            b"",
            h(&[("if-match", "*")])
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(!data_path.exists() && !meta_path.exists());
    assert_eq!(
        call(&client, &keys, Method::DELETE, &object, b"", h(&[]))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&client, &keys, Method::GET, &object, b"", h(&[]))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // Full-covering Range and HTTP second-precision conditional dates.
    let (status, headers, body) = call(
        &client,
        &keys,
        Method::GET,
        &multipart,
        b"",
        h(&[("range", "bytes=0-99")]),
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(body.as_ref(), payload.repeat(2));
    assert_eq!(headers["content-range"], "bytes 0-21/22");
    let (_, headers, _) = call(&client, &keys, Method::HEAD, &multipart, b"", h(&[])).await;
    let modified = headers["last-modified"].to_str().unwrap();
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &multipart,
            b"",
            h(&[("if-modified-since", modified)])
        )
        .await
        .0,
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &multipart,
            b"",
            h(&[("if-unmodified-since", modified)])
        )
        .await
        .0,
        StatusCode::OK
    );
    let mut digest = s3s::checksum::ChecksumHasher {
        sha256: Some(<s3s::crypto::Sha256 as s3s::crypto::Checksum>::new()),
        ..Default::default()
    };
    digest.update(payload);
    let checksum = digest.finalize().checksum_sha256.unwrap();
    for signed_chunks in [false, true] {
        let suffix = if signed_chunks { "signed" } else { "unsigned" };
        let url = format!("{path}/{suffix}-trailer");
        let (status, headers, body) = send(
            &client,
            chunk_request(&keys, &url, payload, signed_chunks, &checksum),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(headers["x-amz-checksum-sha256"], checksum);
        assert_eq!(
            std::fs::read(
                folder
                    .path()
                    .join("data")
                    .join(&root)
                    .join(format!("{suffix}-trailer"))
            )
            .unwrap(),
            payload
        );
        let bad = format!("{path}/{suffix}-bad-trailer");
        let (status, _, _) = send(
            &client,
            chunk_request(
                &keys,
                &bad,
                payload,
                signed_chunks,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            !folder
                .path()
                .join("data")
                .join(&root)
                .join(format!("{suffix}-bad-trailer"))
                .exists()
        );
    }
    let mut broken = chunk_request(
        &keys,
        &format!("{path}/broken-chunk"),
        payload,
        true,
        &checksum,
    );
    let mut wire = broken.body().to_vec();
    let offset = wire
        .windows(payload.len())
        .position(|w| w == payload)
        .unwrap();
    wire[offset] ^= 1;
    *broken.body_mut() = Bytes::from(wire);
    assert!(send(&client, broken).await.0.is_client_error());
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("broken-chunk")
            .exists()
    );
    let mut duplicate = signed(
        &keys,
        Method::PUT,
        &format!("{path}/duplicate-md5"),
        Bytes::copy_from_slice(payload),
        h(&[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")]),
        ("us-east-1", "s3"),
        SignableBody::Bytes(payload),
    );
    duplicate
        .headers_mut()
        .append("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==".parse().unwrap());
    assert!(send(&client, duplicate).await.0.is_client_error());
    let mut expired = signed(
        &keys,
        Method::GET,
        &multipart,
        Bytes::new(),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::empty(),
    );
    expired.headers_mut().insert(
        "x-amz-security-token",
        expired_token(&keys).parse().unwrap(),
    );
    let (status, _, body) = send(&client, expired).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert!(
        String::from_utf8_lossy(&body).contains("<Code>InvalidToken</Code>"),
        "{body:?}"
    );
    let fresh = issuer.issue(&grant).await.unwrap();
    let mut mismatched = signed(
        &fresh,
        Method::GET,
        &multipart,
        Bytes::new(),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::empty(),
    );
    mismatched.headers_mut().insert(
        "x-amz-security-token",
        keys.session_token().parse().unwrap(),
    );
    assert!(send(&client, mismatched).await.0.is_client_error());
    assert_eq!(
        call(&client, &fresh, Method::GET, &multipart, b"", h(&[]))
            .await
            .0,
        StatusCode::OK
    );

    let rejected = format!("{path}/owner-rejected");
    assert_eq!(
        call(
            &client,
            &keys,
            Method::PUT,
            &rejected,
            payload,
            h(&[("x-amz-expected-bucket-owner", "999999999999")])
        )
        .await
        .0,
        StatusCode::NOT_IMPLEMENTED
    );
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("owner-rejected")
            .exists()
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &format!("{multipart}?response-content-type=wrong"),
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::NOT_IMPLEMENTED
    );
    #[cfg(unix)]
    {
        let file = folder.path().join("data").join(&root).join("multipart");
        std::fs::File::options()
            .write(true)
            .open(file)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(UNIX_EPOCH - Duration::from_millis(500)),
            )
            .unwrap();
        let (status, _, body) = call(&client, &keys, Method::GET, &multipart, b"", h(&[])).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(body.as_ref(), payload.repeat(2));
        assert_eq!(
            call(&client, &keys, Method::HEAD, &multipart, b"", h(&[]))
                .await
                .0,
            StatusCode::OK
        );
    }
    // XML digest expectations must be checked before the first per-key delete.
    let batch = xml(&s3s::dto::Delete {
        quiet: Some(true),
        objects: vec![s3s::dto::ObjectIdentifier {
            key: format!("{root}/multipart"),
            ..Default::default()
        }],
    });
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{}/graphit-local?delete", server.endpoint),
        &batch,
        h(&[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
    assert!(
        folder
            .path()
            .join("data")
            .join(&root)
            .join("multipart")
            .exists()
    );
    let mut digest = s3s::checksum::ChecksumHasher {
        md5: Some(<s3s::crypto::Md5 as s3s::crypto::Checksum>::new()),
        ..Default::default()
    };
    digest.update(&batch);
    let md5 = digest.finalize().checksum_md5.unwrap();
    let (status, _, body) = call(
        &client,
        &keys,
        Method::POST,
        &format!("{}/graphit-local?delete", server.endpoint),
        &batch,
        h(&[("content-md5", &md5)]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("multipart")
            .exists()
    );
    let oversized = chunk_request(
        &keys,
        &format!("{path}/decoded-too-large"),
        &[b'x'; 33],
        false,
        &checksum,
    );
    assert_eq!(send(&client, oversized).await.0, StatusCode::BAD_REQUEST);
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("decoded-too-large")
            .exists()
    );
    let mut bad_signature = chunk_request(
        &keys,
        &format!("{path}/bad-trailer-signature"),
        payload,
        true,
        &checksum,
    );
    let mut bytes = bad_signature.body().to_vec();
    let label = b"x-amz-trailer-signature:";
    let offset = bytes.windows(label.len()).position(|w| w == label).unwrap() + label.len();
    bytes[offset] = if bytes[offset] == b'0' { b'1' } else { b'0' };
    *bad_signature.body_mut() = Bytes::from(bytes);
    assert!(send(&client, bad_signature).await.0.is_client_error());
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("bad-trailer-signature")
            .exists()
    );

    let too_large = h(&[("x-extra-head", &"x".repeat(70001))]);
    let r = signed(
        &keys,
        Method::PUT,
        &format!("{path}/large-head"),
        Bytes::copy_from_slice(payload),
        too_large,
        ("us-east-1", "s3"),
        SignableBody::Bytes(payload),
    );
    assert!(send(&client, r).await.0.is_client_error());
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("large-head")
            .exists()
    );
    let query = format!("{path}/query-auth?X-Amz-Signature=0000");
    assert_eq!(
        call(&client, &keys, Method::PUT, &query, payload, h(&[]))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("query-auth")
            .exists()
    );
    assert!(
        call(
            &client,
            &keys,
            Method::PUT,
            &format!("{path}//escape"),
            payload,
            h(&[])
        )
        .await
        .0
        .is_client_error()
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::GET,
            &format!("{}/other-bucket/{root}/file.json", server.endpoint),
            b"",
            h(&[])
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let foreign = FilesystemStorageIssuer::new(
        vec![
            FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                name: "primary".into(),
                bucket: "graphit-local".into(),
                region: "us-east-1".into(),
                base_prefix: "tenant".into(),
                endpoint: "http://127.0.0.1:9000".into(),
                session_duration: Duration::from_secs(900),
                token_bytes: n(65536),
            })
            .unwrap(),
        ],
        Zeroizing::new(vec![0x72; 32]),
    )
    .unwrap();
    let foreign_keys = foreign.issue(&grant).await.unwrap();
    assert!(
        call(
            &client,
            &foreign_keys,
            Method::PUT,
            &format!("{path}/foreign-pepper"),
            payload,
            h(&[])
        )
        .await
        .0
        .is_client_error()
    );
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("foreign-pepper")
            .exists()
    );
    // The native URL-encoded page must not be encoded a second time by S3s.
    let spaced = format!("{path}/probe%20space");
    assert_eq!(
        call(&client, &keys, Method::PUT, &spaced, payload, h(&[]))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &client,
            &keys,
            Method::PUT,
            &format!("{path}/probe/nested"),
            payload,
            h(&[])
        )
        .await
        .0,
        StatusCode::OK
    );
    let mut listing = url::Url::parse(&format!("{}/graphit-local", server.endpoint)).unwrap();
    listing
        .query_pairs_mut()
        .append_pair("list-type", "2")
        .append_pair("prefix", &format!("{root}/probe"))
        .append_pair("encoding-type", "url")
        .append_pair("delimiter", "/");
    let (status, _, body) = call(&client, &keys, Method::GET, listing.as_str(), b"", h(&[])).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("probe%20space"), "{text}");
    assert!(!text.contains("probe%2520space"));
    assert!(text.contains("<CommonPrefixes>"));

    let mut crc = s3s::checksum::ChecksumHasher {
        crc32: Some(<s3s::crypto::Crc32 as s3s::crypto::Checksum>::new()),
        ..Default::default()
    };
    crc.update(payload);
    let crc = crc.finalize().checksum_crc32.unwrap();
    for signed_chunks in [false, true] {
        let name = if signed_chunks {
            "signed-crc32"
        } else {
            "unsigned-crc32"
        };
        let url = format!("{path}/{name}");
        let (status, headers, body) = send(
            &client,
            chunk_request_algorithm(&keys, &url, payload, signed_chunks, "crc32", &crc),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(headers["x-amz-checksum-crc32"], crc);
        assert_eq!(
            std::fs::read(folder.path().join("data").join(&root).join(name)).unwrap(),
            payload
        );
    }

    for (name, value) in [
        ("cache-control", "no-store"),
        ("content-disposition", "attachment"),
        ("content-language", "pt-BR"),
        ("expires", "Wed, 21 Oct 2015 07:28:00 GMT"),
        ("content-encoding", "gzip"),
    ] {
        let url = format!("{path}/unsupported-{name}");
        assert_eq!(
            call(
                &client,
                &keys,
                Method::PUT,
                &url,
                payload,
                h(&[(name, value)])
            )
            .await
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
        assert!(
            !folder
                .path()
                .join("data")
                .join(&root)
                .join(format!("unsupported-{name}"))
                .exists()
        );
        let count = std::fs::read_dir(folder.path().join("multipart"))
            .unwrap()
            .count();
        assert_eq!(
            call(
                &client,
                &keys,
                Method::POST,
                &format!("{url}?uploads"),
                b"",
                h(&[(name, value)])
            )
            .await
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
        assert_eq!(
            std::fs::read_dir(folder.path().join("multipart"))
                .unwrap()
                .count(),
            count
        );
    }
    let post = chunk_request_method(
        &keys,
        &format!("{}/graphit-local?delete", server.endpoint),
        b"<Delete/>",
        true,
        "sha256",
        &checksum,
        Method::POST,
    );
    assert_eq!(send(&client, post).await.0, StatusCode::NOT_IMPLEMENTED);
    let mut post = chunk_request_method(
        &keys,
        &format!("{}/graphit-local?delete", server.endpoint),
        b"<Delete/>",
        false,
        "sha256",
        &checksum,
        Method::POST,
    );
    post.headers_mut().remove("content-encoding");
    assert_eq!(send(&client, post).await.0, StatusCode::NOT_IMPLEMENTED);
    // An accepted GET cannot emit a later frame past its Original deadline.
    let r = signed(
        &keys,
        Method::GET,
        &format!("{path}/signed-trailer"),
        Bytes::new(),
        h(&[]),
        ("us-east-1", "s3"),
        SignableBody::empty(),
    );
    let response = server
        .gateway
        .handle(
            r.map(s3s::Body::from),
            Instant::now() + Duration::from_millis(200),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    let mut body = response.into_body();
    let frame = http_body_util::BodyExt::frame(&mut body).await.unwrap();
    assert!(frame.is_err());
    drop(body);
    // A real stalled TCP PUT owns its IO; shutdown cancels and joins the worker.
    let stalled = format!("{path}/stalled");
    let r = signed(
        &keys,
        Method::PUT,
        &stalled,
        Bytes::new(),
        h(&[("content-length", "11")]),
        ("us-east-1", "s3"),
        SignableBody::Bytes(payload),
    );
    let (parts, _) = r.into_parts();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    tx.send(Ok(Bytes::from_static(b"hello"))).await.unwrap();
    let stream =
        futures_util::stream::unfold(rx, |mut rx| async { rx.recv().await.map(|v| (v, rx)) });
    let body = reqwest::Body::wrap_stream(stream);
    let network = client.clone();
    let io = tokio::spawn(async move {
        network
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if std::fs::read_dir(folder.path().join("tmp"))
                .unwrap()
                .next()
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    server
        .gateway
        .shutdown(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();
    drop(tx);
    let response = tokio::time::timeout(Duration::from_secs(5), io)
        .await
        .unwrap()
        .unwrap();
    assert!(response.is_err() || response.unwrap().status().is_client_error());
    assert!(
        std::fs::read_dir(folder.path().join("tmp"))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        !folder
            .path()
            .join("data")
            .join(&root)
            .join("stalled")
            .exists()
    );
    server.stop().await;
}
