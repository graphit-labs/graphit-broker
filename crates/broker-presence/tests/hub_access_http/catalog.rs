//! Focused catalog consumer using the existing HTTP/PostgreSQL fixture.
use super::*;
use broker_storage::{
    FilesystemConditions, FilesystemPutOptions, FilesystemRequest, FilesystemStorageIssuer,
    FilesystemStorageRoute, FilesystemStorageRouteConfig, FilesystemStore, FilesystemStoreConfig,
    HubCatalogReader, StorageCredentialsService, StorageIssuer,
};
async fn routed(
    c: &mut PgConnection,
    id: &str,
    kind: &str,
    principal: &str,
    cap: &str,
    project: &str,
    route: &str,
) {
    grant(c, id, kind, principal, cap, &[project]).await;
    sqlx_core::query::query("UPDATE public.resource_grants SET s3_route=$2 WHERE id=$1")
        .bind(id)
        .bind(route)
        .execute(&mut *c)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "real HTTP/PostgreSQL and confined filesystem producer; no vendor account"]
async fn hub_catalog_current_metadata_routes_pages_and_authority() {
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION hub_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO hub_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    seed(&mut c).await;
    routed(&mut c, "a-hub", "authenticated", "", "hub", A, "first").await;
    routed(&mut c, "b-hub", "authenticated", "", "hub", B, "second").await;
    routed(&mut c, "writer-a", "user", "alice", "s3", A, "first").await;
    routed(&mut c, "writer-b", "user", "alice", "s3", B, "second").await;
    let tmp = tempfile::tempdir().unwrap();
    let mut volumes = Vec::new();
    let mut routes = Vec::new();
    for name in ["first", "second"] {
        volumes.push(Arc::new(
            FilesystemStore::open(FilesystemStoreConfig {
                directory: tmp.path().join(name),
                bucket: format!("bucket-{name}"),
                max_object_bytes: std::num::NonZeroU64::new(65536).unwrap(),
                metadata_bytes: n(8192),
            })
            .unwrap(),
        ));
        routes.push(
            FilesystemStorageRoute::new(FilesystemStorageRouteConfig {
                name: name.into(),
                bucket: format!("bucket-{name}"),
                region: "local".into(),
                base_prefix: "hub-root".into(),
                endpoint: "https://storage.example.test".into(),
                session_duration: Duration::from_secs(900),
                token_bytes: n(8192),
            })
            .unwrap(),
        );
    }
    let issuer =
        FilesystemStorageIssuer::new(routes, zeroize::Zeroizing::new(vec![7; 32])).unwrap();
    let factory = store
        .local_storage_authorizer("explicit-audience", n(8192), n(65536), "first")
        .unwrap();
    let mut sessions = Vec::new();
    for (index, id) in [A, B].iter().enumerate() {
        let scope =
            broker_control::StorageScope::project(id, broker_control::StorageModule::Hub).unwrap();
        let grant = factory
            .authorize(RAW, &[], &scope, deadline())
            .await
            .unwrap();
        let keys = issuer.issue(&grant).await.unwrap();
        let route = if index == 0 { "first" } else { "second" };
        let session = issuer
            .verify_session(route, keys.access_key_id(), keys.session_token())
            .unwrap();
        let bytes=json!({"v":1,"project":{"id":id,"name":if index==0{"alpha-project"}else{"beta-project"},"status":"active"}}).to_string();
        volumes[index]
            .put(
                &session,
                &format!("hub-root/v1/projects/{id}/hub/metadata/project.json"),
                bytes.as_bytes(),
                FilesystemPutOptions {
                    content_type: Some("application/json"),
                    expected_digest: None,
                    conditions: &FilesystemConditions::default(),
                },
                &FilesystemRequest {
                    deadline: deadline(),
                    cancellation: Default::default(),
                },
            )
            .unwrap();
        sessions.push(session);
    }
    drop(factory);
    let storage =
        Arc::new(StorageCredentialsService::new(vec![StorageIssuer::Filesystem(issuer)]).unwrap());
    let reader = Arc::new(HubCatalogReader::new(
        storage.clone(),
        volumes.clone(),
        n(8192),
    ));
    let signer = Signer::new();
    let mut claims = signer.claims();
    claims["preferred_username"] = json!("reader");
    let jwt = format!("Bearer {}", signer.sign(&claims));
    let opaque = format!("Bearer {RAW}");
    let catalog_router = broker_presence::hub_catalog_router(
        store.clone(),
        Arc::new(signer.verifier()),
        reader.clone(),
        broker_presence::HubCatalogHttpConfig {
            audience: "explicit-audience".into(),
            identity_json_bytes: n(8192),
            grants_json_bytes: n(65536),
            default_route: "first".into(),
            query_bytes: n(8192),
            request_timeout: Duration::from_secs(4),
        },
    )
    .unwrap();
    let credentials_router = broker_presence::broker_storage_credentials_router(
        store.clone(),
        Arc::new(signer.verifier()),
        Some(storage),
        broker_presence::BrokerStorageCredentialsHttpConfig {
            required_scopes: Vec::new(),
            grants_json_bytes: n(65536),
            default_route: "first".into(),
            body_bytes: n(8192),
            request_timeout: Duration::from_secs(4),
            enabled: true,
        },
    )
    .unwrap();
    // Match the productive server: retain one global JSON fallback while composing routes.
    let server = Server::start(credentials_router.merge(catalog_router.reset_fallback())).await;
    let path = "/v1/hub/catalog/projects";
    let first = exchange(
        server.address,
        "GET",
        &format!("{path}?limit=1"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.no_store);
    assert_eq!(
        first.json["projects"],
        json!([{"id":A,"name":"alpha-project"}])
    );
    let cursor = first.json["next_cursor"].as_str().unwrap();
    let second = exchange(
        server.address,
        "GET",
        &format!("{path}?limit=1&cursor={cursor}"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(
        second.json["projects"],
        json!([{"id":B,"name":"beta-project"}])
    );
    assert!(second.json["next_cursor"].is_null());
    let local = exchange(
        server.address,
        "GET",
        &format!("{path}?id={B}"),
        &[&opaque],
        None,
    )
    .await;
    assert_eq!(local.status, StatusCode::OK);
    assert_eq!(local.json["projects"], second.json["projects"]);
    let prefix = exchange(
        server.address,
        "GET",
        &format!("{path}?name_prefix=alpha"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(prefix.json["projects"], first.json["projects"]);
    let anon = exchange(server.address, "GET", path, &[], None).await;
    assert_eq!(anon.status, StatusCode::OK);
    assert_eq!(anon.json["projects"], json!([]));
    for query in [
        "limit=0",
        "id=bad",
        "id=a&name_prefix=b",
        "limit=1&limit=1",
        "route=second",
    ] {
        assert_eq!(
            exchange(
                server.address,
                "GET",
                &format!("{path}?{query}"),
                &[&jwt],
                None
            )
            .await
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        exchange(
            server.address,
            "GET",
            &format!("{path}?limit=2&cursor={cursor}"),
            &[&jwt],
            None
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    claims["aud"] = json!(["another-api", RESOURCE]);
    let wrong = format!("Bearer {}", signer.sign(&claims));
    assert_eq!(
        exchange(server.address, "GET", path, &[&wrong], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    claims = signer.claims();
    claims["exp"] = json!(seconds() - 1);
    let expired = format!("Bearer {}", signer.sign(&claims));
    assert_eq!(
        exchange(server.address, "GET", path, &[&expired], None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    c.execute("DELETE FROM public.resource_grants WHERE id='b-hub'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    assert_eq!(
        exchange(
            server.address,
            "GET",
            &format!("{path}?limit=1&cursor={cursor}"),
            &[&jwt],
            None
        )
        .await
        .status,
        StatusCode::CONFLICT
    );
    let removed = exchange(server.address, "GET", path, &[&jwt], None).await;
    assert_eq!(removed.json["projects"], first.json["projects"]);
    // PROJECT/Presence capabilities do not replace the separate Hub permission.
    c.execute("DELETE FROM public.resource_grants WHERE id='a-hub'; UPDATE public.resource_acl_state SET revision=revision+1 WHERE id=1").await.unwrap();
    grant(
        &mut c,
        "other-module",
        "authenticated",
        "",
        "projects:read",
        &[A],
    )
    .await;
    assert_eq!(
        exchange(server.address, "GET", path, &[&jwt], None)
            .await
            .json["projects"],
        json!([])
    );
    // An all selector enumerates actual project directories, never Presence/grant names.
    routed(&mut c, "all", "authenticated", "", "hub", "*", "first").await;
    let all = exchange(server.address, "GET", path, &[&jwt], None).await;
    assert_eq!(all.json["projects"], first.json["projects"]);
    let malformed=b"{\"v\":1,\"project\":{\"id\":\"01D39ZY06FGSCTVN4T2V9PKHG0\",\"name\":\"wrong\",\"status\":\"active\"}}";
    volumes[0]
        .put(
            &sessions[0],
            &format!("hub-root/v1/projects/{A}/hub/metadata/project.json"),
            &malformed[..],
            FilesystemPutOptions {
                content_type: None,
                expected_digest: None,
                conditions: &FilesystemConditions::default(),
            },
            &FilesystemRequest {
                deadline: deadline(),
                cancellation: Default::default(),
            },
        )
        .unwrap();
    assert_eq!(
        exchange(server.address, "GET", path, &[&jwt], None)
            .await
            .status,
        StatusCode::BAD_GATEWAY
    );
    routed(&mut c, "conflict", "authenticated", "", "hub", A, "second").await;
    assert_eq!(
        exchange(
            server.address,
            "GET",
            &format!("{path}?id={A}"),
            &[&jwt],
            None
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let final_verifier = signer.verifier();
    let mut resolution = store
        .broker_hub_access_resolver(&final_verifier, n(65536))
        .unwrap()
        .resolve(None, deadline())
        .await
        .unwrap();
    assert!(matches!(
        reader
            .page(
                &mut resolution,
                "first",
                broker_storage::HubCatalogQuery {
                    id: None,
                    name_prefix: None,
                    limit: 1,
                    cursor: None
                },
                Instant::now()
            )
            .await,
        Err(broker_storage::HubCatalogError::Deadline)
    ));
    server.stop().await;
    drop(reader);
    drop(volumes);
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
    f.shutdown().unwrap();
}

// One controlled S3 response is deliberately short but truncated. This uses the
// productive object_store client and catches inferring EOF from common-prefix count.
async fn short_s3_page(request: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    let query: std::collections::BTreeMap<_, _> =
        form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
            .into_owned()
            .collect();
    if query.get("list-type").map(String::as_str) == Some("2") {
        assert_eq!(query.get("max-keys").map(String::as_str), Some("2"));
        let (id, truncated) = match query.get("start-after").map(String::as_str) {
            None => (A, true),
            Some(marker) if marker == format!("hub-root/v1/projects/{A}/") => (B, false),
            other => panic!("unexpected S3 offset: {other:?}"),
        };
        let token = if truncated {
            "<NextContinuationToken>internal-backend-token</NextContinuationToken>"
        } else {
            ""
        };
        let xml = format!(
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>catalog-bucket</Name><Prefix>hub-root/v1/projects/</Prefix><MaxKeys>2</MaxKeys><IsTruncated>{truncated}</IsTruncated>{token}<CommonPrefixes><Prefix>hub-root/v1/projects/{id}/</Prefix></CommonPrefixes></ListBucketResult>"
        );
        return ([("content-type", "application/xml")], xml).into_response();
    }
    let path = request.uri().path();
    let (id, name) = if path.ends_with(&format!("/v1/projects/{A}/hub/metadata/project.json")) {
        (A, "alpha-project")
    } else if path.ends_with(&format!("/v1/projects/{B}/hub/metadata/project.json")) {
        (B, "beta-project")
    } else {
        panic!("unexpected S3 metadata path")
    };
    (
        [
            ("content-type", "application/json"),
            ("last-modified", "Wed, 01 Jan 2025 00:00:00 GMT"),
            ("etag", "\"metadata-fixture\""),
        ],
        json!({"v":1,"project":{"id":id,"name":name,"status":"active"}}).to_string(),
    )
        .into_response()
}
#[tokio::test]
#[ignore = "real PostgreSQL Hub authority and controlled paginated S3 HTTP; no vendor account"]
async fn hub_catalog_s3_short_truncated_page_continues_after_prefix_skip() {
    use broker_storage::{
        AwsCredentialSource, AwsEndpointTransport, AwsStorageIssuer, AwsStorageRoute,
        AwsStorageRouteConfig, PrivateStaticCredentials,
    };
    let f = Fixture::new(true).await;
    let mut c = f.connection().await;
    c.execute("CREATE ROLE hub_http_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION hub_http_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO hub_http_owner").await.unwrap();
    let store = Arc::new(
        PostgresControlStore::open(store_config(&f), support::digester(), deadline())
            .await
            .unwrap(),
    );
    routed(&mut c, "hub", "authenticated", "", "hub", "*", "s3page").await;
    let backend = Server::start(Router::new().fallback(short_s3_page)).await;
    let route = AwsStorageRoute::new(AwsStorageRouteConfig {
        name: "s3page".into(),
        region: "us-east-1".into(),
        bucket: "catalog-bucket".into(),
        base_prefix: "hub-root".into(),
        conditional_delete: false,
        s3_endpoint: Some(format!("http://{}", backend.address)),
        sts_endpoint: None,
        role_arn: "arn:aws:iam::123456789012:role/fixture".into(),
        session_name: "catalog-fixture".into(),
        session_duration: Duration::from_secs(900),
        credential_source: AwsCredentialSource::StaticPair(
            PrivateStaticCredentials::new(
                zeroize::Zeroizing::new("fixture-key".into()),
                zeroize::Zeroizing::new("fixture-secret".into()),
            )
            .unwrap(),
        ),
        endpoint_transport: AwsEndpointTransport::LoopbackHttp,
    })
    .unwrap();
    let service = Arc::new(
        StorageCredentialsService::new(vec![StorageIssuer::Aws(
            AwsStorageIssuer::new(vec![route], Duration::from_secs(4)).unwrap(),
        )])
        .unwrap(),
    );
    let reader = Arc::new(HubCatalogReader::new(service, Vec::new(), n(8192)));
    let signer = Signer::new();
    let jwt = format!("Bearer {}", signer.sign(&signer.claims()));
    let server = Server::start(
        broker_presence::hub_catalog_router(
            store.clone(),
            Arc::new(signer.verifier()),
            reader,
            broker_presence::HubCatalogHttpConfig {
                audience: "explicit-audience".into(),
                identity_json_bytes: n(8192),
                grants_json_bytes: n(65536),
                default_route: "s3page".into(),
                query_bytes: n(8192),
                request_timeout: Duration::from_secs(4),
            },
        )
        .unwrap(),
    )
    .await;
    let path = "/v1/hub/catalog/projects";
    let prefix = exchange(
        server.address,
        "GET",
        &format!("{path}?name_prefix=beta&limit=1"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(prefix.status, StatusCode::OK);
    assert_eq!(
        prefix.json["projects"],
        json!([{"id":B,"name":"beta-project"}])
    );
    assert!(prefix.json["next_cursor"].is_null());
    let first = exchange(
        server.address,
        "GET",
        &format!("{path}?limit=1"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(
        first.json["projects"],
        json!([{"id":A,"name":"alpha-project"}])
    );
    let cursor = first.json["next_cursor"].as_str().unwrap();
    let decoded = String::from_utf8(URL_SAFE_NO_PAD.decode(cursor).unwrap()).unwrap();
    assert!(!decoded.contains("internal-backend-token") && !decoded.contains("beta-project"));
    let second = exchange(
        server.address,
        "GET",
        &format!("{path}?limit=1&cursor={cursor}"),
        &[&jwt],
        None,
    )
    .await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(second.json["projects"], prefix.json["projects"]);
    assert!(second.json["next_cursor"].is_null());
    server.stop().await;
    backend.stop().await;
    store.shutdown(deadline()).await.unwrap();
    c.close().await.unwrap();
    f.shutdown().unwrap();
}
