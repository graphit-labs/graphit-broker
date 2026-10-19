//! Genuine browser-code/HTTPS/PKCE producer used by administrative read consumers.
use crate::{
    browser::{BrowserIssuer, ClientAuth, ClientRegistration},
    cookie,
    support::{deadline, n},
};
use broker_control::{
    FlowContinuation, IssuedAdminCookie, PostgresControlStore, UpstreamAccessPolicy,
    UpstreamBearerVerifier, UpstreamBrowserClaimsSource, UpstreamBrowserClient,
    UpstreamClaimSelectors, UpstreamLoginCallback, UpstreamProviderConfig, UpstreamReadLimits,
};
use std::time::Duration;

pub fn provider(issuer: &BrowserIssuer) -> UpstreamProviderConfig {
    UpstreamProviderConfig {
        id: "browser-read".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec!["admin:session".into()],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["public".into()],
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "preferred_username".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: None,
            scope: "scope".into(),
        },
        limits: UpstreamReadLimits {
            token_bytes: n(16384),
            response_bytes: n(65536),
            keys: n(16),
            selector_bytes: n(512),
            claim_string_bytes: n(2048),
            profile_json_bytes: n(8192),
            teams: n(32),
        },
        request_timeout: Duration::from_secs(5),
        cache_max_age: Duration::from_secs(300),
        min_refresh_interval: Duration::from_millis(10),
        allow_loopback_http: false,
        trusted_ca_pem: Some(issuer.ca.clone()),
        browser_clients: vec![UpstreamBrowserClient {
            display_name: "Administrative read fixture".into(),
            client_id: "public".into(),
            client_secret: None,
            redirect_url: "https://broker.example.invalid/oauth/oidc/callback".into(),
            scopes: vec!["profile".into(), "email".into()],
            require_nonce: true,
            claims_source: UpstreamBrowserClaimsSource::IdToken,
            id_token_additional_audiences: vec![],
        }],
    }
}
pub async fn issue(
    store: &PostgresControlStore,
    verifier: &UpstreamBearerVerifier,
    issuer: &BrowserIssuer,
) -> IssuedAdminCookie {
    issuer.register(ClientRegistration {
        id: "public".into(),
        secret: None,
        redirect: "https://broker.example.invalid/oauth/oidc/callback".into(),
        auth: ClientAuth::Public,
    });
    let original = deadline();
    let provider_id = verifier.browser_options(original).unwrap()[0].id.clone();
    let login = store.upstream_logins(verifier);
    let authorization = login
        .begin(FlowContinuation::Admin { provider_id }, original)
        .await
        .unwrap();
    let code = issuer.authorize(&authorization).await;
    let proof = login
        .complete(
            authorization.state(),
            authorization.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            original,
        )
        .await
        .unwrap();
    store
        .admin_cookie_sessions(cookie::limits(), cookie::policy(), Some(verifier))
        .unwrap()
        .issue_upstream(proof, original)
        .await
        .unwrap()
}

pub fn native_yaml(issuer: &BrowserIssuer) -> String {
    // The consumer needs current common issuer trust/mapping, with no browser
    // client YAML or browser callback claimed by this test.
    format!(
        r#"    - id: browser-read
      enabled: true
      issuer: {}
      audiences: [graphit-broker-resource]
      required_scopes: [admin:session]
      allowed_algorithms: [EdDSA]
      access_policy:
        type: resource_audience
        id_token_audiences: [public]
      predicates: []
      claims:
        subject: preferred_username
        username: preferred_username
        name: name
        email: email
        organization: organization.id
        teams: "$.groups[*].name"
        scope: scope
      limits:
        token_bytes: 16384
        response_bytes: 65536
        keys: 16
        selector_bytes: 512
        claim_string_bytes: 2048
        profile_json_bytes: 8192
        teams: 32
      request_timeout: 5s
      cache_max_age: 5m
      min_refresh_interval: 10ms
      allow_loopback_http: false
      ca_file: browser-ca.pem
      ca_bytes: 8192
"#,
        issuer.issuer
    )
}
