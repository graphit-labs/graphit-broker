//! Real H1 → Broker grant composition shared by Control and native HTTP tests.
use crate::{
    browser::{BrowserIssuer, ClientAuth, ClientRegistration},
    oidc::{self, ISSUER, OidcFixture, RESOURCE},
    support::{deadline, n},
};
use broker_control::{
    AuthorizedOidcAuthorization, FlowContinuation, OidcAuthorizationInput,
    PendingOidcAuthorization, UpstreamAccessPolicy, UpstreamBearerVerifier,
    UpstreamBrowserClaimsSource, UpstreamBrowserClient, UpstreamClaimSelectors,
    UpstreamLoginCallback, UpstreamProviderConfig, UpstreamReadLimits, VerifiedUpstreamLogin,
};
use std::time::Duration;

pub const REDIRECT: &str = "https://client.example/cb";
pub fn client(id: &str) -> UpstreamBrowserClient {
    UpstreamBrowserClient {
        display_name: id.into(),
        client_id: id.into(),
        client_secret: None,
        redirect_url: "https://broker.example/oauth/oidc/callback".into(),
        scopes: vec!["profile".into(), "email".into()],
        require_nonce: true,
        claims_source: UpstreamBrowserClaimsSource::IdToken,
        id_token_additional_audiences: vec![],
    }
}
pub fn register(issuer: &BrowserIssuer, id: &str) {
    issuer.register(ClientRegistration {
        id: id.into(),
        secret: None,
        redirect: client(id).redirect_url.clone(),
        auth: ClientAuth::Public,
    });
}
pub fn configured(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamProviderConfig {
    UpstreamProviderConfig {
        id: "external".into(),
        issuer: issuer.issuer.clone(),
        audiences: vec!["graphit-broker-resource".into()],
        required_scopes: vec![],
        allowed_algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
        access_policy: UpstreamAccessPolicy::ResourceAudience {
            id_token_audiences: vec!["public".into(), "other".into()],
        },
        predicates: vec![],
        claims: UpstreamClaimSelectors {
            subject: "mapped_subject".into(),
            username: "preferred_username".into(),
            name: Some("name".into()),
            email: Some("email".into()),
            organization: Some("organization.id".into()),
            teams: Some("$.groups[*].name".into()),
            roles: selector.map(str::to_owned),
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
        browser_clients: clients,
    }
}
pub fn verifier(
    issuer: &BrowserIssuer,
    clients: Vec<UpstreamBrowserClient>,
    selector: Option<&str>,
) -> UpstreamBearerVerifier {
    UpstreamBearerVerifier::new(
        ISSUER,
        n(16384),
        vec![configured(issuer, clients, selector)],
    )
    .unwrap()
}
pub async fn registered(f: &OidcFixture) -> String {
    let r=f.store.oidc_registration_service(&f.policy).register(br#"{"redirect_uris":["https://client.example/cb"],"token_endpoint_auth_method":"none","client_name":"W3 real public client"}"#,deadline()).await.unwrap();
    serde_json::to_value(r).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_owned()
}
pub async fn pending(f: &OidcFixture, client: &str) -> PendingOidcAuthorization {
    pending_with_bindings(f, client, "literal-state", "literal-nonce").await
}
pub async fn pending_with_bindings(
    f: &OidcFixture,
    client: &str,
    state: &str,
    nonce: &str,
) -> PendingOidcAuthorization {
    f.store
        .oidc_authorization_service(&oidc::digester(), &f.policy)
        .create(
            OidcAuthorizationInput {
                client_id: client,
                redirect_uri: REDIRECT,
                response_type: "code",
                scope: "openid profile email offline_access",
                state,
                nonce,
                code_challenge: "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE",
                code_challenge_method: "S256",
                response_mode: Some("query"),
                resources: &[RESOURCE],
                prompts: &[],
            },
            deadline(),
        )
        .await
        .unwrap()
}
pub async fn proof(
    f: &OidcFixture,
    issuer: &BrowserIssuer,
    v: &UpstreamBearerVerifier,
    continuation: FlowContinuation,
) -> VerifiedUpstreamLogin {
    let login = f.store.upstream_logins(v);
    let issued = login.begin(continuation, deadline()).await.unwrap();
    let code = issuer.authorize(&issued).await;
    login
        .complete(
            issued.state(),
            issued.browser_binding(),
            UpstreamLoginCallback::Code(&code),
            deadline(),
        )
        .await
        .unwrap()
}
pub fn continuation(v: &UpstreamBearerVerifier, request: &str) -> FlowContinuation {
    FlowContinuation::OAuth {
        provider_id: v.browser_options(deadline()).unwrap()[0].id.clone(),
        request_id: request.into(),
    }
}
pub async fn code(
    f: &OidcFixture,
    issuer: &BrowserIssuer,
    v: &UpstreamBearerVerifier,
    client: &str,
) -> AuthorizedOidcAuthorization {
    let p = pending(f, client).await;
    let login = proof(f, issuer, v, continuation(v, p.request())).await;
    f.store
        .oidc_authorization_service(&oidc::digester(), &f.policy)
        .complete_upstream(login, v, deadline())
        .await
        .unwrap()
}
