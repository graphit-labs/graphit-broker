//! Genuinely admitted P2a → password → LOCAL completion → P2b code for P3 fixtures.
use crate::support::{self, Fixture, deadline, n};
use broker_control::{
    AuthorizedOidcAuthorization, ConnectionLimits, LocalAuthPolicy, LocalAuthStep,
    LocalPasswordEngine, OidcAuthorizationConfiguration, OidcAuthorizationInput,
    OidcAuthorizationLimits, OidcAuthorizationPolicy, PostgresConfig, PostgresControlStore,
    PostgresCredentials, PostgresEndpoint, PreparedOidcLogin,
};
use broker_security::{
    CredentialDigester, DigestLimits, LocalAuthBinding, LocalMfaProtector, LocalPasswordHasher,
};
use sqlx_core::{connection::Connection, executor::Executor};
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const PEPPER: &str = "native-code-fixture-pepper-32-bytes";
pub const ISSUER: &str = "https://broker.example";
pub const AUDIENCE: &str = "graphit-broker";
pub const RESOURCE: &str = "https://broker.example/v1";
pub const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
pub const PASSWORD: &str = "native P3 fixture-only password";
pub fn micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        .try_into()
        .unwrap()
}
pub fn digester() -> CredentialDigester {
    CredentialDigester::new(
        Zeroizing::new(PEPPER.as_bytes().to_vec().into_boxed_slice()),
        DigestLimits::new(n(256), n(8192), n(256), n(512), n(256)).unwrap(),
    )
    .unwrap()
}
pub fn policy() -> OidcAuthorizationPolicy {
    OidcAuthorizationPolicy::new(
        OidcAuthorizationConfiguration {
            cli_client_id: "graphit-cli".into(),
            cli_redirect_path: "/oauth/callback".into(),
            api_audience: AUDIENCE.into(),
            accepted_resources: vec![RESOURCE.into()],
            dynamic_registration: true,
            authorization_ttl: Duration::from_secs(60),
        },
        OidcAuthorizationLimits::new(n(8192), n(8192)).unwrap(),
    )
    .unwrap()
}
pub fn config(f: &Fixture) -> PostgresConfig {
    config_at(f, f.port)
}
pub fn config_at(f: &Fixture, port: u16) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "exchange_owner".into(),
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
pub struct OidcFixture {
    pub fixture: Fixture,
    pub store: Arc<PostgresControlStore>,
    pub admin: PgConnection,
    pub policy: Arc<OidcAuthorizationPolicy>,
    pub engine: LocalPasswordEngine,
    digester: CredentialDigester,
    protector: LocalMfaProtector,
    login_policy: LocalAuthPolicy,
}
impl OidcFixture {
    pub async fn new() -> Self {
        let fixture = Fixture::new(true).await;
        let mut admin = fixture.connection().await;
        admin.execute("CREATE ROLE exchange_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION exchange_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO exchange_owner").await.unwrap();
        let store = Arc::new(
            PostgresControlStore::open(config(&fixture), digester(), deadline())
                .await
                .unwrap(),
        );
        let ordinary: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT NOT rolsuper FROM pg_roles WHERE rolname='exchange_owner'",
        )
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert!(ordinary);
        let engine = LocalPasswordEngine::new(
            LocalPasswordHasher::new(Zeroizing::new(vec![29; 32].into_boxed_slice())).unwrap(),
            n(1),
            deadline(),
        )
        .await
        .unwrap();
        let hash = engine.hash(PASSWORD, deadline()).await.unwrap();
        sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',$1,'Alice','alice@example.invalid','org','[\"engineering\"]',1,0,1,$2,$2)")
            .bind(hash.as_str()).bind(micros()).execute(&mut admin).await.unwrap();
        sqlx_core::query::query("INSERT INTO public.oauth_dynamic_clients(client_id,client_name,redirect_uris_json,scopes_json,application_type,created_at) VALUES('web-client','Client','[\"https://client.example/cb\"]','[\"openid\",\"offline_access\"]','web',$1)")
            .bind(micros()).execute(&mut admin).await.unwrap();
        Self {
            fixture,
            store,
            admin,
            policy: Arc::new(policy()),
            engine,
            digester: digester(),
            protector: LocalMfaProtector::new(Zeroizing::new(vec![51; 32].into_boxed_slice()))
                .unwrap(),
            login_policy: LocalAuthPolicy::new(
                false,
                "Graphit Broker".into(),
                Duration::from_secs(600),
            )
            .unwrap(),
        }
    }
    pub async fn code(&self, dynamic: bool, offline: bool) -> AuthorizedOidcAuthorization {
        self.code_for("alice", dynamic, offline).await
    }
    pub async fn code_for(
        &self,
        username: &str,
        dynamic: bool,
        offline: bool,
    ) -> AuthorizedOidcAuthorization {
        // SHA-256/base64url fixture vector for VERIFIER; the actual SDK verifies it.
        let challenge = "RqIZl4LIgn8KxW9QO-nTnv7pf0CnNrksx9fF-CXP2FE";
        let service = self
            .store
            .oidc_authorization_service(&self.digester, &self.policy);
        let pending = service
            .create(
                OidcAuthorizationInput {
                    client_id: if dynamic { "web-client" } else { "graphit-cli" },
                    redirect_uri: if dynamic {
                        "https://client.example/cb"
                    } else {
                        "http://localhost:49152/oauth/callback"
                    },
                    response_type: "code",
                    scope: if offline {
                        "openid profile email offline_access"
                    } else {
                        "openid profile email"
                    },
                    state: "literal-state",
                    nonce: "literal-nonce",
                    code_challenge: challenge,
                    code_challenge_method: "S256",
                    response_mode: Some("query"),
                    resources: if dynamic { &[RESOURCE] } else { &[] },
                    prompts: &[],
                },
                deadline(),
            )
            .await
            .unwrap();
        let proof = self
            .store
            .local_password_verifier(&self.engine)
            .verify(username, PASSWORD, deadline())
            .await
            .unwrap();
        let step = self
            .store
            .local_auth_service(&self.digester, &self.protector, &self.login_policy)
            .begin(
                proof,
                LocalAuthBinding::OauthAuthorize(pending.request().as_bytes()),
                deadline(),
            )
            .await
            .unwrap();
        let LocalAuthStep::Complete(login) = step else {
            panic!("fixture must produce genuine completed LOCAL login")
        };
        service
            .complete(
                pending.request(),
                PreparedOidcLogin::try_from(login).unwrap(),
                deadline(),
            )
            .await
            .unwrap()
    }
    pub async fn token_count(&mut self) -> i64 {
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.local_tokens")
            .fetch_one(&mut self.admin)
            .await
            .unwrap()
    }
    pub async fn close(self) {
        self.store.shutdown(deadline()).await.unwrap();
        self.admin.close().await.unwrap();
        self.fixture.shutdown().unwrap();
    }
}
