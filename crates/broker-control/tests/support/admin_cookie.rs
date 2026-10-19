//! Genuine Argon2/LOCAL/SQL cookie fixture shared by SQL and actual server contracts.
use crate::support::{self, Fixture, deadline, n};
use broker_control::{
    ADMIN_COOKIE_MAX_LIFETIME, AdminBrokerSessionLimits, AdminCookieSessionLimits,
    AdminCookieSessionPolicy, CompletedLocalLogin, ConnectionLimits, IdentityReadLimits,
    IssuedAdminCookie, LocalAuthPolicy, LocalAuthStep, LocalPasswordEngine, PostgresConfig,
    PostgresControlStore, PostgresCredentials, PostgresEndpoint, PreparedAdminLogin, SessionLimits,
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
pub const PEPPER: &str = "native-cookie-fixture-pepper-32-bytes";
pub const PASSWORD: &str = "native cookie fixture-only password";
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
pub fn limits() -> AdminCookieSessionLimits {
    AdminCookieSessionLimits {
        authorization: AdminBrokerSessionLimits {
            identity: IdentityReadLimits {
                username_bytes: n(128),
                subject_bytes: n(512),
                role_bytes: n(128),
                roles: n(16),
                rows: n(128),
            },
            profile_json_bytes: n(8192),
        },
        metadata: SessionLimits {
            text_bytes: n(2048),
            csrf_bytes: n(43),
            team_bytes: n(512),
            role_bytes: n(128),
            max_teams: n(16),
            max_roles: n(16),
            teams_json_bytes: n(8192),
            roles_json_bytes: n(8192),
            max_lifetime: ADMIN_COOKIE_MAX_LIFETIME,
        },
    }
}
pub fn policy() -> AdminCookieSessionPolicy {
    AdminCookieSessionPolicy {
        session_ttl: Duration::from_secs(8 * 3600),
    }
}
pub fn config(f: &Fixture, port: u16) -> PostgresConfig {
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "admin_cookie_owner".into(),
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
pub struct CookieFixture {
    pub fixture: Fixture,
    pub store: Arc<PostgresControlStore>,
    pub engine: Arc<LocalPasswordEngine>,
    pub admin: PgConnection,
    pub digester: CredentialDigester,
    pub protector: LocalMfaProtector,
    pub exempt: LocalAuthPolicy,
    pub required: LocalAuthPolicy,
}
impl CookieFixture {
    pub async fn new() -> Self {
        let fixture = Fixture::new(true).await;
        let mut admin = fixture.connection().await;
        admin.execute("CREATE ROLE admin_cookie_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-owner'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION admin_cookie_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO admin_cookie_owner").await.unwrap();
        let store = Arc::new(
            PostgresControlStore::open(config(&fixture, fixture.port), digester(), deadline())
                .await
                .unwrap(),
        );
        let ordinary: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT NOT rolsuper FROM pg_roles WHERE rolname='admin_cookie_owner'",
        )
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert!(ordinary);
        let engine = Arc::new(
            LocalPasswordEngine::new(
                LocalPasswordHasher::new(Zeroizing::new(
                    PEPPER.as_bytes().to_vec().into_boxed_slice(),
                ))
                .unwrap(),
                n(1),
                deadline(),
            )
            .await
            .unwrap(),
        );
        let hash = engine.hash(PASSWORD, deadline()).await.unwrap();
        sqlx_core::query::query("INSERT INTO public.local_users(username,subject,identity_kind,password_hash,name,email,organization,teams_json,enabled,password_change_required,revision,created_at,updated_at) VALUES('alice','alice-subject','human',$1,'Alice','alice@example.invalid','org','[\"engineering\"]',1,0,1,$2,$2)")
            .bind(hash.as_str()).bind(micros()).execute(&mut admin).await.unwrap();
        Self {
            fixture,
            store,
            engine,
            admin,
            digester: digester(),
            protector: LocalMfaProtector::new(Zeroizing::new(
                PEPPER.as_bytes().to_vec().into_boxed_slice(),
            ))
            .unwrap(),
            exempt: LocalAuthPolicy::new(false, "Graphit Broker".into(), Duration::from_secs(600))
                .unwrap(),
            required: LocalAuthPolicy::new(true, "Graphit Broker".into(), Duration::from_secs(600))
                .unwrap(),
        }
    }
    pub async fn login(&self, context: LocalAuthBinding<'_>) -> CompletedLocalLogin {
        self.login_with_original(context, deadline()).await
    }
    pub async fn login_with_original(
        &self,
        context: LocalAuthBinding<'_>,
        original: std::time::Instant,
    ) -> CompletedLocalLogin {
        let proof = self
            .store
            .local_password_verifier(&self.engine)
            .verify("alice", PASSWORD, original)
            .await
            .unwrap();
        match self
            .store
            .local_auth_service(&self.digester, &self.protector, &self.exempt)
            .begin(proof, context, original)
            .await
            .unwrap()
        {
            LocalAuthStep::Complete(login) => login,
            _ => panic!("fixture must obtain actual LOCAL completion"),
        }
    }
    pub async fn cookie(&self) -> IssuedAdminCookie {
        let original = deadline();
        self.store
            .admin_cookie_sessions(limits(), policy(), None)
            .unwrap()
            .issue_local(
                PreparedAdminLogin::try_from(
                    self.login_with_original(LocalAuthBinding::AdminLogin, original)
                        .await,
                )
                .unwrap(),
                &self.exempt,
                original,
            )
            .await
            .unwrap()
    }
    pub async fn count(&mut self) -> i64 {
        sqlx_core::query_scalar::query_scalar("SELECT count(*) FROM public.admin_sessions")
            .fetch_one(&mut self.admin)
            .await
            .unwrap()
    }
    pub async fn close(self) {
        self.admin.close().await.unwrap();
        self.store.shutdown(deadline()).await.unwrap();
        self.fixture.shutdown().unwrap();
    }
}
