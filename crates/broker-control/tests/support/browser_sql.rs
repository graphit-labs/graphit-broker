use crate::support::{Fixture, deadline, digester, limits, n, pool};
use broker_control::{
    ConnectionLimits, PostgresConfig, PostgresControlStore, PostgresCredentials, PostgresEndpoint,
};
use sqlx_core::connection::Connection;
use sqlx_postgres::PgConnection;
use std::{
    num::NonZeroU16,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
pub struct BrowserSql {
    pub fixture: Fixture,
    pub admin: PgConnection,
    pub store: Arc<PostgresControlStore>,
}
pub fn config(f: &Fixture, port: u16, operation: Duration) -> PostgresConfig {
    let mut budgets = pool(2);
    budgets.operation_timeout = operation;
    PostgresConfig::new(
        PostgresEndpoint {
            host: "127.0.0.1".into(),
            port: NonZeroU16::new(port).unwrap(),
            database: "postgres".into(),
        },
        PostgresCredentials::new(
            "browser_login_owner".into(),
            Zeroizing::new("ephemeral-browser".into()),
        ),
        f.ca.clone(),
        ConnectionLimits {
            text_bytes: n(256),
            ca_bytes: n(8192),
        },
        budgets,
        limits(),
    )
    .unwrap()
}
impl BrowserSql {
    pub async fn new() -> Self {
        let fixture = Fixture::new(true).await;
        let mut admin = fixture.connection().await;
        sqlx_core::raw_sql::raw_sql("CREATE ROLE browser_login_owner LOGIN NOSUPERUSER PASSWORD 'ephemeral-browser'; DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION browser_login_owner; GRANT CONNECT,TEMP ON DATABASE postgres TO browser_login_owner").execute(&mut admin).await.unwrap();
        let ordinary: bool = sqlx_core::query_scalar::query_scalar(
            "SELECT NOT rolsuper FROM pg_roles WHERE rolname='browser_login_owner'",
        )
        .fetch_one(&mut admin)
        .await
        .unwrap();
        assert!(ordinary);
        let store = Arc::new(
            PostgresControlStore::open(
                config(&fixture, fixture.port, Duration::from_secs(8)),
                digester(),
                deadline(),
            )
            .await
            .unwrap(),
        );
        Self {
            fixture,
            admin,
            store,
        }
    }
    pub async fn close(self) {
        self.store
            .shutdown(Instant::now() + Duration::from_secs(3))
            .await
            .unwrap();
        self.admin.close().await.unwrap();
        self.fixture.shutdown().unwrap();
    }
}
