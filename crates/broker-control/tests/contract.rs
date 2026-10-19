use broker_control::{
    ConnectionLimits, ControlError, FlowContinuation, FlowLimits, FlowPurpose, OidcFlow,
    PoolConfig, PostgresConfig, PostgresCredentials, PostgresEndpoint,
};
use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn limits() -> FlowLimits {
    FlowLimits {
        provider_bytes: n(32),
        request_bytes: n(32),
        continuation_bytes: n(160),
    }
}
fn pool() -> PoolConfig {
    PoolConfig {
        max_connections: NonZeroU32::new(2).unwrap(),
        min_connections: 0,
        statement_cache_capacity: 0,
        connect_timeout: Duration::from_secs(2),
        acquire_timeout: Duration::from_secs(2),
        operation_timeout: Duration::from_secs(2),
        startup_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(2),
        max_lifetime: Duration::from_secs(60),
        idle_timeout: Duration::from_secs(30),
        statement_timeout: Duration::from_secs(2),
        lock_timeout: Duration::from_secs(2),
        idle_transaction_timeout: Duration::from_secs(2),
    }
}
fn config(host: &str, budget: PoolConfig) -> Result<PostgresConfig, ControlError> {
    PostgresConfig::new(
        PostgresEndpoint {
            host: host.into(),
            port: NonZeroU16::new(5432).unwrap(),
            database: "test".into(),
        },
        PostgresCredentials::new("user".into(), Zeroizing::new("private-value".into())),
        b"explicit-pem".to_vec(),
        ConnectionLimits {
            text_bytes: n(64),
            ca_bytes: n(128),
        },
        budget,
        limits(),
    )
}
#[test]
fn typed_continuations_reject_unknown_duplicate_empty_and_overlong_fields() {
    let oauth = FlowContinuation::OAuth {
        provider_id: "provider".into(),
        request_id: "request".into(),
    };
    let json = oauth.to_json(limits()).unwrap();
    let value = FlowContinuation::from_json(FlowPurpose::OAuth, &json, limits()).unwrap();
    assert_eq!(value.provider_id(), "provider");
    assert_eq!(value.request_id(), Some("request"));
    assert_eq!(
        FlowContinuation::Admin {
            provider_id: "provider".into()
        }
        .purpose(),
        FlowPurpose::Admin
    );
    for value in [
        r#"{"provider_id":"p","request_id":"r","extra":1}"#,
        r#"{"provider_id":"p","provider_id":"q","request_id":"r"}"#,
        r#"{"provider_id":"p"}"#,
        r#"{"provider_id":"","request_id":"r"}"#,
        r#"{"provider_id":"p","request_id":"\u0000"}"#,
    ] {
        assert!(FlowContinuation::from_json(FlowPurpose::OAuth, value, limits()).is_err());
    }
    assert!(
        FlowContinuation::Admin {
            provider_id: "é".repeat(17)
        }
        .to_json(limits())
        .is_err()
    );
    let tiny = FlowLimits {
        continuation_bytes: n(1),
        ..limits()
    };
    assert!(oauth.to_json(tiny).is_err());
}
#[test]
fn nonce_pkce_and_expiry_have_protocol_bounds_and_redacted_debug() {
    for (nonce, verifier, valid) in [
        ("nonce".into(), "a".repeat(43), true),
        ("é".repeat(64), "~".repeat(128), true),
        (String::new(), "a".repeat(43), false),
        ("é".repeat(65), "a".repeat(43), false),
        ("nonce".into(), "a".repeat(42), false),
        ("nonce".into(), "a".repeat(129), false),
        ("nonce".into(), "+".repeat(43), false),
    ] {
        let flow = OidcFlow::new(
            nonce,
            verifier,
            FlowContinuation::Admin {
                provider_id: "private-provider".into(),
            },
            SystemTime::now() + Duration::from_secs(60),
            limits(),
        );
        assert_eq!(flow.is_ok(), valid);
        if let Ok(flow) = flow {
            assert_eq!(format!("{flow:?}"), "OidcFlow([REDACTED])");
        }
    }
}
#[test]
fn configuration_requires_explicit_finite_positive_budgets_and_tcp() {
    assert!(config("127.0.0.1", pool()).is_ok());
    for host in [
        "",
        "/tmp/socket",
        "\\socket",
        "host\0suffix",
        &"h".repeat(65),
    ] {
        assert!(config(host, pool()).is_err());
    }
    let mut budget = pool();
    budget.min_connections = 3;
    assert!(config("host", budget).is_err());
    budget = pool();
    budget.operation_timeout = Duration::ZERO;
    assert!(config("host", budget).is_err());
    budget = pool();
    budget.statement_timeout = Duration::from_nanos(1);
    assert!(config("host", budget).is_err());
    budget = pool();
    budget.lock_timeout = Duration::from_millis(i32::MAX as u64 + 1);
    assert!(config("host", budget).is_err());
    assert_eq!(
        format!("{:?}", config("host", pool()).unwrap()),
        "PostgresConfig([REDACTED])"
    );
    assert_eq!(
        ControlError::OutcomeUncertain.to_string(),
        "transaction outcome uncertain; do not replay automatically"
    );
}
