use broker_control::{
    ControlError, NewAdminSession, SessionClaimRoles, SessionLimits, SessionPrincipal,
    SessionProfile,
};
use std::{
    num::NonZeroUsize,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
fn n(v: usize) -> NonZeroUsize {
    NonZeroUsize::new(v).unwrap()
}
fn limits() -> SessionLimits {
    SessionLimits {
        text_bytes: n(8192),
        csrf_bytes: n(512),
        team_bytes: n(512),
        role_bytes: n(512),
        max_teams: n(8),
        max_roles: n(8),
        teams_json_bytes: n(1024),
        roles_json_bytes: n(1024),
        max_lifetime: Duration::from_secs(3600),
    }
}
fn profile() -> SessionProfile {
    SessionProfile {
        subject: "private-subject".into(),
        name: String::new(),
        email: String::new(),
    }
}
fn principal() -> SessionPrincipal {
    SessionPrincipal {
        issuer: "private-issuer".into(),
        username: String::new(),
        organization: String::new(),
        teams: vec![],
        local_user_revision: 0,
    }
}
fn make(
    p: SessionProfile,
    q: SessionPrincipal,
    csrf: &str,
    claims: Option<SessionClaimRoles>,
    expiry: SystemTime,
    l: &SessionLimits,
) -> Result<NewAdminSession, ControlError> {
    NewAdminSession::new(p, q, Zeroizing::new(csrf.into()), claims, expiry, l)
}
fn expiry() -> SystemTime {
    SystemTime::now() + Duration::from_secs(60)
}
#[test]
fn session_errors_are_specific_static_and_redacted() {
    let errors = [
        (
            ControlError::SessionUnavailable,
            "administrative session unavailable",
        ),
        (
            ControlError::SessionExpired,
            "administrative session expired",
        ),
        (
            ControlError::InvalidSession,
            "invalid administrative session",
        ),
        (
            ControlError::CorruptSession,
            "corrupt administrative session",
        ),
        (
            ControlError::SessionExists,
            "administrative session already exists",
        ),
    ];
    for (error, message) in errors {
        assert_eq!(error.to_string(), message, "SESSION_ERROR_ORACLE");
        assert!(std::error::Error::source(&error).is_none());
    }
    assert_eq!(
        ControlError::Unavailable.to_string(),
        "login flow unavailable"
    );
    assert_eq!(ControlError::Expired.to_string(), "login flow expired");
}
#[test]
fn canonicalization_preserves_identity_and_case_but_not_list_noise() {
    let mut p = profile();
    p.subject = "  subject  ".into();
    p.email = "Case@Example".into();
    let mut q = principal();
    q.issuer = " issuer ".into();
    q.teams = vec![
        " beta ".into(),
        "\u{2003}alpha\u{2003}".into(),
        "alpha".into(),
        "".into(),
        "Beta".into(),
    ];
    let at = expiry();
    let s = make(
        p,
        q,
        "private-csrf",
        Some(SessionClaimRoles {
            selector: " selector ".into(),
            roles: vec![" unknown ".into(), "unknown".into(), "Admin".into()],
        }),
        at,
        &limits(),
    )
    .unwrap();
    assert_eq!(s.profile().subject, "  subject  ");
    assert_eq!(s.profile().email, "Case@Example");
    assert_eq!(s.principal().issuer, " issuer ");
    assert_eq!(s.principal().teams, ["Beta", "alpha", "beta"]);
    assert_eq!(s.principal().local_user_revision, 0);
    assert_eq!(s.claimed_roles().unwrap().selector, " selector ");
    assert_eq!(s.claimed_roles().unwrap().roles, ["Admin", "unknown"]);
    assert_eq!(s.csrf_token(), "private-csrf");
    assert_eq!(s.expires_at(), at);
    for debug in [
        format!("{:?}", s.profile()),
        format!("{:?}", s.principal()),
        format!("{:?}", s.claimed_roles().unwrap()),
        format!("{s:?}"),
    ] {
        assert!(debug.contains("[REDACTED]"));
        for value in [
            "subject",
            "issuer",
            "Case@Example",
            "csrf",
            "selector",
            "unknown",
        ] {
            assert!(!debug.contains(value));
        }
    }
    assert!(
        make(profile(), principal(), "csrf", None, expiry(), &limits())
            .unwrap()
            .claimed_roles()
            .is_none()
    );
}
#[test]
fn character_width_and_utf8_bytes_are_independent() {
    let l = limits();
    let mut p = profile();
    p.subject = "é".repeat(512);
    assert!(make(p, principal(), &"é".repeat(128), None, expiry(), &l).is_ok());
    let mut p = profile();
    p.subject = "é".repeat(513);
    assert!(matches!(
        make(p, principal(), "csrf", None, expiry(), &l),
        Err(ControlError::InvalidSession)
    ));
    let mut short = l;
    short.text_bytes = n(1023);
    let mut p = profile();
    p.subject = "é".repeat(512);
    assert!(matches!(
        make(p, principal(), "csrf", None, expiry(), &short),
        Err(ControlError::InvalidSession)
    ));
    let mut q = principal();
    q.issuer = "é".repeat(1025);
    assert!(make(profile(), q, "csrf", None, expiry(), &l).is_err());
    assert!(make(profile(), principal(), &"é".repeat(129), None, expiry(), &l).is_err());
    let c = Some(SessionClaimRoles {
        selector: "s".into(),
        roles: vec!["é".repeat(129)],
    });
    assert!(make(profile(), principal(), "csrf", c, expiry(), &l).is_err());
    let c = Some(SessionClaimRoles {
        selector: "s".into(),
        roles: vec![format!(" {} ", "é".repeat(128))],
    });
    assert!(make(profile(), principal(), "csrf", c, expiry(), &l).is_ok());
}
#[test]
fn raw_bounds_precede_dedup_trim_and_json_is_bounded() {
    let l = limits();
    let mut q = principal();
    q.teams = vec!["duplicate".into(); 9];
    assert!(make(profile(), q, "csrf", None, expiry(), &l).is_err());
    let mut q = principal();
    q.teams = vec![" ".repeat(513)];
    assert!(make(profile(), q, "csrf", None, expiry(), &l).is_err());
    for teams in [vec!["contains\0nul".into()], vec!["entry".into(); 9]] {
        let mut q = principal();
        q.teams = teams;
        assert!(make(profile(), q, "csrf", None, expiry(), &l).is_err());
    }
    let mut small = l;
    small.teams_json_bytes = n(4);
    let mut q = principal();
    q.teams = vec!["aa".into()];
    assert!(make(profile(), q, "csrf", None, expiry(), &small).is_err());
    // Selector identity is literal; an empty claim snapshot differs from absent claims.
    for (selector, roles) in [
        (" ", vec!["user".into()]),
        ("s", vec![]),
        ("s", vec![" ".into()]),
    ] {
        let value = make(
            profile(),
            principal(),
            "csrf",
            Some(SessionClaimRoles {
                selector: selector.into(),
                roles,
            }),
            expiry(),
            &l,
        )
        .unwrap();
        assert_eq!(value.claimed_roles().unwrap().selector, selector);
    }
    // Escaped control characters exceed a JSON cap even when the raw entry fits it.
    let mut q = principal();
    q.teams = vec!["a\u{0001}b".into()];
    small.teams_json_bytes = n(9);
    assert!(make(profile(), q, "csrf", None, expiry(), &small).is_err());
    for (selector, roles) in [("", vec!["user".into()]), ("s\0", vec!["user".into()])] {
        assert!(
            make(
                profile(),
                principal(),
                "csrf",
                Some(SessionClaimRoles {
                    selector: selector.into(),
                    roles
                }),
                expiry(),
                &l
            )
            .is_err()
        );
    }
}
#[test]
fn required_fields_optional_empty_fields_and_revisions_are_explicit() {
    let l = limits();
    let mut p = profile();
    p.subject.clear();
    assert!(make(p, principal(), "csrf", None, expiry(), &l).is_err());
    let mut q = principal();
    q.issuer.clear();
    assert!(make(profile(), q, "csrf", None, expiry(), &l).is_err());
    assert!(make(profile(), principal(), "", None, expiry(), &l).is_err());
    let mut q = principal();
    q.local_user_revision = -1;
    assert!(make(profile(), q, "csrf", None, expiry(), &l).is_err());
    for field in 0..5 {
        let mut p = profile();
        let mut q = principal();
        match field {
            0 => p.name = "\0".into(),
            1 => p.email = "\0".into(),
            2 => q.username = "\0".into(),
            3 => q.organization = "\0".into(),
            _ => q.issuer = "\0".into(),
        };
        assert!(make(p, q, "csrf", None, expiry(), &l).is_err());
    }
    assert!(make(profile(), principal(), "csrf", None, expiry(), &l).is_ok());
}
#[test]
fn limits_and_timestamp_conversion_reject_overflow_without_defaults() {
    let l = limits();
    assert!(l.validate().is_ok());
    for duration in [Duration::ZERO, Duration::from_nanos(999), Duration::MAX] {
        let mut bad = l;
        bad.max_lifetime = duration;
        assert_eq!(bad.validate(), Err(ControlError::Configuration));
    }
    let mut bad = l;
    bad.max_teams = n(usize::MAX);
    assert_eq!(bad.validate(), Err(ControlError::Configuration));
    let mut bad = l;
    bad.team_bytes = n(isize::MAX as usize);
    assert_eq!(bad.validate(), Err(ControlError::Configuration));
    for at in [UNIX_EPOCH, UNIX_EPOCH - Duration::from_micros(1)] {
        assert!(make(profile(), principal(), "csrf", None, at, &l).is_err());
    }
    if let Some(overflow) = UNIX_EPOCH.checked_add(Duration::from_secs(i64::MAX as u64)) {
        assert!(make(profile(), principal(), "csrf", None, overflow, &l).is_err());
    }
    // Expiration is absolute: constructing an input does not renew it or invent a creation time.
    let at = UNIX_EPOCH + Duration::from_micros(1);
    assert_eq!(
        make(profile(), principal(), "csrf", None, at, &l)
            .unwrap()
            .expires_at(),
        at
    );
}
