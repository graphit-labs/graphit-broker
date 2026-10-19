use super::OidcAuthorizationRequestInfo;
use broker_security::NativeOidcSubject;
use broker_store::time::TimestampMicros;
use std::fmt;
use zeroize::Zeroizing;

/// A committed authorization code, not an access token or a PROJECT permission.
/// ```compile_fail
/// fn clone<T: Clone>() {}
/// clone::<broker_control::AuthorizedOidcAuthorization>();
/// ```
/// ```compile_fail
/// fn deserialize<T: for<'a> serde::Deserialize<'a>>() {}
/// deserialize::<broker_control::AuthorizedOidcAuthorization>();
/// ```
/// ```compile_fail
/// fn expose(value: broker_control::AuthorizedOidcAuthorization) { let _ = value.code; }
/// ```
/// The consumer crate has serde, so this checks the subject's actual trait boundary.
/// ```compile_fail
/// fn deserialize<T: for<'a> serde::Deserialize<'a>>() {}
/// deserialize::<broker_security::NativeOidcSubject>();
/// ```
pub struct AuthorizedOidcAuthorization {
    pub(crate) code: Zeroizing<String>,
    pub(crate) info: OidcAuthorizationRequestInfo,
    pub(crate) subject: NativeOidcSubject,
    pub(crate) amr: Vec<&'static str>,
    pub(crate) auth_time: TimestampMicros,
}
impl fmt::Debug for AuthorizedOidcAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedOidcAuthorization([REDACTED])")
    }
}
impl AuthorizedOidcAuthorization {
    pub fn code(&self) -> &str {
        &self.code
    }
    pub const fn info(&self) -> &OidcAuthorizationRequestInfo {
        &self.info
    }
    pub fn oidc_subject(&self) -> &str {
        self.subject.as_str()
    }
    pub fn amr(&self) -> &[&'static str] {
        &self.amr
    }
    pub const fn auth_time(&self) -> TimestampMicros {
        self.auth_time
    }
}
