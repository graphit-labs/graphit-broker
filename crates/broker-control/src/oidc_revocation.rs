//! RFC7009 input. Only possession of the bound raw credential permits revocation.
use std::fmt;

pub struct OidcRevocationInput<'a> {
    pub token: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub token_type_hint: Option<&'a str>,
    pub authorization: Option<(&'a str, &'a [u8])>,
}
impl fmt::Debug for OidcRevocationInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcRevocationInput([REDACTED])")
    }
}
