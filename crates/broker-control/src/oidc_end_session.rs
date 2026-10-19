//! Disposal input: only a verified Broker ID hint can select the subject/client pair.
use std::fmt;
pub struct OidcEndSessionInput<'a> {
    pub id_token_hint: Option<&'a str>,
    pub client_id: Option<&'a str>,
}
impl fmt::Debug for OidcEndSessionInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcEndSessionInput([REDACTED])")
    }
}
