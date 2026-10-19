//! Native refresh request; its SQL producer owns all grant admission and rotation.
use crate::{OidcTokenExchangeError as Error, oidc_authorization::guard_original};
use oxide_auth::{code_grant::refresh::Request, primitives::scope::Scope};
use std::{borrow::Cow, fmt, time::Instant};

pub struct OidcRefreshInput<'a> {
    pub grant_type: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub resource: Option<&'a str>,
    pub authorization: Option<(&'a str, &'a [u8])>,
}
impl fmt::Debug for OidcRefreshInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcRefreshInput([REDACTED])")
    }
}
impl Request for OidcRefreshInput<'_> {
    fn valid(&self) -> bool {
        true
    }
    fn refresh_token(&self) -> Option<Cow<'_, str>> {
        self.refresh_token.map(Cow::Borrowed)
    }
    fn scope(&self) -> Option<Cow<'_, str>> {
        self.scope.map(Cow::Borrowed)
    }
    fn grant_type(&self) -> Option<Cow<'_, str>> {
        self.grant_type.map(Cow::Borrowed)
    }
    fn authorization(&self) -> Option<(Cow<'_, str>, Cow<'_, [u8]>)> {
        self.authorization
            .map(|(u, p)| (Cow::Borrowed(u), Cow::Borrowed(p)))
    }
    fn extension(&self, key: &str) -> Option<Cow<'_, str>> {
        match key {
            "client_id" => self.client_id.map(Cow::Borrowed),
            "resource" => self.resource.map(Cow::Borrowed),
            _ => None,
        }
    }
}
pub(crate) fn requested_scopes(
    raw: Option<&str>,
    granted: &[String],
    original: Instant,
) -> Result<Vec<String>, Error> {
    guard_original(original)?;
    let Some(raw) = raw else {
        return Ok(granted.to_vec());
    };
    // The protocol distinguishes missing scope from a present empty element.
    raw.parse::<Scope>().map_err(|_| Error::InvalidScope)?;
    let mut result = Vec::new();
    for token in raw.split(' ') {
        guard_original(original)?;
        if token.is_empty() || !granted.iter().any(|v| v == token) {
            return Err(Error::InvalidScope);
        }
        if !result.iter().any(|v| v == token) {
            result.push(token.to_owned());
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn absence_empty_elements_and_narrowing_remain_distinct() {
        let grant = vec!["openid".into(), "offline_access".into()];
        let end = Instant::now() + Duration::from_secs(1);
        assert_eq!(requested_scopes(None, &grant, end).unwrap(), grant);
        assert_eq!(
            requested_scopes(Some("openid openid"), &grant, end).unwrap(),
            ["openid"]
        );
        for raw in [
            "",
            " ",
            " openid",
            "openid ",
            "openid  offline_access",
            "openid\toffline_access",
            "email",
        ] {
            assert_eq!(
                requested_scopes(Some(raw), &grant, end),
                Err(Error::InvalidScope)
            );
        }
        assert!(requested_scopes(None, &grant, Instant::now()).is_err());
    }
}
