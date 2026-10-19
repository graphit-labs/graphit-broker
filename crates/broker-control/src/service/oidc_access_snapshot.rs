//! Bounded immutable access-grant snapshot; profile/trust revalidation stays in UserInfo.
use super::oidc_principal::OidcPrincipal;
use crate::{
    BrokerAccessError, ControlError, OidcAuthorizationPolicy, OidcTokenExchangeError,
    VerifiedBrokerAccess, flow::now_micros,
};
use broker_security::{CredentialDigester, TokenKind, validate_local_auth_challenge};
use sqlx_core::row::Row;
use sqlx_postgres::PgRow;
use std::time::UNIX_EPOCH;
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessGrantError {
    InvalidToken,
    MalformedStored,
    ReadLimitExceeded,
    Credential,
    Control(ControlError),
}
impl From<ControlError> for AccessGrantError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

pub(super) const COLUMNS: &str = r#"token_hash,
 local_user_revision,
 expires_at,
 created_at,
 auth_time,
 revoked_at,
 OCTET_LENGTH(token_id)::bigint AS token_id_bytes,
 CASE WHEN OCTET_LENGTH(token_id)<=$2 THEN token_id END AS token_id,
 OCTET_LENGTH(oidc_subject)::bigint AS oidc_subject_bytes,
 CASE WHEN OCTET_LENGTH(oidc_subject)<=$2 THEN oidc_subject END AS oidc_subject,
 OCTET_LENGTH(client_id)::bigint AS client_id_bytes,
 CASE WHEN OCTET_LENGTH(client_id)<=$2 THEN client_id END AS client_id,
 OCTET_LENGTH(audience)::bigint AS audience_bytes,
 CASE WHEN OCTET_LENGTH(audience)<=$2 THEN audience END AS audience,
 OCTET_LENGTH(resource)::bigint AS resource_bytes,
 CASE WHEN OCTET_LENGTH(resource)<=$2 THEN resource END AS resource,
 OCTET_LENGTH(subject)::bigint AS subject_bytes,
 CASE WHEN OCTET_LENGTH(subject)<=$2 THEN subject END AS subject,
 OCTET_LENGTH(principal_json)::bigint AS principal_bytes,
 CASE WHEN OCTET_LENGTH(principal_json)<=$2 THEN principal_json END AS principal_json,
 OCTET_LENGTH(scopes_json)::bigint AS scope_bytes,
 CASE WHEN OCTET_LENGTH(scopes_json)<=$2 THEN scopes_json END AS scopes_json"#;
pub(crate) fn bearer_error(error: BrokerAccessError) -> AccessGrantError {
    match error {
        BrokerAccessError::Deadline => ControlError::Deadline.into(),
        _ => AccessGrantError::InvalidToken,
    }
}
pub(crate) fn token_hash(
    digester: &CredentialDigester,
    proof: &VerifiedBrokerAccess<'_>,
) -> Result<String, AccessGrantError> {
    validate_local_auth_challenge(proof.jti()).map_err(|_| AccessGrantError::InvalidToken)?;
    Ok(digester
        .token(TokenKind::OidcStoredAccess, proof.jti().as_bytes())
        .map_err(|_| AccessGrantError::Credential)?
        .to_sql_hex())
}
fn principal_error(error: OidcTokenExchangeError) -> AccessGrantError {
    match error {
        OidcTokenExchangeError::InvalidGrant => AccessGrantError::InvalidToken,
        OidcTokenExchangeError::Control(error) => error.into(),
        OidcTokenExchangeError::ReadLimitExceeded => AccessGrantError::ReadLimitExceeded,
        _ => AccessGrantError::MalformedStored,
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct AccessGrant {
    pub hash: String,
    pub id: String,
    pub subject: String,
    pub oidc_subject: String,
    pub client: String,
    pub audience: String,
    pub resource: String,
    pub revision: i64,
    pub expiry: i64,
    pub created: i64,
    pub auth_time: i64,
    pub principal: Zeroizing<String>,
    pub scopes: Vec<String>,
}
impl AccessGrant {
    pub fn matches(
        &self,
        proof: &VerifiedBrokerAccess<'_>,
        revoked: Option<i64>,
        policy: &OidcAuthorizationPolicy,
    ) -> Result<(), AccessGrantError> {
        proof.check().map_err(bearer_error)?;
        let expiry = proof
            .expires_at()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|v| i64::try_from(v.as_secs()).ok())
            .and_then(|v| v.checked_mul(1_000_000))
            .ok_or(AccessGrantError::InvalidToken)?;
        let now = now_micros()?;
        if now < self.created {
            return Err(ControlError::Clock.into());
        }
        if revoked.is_some()
            || self.expiry <= now
            || self.expiry != expiry
            || self.id != proof.jti()
            || self.oidc_subject != proof.subject()
            || self.client != proof.client_id()
            || self.audience != policy.api_audience
            || self.scopes != proof.scopes()
            || !proof.matches_oidc_resource(&self.resource)
        {
            return Err(AccessGrantError::InvalidToken);
        }
        Ok(())
    }
}
pub(super) fn decode(
    row: &PgRow,
    cap: i64,
) -> Result<(AccessGrant, Option<i64>), AccessGrantError> {
    let text = |name| {
        row.try_get::<String, _>(name)
            .map_err(|_| AccessGrantError::MalformedStored)
    };
    let number = |name| {
        row.try_get::<i64, _>(name)
            .map_err(|_| AccessGrantError::MalformedStored)
    };
    let bounded = |length, name| {
        if !(0..=cap).contains(&number(length)?) {
            return Err(AccessGrantError::ReadLimitExceeded);
        }
        text(name)
    };
    let scopes = serde_json::from_str(&bounded("scope_bytes", "scopes_json")?)
        .map_err(|_| AccessGrantError::MalformedStored)?;
    let stored = AccessGrant {
        hash: text("token_hash")?,
        id: bounded("token_id_bytes", "token_id")?,
        subject: bounded("subject_bytes", "subject")?,
        oidc_subject: bounded("oidc_subject_bytes", "oidc_subject")?,
        client: bounded("client_id_bytes", "client_id")?,
        audience: bounded("audience_bytes", "audience")?,
        resource: bounded("resource_bytes", "resource")?,
        revision: number("local_user_revision")?,
        expiry: number("expires_at")?,
        created: number("created_at")?,
        auth_time: number("auth_time")?,
        principal: Zeroizing::new(bounded("principal_bytes", "principal_json")?),
        scopes,
    };
    let revoked: Option<i64> = row
        .try_get("revoked_at")
        .map_err(|_| AccessGrantError::MalformedStored)?;
    if stored.created <= 0
        || stored.expiry <= stored.created
        || stored.auth_time <= 0
        || stored.auth_time > stored.created
        || revoked.is_some_and(|v| v < stored.created)
    {
        return Err(AccessGrantError::MalformedStored);
    }
    Ok((stored, revoked))
}

impl AccessGrant {
    pub fn principal(
        &self,
        digester: &CredentialDigester,
    ) -> Result<OidcPrincipal, AccessGrantError> {
        let principal = OidcPrincipal::parse(&self.principal).map_err(principal_error)?;
        let subject = digester
            .oidc_subject(
                principal.issuer().as_bytes(),
                principal.subject().as_bytes(),
            )
            .map_err(|_| AccessGrantError::Credential)?;
        if self.subject != principal.subject()
            || self.revision != principal.revision()
            || self.oidc_subject != subject.as_str()
        {
            return Err(AccessGrantError::InvalidToken);
        }
        Ok(principal)
    }
}
