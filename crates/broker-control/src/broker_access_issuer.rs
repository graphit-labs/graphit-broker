//! Ed25519 access and ID JWT signing. Grant admission belongs to the protocol producer.
//! See [the issuer contract](../../../docs/rust-broker-access-issuer.md).
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header,
    crypto::aws_lc::DEFAULT_PROVIDER,
    encode,
    jwk::{EllipticCurve, Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::{
    fmt,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAccessIssueError {
    InvalidConfiguration,
    InvalidClaims,
    Signing,
    Deadline,
}
impl fmt::Display for BrokerAccessIssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid Broker access issuer configuration",
            Self::InvalidClaims => "invalid Broker access issuance claims",
            Self::Signing => "Broker access signing failed",
            Self::Deadline => "Broker access issuance deadline exceeded",
        })
    }
}
impl std::error::Error for BrokerAccessIssueError {}

/// Cryptographic input, never evidence of authentication or grant admission.
/// A production protocol producer must establish these values before signing.
pub struct BrokerAccessTokenInput<'a> {
    pub subject: &'a str,
    pub client_id: &'a str,
    pub resource: Option<&'a str>,
    pub scope: &'a str,
    pub jti: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
    pub preferred_username: Option<&'a str>,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub organization: Option<&'a str>,
    pub groups: &'a [String],
    pub roles: &'a [String],
}
impl fmt::Debug for BrokerAccessTokenInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerAccessTokenInput([REDACTED])")
    }
}

/// Cryptographic input established by the admitted OIDC protocol producer.
pub struct BrokerIdTokenInput<'a> {
    pub subject: &'a str,
    pub client_id: &'a str,
    pub resource: Option<&'a str>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub auth_time: u64,
    pub amr: &'a [String],
    pub nonce: Option<&'a str>,
    pub access_token: &'a str,
    pub code: Option<&'a str>,
    pub preferred_username: Option<&'a str>,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
    pub organization: Option<&'a str>,
    pub groups: &'a [String],
    pub roles: &'a [String],
}
impl fmt::Debug for BrokerIdTokenInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerIdTokenInput([REDACTED])")
    }
}

/// Immutable owner of an explicitly configured PKCS#8 Ed25519 key and issuer.
/// The SDK zeroizes its private DER when the owner drops. Only public keys escape.
/// This primitive performs no grant admission, discovery, SQL, or network request.
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::BrokerAccessIssuer>();
/// ~~~
/// ~~~compile_fail
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<broker_control::BrokerAccessIssuer>();
/// ~~~
pub struct BrokerAccessIssuer {
    issuer: String,
    api_audience: String,
    header: Header,
    key: EncodingKey,
    jwks: JwkSet,
}
impl fmt::Debug for BrokerAccessIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerAccessIssuer([REDACTED])")
    }
}
impl BrokerAccessIssuer {
    pub fn new(
        issuer: &str,
        api_audience: &str,
        kid: &str,
        pkcs8: &[u8],
    ) -> Result<Self, BrokerAccessIssueError> {
        if [issuer, api_audience, kid]
            .iter()
            .any(|s| s.trim().is_empty())
        {
            return Err(BrokerAccessIssueError::InvalidConfiguration);
        }
        let public =
            (DEFAULT_PROVIDER
                .key_utils
                .ed_pub_components_from_private_key)(pkcs8, &EllipticCurve::Ed25519)
            .map_err(|_| BrokerAccessIssueError::InvalidConfiguration)?;
        if public.len() != 32 {
            return Err(BrokerAccessIssueError::InvalidConfiguration);
        }
        let mut jwk =
            Jwk::from_decoding_key(&DecodingKey::from_ed_der(&public), Some(Algorithm::EdDSA))
                .map_err(|_| BrokerAccessIssueError::InvalidConfiguration)?;
        jwk.common.key_id = Some(kid.to_owned());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_owned());
        Ok(Self {
            issuer: issuer.to_owned(),
            api_audience: api_audience.to_owned(),
            header,
            key: EncodingKey::from_ed_der(pkcs8),
            jwks: JwkSet { keys: vec![jwk] },
        })
    }
    pub fn jwks(&self) -> &JwkSet {
        &self.jwks
    }
    pub(crate) fn api_audience(&self) -> &str {
        &self.api_audience
    }

    /// Sign admitted values using the captured key, issuer, and API audience.
    /// The returned bearer must remain private. Input alone grants no authority.
    pub fn sign_access(
        &self,
        input: BrokerAccessTokenInput<'_>,
        original: Instant,
    ) -> Result<String, BrokerAccessIssueError> {
        check_deadline(original)?;
        let result = (|| {
            let mono = Instant::now();
            let utc = SystemTime::now();
            let now = utc
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BrokerAccessIssueError::InvalidClaims)?
                .as_secs();
            if input.subject.is_empty()
                || input.client_id.is_empty()
                || input.jti.is_empty()
                || input.resource.is_some_and(|v| v.trim().is_empty())
                || input.issued_at > now
                || input.expires_at <= input.issued_at
                || input.expires_at <= now
            {
                return Err(BrokerAccessIssueError::InvalidClaims);
            }
            let expiry = UNIX_EPOCH
                .checked_add(Duration::from_secs(input.expires_at))
                .ok_or(BrokerAccessIssueError::InvalidClaims)?;
            let remaining = expiry
                .duration_since(utc)
                .map_err(|_| BrokerAccessIssueError::InvalidClaims)?;
            let expiry_mono = mono
                .checked_add(remaining)
                .ok_or(BrokerAccessIssueError::InvalidClaims)?;
            let mut audiences = vec![self.api_audience.as_str()];
            if let Some(resource) = input.resource.filter(|v| *v != self.api_audience) {
                audiences.push(resource);
            }
            let claims = AccessClaims {
                iss: &self.issuer,
                sub: input.subject,
                aud: audiences,
                iat: input.issued_at,
                exp: input.expires_at,
                token_use: "access",
                client_id: input.client_id,
                jti: input.jti,
                scope: input.scope,
                preferred_username: input.preferred_username,
                name: input.name,
                email: input.email,
                organization: input.organization,
                groups: input.groups,
                roles: input.roles,
            };
            let token = encode(&self.header, &claims, &self.key)
                .map_err(|_| BrokerAccessIssueError::Signing)?;
            if SystemTime::now() >= expiry || Instant::now() >= expiry_mono {
                return Err(BrokerAccessIssueError::InvalidClaims);
            }
            Ok(token)
        })();
        check_deadline(original)?;
        result
    }

    /// Sign ID claims with the same configured key used for access JWTs.
    /// Hash claims bind the actual access bearer and redeemed code, not their IDs.
    pub fn sign_id(
        &self,
        input: BrokerIdTokenInput<'_>,
        original: Instant,
    ) -> Result<String, BrokerAccessIssueError> {
        check_deadline(original)?;
        let result = (|| {
            let mono = Instant::now();
            let utc = SystemTime::now();
            let now = utc
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BrokerAccessIssueError::InvalidClaims)?
                .as_secs();
            if input.subject.is_empty()
                || input.client_id.is_empty()
                || input.resource.is_some_and(|v| v.trim().is_empty())
                || input.issued_at > now
                || input.expires_at <= input.issued_at
                || input.expires_at <= now
                || input.auth_time == 0
                || input.auth_time > now
                || input.amr.is_empty()
                || input.amr.iter().any(|v| v.trim().is_empty())
                || input.access_token.is_empty()
                || input.code.is_some_and(str::is_empty)
            {
                return Err(BrokerAccessIssueError::InvalidClaims);
            }
            let expiry = UNIX_EPOCH
                .checked_add(Duration::from_secs(input.expires_at))
                .ok_or(BrokerAccessIssueError::InvalidClaims)?;
            let expiry_mono = mono
                .checked_add(
                    expiry
                        .duration_since(utc)
                        .map_err(|_| BrokerAccessIssueError::InvalidClaims)?,
                )
                .ok_or(BrokerAccessIssueError::InvalidClaims)?;
            let mut aud = vec![self.api_audience.as_str()];
            if let Some(resource) = input.resource.filter(|v| *v != self.api_audience) {
                aud.push(resource);
            }
            if !aud.contains(&input.client_id) {
                aud.push(input.client_id);
            }
            let claims = IdClaims {
                iss: &self.issuer,
                sub: input.subject,
                aud,
                iat: input.issued_at,
                exp: input.expires_at,
                auth_time: input.auth_time,
                amr: input.amr,
                azp: input.client_id,
                client_id: input.client_id,
                nonce: input.nonce.filter(|v| !v.is_empty()),
                at_hash: eddsa_claim_hash(input.access_token),
                c_hash: input.code.map(eddsa_claim_hash),
                preferred_username: input.preferred_username,
                name: input.name,
                email: input.email,
                organization: input.organization,
                groups: input.groups,
                roles: input.roles,
            };
            let token = encode(&self.header, &claims, &self.key)
                .map_err(|_| BrokerAccessIssueError::Signing)?;
            if SystemTime::now() >= expiry || Instant::now() >= expiry_mono {
                return Err(BrokerAccessIssueError::InvalidClaims);
            }
            Ok(token)
        })();
        check_deadline(original)?;
        result
    }
}
fn eddsa_claim_hash(value: &str) -> String {
    let hash = Sha512::digest(value.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash[..32])
}
fn check_deadline(original: Instant) -> Result<(), BrokerAccessIssueError> {
    if Instant::now() >= original {
        Err(BrokerAccessIssueError::Deadline)
    } else {
        Ok(())
    }
}
#[derive(Serialize)]
struct AccessClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: Vec<&'a str>,
    iat: u64,
    exp: u64,
    token_use: &'a str,
    client_id: &'a str,
    jti: &'a str,
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    groups: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    roles: &'a [String],
}

#[derive(Serialize)]
struct IdClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: Vec<&'a str>,
    iat: u64,
    exp: u64,
    auth_time: u64,
    amr: &'a [String],
    azp: &'a str,
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    at_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    c_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<&'a str>,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    groups: &'a [String],
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    roles: &'a [String],
}
