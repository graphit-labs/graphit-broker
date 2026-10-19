//! Local Broker access JWT authentication; PROJECT authorization remains separate.
//! See [the server contract](../../../docs/rust-broker-access-jwt.md).
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode,
    errors::ErrorKind,
    jwk::{AlgorithmParameters, EllipticCurve, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use serde::{
    Deserialize,
    de::{self, DeserializeSeed, MapAccess, Visitor},
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    marker::PhantomData,
    num::NonZeroUsize,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAccessError {
    InvalidConfiguration,
    InvalidToken,
    Expired,
    InsufficientScope,
    Deadline,
}
impl fmt::Display for BrokerAccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid Broker access verifier configuration",
            Self::InvalidToken => "invalid Broker access token",
            Self::Expired => "Broker access token expired",
            Self::InsufficientScope => "Broker access scope denied",
            Self::Deadline => "Broker access deadline exceeded",
        })
    }
}
impl std::error::Error for BrokerAccessError {}

/// Explicit immutable trust from the Broker configuration/OP key owner.
/// Rotation replaces this snapshot; request headers can never supply trusted keys.
/// See [the server contract](../../../docs/rust-broker-access-jwt.md).
/// ~~~
/// use broker_control::{BrokerAccessError, BrokerAccessVerifier};
/// use jsonwebtoken::jwk::JwkSet;
/// use std::num::NonZeroUsize;
/// fn configured(
///     issuer: &str, api_audience: &str, resource: Option<&str>,
///     trusted_jwks: &JwkSet, token_bytes: NonZeroUsize,
/// ) -> Result<BrokerAccessVerifier, BrokerAccessError> {
///     BrokerAccessVerifier::new(issuer, api_audience, resource, trusted_jwks, token_bytes)
/// }
/// ~~~
pub struct BrokerAccessVerifier {
    issuer: String,
    api_audience: String,
    resource: Option<String>,
    token_bytes: NonZeroUsize,
    keys: HashMap<String, DecodingKey>,
}
impl fmt::Debug for BrokerAccessVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrokerAccessVerifier([REDACTED])")
    }
}
impl BrokerAccessVerifier {
    pub fn new(
        issuer: &str,
        api_audience: &str,
        resource: Option<&str>,
        trusted_jwks: &JwkSet,
        token_bytes: NonZeroUsize,
    ) -> Result<Self, BrokerAccessError> {
        if [issuer, api_audience].iter().any(|v| v.trim().is_empty())
            || resource.is_some_and(|v| v.trim().is_empty())
            || trusted_jwks.keys.is_empty()
            || token_bytes.get() > isize::MAX as usize
        {
            return Err(BrokerAccessError::InvalidConfiguration);
        }
        let mut keys = HashMap::new();
        for jwk in &trusted_jwks.keys {
            let common = &jwk.common;
            let kid = common
                .key_id
                .as_deref()
                .filter(|kid| !kid.is_empty())
                .ok_or(BrokerAccessError::InvalidConfiguration)?;
            let AlgorithmParameters::OctetKeyPair(parameters) = &jwk.algorithm else {
                return Err(BrokerAccessError::InvalidConfiguration);
            };
            if parameters.curve != EllipticCurve::Ed25519
                || common
                    .key_algorithm
                    .as_ref()
                    .is_some_and(|v| v != &KeyAlgorithm::EdDSA)
                || common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|v| v != &PublicKeyUse::Signature)
                || common
                    .key_operations
                    .as_ref()
                    .is_some_and(|v| v.as_slice() != [KeyOperations::Verify])
                || URL_SAFE_NO_PAD
                    .decode(&parameters.x)
                    .map_err(|_| BrokerAccessError::InvalidConfiguration)?
                    .len()
                    != 32
            {
                return Err(BrokerAccessError::InvalidConfiguration);
            }
            let key =
                DecodingKey::from_jwk(jwk).map_err(|_| BrokerAccessError::InvalidConfiguration)?;
            if keys.insert(kid.to_owned(), key).is_some() {
                return Err(BrokerAccessError::InvalidConfiguration);
            }
        }
        Ok(Self {
            issuer: issuer.into(),
            api_audience: api_audience.into(),
            resource: resource.map(str::to_owned),
            token_bytes,
            keys,
        })
    }

    /// Authenticate locally. This does not query SQL or grant PROJECT permission.
    pub fn verify<'a>(
        &'a self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<VerifiedBrokerAccess<'a>, BrokerAccessError> {
        self.verify_bound(raw, required_scopes, self.resource.as_deref(), original)
    }

    /// Only the explicit token revoker may omit the resource-specific API binding.
    /// Issuer, signing keys, API audience, access-token shape and expiry stay mandatory.
    pub(crate) fn verify_for_revocation<'a>(
        &'a self,
        raw: &str,
        original: Instant,
    ) -> Result<VerifiedBrokerAccess<'a>, BrokerAccessError> {
        self.verify_bound(raw, &[], None, original)
    }

    /// Explicit OP operations bind the signed resource to their SQL grant snapshot.
    pub(crate) fn verify_for_oidc_operation<'a>(
        &'a self,
        raw: &str,
        original: Instant,
    ) -> Result<VerifiedBrokerAccess<'a>, BrokerAccessError> {
        self.verify_bound(raw, &[], None, original)
    }

    pub(crate) fn api_audience(&self) -> &str {
        &self.api_audience
    }

    fn verify_bound<'a>(
        &'a self,
        raw: &str,
        required_scopes: &[String],
        resource: Option<&str>,
        original: Instant,
    ) -> Result<VerifiedBrokerAccess<'a>, BrokerAccessError> {
        check_deadline(original)?;
        let outcome = (|| {
            if raw.len() > self.token_bytes.get() || raw.is_empty() {
                return Err(BrokerAccessError::InvalidToken);
            }
            if required_scopes
                .iter()
                .any(|s| s.trim().is_empty() || s.contains(' '))
            {
                return Err(BrokerAccessError::InvalidConfiguration);
            }
            let key = self.trusted_key(raw)?;
            let anchor_mono = Instant::now();
            let anchor_utc = SystemTime::now();
            let now = anchor_utc
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BrokerAccessError::InvalidToken)?
                .as_secs();
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.leeway = 0;
            validation.reject_tokens_expiring_in_less_than = 0;
            validation.validate_nbf = true;
            validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
            validation.set_issuer(&[&self.issuer]);
            validation.set_audience(&[&self.api_audience]);
            let UniqueRoot(claims) = decode::<UniqueRoot<Claims>>(raw, key, &validation)
                .map_err(|e| match e.kind() {
                    ErrorKind::ExpiredSignature => BrokerAccessError::Expired,
                    _ => BrokerAccessError::InvalidToken,
                })?
                .claims;
            if claims.iss != self.issuer
                || claims.sub.is_empty()
                || claims.client_id.is_empty()
                || claims.jti.is_empty()
                || claims.token_use != "access"
                || !claims.aud.valid_for(&self.api_audience, resource)
                || claims.iat > now
                || claims.exp <= claims.iat
                || claims.nbf.is_some_and(|nbf| nbf > now)
            {
                return Err(BrokerAccessError::InvalidToken);
            }
            if claims.exp <= now {
                return Err(BrokerAccessError::Expired);
            }
            let expires_at = UNIX_EPOCH
                .checked_add(Duration::from_secs(claims.exp))
                .ok_or(BrokerAccessError::InvalidToken)?;
            let remaining = expires_at
                .duration_since(anchor_utc)
                .map_err(|_| BrokerAccessError::Expired)?;
            let expires_mono = anchor_mono
                .checked_add(remaining)
                .ok_or(BrokerAccessError::InvalidToken)?;
            let scopes: Vec<String> = claims
                .scope
                .split(' ')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            if !required_scopes
                .iter()
                .all(|required| scopes.iter().any(|s| s == required))
            {
                return Err(BrokerAccessError::InsufficientScope);
            }
            let result = VerifiedBrokerAccess {
                verifier: self,
                subject: claims.sub,
                client_id: claims.client_id,
                jti: claims.jti,
                audience: claims.aud,
                username: claims.preferred_username.filter(|s| !s.is_empty()),
                organization: claims.organization,
                teams: claims.groups,
                scopes,
                expires_at,
                expires_mono,
                original,
            };
            result.check()?;
            Ok(result)
        })();
        // A rejected token cannot extend the captured request deadline either.
        check_deadline(original)?;
        outcome
    }
    fn trusted_key(&self, raw: &str) -> Result<&DecodingKey, BrokerAccessError> {
        if raw.is_empty() || raw.len() > self.token_bytes.get() {
            return Err(BrokerAccessError::InvalidToken);
        }
        let mut parts = raw.split('.');
        let encoded_header = parts
            .next()
            .filter(|p| !p.is_empty())
            .ok_or(BrokerAccessError::InvalidToken)?;
        if parts.next().is_none_or(str::is_empty)
            || parts.next().is_none_or(str::is_empty)
            || parts.next().is_some()
        {
            return Err(BrokerAccessError::InvalidToken);
        }
        let header_bytes = URL_SAFE_NO_PAD
            .decode(encoded_header)
            .map_err(|_| BrokerAccessError::InvalidToken)?;
        let UniqueRoot(header): UniqueRoot<HashMap<String, serde_json::Value>> =
            serde_json::from_slice(&header_bytes).map_err(|_| BrokerAccessError::InvalidToken)?;
        if header.get("alg").and_then(serde_json::Value::as_str) != Some("EdDSA")
            || ["crit", "b64", "jku", "x5u", "jwk", "x5c"]
                .iter()
                .any(|name| header.contains_key(*name))
        {
            return Err(BrokerAccessError::InvalidToken);
        }
        let kid = header
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .filter(|v| !v.is_empty())
            .ok_or(BrokerAccessError::InvalidToken)?;
        let key = self.keys.get(kid).ok_or(BrokerAccessError::InvalidToken)?;

        Ok(key)
    }

    /// A signed ID hint authorizes disposal only, including after ID expiry.
    pub(crate) fn verify_end_session_hint(
        &self,
        raw: &str,
        original: Instant,
    ) -> Result<VerifiedEndSessionHint, crate::OidcTokenExchangeError> {
        use crate::OidcTokenExchangeError as Error;
        crate::oidc_authorization::guard_original(original)?;
        let outcome = (|| {
            let key = self.trusted_key(raw).map_err(|_| Error::InvalidRequest)?;
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.leeway = 0;
            validation.reject_tokens_expiring_in_less_than = 0;
            // Keep exp mandatory and typed; only its elapsed-time check differs.
            validation.validate_exp = false;
            validation.validate_nbf = true;
            validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
            validation.set_issuer(&[&self.issuer]);
            validation.set_audience(&[&self.api_audience]);
            let UniqueRoot(claims) = decode::<UniqueRoot<EndSessionClaims>>(raw, key, &validation)
                .map_err(|_| Error::InvalidRequest)?
                .claims;
            let now = u64::try_from(crate::flow::now_micros()? / 1_000_000)
                .map_err(|_| crate::ControlError::Clock)?;
            let mut audience = HashSet::new();
            let hash = |v: &str| {
                URL_SAFE_NO_PAD
                    .decode(v)
                    .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == v)
            };
            let date = |value| {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(value))
                    .is_some_and(|value| {
                        broker_store::time::TimestampMicros::try_from(value).is_ok()
                    })
            };
            if claims.iss != self.issuer
                || broker_security::validate_local_auth_challenge(&claims.sub).is_err()
                || crate::oidc_authorization::OidcClientId::parse(&claims.client_id).is_none()
                || claims.azp != claims.client_id
                || claims.aud.is_empty()
                || claims.aud.len() > 3
                || !claims
                    .aud
                    .iter()
                    .all(|v| !v.trim().is_empty() && audience.insert(v.as_str()))
                || !audience.contains(self.api_audience.as_str())
                || !audience.contains(claims.client_id.as_str())
                || claims.iat > now
                || claims.auth_time == 0
                || claims.auth_time > claims.iat
                || claims.exp <= claims.iat
                || claims.nbf.is_some_and(|v| v > now)
                || [claims.iat, claims.exp, claims.auth_time]
                    .into_iter()
                    .any(|v| !date(v))
                || claims.nbf.is_some_and(|v| !date(v))
                || claims.amr.is_empty()
                || claims.amr.iter().any(|v| v.trim().is_empty())
                || !hash(&claims.at_hash)
                || claims.c_hash.as_ref().is_some_and(|v| !hash(v))
                || claims.nonce.as_ref().is_some_and(String::is_empty)
            {
                return Err(Error::InvalidRequest);
            }
            let proof = VerifiedEndSessionHint {
                subject: claims.sub,
                client_id: claims.client_id,
                issued_at: claims.iat,
                auth_time: claims.auth_time,
                nbf: claims.nbf,
                original,
            };
            proof.check()?;
            Ok(proof)
        })();
        crate::oidc_authorization::guard_original(original)?;
        outcome
    }
}

/// An authenticated signed identity, never a PROJECT/Records grant.
/// No bearer, private key or original upstream identity is retained.
/// ~~~compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<broker_control::VerifiedBrokerAccess<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<broker_control::VerifiedBrokerAccess<'static>>();
/// ~~~
/// ~~~compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<broker_control::VerifiedBrokerAccess<'static>>();
/// ~~~
pub struct VerifiedBrokerAccess<'a> {
    verifier: &'a BrokerAccessVerifier,
    subject: String,
    client_id: String,
    jti: String,
    audience: Audience,
    username: Option<String>,
    organization: Option<String>,
    teams: Vec<String>,
    scopes: Vec<String>,
    expires_at: SystemTime,
    expires_mono: Instant,
    original: Instant,
}
impl fmt::Debug for VerifiedBrokerAccess<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedBrokerAccess([REDACTED])")
    }
}
impl VerifiedBrokerAccess<'_> {
    pub(crate) fn matches_oidc_resource(&self, resource: &str) -> bool {
        let api = self.verifier.api_audience.as_str();
        let expected = if resource.is_empty() || resource == api {
            1
        } else {
            2
        };
        match &self.audience {
            Audience::One(value) => expected == 1 && value == api,
            Audience::Many(values) => {
                values.len() == expected
                    && values.iter().any(|v| v == api)
                    && (expected == 1 || values.iter().any(|v| v == resource))
            }
        }
    }
    pub(crate) fn jti(&self) -> &str {
        &self.jti
    }
    pub(crate) fn owned_by(&self, verifier: &BrokerAccessVerifier) -> bool {
        std::ptr::eq(self.verifier, verifier)
    }
    pub fn issuer(&self) -> &str {
        &self.verifier.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    pub fn organization(&self) -> Option<&str> {
        self.organization.as_deref()
    }
    pub fn teams(&self) -> &[String] {
        &self.teams
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    /// Original UTC/monotonic authentication expiry, captured by this verifier.
    /// Consumers can bound transport waits without reanchoring UTC or renewing
    /// authentication. Keep checking the proof and the operation's Original.
    /// ~~~
    /// fn expiry(proof: &broker_control::VerifiedBrokerAccess<'_>)
    ///     -> (std::time::SystemTime, std::time::Instant) {
    ///     proof.authentication_expiry()
    /// }
    /// ~~~
    pub fn authentication_expiry(&self) -> (SystemTime, Instant) {
        (self.expires_at, self.expires_mono)
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
    pub fn check(&self) -> Result<(), BrokerAccessError> {
        check_deadline(self.original)?;
        if SystemTime::now() >= self.expires_at || Instant::now() >= self.expires_mono {
            return Err(BrokerAccessError::Expired);
        }
        Ok(())
    }
}
fn check_deadline(deadline: Instant) -> Result<(), BrokerAccessError> {
    if Instant::now() >= deadline {
        Err(BrokerAccessError::Deadline)
    } else {
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn valid_for(&self, api: &str, resource: Option<&str>) -> bool {
        match self {
            Self::One(value) => {
                !value.is_empty() && value == api && resource.is_none_or(|r| value == r)
            }
            Self::Many(values) => {
                let mut seen = HashSet::new();
                !values.is_empty()
                    && values
                        .iter()
                        .all(|v| !v.is_empty() && seen.insert(v.as_str()))
                    && seen.contains(api)
                    && resource.is_none_or(|r| seen.contains(r))
            }
        }
    }
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    iat: u64,
    exp: u64,
    token_use: String,
    client_id: String,
    jti: String,
    scope: String,
    #[serde(default, deserialize_with = "numeric_date")]
    nbf: Option<u64>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
}
fn numeric_date<'de, D: de::Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    u64::deserialize(deserializer).map(Some)
}

// Delegate JSON parsing and field decoding to Serde, while forbidding positional
// objects and duplicate root fields, including ignored extension claims.
pub(crate) struct UniqueRoot<T>(pub(crate) T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for UniqueRoot<T> {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RootVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for RootVisitor<T> {
            type Value = UniqueRoot<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JWT JSON object")
            }
            fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(UniqueMap {
                    map,
                    seen: HashSet::new(),
                }))
                .map(UniqueRoot)
            }
        }
        deserializer.deserialize_map(RootVisitor(PhantomData))
    }
}
struct UniqueMap<M> {
    map: M,
    seen: HashSet<String>,
}
impl<'de, M: MapAccess<'de>> MapAccess<'de> for UniqueMap<M> {
    type Error = M::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        let Some(key) = self.map.next_key::<String>()? else {
            return Ok(None);
        };
        if !self.seen.insert(key.clone()) {
            return Err(de::Error::custom("duplicate JWT field"));
        }
        seed.deserialize(de::value::StringDeserializer::<M::Error>::new(key))
            .map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        self.map.next_value_seed(seed)
    }
}

/// Private disposal authority, never access authentication or a PROJECT grant.
pub(crate) struct VerifiedEndSessionHint {
    subject: String,
    client_id: String,
    issued_at: u64,
    auth_time: u64,
    nbf: Option<u64>,
    original: Instant,
}
impl VerifiedEndSessionHint {
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }
    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }
    pub(crate) fn check(&self) -> Result<(), crate::OidcTokenExchangeError> {
        crate::oidc_authorization::guard_original(self.original)?;
        let now = u64::try_from(crate::flow::now_micros()? / 1_000_000)
            .map_err(|_| crate::ControlError::Clock)?;
        if now < self.issued_at || now < self.auth_time || self.nbf.is_some_and(|v| v > now) {
            return Err(crate::ControlError::Clock.into());
        }
        Ok(())
    }
}
#[derive(Deserialize)]
struct EndSessionClaims {
    iss: String,
    sub: String,
    aud: Vec<String>,
    iat: u64,
    exp: u64,
    auth_time: u64,
    amr: Vec<String>,
    azp: String,
    client_id: String,
    at_hash: String,
    #[serde(default, deserialize_with = "hint_string")]
    c_hash: Option<String>,
    #[serde(default, deserialize_with = "hint_string")]
    nonce: Option<String>,
    #[serde(default, deserialize_with = "numeric_date")]
    nbf: Option<u64>,
    #[serde(
        default,
        rename = "token_use",
        deserialize_with = "forbidden_access_claim"
    )]
    _token_use: (),
    #[serde(default, rename = "jti", deserialize_with = "forbidden_access_claim")]
    _jti: (),
    #[serde(default, rename = "scope", deserialize_with = "forbidden_access_claim")]
    _scope: (),
    #[serde(
        default,
        rename = "preferred_username",
        deserialize_with = "hint_string"
    )]
    _preferred_username: Option<String>,
    #[serde(default, rename = "name", deserialize_with = "hint_string")]
    _name: Option<String>,
    #[serde(default, rename = "email", deserialize_with = "hint_string")]
    _email: Option<String>,
    #[serde(default, rename = "organization", deserialize_with = "hint_string")]
    _organization: Option<String>,
    #[serde(default, rename = "groups")]
    _groups: Vec<String>,
    #[serde(default, rename = "roles")]
    _roles: Vec<String>,
}
fn hint_string<'de, D: de::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn forbidden_access_claim<'de, D: de::Deserializer<'de>>(_: D) -> Result<(), D::Error> {
    Err(de::Error::custom("access claim is not an ID hint"))
}
