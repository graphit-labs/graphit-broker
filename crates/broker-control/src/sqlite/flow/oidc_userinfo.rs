use super::{
    SqliteControlStore,
    oidc_access_snapshot::{COLUMNS, decode, sql},
    oidc_authorization::completion::current_principal,
};
use crate::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcTokenExchangeError,
    OidcUserInfo, OidcUserInfoError as Error, UpstreamBearerVerifier,
    service::oidc_access_snapshot::{bearer_error, token_hash},
};
use rusqlite::{OptionalExtension, params};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// A borrowed profile operation retaining the actual verifier and trust owners.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     policy: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>)
///     -> broker_control::SqliteOidcUserInfo<'static> {
///     store.oidc_userinfo(policy, verifier).unwrap()
/// }
/// ```
pub struct SqliteOidcUserInfo<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    verifier: Arc<BrokerAccessVerifier>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
}
impl fmt::Debug for SqliteOidcUserInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcUserInfo([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_userinfo(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        verifier: Arc<BrokerAccessVerifier>,
    ) -> Result<SqliteOidcUserInfo<'_>, Error> {
        if authorization.api_audience != verifier.api_audience() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(SqliteOidcUserInfo {
            store: self,
            authorization,
            verifier,
            upstream: None,
        })
    }
}
impl SqliteOidcUserInfo<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    pub fn with_upstream(mut self, verifier: Arc<UpstreamBearerVerifier>) -> Self {
        self.upstream = Some(verifier);
        self
    }
    pub async fn profile(&self, raw: &str, original: Instant) -> Result<OidcUserInfo, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        // Verify and apply the independent JWT byte cap before an owned copy.
        self.verifier
            .verify_for_oidc_operation(raw, end)
            .map_err(bearer_error)?;
        let raw = Zeroizing::new(raw.to_owned());
        let worker_raw = raw.clone();
        let verifier = Arc::clone(&self.verifier);
        let authorization = Arc::clone(&self.authorization);
        let upstream = self.upstream.clone();
        let digester = Arc::clone(&self.store.digester);
        let result = self.store.executor.execute(end, move |owner, work| Ok((|| {
            let proof = verifier.verify_for_oidc_operation(&worker_raw, end).map_err(bearer_error)?;
            let hash = token_hash(&digester, &proof)?;
            let tx = owner.begin(work).map_err(ControlError::from)?;
            let cap = authorization.limits.json_bytes;
            let query = format!("SELECT {COLUMNS} FROM local_tokens WHERE token_kind='oidc_access' AND token_hash=?1");
            let (stored, revoked) = tx.query_row(&query, params![hash, cap], |row| Ok(decode(row, cap)))
                .optional().map_err(|e| sql(e, work))?.ok_or(Error::InvalidToken)??;
            stored.matches(&proof, revoked, &authorization)?;
            let observed = stored.principal(&digester)?;
            // IMMEDIATE prevents an intervening identity/token writer until known COMMIT.
            let principal = if let Some(local) = observed.as_local() {
                current_principal(&tx, work, &local.subject, &local.username,
                    local.local_user_revision, cap, end).map_err(|error| principal_error(error.into()))?
            } else {
                if !observed.current_trust(upstream.as_deref()) { return Err(Error::InvalidToken); }
                observed
            };
            if !principal.current_trust(upstream.as_deref()) { return Err(Error::InvalidToken); }
            let optional = |value: &str| (!value.is_empty()).then(|| value.to_owned());
            let result = OidcUserInfo {
                sub: stored.oidc_subject,
                preferred_username: optional(principal.username()),
                name: optional(principal.name()), email: optional(principal.email()),
                organization: optional(principal.organization()), groups: principal.teams().to_vec(),
                roles: principal.roles().to_vec(),
            };
            proof.check().map_err(bearer_error)?;
            let changed = tx.execute("UPDATE local_tokens SET last_used_at=?1 WHERE token_hash=?2 AND token_kind='oidc_access' AND revoked_at IS NULL",
                params![crate::flow::now_micros()?, hash]).map_err(|e| sql(e, work))?;
            if changed != 1 { return Err(ControlError::Storage.into()); }
            proof.check().map_err(bearer_error)?;
            work.commit(tx).map_err(ControlError::from)?;
            proof.check().map_err(bearer_error)?;
            Ok::<_, Error>(result)
        })())).await.map_err(ControlError::from)??;
        self.verifier
            .verify_for_oidc_operation(&raw, end)
            .map_err(bearer_error)?;
        Ok(result)
    }
}
fn principal_error(error: OidcTokenExchangeError) -> Error {
    match error {
        OidcTokenExchangeError::InvalidGrant => Error::InvalidToken,
        OidcTokenExchangeError::Control(error) => error.into(),
        OidcTokenExchangeError::ReadLimitExceeded => Error::ReadLimitExceeded,
        _ => Error::MalformedStored,
    }
}
