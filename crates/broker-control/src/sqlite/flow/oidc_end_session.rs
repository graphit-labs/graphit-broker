use super::{
    SqliteControlStore,
    oidc_access_snapshot::{bounded, exchange_error, number, sql},
};
use crate::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcEndSessionInput,
    OidcTokenExchangeError as Error, flow::now_micros, oidc_authorization::guard_original,
    service::oidc_principal::OidcPrincipal,
};
use rusqlite::{OptionalExtension, params};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// Disposes all SQL OIDC grants of the signed pair, retaining JWT local validity.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     policy: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>)
///     -> broker_control::SqliteOidcEndSession<'static> {
///     store.oidc_end_session(policy, verifier).unwrap()
/// }
/// ```
pub struct SqliteOidcEndSession<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    verifier: Arc<BrokerAccessVerifier>,
}
impl fmt::Debug for SqliteOidcEndSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcEndSession([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_end_session(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        verifier: Arc<BrokerAccessVerifier>,
    ) -> Result<SqliteOidcEndSession<'_>, Error> {
        if authorization.api_audience != verifier.api_audience() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(SqliteOidcEndSession {
            store: self,
            authorization,
            verifier,
        })
    }
}
impl SqliteOidcEndSession<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    pub async fn end_session(
        &self,
        input: OidcEndSessionInput<'_>,
        original: Instant,
    ) -> Result<(), Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let bytes = input
            .id_token_hint
            .unwrap_or("")
            .len()
            .checked_add(input.client_id.unwrap_or("").len())
            .ok_or(Error::InvalidRequest)?;
        if bytes > self.parameter_bytes() {
            return Err(Error::InvalidRequest);
        }
        let raw = input
            .id_token_hint
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        let raw = Zeroizing::new(raw.to_owned());
        let saved = raw.clone();
        let client = input.client_id.map(str::to_owned);
        let policy = Arc::clone(&self.authorization);
        let verifier = Arc::clone(&self.verifier);
        let digester = Arc::clone(&self.store.digester);
        self.store.executor.execute(end,move|owner,work|Ok((|| -> Result<(),Error> {
            let proof=verifier.verify_end_session_hint(&raw,end)?;
            if client.as_ref().is_some_and(|v|v!=proof.client_id()) { return Err(Error::InvalidRequest); }
            let tx=owner.begin(work).map_err(ControlError::from)?;
            let cap=policy.limits.json_bytes;
            let query=r#"SELECT local_user_revision,created_at,
 CASE WHEN typeof(subject)='text' THEN length(CAST(subject AS BLOB)) END AS subject_bytes,
 CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=?4 THEN subject END AS subject,
 CASE WHEN typeof(principal_json)='text' THEN length(CAST(principal_json AS BLOB)) END AS principal_bytes,
 CASE WHEN typeof(principal_json)='text' AND length(CAST(principal_json AS BLOB))<=?4 THEN principal_json END AS principal_json
 FROM local_tokens WHERE oidc_subject=?1 AND client_id=?2 AND audience=?3 AND token_kind IN ('oidc_access','refresh') ORDER BY created_at DESC LIMIT 1"#;
            let newest=tx.query_row(query,params![proof.subject(),proof.client_id(),policy.api_audience,cap],|row|Ok((|| {
                Ok((bounded(row,"subject_bytes","subject",cap)?,Zeroizing::new(bounded(row,"principal_bytes","principal_json",cap)?),number(row,"local_user_revision")?,number(row,"created_at")?))
            })())).optional().map_err(|e|exchange_error(sql(e,work)))?.transpose().map_err(exchange_error)?;
            let mut created=0;
            if let Some((subject,json,revision,stamp))=newest {
                let principal=OidcPrincipal::parse(&json)?;
                if stamp<=0 || principal.subject()!=subject || principal.revision()!=revision { return Err(Error::MalformedStored); }
                if stamp>now_micros()? { return Err(ControlError::Clock.into()); }
                let pseud=digester.oidc_subject(principal.issuer().as_bytes(),subject.as_bytes()).map_err(|_|Error::Credential)?;
                if pseud.as_str()!=proof.subject() { return Err(Error::MalformedStored); }
                created=stamp;
            }
            proof.check()?;
            let now=now_micros()?;
            if now<created { return Err(ControlError::Clock.into()); }
            tx.execute("UPDATE local_tokens SET revoked_at=?1 WHERE oidc_subject=?2 AND client_id=?3 AND audience=?4 AND token_kind IN ('oidc_access','refresh') AND revoked_at IS NULL",params![now,proof.subject(),proof.client_id(),policy.api_audience]).map_err(|e|ControlError::from(work.sql(e)))?;
            proof.check()?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok(())
        })())).await.map_err(ControlError::from)??;
        guard_original(end)?;
        self.verifier
            .verify_end_session_hint(&saved, end)?
            .check()?;
        Ok(())
    }
}
