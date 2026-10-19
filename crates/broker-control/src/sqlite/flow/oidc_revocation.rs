use super::{
    SqliteControlStore,
    oidc_access_snapshot::{COLUMNS, bounded, decode, exchange_error, sql},
    oidc_authorization::current_client,
};
use crate::{
    BrokerAccessError, BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy,
    OidcRevocationInput, OidcTokenExchangeError as Error,
    flow::now_micros,
    oidc_authorization::{OidcClientId, guard_original},
    service::oidc_access_snapshot::token_hash,
};
use broker_security::{TokenKind, validate_local_auth_challenge};
use rusqlite::{OptionalExtension, params};
use std::{
    fmt,
    sync::Arc,
    time::{Instant, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// Explicit disposal, independent of current LOCAL identity and upstream trust.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     policy: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>)
///     -> broker_control::SqliteOidcRevocation<'static> {
///     store.oidc_revocation(policy, verifier).unwrap()
/// }
/// ```
pub struct SqliteOidcRevocation<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    verifier: Arc<BrokerAccessVerifier>,
}
impl fmt::Debug for SqliteOidcRevocation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcRevocation([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_revocation(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        verifier: Arc<BrokerAccessVerifier>,
    ) -> Result<SqliteOidcRevocation<'_>, Error> {
        if authorization.api_audience != verifier.api_audience() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(SqliteOidcRevocation {
            store: self,
            authorization,
            verifier,
        })
    }
}
impl SqliteOidcRevocation<'_> {
    pub async fn revoke(
        &self,
        input: OidcRevocationInput<'_>,
        original: Instant,
    ) -> Result<(), Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        if input.authorization.is_some() {
            return Err(Error::InvalidClient);
        }
        let bytes = [input.token, input.client_id, input.token_type_hint]
            .into_iter()
            .flatten()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .ok_or(Error::InvalidRequest)?;
        if bytes > self.authorization.limits.parameter_bytes() {
            return Err(Error::InvalidRequest);
        }
        let raw = input
            .token
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        let client = input
            .client_id
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidRequest)?;
        if OidcClientId::parse(client).is_none() {
            return Err(Error::InvalidRequest);
        }
        let raw = Zeroizing::new(raw.to_owned());
        let client = client.to_owned();
        let policy = Arc::clone(&self.authorization);
        let verifier = Arc::clone(&self.verifier);
        let digester = Arc::clone(&self.store.digester);
        self.store.executor.execute(end,move|owner,work|Ok((|| -> Result<(),Error> {
            let refresh=raw.strip_prefix("gb_rt_").filter(|v|validate_local_auth_challenge(v).is_ok())
                .map(|_|digester.token(TokenKind::LocalRefresh,raw.as_bytes()).map(|d|d.to_sql_hex()).map_err(|_|Error::Credential)).transpose()?;
            let access=if refresh.is_none() { match verifier.verify_for_revocation(&raw,end) {
                Ok(proof)=>Some(proof),Err(BrokerAccessError::Deadline)=>return Err(ControlError::Deadline.into()),Err(_)=>None,
            }} else { None };
            let tx=owner.begin(work).map_err(ControlError::from)?;
            current_client(&tx,work,&policy,&client,end)?;
            let cap=policy.limits.json_bytes;
            if let Some(hash)=refresh {
                let query=format!("SELECT {COLUMNS}, CASE WHEN typeof(family_id)='text' THEN length(CAST(family_id AS BLOB)) END AS family_bytes, CASE WHEN typeof(family_id)='text' AND length(CAST(family_id AS BLOB))<=?2 THEN family_id END AS family_id FROM local_tokens WHERE token_hash=?1 AND token_kind='refresh'");
                let row=tx.query_row(&query,params![hash,cap],|row|Ok((||{
                    let (stored,revoked)=decode(row,cap)?;
                    let family=bounded(row,"family_bytes","family_id",cap)?;
                    Ok((stored,revoked,family))
                })())).optional().map_err(|e|exchange_error(sql(e,work)))?.transpose().map_err(exchange_error)?;
                if let Some((stored,revoked,family))=row.filter(|(s,_,_)|s.client==client) {
                    for value in [&stored.id,&stored.oidc_subject,&family] { validate_local_auth_challenge(value).map_err(|_|Error::MalformedStored)?; }
                    stored.principal(&digester).map_err(|e|match exchange_error(e) { Error::InvalidGrant=>Error::MalformedStored,e=>e })?;
                    let now=now_micros()?;
                    if now<stored.created { return Err(ControlError::Clock.into()); }
                    if revoked.is_some_and(|v|v>now) { return Err(Error::MalformedStored); }
                    if stored.audience==policy.api_audience && stored.expiry>now && revoked.is_none() {
                        guard_original(end)?;
                        let count=tx.execute("UPDATE local_tokens SET revoked_at=?1 WHERE family_id=?2 AND client_id=?3 AND audience=?4 AND revoked_at IS NULL",params![now,family,client,policy.api_audience]).map_err(|e|ControlError::from(work.sql(e)))?;
                        if count==0 { return Err(ControlError::Storage.into()); }
                    }
                }
            } else if let Some(proof)=access.as_ref().filter(|p|p.client_id()==client) {
                match proof.check() {
                    Ok(())=>{
                        if validate_local_auth_challenge(proof.jti()).is_ok() {
                            let expiry=proof.expires_at().duration_since(UNIX_EPOCH).ok().and_then(|v|i64::try_from(v.as_secs()).ok()).and_then(|v|v.checked_mul(1_000_000));
                            if let Some(expiry)=expiry {
                                let hash=token_hash(&digester,proof).map_err(exchange_error)?;
                                tx.execute("UPDATE local_tokens SET revoked_at=?1 WHERE token_hash=?2 AND token_kind='oidc_access' AND token_id=?3 AND client_id=?4 AND oidc_subject=?5 AND expires_at=?6 AND audience=?7 AND expires_at>?1 AND revoked_at IS NULL",params![now_micros()?,hash,proof.jti(),client,proof.subject(),expiry,policy.api_audience]).map_err(|e|ControlError::from(work.sql(e)))?;
                            }
                        }
                    },Err(BrokerAccessError::Deadline)=>return Err(ControlError::Deadline.into()),Err(_)=>{},
                }
            }
            guard_original(end)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok(())
        })())).await.map_err(ControlError::from)??;
        guard_original(end)?;
        Ok(())
    }
}
