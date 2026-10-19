use super::{
    SqliteControlStore,
    oidc_access_snapshot::{COLUMNS, decode, sql},
};
use crate::{
    BrokerAccessVerifier, ControlError, OidcAuthorizationPolicy, OidcIntrospection,
    OidcIntrospectionError as Error,
    service::oidc_access_snapshot::{AccessGrant, AccessGrantError, bearer_error, token_hash},
};
use rusqlite::{OptionalExtension, params};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// Borrowed inspection retaining its real policy and verifier in the SQLite worker.
/// ```compile_fail
/// fn escape(store: &broker_control::SqliteControlStore,
///     policy: std::sync::Arc<broker_control::OidcAuthorizationPolicy>,
///     verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>)
///     -> broker_control::SqliteOidcIntrospection<'static> {
///     store.oidc_introspection(policy, verifier).unwrap()
/// }
/// ```
pub struct SqliteOidcIntrospection<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    verifier: Arc<BrokerAccessVerifier>,
}
impl fmt::Debug for SqliteOidcIntrospection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteOidcIntrospection([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn oidc_introspection(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        verifier: Arc<BrokerAccessVerifier>,
    ) -> Result<SqliteOidcIntrospection<'_>, Error> {
        if authorization.api_audience != verifier.api_audience() {
            return Err(Error::InvalidConfiguration);
        }
        Ok(SqliteOidcIntrospection {
            store: self,
            authorization,
            verifier,
        })
    }
}
impl SqliteOidcIntrospection<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    pub async fn introspect(
        &self,
        authority: &str,
        token: Option<&str>,
        original: Instant,
    ) -> Result<OidcIntrospection, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        // Verify the authority before copying it; the verifier applies its independent token cap.
        self.verifier
            .verify_for_oidc_operation(authority, end)
            .map_err(bearer_error)?;
        let authority = Zeroizing::new(authority.to_owned());
        // Classification applies the verifier's own byte cap before any owned copy.
        // Invalid targets remain inactive after the SQL authority is admitted.
        let target = match token.filter(|value| !value.is_empty()) {
            Some(raw) => match self
                .verifier
                .verify_for_oidc_operation(raw, end)
                .map_err(bearer_error)
            {
                Ok(_) => Some(Zeroizing::new(raw.to_owned())),
                Err(AccessGrantError::InvalidToken) => None,
                Err(error) => return Err(error.into()),
            },
            None => None,
        };
        let raw_authority = authority.clone();
        let raw_target = target.clone();
        let verifier = Arc::clone(&self.verifier);
        let policy = Arc::clone(&self.authorization);
        let digester = Arc::clone(&self.store.digester);
        let result=self.store.executor.execute(end,move|owner,work|Ok((|| -> Result<OidcIntrospection,Error> {
            let authority=verifier.verify_for_oidc_operation(&raw_authority,end).map_err(bearer_error)?;
            let authority_hash=token_hash(&digester,&authority)?;
            let target=match raw_target.as_deref().filter(|v|!v.is_empty()) {
                Some(raw)=>match verifier.verify_for_oidc_operation(raw,end) {
                    Ok(proof) if proof.client_id()==authority.client_id() && proof.subject()==authority.subject()=>match token_hash(&digester,&proof) {
                        Ok(hash)=>Some((proof,hash)),Err(AccessGrantError::InvalidToken)=>None,Err(e)=>return Err(e.into()) },
                    Ok(_)=>None,
                    Err(e)=>match bearer_error(e) { AccessGrantError::InvalidToken=>None,e=>return Err(e.into()) },
                },None=>None,
            };
            let tx=owner.begin(work).map_err(ControlError::from)?;
            let cap=policy.limits.json_bytes;
            let query=format!("SELECT {COLUMNS} FROM local_tokens WHERE token_kind='oidc_access' AND token_hash=?1");
            let load=|hash:&str|->Result<Option<(AccessGrant,Option<i64>)>,AccessGrantError> {
                tx.query_row(&query,params![hash,cap],|row|Ok(decode(row,cap))).optional().map_err(|e|sql(e,work))?.transpose()
            };
            // IMMEDIATE excludes intervening writers. Admit authority before decoding a different target.
            let (stored_authority,revoked_authority)=load(&authority_hash)?.ok_or(Error::InvalidAuthority)?;
            admit(&stored_authority,revoked_authority,&authority,&policy,&digester)?;
            let other=match target.as_ref() {Some((_,hash)) if hash!=&authority_hash=>load(hash)?,_=>None};
            let candidate=match target.as_ref() {
                Some((_,hash)) if hash==&authority_hash=>Some((&stored_authority,&revoked_authority)),
                _=>other.as_ref().map(|(s,r)|(s,r)),
            };
            let mut result=OidcIntrospection::inactive();
            if let (Some((proof,hash)),Some((stored,revoked)))=(target.as_ref(),candidate) {
                match admit(stored,*revoked,proof,&policy,&digester) {
                    Ok(())=>{
                        authority.check().map_err(bearer_error)?;
                        let changed=tx.execute("UPDATE local_tokens SET last_used_at=?1 WHERE token_hash=?2 AND token_kind='oidc_access' AND revoked_at IS NULL",params![crate::flow::now_micros()?,hash]).map_err(|e|sql(e,work))?;
                        if changed!=1 { return Err(ControlError::Storage.into()); }
                        authority.check().map_err(bearer_error)?;
                        match admit(stored,*revoked,proof,&policy,&digester) {
                            Ok(())=>{}, Err(AccessGrantError::InvalidToken)=>{
                                tx.rollback().map_err(|e|sql(e,work))?;
                                authority.check().map_err(bearer_error)?;
                                return Ok(OidcIntrospection::inactive());
                            },Err(e)=>return Err(e.into()),
                        }
                        result=OidcIntrospection::active(stored.client.clone(),&stored.scopes,stored.expiry);
                        work.commit(tx).map_err(ControlError::from)?;
                        return Ok(result);
                    },
                    Err(AccessGrantError::InvalidToken)=>{},Err(e)=>return Err(e.into()),
                }
            }
            authority.check().map_err(bearer_error)?;
            tx.rollback().map_err(|e|sql(e,work))?;
            work.check().map_err(ControlError::from)?;
            authority.check().map_err(bearer_error)?;
            Ok(result)
        })())).await.map_err(ControlError::from)??;
        self.verifier
            .verify_for_oidc_operation(&authority, end)
            .map_err(bearer_error)?;
        if let Some(raw) = target.as_deref().filter(|v| !v.is_empty()) {
            match self
                .verifier
                .verify_for_oidc_operation(raw, end)
                .map_err(bearer_error)
            {
                Ok(_) => {}
                Err(AccessGrantError::InvalidToken) => return Ok(OidcIntrospection::inactive()),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(result)
    }
}
fn admit(
    stored: &AccessGrant,
    revoked: Option<i64>,
    proof: &crate::VerifiedBrokerAccess<'_>,
    policy: &OidcAuthorizationPolicy,
    digester: &broker_security::CredentialDigester,
) -> Result<(), AccessGrantError> {
    stored.matches(proof, revoked, policy)?;
    stored.principal(digester)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn minimal_active_result_omits_empty_scope_and_profile() {
        let result = crate::OidcIntrospection::active("client".into(), &[], 2_000_000_000_000_000);
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            serde_json::json!({"active":true,"client_id":"client","exp":2_000_000_000})
        );
    }
}
