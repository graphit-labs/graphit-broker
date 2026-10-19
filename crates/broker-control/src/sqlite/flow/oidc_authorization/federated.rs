//! Complete only the pending request carried by genuine H1 evidence.
use super::*;
use crate::{
    AuthorizedOidcAuthorization, FlowContinuation, UpstreamBearerVerifier, VerifiedUpstreamLogin,
    service::{oidc_authorization::completion::AuthorizedPayload, oidc_principal::OidcPrincipal},
};
fn proof_error(error: ControlError) -> Error {
    match error {
        ControlError::InvalidFlow | ControlError::Expired => Error::InvalidLogin,
        other => Error::Control(other),
    }
}
impl SqliteOidcAuthorizationService<'_> {
    pub async fn complete_upstream(
        &self,
        login: VerifiedUpstreamLogin,
        verifier: Arc<UpstreamBearerVerifier>,
        original: Instant,
    ) -> Result<AuthorizedOidcAuthorization, Error> {
        // Apply the protected H1 cutoff to the actual worker wait, before SQL starts.
        let end = self
            .store
            .executor
            .deadline(original.min(login.original()))
            .map_err(ControlError::from)?;
        login.check(&verifier).map_err(proof_error)?;
        let raw = match login.continuation() {
            FlowContinuation::OAuth { request_id, .. } => request_id.as_str(),
            FlowContinuation::Admin { .. } => return Err(Error::InvalidLogin),
        };
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidRequest)?;
        let hash = self
            .store
            .digester
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let policy = Arc::clone(&self.policy);
        let digester = Arc::clone(&self.store.digester);
        let (authorized,login)=self.store.executor.execute(end,move|state,work|Ok((||{
            login.check(&verifier).map_err(proof_error)?;
            let tx=state.begin(work).map_err(ControlError::from)?;
            let current=tx.query_row(REQUEST,params![hash,policy.limits.json_bytes],|row|Ok(decode_request(row,policy.limits.json_bytes))).optional().map_err(|e|ControlError::from(work.sql(e)))?.ok_or(Error::InvalidRequest)??;
            if current.completed() {return Err(Error::InvalidRequest);}
            final_gate(end,current.expires_at)?;
            if current.hash!=hash||current.created_at<=0||current.created_at>now_micros()?||current.expires_at.checked_sub(current.created_at)!=Some(policy.ttl_micros) {return Err(Error::MalformedStored);}
            let mut fields=parse_pending(current.json.as_deref().ok_or(Error::MalformedStored)?)?;
            let client=current_client(&tx,work,&policy,&fields.client_id,end)?;
            policy.revalidate(&fields,&client,end)?;
            let principal=OidcPrincipal::from_upstream(&login,&verifier).map_err(proof_error)?;
            if !principal.current_trust(Some(&verifier)) {return Err(Error::InvalidLogin);}
            let subject=digester.oidc_subject(principal.issuer().as_bytes(),principal.subject().as_bytes()).map_err(|_|Error::Credential)?;
            let code=new_local_auth_challenge().map_err(|_|Error::Random)?;
            let code_hash=digester.token(TokenKind::OidcAuthorizationCode,code.as_bytes()).map_err(|_|Error::Credential)?.to_sql_hex();
            let amr=vec!["federated"];
            let auth_time=now_micros()?;
            if auth_time<=0||auth_time<current.created_at {return Err(ControlError::Clock.into());}
            fields.phase="authorized".into();
            let json=Zeroizing::new(serde_json::to_string(&AuthorizedPayload {request:&fields,principal:&principal,oidc_subject:subject.as_str(),amr:&amr,auth_time}).map_err(|_|Error::MalformedStored)?);
            if i64::try_from(json.len()).map_err(|_|Error::ReadLimitExceeded)?>policy.limits.json_bytes {return Err(Error::ReadLimitExceeded);}
            final_gate(end,current.expires_at)?;login.check(&verifier).map_err(proof_error)?;
            let count=tx.execute("UPDATE oidc_auth_requests SET identity_subject=?1,request_json=?2,code_hash=?3 WHERE request_hash=?4 AND identity_subject='' AND code_hash IS NULL AND request_json=?5 AND created_at=?6 AND expires_at=?7 AND expires_at>?8",params![principal.subject(),&*json,code_hash,hash,current.json.as_deref().ok_or(Error::MalformedStored)?,current.created_at,current.expires_at,now_micros()?]).map_err(|e|ControlError::from(work.sql(e)))?;
            if count!=1 {return Err(Error::InvalidRequest);}
            final_gate(end,current.expires_at)?;login.check(&verifier).map_err(proof_error)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok::<_,Error>((AuthorizedOidcAuthorization {code,info:OidcAuthorizationRequestInfo {fields,created_at:current.created_at,expires_at:current.expires_at},subject,amr,auth_time:broker_store::time::TimestampMicros::new(auth_time).map_err(|_|ControlError::Clock)?},(login,verifier)))
        })())).await.map_err(ControlError::from)??;
        final_gate(end, authorized.info.expires_at)?;
        login.0.check(&login.1).map_err(proof_error)?;
        Ok(authorized)
    }
}
