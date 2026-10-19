use super::completion::AuthorizedPayload;
use super::*;
use crate::{
    AuthorizedOidcAuthorization, FlowContinuation, UpstreamBearerVerifier, VerifiedUpstreamLogin,
    service::oidc_principal::OidcPrincipal,
};

fn proof_error(e: ControlError) -> Error {
    match e {
        ControlError::InvalidFlow | ControlError::Expired => Error::InvalidLogin,
        other => Error::Control(other),
    }
}
impl PostgresOidcAuthorizationService<'_> {
    /// Consume genuine upstream OAuth evidence for its protected pending request.
    /// Administrative evidence and DATA profiles cannot complete this operation.
    pub async fn complete_upstream(
        &self,
        login: VerifiedUpstreamLogin,
        verifier: &UpstreamBearerVerifier,
        original: Instant,
    ) -> Result<AuthorizedOidcAuthorization, Error> {
        let deadline = bounded_deadline(
            original.min(login.original()),
            self.store.budgets.operation_timeout,
        )?;
        login.check(verifier).map_err(proof_error)?;
        let raw = match login.continuation() {
            FlowContinuation::OAuth { request_id, .. } => request_id.as_str(),
            FlowContinuation::Admin { .. } => return Err(Error::InvalidLogin),
        };
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidRequest)?;
        let principal = OidcPrincipal::from_upstream(&login, verifier).map_err(proof_error)?;
        let hash = self
            .digester
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        guard_original(deadline)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED")
                .await.map_err(storage_error)?;
            let row = sqlx_core::query::query(REQUEST).bind(&hash).bind(self.policy.limits.json_bytes)
                .fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidRequest)?;
            let initial = decode_request(&row, self.policy.limits.json_bytes)?;
            if initial.completed() { return Err(Error::InvalidRequest); }
            final_gate(deadline, initial.expires_at)?;
            if initial.hash != hash || initial.created_at <= 0 || initial.created_at > now_micros()?
                || initial.expires_at.checked_sub(initial.created_at) != Some(self.policy.ttl_micros) { return Err(Error::MalformedStored); }
            let mut fields = parse_pending(initial.json.as_deref().ok_or(Error::MalformedStored)?)?;
            // No fabricated LOCAL row: the authenticated issuer is the federated authority.
            let client = self.client(&mut tx, &fields.client_id, deadline).await?;
            let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("{REQUEST} FOR UPDATE")))
                .bind(&hash).bind(self.policy.limits.json_bytes).fetch_optional(&mut *tx)
                .await.map_err(storage_error)?.ok_or(Error::InvalidRequest)?;
            let current = decode_request(&row, self.policy.limits.json_bytes)?;
            if current.completed() { return Err(Error::InvalidRequest); }
            final_gate(deadline, current.expires_at)?;
            if current != initial { return Err(Error::MalformedStored); }
            self.policy.revalidate(&fields, &client, deadline)?;
            login.check(verifier).map_err(proof_error)?;
            if !principal.current_trust(Some(verifier)) { return Err(Error::InvalidLogin); }
            let subject = self.digester.oidc_subject(principal.issuer().as_bytes(), principal.subject().as_bytes())
                .map_err(|_| Error::Credential)?;
            let code = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let code_hash = self.digester.token(TokenKind::OidcAuthorizationCode, code.as_bytes())
                .map_err(|_| Error::Credential)?.to_sql_hex();
            let amr = vec!["federated"];
            let auth_time = now_micros()?;
            if auth_time <= 0 || auth_time < current.created_at { return Err(ControlError::Clock.into()); }
            fields.phase = "authorized".into();
            let json = Zeroizing::new(serde_json::to_string(&AuthorizedPayload {
                request: &fields, principal: &principal, oidc_subject: subject.as_str(), amr: &amr, auth_time,
            }).map_err(|_| Error::MalformedStored)?);
            if i64::try_from(json.len()).map_err(|_| Error::ReadLimitExceeded)? > self.policy.limits.json_bytes { return Err(Error::ReadLimitExceeded); }
            final_gate(deadline, current.expires_at)?;
            login.check(verifier).map_err(proof_error)?;
            let count = sqlx_core::query::query("UPDATE public.oidc_auth_requests SET identity_subject=$1,request_json=$2,code_hash=$3 WHERE request_hash=$4 AND identity_subject='' AND code_hash IS NULL AND request_json=$5 AND created_at=$6 AND expires_at=$7 AND expires_at>$8")
                .bind(principal.subject()).bind(&*json).bind(&code_hash).bind(&hash)
                .bind(initial.json.as_deref().ok_or(Error::MalformedStored)?).bind(initial.created_at)
                .bind(initial.expires_at).bind(now_micros()?).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if count != 1 { return Err(Error::InvalidRequest); }
            final_gate(deadline, current.expires_at)?;
            login.check(verifier).map_err(proof_error)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            final_gate(deadline, current.expires_at)?;
            login.check(verifier).map_err(proof_error)?;
            Ok(AuthorizedOidcAuthorization {
                code, info: OidcAuthorizationRequestInfo { fields, created_at: current.created_at, expires_at: current.expires_at },
                subject, amr, auth_time: broker_store::time::TimestampMicros::new(auth_time).map_err(|_| ControlError::Clock)?,
            })
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}
