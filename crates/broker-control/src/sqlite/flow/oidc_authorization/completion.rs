use super::*;
use crate::{
    AuthorizedOidcAuthorization, PreparedOidcLogin,
    identity::{safe_identity_segment, valid_identity_subject},
    service::{
        oidc_authorization::completion::AuthorizedPayload,
        oidc_principal::{LocalPrincipal, OidcPrincipal},
    },
};
use broker_security::LocalAuthBinding;
use std::collections::HashSet;

impl SqliteOidcAuthorizationService<'_> {
    /// Complete the exact request with a genuine, prepared LOCAL login.
    pub async fn complete(
        &self,
        raw: &str,
        login: PreparedOidcLogin,
        original: Instant,
    ) -> Result<AuthorizedOidcAuthorization, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidRequest)?;
        let PreparedOidcLogin { login } = login;
        login
            .verify_binding(
                &self.store.digester,
                LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
            )
            .map_err(|_| Error::InvalidLogin)?;
        let hash = self
            .store
            .digester
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        let policy = Arc::clone(&self.policy);
        let digester = Arc::clone(&self.store.digester);
        let authorized = self.store.executor.execute(end, move |state, work| Ok((|| {
            let tx = state.begin(work).map_err(ControlError::from)?;
            let initial = tx.query_row(REQUEST, params![hash,policy.limits.json_bytes], |row| Ok(decode_request(row,policy.limits.json_bytes)))
                .optional().map_err(|e| ControlError::from(work.sql(e)))?.ok_or(Error::InvalidRequest)??;
            if initial.completed() { return Err(Error::InvalidRequest); }
            final_gate(end, initial.expires_at)?;
            if initial.hash != hash || initial.created_at <= 0 || initial.created_at > now_micros()?
                || initial.expires_at.checked_sub(initial.created_at) != Some(policy.ttl_micros) { return Err(Error::MalformedStored); }
            if initial.created_at > login.observed_at.as_i64() || login.observed_at.as_i64() <= 0 || login.observed_at.as_i64() > now_micros()? { return Err(Error::InvalidLogin); }
            let mut fields = parse_pending(initial.json.as_deref().ok_or(Error::MalformedStored)?)?;
            let principal = current_principal(&tx,work,&login.subject,&login.username,login.revision,policy.limits.json_bytes,end)?;
            let client = current_client(&tx,work,&policy,&fields.client_id,end)?;
            policy.revalidate(&fields,&client,end)?;
            let subject = digester.oidc_subject(principal.issuer().as_bytes(),principal.subject().as_bytes()).map_err(|_| Error::Credential)?;
            let code = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let code_hash = digester.token(TokenKind::OidcAuthorizationCode,code.as_bytes()).map_err(|_| Error::Credential)?.to_sql_hex();
            let amr = if login.factor_verified { vec!["pwd","otp"] } else { vec!["pwd"] };
            let auth_time = now_micros()?;
            if auth_time <= 0 || auth_time < login.observed_at.as_i64() { return Err(ControlError::Clock.into()); }
            fields.phase = "authorized".into();
            let json = Zeroizing::new(serde_json::to_string(&AuthorizedPayload { request:&fields,principal:&principal,oidc_subject:subject.as_str(),amr:&amr,auth_time }).map_err(|_| Error::MalformedStored)?);
            if i64::try_from(json.len()).map_err(|_| Error::ReadLimitExceeded)? > policy.limits.json_bytes { return Err(Error::ReadLimitExceeded); }
            final_gate(end,initial.expires_at)?;
            let changed = tx.execute("UPDATE oidc_auth_requests SET identity_subject=?1,request_json=?2,code_hash=?3 WHERE request_hash=?4 AND identity_subject='' AND code_hash IS NULL AND request_json=?5 AND created_at=?6 AND expires_at=?7 AND expires_at>?8",
                params![principal.subject(),&*json,code_hash,hash,initial.json.as_deref().ok_or(Error::MalformedStored)?,initial.created_at,initial.expires_at,now_micros()?]).map_err(|e| ControlError::from(work.sql(e)))?;
            if changed != 1 { return Err(Error::InvalidRequest); }
            final_gate(end,initial.expires_at)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok(AuthorizedOidcAuthorization { code,info:OidcAuthorizationRequestInfo { fields,created_at:initial.created_at,expires_at:initial.expires_at },subject,amr,
                auth_time:broker_store::time::TimestampMicros::new(auth_time).map_err(|_| ControlError::Clock)? })
        })())).await.map_err(ControlError::from)??;
        final_gate(end, authorized.info.expires_at)?;
        Ok(authorized)
    }
}

pub(in crate::sqlite::flow) fn current_principal(
    tx: &Transaction<'_>,
    work: &Work,
    expected_subject: &str,
    expected_username: &str,
    expected_revision: i64,
    cap: i64,
    end: Instant,
) -> Result<OidcPrincipal, Error> {
    guard_original(end)?;
    let mut principal = tx
        .query_row(USER, params![expected_subject, cap], |row| {
            Ok((|| {
                let username = text(row, "username")?;
                let subject = text(row, "subject")?;
                let revision = number(row, "revision")?;
                if !safe_identity_segment(username, 128)
                    || !valid_identity_subject(subject, 512)
                    || username != expected_username
                    || subject != expected_subject
                    || revision != expected_revision
                    || revision < 1
                    || text(row, "identity_kind")? != "human"
                    || number(row, "enabled")? != 1
                    || number(row, "password_change_required")? != 0
                {
                    return Err(Error::InvalidLogin);
                }
                let profile = |name| -> Result<String, Error> {
                    let value = text(row, name)?;
                    if value.chars().count() > 512 {
                        return Err(Error::MalformedStored);
                    }
                    Ok(value.to_owned())
                };
                let teams: Vec<String> =
                    serde_json::from_str(bounded(row, "team_bytes", "teams_json", cap)?)
                        .map_err(|_| Error::MalformedStored)?;
                let mut seen = HashSet::new();
                let teams = teams
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty() && seen.insert(*s))
                    .map(str::to_owned)
                    .collect();
                Ok(LocalPrincipal {
                    issuer: "local".into(),
                    subject: subject.into(),
                    username: username.into(),
                    local_user_revision: revision,
                    name: profile("name")?,
                    email: profile("email")?,
                    organization: profile("organization")?,
                    teams,
                    roles: Vec::new(),
                })
            })())
        })
        .optional()
        .map_err(|e| ControlError::from(work.sql(e)))?
        .ok_or(Error::InvalidLogin)??;
    let canonical_subject = format!("local|{}", principal.subject);
    let mut stmt = tx
        .prepare(ROLES)
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut rows = stmt
        .query(params![
            canonical_subject,
            cap.checked_add(1).ok_or(Error::ReadLimitExceeded)?
        ])
        .map_err(|e| ControlError::from(work.sql(e)))?;
    let mut encoded_bytes = 2i64;
    while let Some(row) = rows.next().map_err(|e| ControlError::from(work.sql(e)))? {
        guard_original(end)?;
        let role = text(row, "role")?;
        if role.is_empty()
            || role.trim() != role
            || role.chars().count() > 128
            || role.contains('\0')
        {
            return Err(Error::MalformedStored);
        }
        let encoded = serde_json::to_string(role).map_err(|_| Error::MalformedStored)?;
        encoded_bytes = encoded_bytes
            .checked_add(i64::try_from(encoded.len()).map_err(|_| Error::ReadLimitExceeded)?)
            .and_then(|n| n.checked_add(i64::from(!principal.roles.is_empty())))
            .ok_or(Error::ReadLimitExceeded)?;
        if encoded_bytes > cap {
            return Err(Error::ReadLimitExceeded);
        }
        principal.roles.push(role.to_owned());
    }
    Ok(OidcPrincipal::Local(principal))
}
const USER: &str = r#"SELECT
 CASE WHEN typeof(username)='text' AND length(CAST(username AS BLOB))<=128 THEN username END AS username,
 CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=512 THEN subject END AS subject,
 CASE WHEN typeof(identity_kind)='text' AND length(CAST(identity_kind AS BLOB))<=16 THEN identity_kind END AS identity_kind,
 enabled,password_change_required,revision,
 CASE WHEN typeof(name)='text' AND length(CAST(name AS BLOB))<=2048 THEN name END AS name,
 CASE WHEN typeof(email)='text' AND length(CAST(email AS BLOB))<=2048 THEN email END AS email,
 CASE WHEN typeof(organization)='text' AND length(CAST(organization AS BLOB))<=2048 THEN organization END AS organization,
 CASE WHEN typeof(teams_json)='text' THEN length(CAST(teams_json AS BLOB)) END AS team_bytes,
 CASE WHEN typeof(teams_json)='text' AND length(CAST(teams_json AS BLOB))<=?2 THEN teams_json END AS teams_json
 FROM local_users WHERE subject=?1"#;
const ROLES: &str = r#"SELECT CASE WHEN typeof(role)='text' AND length(CAST(role AS BLOB))<=512 THEN role END AS role
 FROM (SELECT role FROM role_assignments WHERE subject=?1 UNION SELECT 'user') ORDER BY role LIMIT ?2"#;
