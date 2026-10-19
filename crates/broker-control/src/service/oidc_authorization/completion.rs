use super::*;
use crate::service::oidc_principal::{LocalPrincipal, OidcPrincipal};
use crate::{
    AuthorizedOidcAuthorization, PreparedOidcLogin,
    identity::{safe_identity_segment, valid_identity_subject},
    oidc_authorization::PendingFields,
};
use broker_security::LocalAuthBinding;
use futures_util::TryStreamExt;
use serde::Serialize;
use std::collections::HashSet;

const USER: &str = r#"SELECT
 CASE WHEN OCTET_LENGTH(username)<=128 THEN username END AS username,
 CASE WHEN OCTET_LENGTH(subject)<=512 THEN subject END AS subject,
 CASE WHEN OCTET_LENGTH(identity_kind)<=16 THEN identity_kind END AS identity_kind,
 enabled::bigint,password_change_required::bigint,revision,
 CASE WHEN OCTET_LENGTH(name)<=2048 THEN name END AS name,
 CASE WHEN OCTET_LENGTH(email)<=2048 THEN email END AS email,
 CASE WHEN OCTET_LENGTH(organization)<=2048 THEN organization END AS organization,
 OCTET_LENGTH(teams_json)::bigint AS team_bytes,
 CASE WHEN OCTET_LENGTH(teams_json)<=$2 THEN teams_json END AS teams_json
 FROM public.local_users WHERE subject=$1 FOR SHARE"#;
const ROLES: &str = r#"SELECT CASE WHEN OCTET_LENGTH(role)<=512 THEN role END AS role
 FROM (SELECT role FROM public.role_assignments WHERE subject=$1 UNION SELECT 'user') r
 ORDER BY role LIMIT $2"#;

#[derive(Serialize)]
pub(crate) struct AuthorizedPayload<'a> {
    #[serde(flatten)]
    pub(crate) request: &'a PendingFields,
    pub(crate) principal: &'a OidcPrincipal,
    pub(crate) oidc_subject: &'a str,
    pub(crate) amr: &'a [&'static str],
    pub(crate) auth_time: i64,
}

impl PostgresOidcAuthorizationService<'_> {
    /// Consume a prepared native login and complete its exact pending request.
    /// The caller has already taken any enrollment codes before this future exists.
    pub async fn complete(
        &self,
        raw: &str,
        login: PreparedOidcLogin,
        original: Instant,
    ) -> Result<AuthorizedOidcAuthorization, Error> {
        let deadline = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidRequest)?;
        let PreparedOidcLogin { login } = login;
        login
            .verify_binding(
                self.digester,
                LocalAuthBinding::OauthAuthorize(raw.as_bytes()),
            )
            .map_err(|_| Error::InvalidLogin)?;
        let hash = self
            .digester
            .token(TokenKind::OidcAuthRequest, raw.as_bytes())
            .map_err(|_| Error::Credential)?
            .to_sql_hex();
        guard_original(deadline)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(deadline.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = sqlx_core::connection::Connection::begin_with(
                guard.connection()?, "BEGIN ISOLATION LEVEL READ COMMITTED",
            ).await.map_err(storage_error)?;
            let row = sqlx_core::query::query(REQUEST).bind(&hash).bind(self.policy.limits.json_bytes)
                .fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(Error::InvalidRequest)?;
            let initial = decode_request(&row, self.policy.limits.json_bytes)?;
            if initial.completed() { return Err(Error::InvalidRequest); }
            final_gate(deadline, initial.expires_at)?;
            if initial.hash != hash || initial.created_at <= 0 || initial.created_at > now_micros()?
                || initial.expires_at.checked_sub(initial.created_at) != Some(self.policy.ttl_micros) {
                return Err(Error::MalformedStored);
            }
            if initial.created_at > login.observed_at.as_i64() { return Err(Error::InvalidLogin); }
            let mut fields = parse_pending(initial.json.as_deref().ok_or(Error::MalformedStored)?)?;
            // Read pending without a lock; take locks in user → client → request order.
            if login.observed_at.as_i64() <= 0 || login.observed_at.as_i64() > now_micros()? {
                return Err(Error::InvalidLogin);
            }
            let principal = current_principal(&mut tx, &login.subject, &login.username, login.revision, self.policy.limits.json_bytes, deadline).await?;
            let client = self.client(&mut tx, &fields.client_id, deadline).await?;
            let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(format!("{REQUEST} FOR UPDATE")))
                .bind(&hash).bind(self.policy.limits.json_bytes).fetch_optional(&mut *tx)
                .await.map_err(storage_error)?.ok_or(Error::InvalidRequest)?;
            let current = decode_request(&row, self.policy.limits.json_bytes)?;
            if current.completed() { return Err(Error::InvalidRequest); }
            final_gate(deadline, current.expires_at)?;
            if current != initial { return Err(Error::MalformedStored); }
            self.policy.revalidate(&fields, &client, deadline)?;
            let subject = self.digester.oidc_subject(principal.issuer().as_bytes(), principal.subject().as_bytes())
                .map_err(|_| Error::Credential)?;
            let code = new_local_auth_challenge().map_err(|_| Error::Random)?;
            let code_hash = self.digester.token(TokenKind::OidcAuthorizationCode, code.as_bytes())
                .map_err(|_| Error::Credential)?.to_sql_hex();
            let amr = if login.factor_verified { vec!["pwd", "otp"] } else { vec!["pwd"] };
            let auth_time = now_micros()?;
            if auth_time <= 0 || auth_time < login.observed_at.as_i64() { return Err(ControlError::Clock.into()); }
            fields.phase = "authorized".into();
            let json = Zeroizing::new(serde_json::to_string(&AuthorizedPayload {
                request: &fields, principal: &principal, oidc_subject: subject.as_str(), amr: &amr, auth_time,
            }).map_err(|_| Error::MalformedStored)?);
            if i64::try_from(json.len()).map_err(|_| Error::ReadLimitExceeded)? > self.policy.limits.json_bytes {
                return Err(Error::ReadLimitExceeded);
            }
            final_gate(deadline, current.expires_at)?;
            let changed = sqlx_core::query::query("UPDATE public.oidc_auth_requests SET identity_subject=$1,request_json=$2,code_hash=$3 WHERE request_hash=$4 AND identity_subject='' AND code_hash IS NULL AND request_json=$5 AND created_at=$6 AND expires_at=$7 AND expires_at>$8")
                .bind(principal.subject()).bind(&*json).bind(&code_hash).bind(&hash)
                .bind(initial.json.as_deref().ok_or(Error::MalformedStored)?).bind(initial.created_at)
                .bind(initial.expires_at).bind(now_micros()?).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if changed != 1 { return Err(Error::InvalidRequest); }
            final_gate(deadline, current.expires_at)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            final_gate(deadline, current.expires_at)?;
            Ok(AuthorizedOidcAuthorization {
                code, info: OidcAuthorizationRequestInfo { fields, created_at: current.created_at, expires_at: current.expires_at },
                subject, amr, auth_time: broker_store::time::TimestampMicros::new(auth_time).map_err(|_| ControlError::Clock)?,
            })
        }).await.map_err(|_| Error::Control(timeout_error(&commit_started)))?
    }
}

pub(in crate::service) async fn current_principal(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    expected_subject: &str,
    expected_username: &str,
    expected_revision: i64,
    cap: i64,
    original: Instant,
) -> Result<OidcPrincipal, Error> {
    guard_original(original)?;
    let row = sqlx_core::query::query(USER)
        .bind(expected_subject)
        .bind(cap)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .ok_or(Error::InvalidLogin)?;
    let username: Option<String> = get(&row, "username")?;
    let subject: Option<String> = get(&row, "subject")?;
    let username = username.ok_or(Error::InvalidLogin)?;
    let subject = subject.ok_or(Error::InvalidLogin)?;
    let revision: i64 = get(&row, "revision")?;
    if !safe_identity_segment(&username, 128)
        || !valid_identity_subject(&subject, 512)
        || username != expected_username
        || subject != expected_subject
        || revision != expected_revision
        || revision < 1
        || get::<Option<&str>>(&row, "identity_kind")? != Some("human")
        || get::<i64>(&row, "enabled")? != 1
        || get::<i64>(&row, "password_change_required")? != 0
    {
        return Err(Error::InvalidLogin);
    }
    let profile = |name| -> Result<String, Error> {
        let value: String = get(&row, name)?;
        if value.chars().count() > 512 {
            return Err(Error::MalformedStored);
        }
        Ok(value)
    };
    let teams: Vec<String> = serde_json::from_str(bounded(&row, "team_bytes", "teams_json", cap)?)
        .map_err(|_| Error::MalformedStored)?;
    let mut seen = HashSet::new();
    let teams = teams
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && seen.insert(*s))
        .map(str::to_owned)
        .collect();
    let mut principal = LocalPrincipal {
        issuer: "local".into(),
        subject,
        username,
        local_user_revision: revision,
        name: profile("name")?,
        email: profile("email")?,
        organization: profile("organization")?,
        teams,
        roles: Vec::new(),
    };
    // The JSON byte cap itself bounds possible role elements; no independent quota.
    let rows = cap.checked_add(1).ok_or(Error::ReadLimitExceeded)?;
    let canonical_subject = format!("local|{}", principal.subject);
    let mut stream = sqlx_core::query::query(ROLES)
        .bind(&canonical_subject)
        .bind(rows)
        .fetch(&mut **tx);
    let mut encoded_bytes = 2i64;
    while let Some(row) = stream.try_next().await.map_err(storage_error)? {
        guard_original(original)?;
        let role: String = get(&row, "role")?;
        if role.is_empty()
            || role.trim() != role
            || role.chars().count() > 128
            || role.contains('\0')
        {
            return Err(Error::MalformedStored);
        }
        let encoded = serde_json::to_string(&role).map_err(|_| Error::MalformedStored)?;
        encoded_bytes = encoded_bytes
            .checked_add(i64::try_from(encoded.len()).map_err(|_| Error::ReadLimitExceeded)?)
            .and_then(|n| n.checked_add(i64::from(!principal.roles.is_empty())))
            .ok_or(Error::ReadLimitExceeded)?;
        if encoded_bytes > cap {
            return Err(Error::ReadLimitExceeded);
        }
        principal.roles.push(role);
    }
    drop(stream);
    Ok(OidcPrincipal::Local(principal))
}
