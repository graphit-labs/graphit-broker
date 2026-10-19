use super::oidc_authorization::completion::current_principal;
use super::oidc_tokens::{TokenData, insert, lock_pair_shared};
use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    BrokerAccessIssuer, BrokerAccessTokenInput, CompletedLocalLogin, ControlError,
    DeviceAccessToken, DeviceAuthorizationCodes, DeviceAuthorizationPolicy, DeviceConsent,
    DeviceError as Error, OidcAuthorizationPolicy, OidcTokenExchangeError as Protocol,
    device::{check, normalize_device_user_code},
    flow::now_micros,
};
use broker_security::{
    LocalAuthBinding, TokenKind, new_local_auth_challenge, validate_local_auth_challenge,
};
use sqlx_core::{connection::Connection, row::Row};
use sqlx_postgres::{PgRow, Postgres};
use std::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use zeroize::Zeroizing;

const DEVICE: &str = r#"SELECT
 CASE WHEN octet_length(device_hash)<=64 THEN device_hash END AS device_hash,
 CASE WHEN octet_length(user_hash)<=64 THEN user_hash END AS user_hash,
 CASE WHEN octet_length(client_id)<=128 THEN client_id END AS client_id,
 octet_length(scopes_json)::bigint AS scope_bytes,
 CASE WHEN octet_length(scopes_json)<=$2 THEN scopes_json END AS scopes_json,
 CASE WHEN octet_length(subject)<=512 THEN subject END AS subject,
 local_user_revision,CASE WHEN octet_length(status)<=16 THEN status END AS status,
 interval_seconds,last_poll_at,expires_at,created_at FROM public.oauth_device_codes"#;
const CONSENT: &str = r#"SELECT
 CASE WHEN octet_length(subject)<=512 THEN subject END AS subject,
 local_user_revision,CASE WHEN octet_length(purpose)<=32 THEN purpose END AS purpose,
 CASE WHEN octet_length(binding_hash)<=64 THEN binding_hash END AS binding_hash,
 CASE WHEN octet_length(stage)<=32 THEN stage END AS stage,
 CASE WHEN octet_length(secret_ciphertext)<=90 THEN secret_ciphertext END AS secret_ciphertext,
 expires_at,created_at FROM public.local_auth_challenges WHERE challenge_hash=$1"#;

pub struct PostgresDeviceAuthorizations<'a> {
    store: &'a PostgresControlStore,
    authorization: &'a OidcAuthorizationPolicy,
    policy: &'a DeviceAuthorizationPolicy,
    issuer: &'a BrokerAccessIssuer,
}
impl fmt::Debug for PostgresDeviceAuthorizations<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresDeviceAuthorizations([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn device_authorizations<'a>(
        &'a self,
        authorization: &'a OidcAuthorizationPolicy,
        policy: &'a DeviceAuthorizationPolicy,
        issuer: &'a BrokerAccessIssuer,
    ) -> Result<PostgresDeviceAuthorizations<'a>, Error> {
        if authorization.api_audience != issuer.api_audience() {
            return Err(Protocol::InvalidConfiguration.into());
        }
        Ok(PostgresDeviceAuthorizations {
            store: self,
            authorization,
            policy,
            issuer,
        })
    }
}
impl PostgresDeviceAuthorizations<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    fn parameters(&self, values: &[&str]) -> Result<(), Error> {
        let size = values
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .ok_or(Protocol::InvalidRequest)?;
        if size > self.parameter_bytes() {
            return Err(Protocol::InvalidRequest.into());
        }
        Ok(())
    }
    fn client(&self, client: &str) -> Result<(), Error> {
        if client.is_empty() {
            return Err(Protocol::InvalidRequest.into());
        }
        if client != self.authorization.cli_client_id {
            return Err(Protocol::InvalidClient.into());
        }
        Ok(())
    }
    fn digest(&self, kind: TokenKind, raw: &str) -> Result<String, Error> {
        self.store
            .digester
            .token(kind, raw.as_bytes())
            .map(|v| v.to_sql_hex())
            .map_err(|_| Protocol::Credential.into())
    }
    pub async fn issue(
        &self,
        client: &str,
        scope: &str,
        original: Instant,
    ) -> Result<DeviceAuthorizationCodes, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        if !scope.is_empty() {
            return Err(Protocol::InvalidScope.into());
        }
        self.parameters(&[client])?;
        self.client(client)?;
        let scopes: Vec<String> = Vec::new();
        let json = serde_json::to_string(&scopes).map_err(|_| Protocol::InvalidScope)?;
        if json.len() as i64 > self.authorization.limits.json_bytes {
            return Err(Protocol::ReadLimitExceeded.into());
        }
        let device = Zeroizing::new(format!(
            "gb_dc_{}",
            new_local_auth_challenge()
                .map_err(|_| Protocol::Random)?
                .as_str()
        ));
        let mut random = [0u8; 8];
        getrandom::fill(&mut random).map_err(|_| Protocol::Random)?;
        let user: String = random
            .into_iter()
            .map(|v| b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[(v & 31) as usize] as char)
            .collect();
        let user_display = format!("{}-{}", &user[..4], &user[4..]);
        let hash = self.digest(TokenKind::DeviceCode, &device)?;
        let user_hash = self.digest(TokenKind::DeviceUserCode, &user)?;
        let started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin().await.map_err(storage_error)?;
            let now = now_micros()?;
            let expires = now.checked_add(self.policy.ttl_micros).ok_or(ControlError::Clock)?;
            check(end, expires)?;
            let n = sqlx_core::query::query("INSERT INTO public.oauth_device_codes(device_hash,user_hash,client_id,scopes_json,subject,local_user_revision,status,interval_seconds,last_poll_at,expires_at,created_at) VALUES($1,$2,$3,$4,'',0,'pending',$5,NULL,$6,$7)")
                .bind(&hash).bind(&user_hash).bind(client).bind(&json).bind(self.policy.interval_seconds).bind(expires).bind(now)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if n != 1 { return Err(ControlError::Storage.into()); }
            check(end, expires)?;
            started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            check(end, expires)?;
            Ok(DeviceAuthorizationCodes { device, user: user_display, expires_at: expires, interval: self.policy.interval_seconds as u64 })
        }).await.map_err(|_| Error::from(timeout_error(&started)))?
    }
    /// Transfers the one-time enrollment output into a consent presentation. Never approves.
    pub async fn prepare(
        &self,
        user_code: &str,
        mut login: CompletedLocalLogin,
        original: Instant,
    ) -> Result<DeviceConsent, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        self.parameters(&[user_code])?;
        let user = normalize_device_user_code(user_code).ok_or(Protocol::InvalidRequest)?;
        login
            .verify_binding(
                &self.store.digester,
                LocalAuthBinding::DeviceApprove(user.as_bytes()),
            )
            .map_err(|_| Protocol::InvalidGrant)?;
        let user_hash = self.digest(TokenKind::DeviceUserCode, &user)?;
        let binding = self
            .store
            .digester
            .local_auth_binding(LocalAuthBinding::DeviceApprove(user.as_bytes()))
            .map_err(|_| Protocol::Credential)?
            .to_sql_hex();
        let secret = new_local_auth_challenge().map_err(|_| Protocol::Random)?;
        let hash = self.digest(TokenKind::LocalAuthChallenge, &secret)?;
        let started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            // User precedes device and challenge, matching LOCAL invalidators.
            current_principal(&mut tx, &login.subject, &login.username, login.revision, self.authorization.limits.json_bytes, end).await?;
            let d = self.read(&mut tx, &user_hash, true, true).await?;
            check(end, d.expires)?;
            if d.status != "pending" || login.observed_at.as_i64() < d.created || login.observed_at.as_i64() > now_micros()? { return Err(Protocol::InvalidGrant.into()); }
            let now = now_micros()?;
            let n = sqlx_core::query::query("INSERT INTO public.local_auth_challenges(challenge_hash,subject,local_user_revision,purpose,binding_hash,stage,secret_ciphertext,expires_at,created_at) VALUES($1,$2,$3,'device-approve',$4,'device_consent','',$5,$6)")
                .bind(hash).bind(&login.subject).bind(login.revision).bind(binding).bind(d.expires).bind(now)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if n != 1 { return Err(ControlError::Storage.into()); }
            check(end, d.expires)?;
            started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            check(end, d.expires)?;
            Ok(DeviceConsent { secret, recovery: login.take_recovery_codes(), user_code: format!("{}-{}", &user[..4], &user[4..]), client: d.client, scope: d.scopes.join(" "), expires_at: d.expires })
        }).await.map_err(|_| Error::from(timeout_error(&started)))?
    }
    pub async fn decide(
        &self,
        user_code: &str,
        client: &str,
        secret: &str,
        allow: bool,
        original: Instant,
    ) -> Result<(), Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        self.parameters(&[user_code, client, secret])?;
        self.client(client)?;
        let user = normalize_device_user_code(user_code).ok_or(Protocol::InvalidRequest)?;
        validate_local_auth_challenge(secret).map_err(|_| Protocol::InvalidGrant)?;
        let hash = self.digest(TokenKind::LocalAuthChallenge, secret)?;
        let user_hash = self.digest(TokenKind::DeviceUserCode, &user)?;
        let binding = self
            .store
            .digester
            .local_auth_binding(LocalAuthBinding::DeviceApprove(user.as_bytes()))
            .map_err(|_| Protocol::Credential)?
            .to_sql_hex();
        let started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            let initial = consent_row(&mut tx, &hash, false).await?;
            initial.valid(&binding, end)?;
            let username = username(&mut tx, &initial.subject).await?;
            current_principal(&mut tx, &initial.subject, &username, initial.revision, self.authorization.limits.json_bytes, end).await?;
            let d = self.read(&mut tx, &user_hash, true, true).await?;
            let current = consent_row(&mut tx, &hash, true).await?;
            current.valid(&binding, end)?;
            check(end, d.expires)?;
            if initial != current || d.status != "pending" || d.client != client || current.created < d.created || current.expires != d.expires { return Err(Protocol::InvalidGrant.into()); }
            let n = sqlx_core::query::query("UPDATE public.oauth_device_codes SET subject=$1,local_user_revision=$2,status=$3 WHERE device_hash=$4 AND status='pending' AND expires_at>$5")
                .bind(&current.subject).bind(current.revision).bind(if allow { "approved" } else { "denied" }).bind(&d.hash).bind(now_micros()?)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if n != 1 { return Err(Protocol::InvalidGrant.into()); }
            let n = sqlx_core::query::query("DELETE FROM public.local_auth_challenges WHERE challenge_hash=$1").bind(hash).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if n != 1 { return Err(ControlError::Storage.into()); }
            check(end, d.expires)?;
            started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            check(end, d.expires)
        }).await.map_err(|_| Error::from(timeout_error(&started)))?
    }
    pub async fn poll(
        &self,
        client: &str,
        device: &str,
        original: Instant,
    ) -> Result<DeviceAccessToken, Error> {
        let end = bounded_deadline(original, self.store.budgets.operation_timeout)?;
        self.parameters(&[client, device])?;
        self.client(client)?;
        let suffix = device
            .strip_prefix("gb_dc_")
            .ok_or(Protocol::InvalidGrant)?;
        validate_local_auth_challenge(suffix).map_err(|_| Protocol::InvalidGrant)?;
        let hash = self.digest(TokenKind::DeviceCode, device)?;
        let started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.store.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            let initial = self.read(&mut tx, &hash, false, false).await?;
            let principal = if initial.status == "approved" && initial.expires > now_micros()? {
                let subject = self.store.digester.oidc_subject(b"local", initial.subject.as_bytes()).map_err(|_| Protocol::Credential)?;
                lock_pair_shared(&mut tx, subject.as_str(), client, end).await?;
                let name = username(&mut tx, &initial.subject).await?;
                Some(current_principal(&mut tx, &initial.subject, &name, initial.revision, self.authorization.limits.json_bytes, end).await?)
            } else { None };
            let d = self.read(&mut tx, &hash, false, true).await?;
            if d.client != client { return Err(Protocol::InvalidGrant.into()); }
            // A pending observation may become approved while acquiring its row. Restarting
            // requires a later client poll, never acquiring a user lock behind a device lock.
            if d.expires > now_micros()? && d.status == "approved" && (initial.subject != d.subject || initial.revision != d.revision || principal.is_none()) { return Err(Error::AuthorizationPending); }
            let now = now_micros()?;
            let response = if d.expires <= now {
                delete_device(&mut tx, &d.hash).await?;
                Err(Error::ExpiredToken)
            } else if d.status == "denied" {
                delete_device(&mut tx, &d.hash).await?;
                Err(Error::AccessDenied)
            } else if d.last_poll.is_some_and(|last| now - last < d.interval.saturating_mul(1_000_000)) {
                let next = d.interval.checked_add(5).ok_or(Protocol::MalformedStored)?;
                sqlx_core::query::query("UPDATE public.oauth_device_codes SET interval_seconds=$1,last_poll_at=$2 WHERE device_hash=$3")
                    .bind(next).bind(now).bind(&d.hash).execute(&mut *tx).await.map_err(storage_error)?;
                Err(Error::SlowDown)
            } else if d.status == "pending" {
                sqlx_core::query::query("UPDATE public.oauth_device_codes SET last_poll_at=$1 WHERE device_hash=$2")
                    .bind(now).bind(&d.hash).execute(&mut *tx).await.map_err(storage_error)?;
                Err(Error::AuthorizationPending)

            } else {
                let principal = principal.ok_or(Protocol::InvalidGrant)?;
                let subject = self.store.digester.oidc_subject(principal.issuer().as_bytes(), principal.subject().as_bytes()).map_err(|_| Protocol::Credential)?;
                let expires = now.checked_add(self.policy.access_micros).ok_or(ControlError::Clock)? / 1_000_000 * 1_000_000;
                let jti = new_local_auth_challenge().map_err(|_| Protocol::Random)?;
                let scope = d.scopes.join(" ");
                let access = Zeroizing::new(self.issuer.sign_access(BrokerAccessTokenInput {
                    subject: subject.as_str(),client_id: client,resource: None,scope: &scope,jti: &jti,
                    issued_at: seconds(now)?,expires_at: seconds(expires)?,preferred_username: Some(principal.username()),
                    name: nonempty(principal.name()),email: nonempty(principal.email()),organization: nonempty(principal.organization()),
                    groups: principal.teams(),roles: principal.roles(),
                }, end).map_err(|e| match e { crate::BrokerAccessIssueError::Deadline => Protocol::Control(ControlError::Deadline), _ => Protocol::Signing })?);
                let json = Zeroizing::new(serde_json::to_string(&principal).map_err(|_| Protocol::MalformedStored)?);
                let scopes_json = serde_json::to_string(&d.scopes).map_err(|_| Protocol::MalformedStored)?;
                if json.len() as i64 > self.authorization.limits.json_bytes || scopes_json.len() as i64 > self.authorization.limits.json_bytes { return Err(Protocol::ReadLimitExceeded.into()); }
                let data = TokenData { principal: &principal,oidc_subject: subject.as_str(),client_id: client,audience: &self.authorization.api_audience,
                    resource: None,principal_json: &json,scopes_json: &scopes_json,family: "",auth_time: now,created_at: now };
                let token_hash = self.digest(TokenKind::OidcStoredAccess, &jti)?;
                insert(&mut tx, &data, &token_hash, &jti, "oidc_access", expires).await?;
                delete_device(&mut tx, &d.hash).await?;
                check(end, d.expires)?;
                check(end, expires)?;
                Ok(DeviceAccessToken { access, scope, expires_at: expires })
            };
            if Instant::now() >= end { return Err(ControlError::Deadline.into()); }
            started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            if Instant::now() >= end { return Err(ControlError::Deadline.into()); }
            if let Ok(token) = &response { check(end, d.expires)?; token.expires_in(end)?; }
            response
        }).await.map_err(|_| Error::from(timeout_error(&started)))?
    }
    async fn read(
        &self,
        tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
        hash: &str,
        by_user: bool,
        lock: bool,
    ) -> Result<DeviceRow, Error> {
        let sql = format!(
            "{DEVICE} WHERE {}=$1{}",
            if by_user { "user_hash" } else { "device_hash" },
            if lock { " FOR UPDATE" } else { "" }
        );
        let row = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
            .bind(hash)
            .bind(self.authorization.limits.json_bytes)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage_error)?
            .ok_or(Protocol::InvalidGrant)?;
        let d = DeviceRow::decode(&row, self.authorization.limits.json_bytes)?;
        d.valid(self.policy)?;
        if (if by_user { &d.user_hash } else { &d.hash }) != hash
            || d.client != self.authorization.cli_client_id
        {
            return Err(Protocol::MalformedStored.into());
        }
        Ok(d)
    }
}

#[derive(PartialEq, Eq)]
struct DeviceRow {
    hash: String,
    user_hash: String,
    client: String,
    scopes: Vec<String>,
    subject: String,
    revision: i64,
    status: String,
    interval: i64,
    last_poll: Option<i64>,
    expires: i64,
    created: i64,
}
impl DeviceRow {
    fn decode(r: &PgRow, cap: i64) -> Result<Self, Error> {
        let size: i64 = get(r, "scope_bytes")?;
        if size < 0 {
            return Err(Protocol::MalformedStored.into());
        }
        if size > cap {
            return Err(Protocol::ReadLimitExceeded.into());
        }
        let raw: String = get(r, "scopes_json")?;
        let scopes: Vec<String> =
            serde_json::from_str(&raw).map_err(|_| Protocol::MalformedStored)?;
        if !scopes.is_empty() {
            return Err(Protocol::MalformedStored.into());
        }
        Ok(Self {
            hash: get(r, "device_hash")?,
            user_hash: get(r, "user_hash")?,
            client: get(r, "client_id")?,
            scopes,
            subject: get(r, "subject")?,
            revision: get(r, "local_user_revision")?,
            status: get(r, "status")?,
            interval: get(r, "interval_seconds")?,
            last_poll: get(r, "last_poll_at")?,
            expires: get(r, "expires_at")?,
            created: get(r, "created_at")?,
        })
    }
    fn valid(&self, p: &DeviceAuthorizationPolicy) -> Result<(), Error> {
        let now = now_micros()?;
        let digest = |s: &str| broker_security::CredentialDigest::parse_sql_hex(s).is_ok();
        if !digest(&self.hash)
            || !digest(&self.user_hash)
            || self.created <= 0
            || self.created > now
            || self.expires.checked_sub(self.created) != Some(p.ttl_micros)
            || self.interval < p.interval_seconds
            || (self.interval - p.interval_seconds) % 5 != 0
            || self.interval > i64::MAX / 1_000_000
            || self.last_poll.is_some_and(|v| v < self.created || v > now)
            || match self.status.as_str() {
                "pending" => !self.subject.is_empty() || self.revision != 0,
                "approved" | "denied" => {
                    !crate::identity::valid_identity_subject(&self.subject, 512)
                        || self.revision < 1
                }
                _ => true,
            }
        {
            return Err(Protocol::MalformedStored.into());
        }
        Ok(())
    }
}
#[derive(PartialEq, Eq)]
struct ConsentRow {
    subject: String,
    revision: i64,
    purpose: String,
    binding: String,
    stage: String,
    cipher: String,
    expires: i64,
    created: i64,
}
impl ConsentRow {
    fn valid(&self, binding: &str, end: Instant) -> Result<(), Error> {
        check(end, self.expires)?;
        if self.purpose != "device-approve"
            || self.binding != binding
            || self.stage != "device_consent"
            || !self.cipher.is_empty()
            || self.revision < 1
            || !crate::identity::valid_identity_subject(&self.subject, 512)
            || self.created <= 0
            || self.created > now_micros()?
            || self.expires <= self.created
        {
            return Err(Protocol::InvalidGrant.into());
        }
        Ok(())
    }
}
async fn consent_row(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    hash: &str,
    lock: bool,
) -> Result<ConsentRow, Error> {
    let sql = format!("{CONSENT}{}", if lock { " FOR UPDATE" } else { "" });
    let r = sqlx_core::query::query(sqlx_core::sql_str::AssertSqlSafe(sql))
        .bind(hash)
        .fetch_optional(&mut **tx)
        .await
        .map_err(storage_error)?
        .ok_or(Protocol::InvalidGrant)?;
    Ok(ConsentRow {
        subject: get(&r, "subject")?,
        revision: get(&r, "local_user_revision")?,
        purpose: get(&r, "purpose")?,
        binding: get(&r, "binding_hash")?,
        stage: get(&r, "stage")?,
        cipher: get(&r, "secret_ciphertext")?,
        expires: get(&r, "expires_at")?,
        created: get(&r, "created_at")?,
    })
}
async fn username(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    subject: &str,
) -> Result<String, Error> {
    sqlx_core::query_scalar::query_scalar::<_,Option<String>>("SELECT CASE WHEN octet_length(username)<=128 THEN username END FROM public.local_users WHERE subject=$1")
        .bind(subject).fetch_optional(&mut **tx).await.map_err(storage_error)?.flatten().ok_or_else(|| Protocol::InvalidGrant.into())
}
async fn delete_device(
    tx: &mut sqlx_core::transaction::Transaction<'_, Postgres>,
    hash: &str,
) -> Result<(), Error> {
    let n = sqlx_core::query::query("DELETE FROM public.oauth_device_codes WHERE device_hash=$1")
        .bind(hash)
        .execute(&mut **tx)
        .await
        .map_err(storage_error)?
        .rows_affected();
    if n != 1 {
        return Err(ControlError::Storage.into());
    }
    Ok(())
}
fn get<'r, T: sqlx_core::decode::Decode<'r, Postgres> + sqlx_core::types::Type<Postgres>>(
    r: &'r PgRow,
    k: &str,
) -> Result<T, Error> {
    r.try_get(k).map_err(|_| Protocol::MalformedStored.into())
}
fn seconds(now: i64) -> Result<u64, Error> {
    u64::try_from(now / 1_000_000).map_err(|_| ControlError::Clock.into())
}
fn nonempty(raw: &str) -> Option<&str> {
    (!raw.trim().is_empty()).then_some(raw)
}
