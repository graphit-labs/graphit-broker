//! Device LOCAL operations over the physical SQLite transaction owner.
use super::{
    SqliteControlStore, oidc_authorization::completion::current_principal, oidc_tokens::insert,
};
use crate::{
    BrokerAccessIssuer, BrokerAccessTokenInput, CompletedLocalLogin, ControlError,
    DeviceAccessToken, DeviceAuthorizationCodes, DeviceAuthorizationPolicy, DeviceConsent,
    DeviceError as Error, OidcAuthorizationPolicy, OidcTokenExchangeError as Protocol,
    device::{check, normalize_device_user_code},
    flow::now_micros,
    service::oidc_tokens::TokenData,
    sqlite::executor::Work,
};
use broker_security::{
    CredentialDigester, LocalAuthBinding, TokenKind, new_local_auth_challenge,
    validate_local_auth_challenge,
};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

/// A borrowed Device view; its store and startup signing owners remain alive.
/// ```compile_fail
/// fn escape(v: broker_control::SqliteDeviceAuthorizations<'_>) { let _ = v.store; }
/// ```
pub struct SqliteDeviceAuthorizations<'a> {
    store: &'a SqliteControlStore,
    authorization: Arc<OidcAuthorizationPolicy>,
    policy: Arc<DeviceAuthorizationPolicy>,
    issuer: Arc<BrokerAccessIssuer>,
}
impl fmt::Debug for SqliteDeviceAuthorizations<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteDeviceAuthorizations([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn device_authorizations(
        &self,
        authorization: Arc<OidcAuthorizationPolicy>,
        policy: Arc<DeviceAuthorizationPolicy>,
        issuer: Arc<BrokerAccessIssuer>,
    ) -> Result<SqliteDeviceAuthorizations<'_>, Error> {
        if authorization.api_audience != issuer.api_audience() {
            return Err(Protocol::InvalidConfiguration.into());
        }
        Ok(SqliteDeviceAuthorizations {
            store: self,
            authorization,
            policy,
            issuer,
        })
    }
}
impl SqliteDeviceAuthorizations<'_> {
    pub fn parameter_bytes(&self) -> usize {
        self.authorization.limits.parameter_bytes()
    }
    fn parameters(&self, values: &[&str]) -> Result<(), Error> {
        let bytes = values
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(v.len()))
            .ok_or(Protocol::InvalidRequest)?;
        if bytes > self.parameter_bytes() {
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
    pub async fn issue(
        &self,
        client: &str,
        scope: &str,
        original: Instant,
    ) -> Result<DeviceAuthorizationCodes, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        if !scope.is_empty() {
            return Err(Protocol::InvalidScope.into());
        }
        self.parameters(&[client])?;
        self.client(client)?;
        if self.authorization.limits.json_bytes < 2 {
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
        let user = format!("{}-{}", &user[..4], &user[4..]);
        let hash = digest(&self.store.digester, TokenKind::DeviceCode, &device)?;
        let user_hash = digest(
            &self.store.digester,
            TokenKind::DeviceUserCode,
            &normalize_device_user_code(&user).ok_or(Protocol::InvalidRequest)?,
        )?;
        let client = client.to_owned();
        let policy = Arc::clone(&self.policy);
        let codes = self.store.executor.execute(end, move |state,work| Ok((|| {
            let tx = state.begin(work).map_err(ControlError::from)?;
            let now = now_micros()?;
            let expires = now.checked_add(policy.ttl_micros).ok_or(ControlError::Clock)?;
            check(end,expires)?;
            let n = tx.execute("INSERT INTO oauth_device_codes(device_hash,user_hash,client_id,scopes_json,subject,local_user_revision,status,interval_seconds,last_poll_at,expires_at,created_at) VALUES(?1,?2,?3,'[]','',0,'pending',?4,NULL,?5,?6)",params![hash,user_hash,client,policy.interval_seconds,expires,now]).map_err(|e|ControlError::from(work.sql(e)))?;
            affected(n)?;
            check(end,expires)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok::<_,Error>(DeviceAuthorizationCodes {device,user,expires_at:expires,interval:policy.interval_seconds as u64})
        })())).await.map_err(ControlError::from)??;
        codes.expires_in(end)?;
        Ok(codes)
    }
    /// Consume a genuine LOCAL completion into protected review data, never approval.
    pub async fn prepare(
        &self,
        user_code: &str,
        mut login: CompletedLocalLogin,
        original: Instant,
    ) -> Result<DeviceConsent, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        self.parameters(&[user_code])?;
        let user = normalize_device_user_code(user_code).ok_or(Protocol::InvalidRequest)?;
        login
            .verify_binding(
                &self.store.digester,
                LocalAuthBinding::DeviceApprove(user.as_bytes()),
            )
            .map_err(|_| Protocol::InvalidGrant)?;
        let user_hash = digest(&self.store.digester, TokenKind::DeviceUserCode, &user)?;
        let binding = self
            .store
            .digester
            .local_auth_binding(LocalAuthBinding::DeviceApprove(user.as_bytes()))
            .map_err(|_| Protocol::Credential)?
            .to_sql_hex();
        let secret = new_local_auth_challenge().map_err(|_| Protocol::Random)?;
        let hash = digest(&self.store.digester, TokenKind::LocalAuthChallenge, &secret)?;
        let authorization = Arc::clone(&self.authorization);
        let policy = Arc::clone(&self.policy);
        let consent = self.store.executor.execute(end,move |state,work| Ok((|| {
            let tx = state.begin(work).map_err(ControlError::from)?;
            current_principal(&tx,work,&login.subject,&login.username,login.revision,authorization.limits.json_bytes,end)?;
            let d = read(&tx,work,&user_hash,true,&authorization,&policy)?;
            check(end,d.expires)?;
            if d.status != "pending" || login.observed_at.as_i64() < d.created || login.observed_at.as_i64() > now_micros()? { return Err(Protocol::InvalidGrant.into()); }
            let now = now_micros()?;
            let n = tx.execute("INSERT INTO local_auth_challenges(challenge_hash,subject,local_user_revision,purpose,binding_hash,stage,secret_ciphertext,expires_at,created_at) VALUES(?1,?2,?3,'device-approve',?4,'device_consent','',?5,?6)",params![hash,login.subject,login.revision,binding,d.expires,now]).map_err(|e|ControlError::from(work.sql(e)))?;
            affected(n)?;
            check(end,d.expires)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok::<_,Error>(DeviceConsent {secret,recovery:login.take_recovery_codes(),user_code:format!("{}-{}",&user[..4],&user[4..]),client:d.client,scope:String::new(),expires_at:d.expires})
        })())).await.map_err(ControlError::from)??;
        check(end, consent.expires_at)?;
        Ok(consent)
    }
    pub async fn decide(
        &self,
        user_code: &str,
        client: &str,
        secret: &str,
        allow: bool,
        original: Instant,
    ) -> Result<(), Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        self.parameters(&[user_code, client, secret])?;
        self.client(client)?;
        let user = normalize_device_user_code(user_code).ok_or(Protocol::InvalidRequest)?;
        validate_local_auth_challenge(secret).map_err(|_| Protocol::InvalidGrant)?;
        let hash = digest(&self.store.digester, TokenKind::LocalAuthChallenge, secret)?;
        let user_hash = digest(&self.store.digester, TokenKind::DeviceUserCode, &user)?;
        let binding = self
            .store
            .digester
            .local_auth_binding(LocalAuthBinding::DeviceApprove(user.as_bytes()))
            .map_err(|_| Protocol::Credential)?
            .to_sql_hex();
        let authorization = Arc::clone(&self.authorization);
        let policy = Arc::clone(&self.policy);
        let client = client.to_owned();
        let expires = self.store.executor.execute(end,move |state,work| Ok((|| {
            let tx = state.begin(work).map_err(ControlError::from)?;
            let c = consent_row(&tx,work,&hash)?;
            c.valid(&binding,end)?;
            let name = username(&tx,work,&c.subject)?;
            current_principal(&tx,work,&c.subject,&name,c.revision,authorization.limits.json_bytes,end)?;
            let d = read(&tx,work,&user_hash,true,&authorization,&policy)?;
            check(end,d.expires)?;
            if d.status != "pending" || d.client != client || c.created < d.created || c.expires != d.expires { return Err(Protocol::InvalidGrant.into()); }
            let n = tx.execute("UPDATE oauth_device_codes SET subject=?1,local_user_revision=?2,status=?3 WHERE device_hash=?4 AND status='pending' AND expires_at>?5",params![c.subject,c.revision,if allow {"approved"} else {"denied"},d.hash,now_micros()?]).map_err(|e|ControlError::from(work.sql(e)))?;
            affected(n)?;
            let n = tx.execute("DELETE FROM local_auth_challenges WHERE challenge_hash=?1",params![hash]).map_err(|e|ControlError::from(work.sql(e)))?;
            affected(n)?;
            check(end,d.expires)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok::<_,Error>(d.expires)
        })())).await.map_err(ControlError::from)??;
        check(end, expires)
    }
    pub async fn poll(
        &self,
        client: &str,
        device: &str,
        original: Instant,
    ) -> Result<DeviceAccessToken, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        self.parameters(&[client, device])?;
        self.client(client)?;
        validate_local_auth_challenge(
            device
                .strip_prefix("gb_dc_")
                .ok_or(Protocol::InvalidGrant)?,
        )
        .map_err(|_| Protocol::InvalidGrant)?;
        let hash = digest(&self.store.digester, TokenKind::DeviceCode, device)?;
        let authorization = Arc::clone(&self.authorization);
        let policy = Arc::clone(&self.policy);
        let issuer = Arc::clone(&self.issuer);
        let digester = Arc::clone(&self.store.digester);
        let client = client.to_owned();
        let (response,device_expiry) = self.store.executor.execute(end,move |state,work| Ok((|| {
            // BEGIN IMMEDIATE serializes current identity, consent and redemption across owners.
            let tx = state.begin(work).map_err(ControlError::from)?;
            let d = read(&tx,work,&hash,false,&authorization,&policy)?;
            if d.client != client { return Err(Protocol::InvalidGrant.into()); }
            let now = now_micros()?;
            let response = if d.expires <= now {
                delete_device(&tx,work,&d.hash)?;
                Err(Error::ExpiredToken)
            } else if d.status == "denied" {
                delete_device(&tx,work,&d.hash)?;
                Err(Error::AccessDenied)
            } else if d.last_poll.is_some_and(|last|now-last < d.interval.saturating_mul(1_000_000)) {
                let next = d.interval.checked_add(5).ok_or(Protocol::MalformedStored)?;
                let n = tx.execute("UPDATE oauth_device_codes SET interval_seconds=?1,last_poll_at=?2 WHERE device_hash=?3",params![next,now,d.hash]).map_err(|e|ControlError::from(work.sql(e)))?;
                affected(n)?;
                Err(Error::SlowDown)
            } else if d.status == "pending" {
                let n = tx.execute("UPDATE oauth_device_codes SET last_poll_at=?1 WHERE device_hash=?2",params![now,d.hash]).map_err(|e|ControlError::from(work.sql(e)))?;
                affected(n)?;
                Err(Error::AuthorizationPending)
            } else {
                let name = username(&tx,work,&d.subject)?;
                let principal = current_principal(&tx,work,&d.subject,&name,d.revision,authorization.limits.json_bytes,end)?;
                let subject = digester.oidc_subject(principal.issuer().as_bytes(),principal.subject().as_bytes()).map_err(|_|Protocol::Credential)?;
                let expires = now.checked_add(policy.access_micros).ok_or(ControlError::Clock)? / 1_000_000 * 1_000_000;
                let jti = new_local_auth_challenge().map_err(|_|Protocol::Random)?;
                let access = Zeroizing::new(issuer.sign_access(BrokerAccessTokenInput {subject:subject.as_str(),client_id:&client,resource:None,scope:"",jti:&jti,issued_at:seconds(now)?,expires_at:seconds(expires)?,preferred_username:Some(principal.username()),name:nonempty(principal.name()),email:nonempty(principal.email()),organization:nonempty(principal.organization()),groups:principal.teams(),roles:principal.roles()},end).map_err(|e|match e {crate::BrokerAccessIssueError::Deadline=>Protocol::Control(ControlError::Deadline),_=>Protocol::Signing})?);
                let json = Zeroizing::new(serde_json::to_string(&principal).map_err(|_|Protocol::MalformedStored)?);
                if json.len() as i64 > authorization.limits.json_bytes { return Err(Protocol::ReadLimitExceeded.into()); }
                let data = TokenData {principal:&principal,oidc_subject:subject.as_str(),client_id:&client,audience:&authorization.api_audience,resource:None,principal_json:&json,scopes_json:"[]",family:"",auth_time:now,created_at:now};
                let token_hash = digest(&digester,TokenKind::OidcStoredAccess,&jti)?;
                insert(&tx,work,&data,&token_hash,&jti,"oidc_access",expires)?;
                delete_device(&tx,work,&d.hash)?;
                check(end,d.expires)?;
                check(end,expires)?;
                Ok(DeviceAccessToken {access,scope:String::new(),expires_at:expires})
            };
            // Protocol denials above are committed outcomes, not rollback errors.
            gate(end)?;
            work.commit(tx).map_err(ControlError::from)?;
            Ok::<_,Error>((response,d.expires))
        })())).await.map_err(ControlError::from)??;
        gate(end)?;
        if let Ok(token) = &response {
            check(end, device_expiry)?;
            token.expires_in(end)?;
        }
        response
    }
}
fn gate(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        Err(ControlError::Deadline.into())
    } else {
        Ok(())
    }
}
fn digest(d: &CredentialDigester, kind: TokenKind, raw: &str) -> Result<String, Error> {
    d.token(kind, raw.as_bytes())
        .map(|v| v.to_sql_hex())
        .map_err(|_| Protocol::Credential.into())
}
fn affected(n: usize) -> Result<(), Error> {
    if n == 1 {
        Ok(())
    } else {
        Err(ControlError::Storage.into())
    }
}
fn seconds(now: i64) -> Result<u64, Error> {
    u64::try_from(now / 1_000_000).map_err(|_| ControlError::Clock.into())
}
fn nonempty(raw: &str) -> Option<&str> {
    (!raw.trim().is_empty()).then_some(raw)
}
fn text<'a>(r: &'a Row<'_>, k: &str) -> Result<&'a str, Error> {
    r.get_ref(k)
        .map_err(|_| Protocol::MalformedStored)?
        .as_str()
        .map_err(|_| Protocol::MalformedStored.into())
}
fn number(r: &Row<'_>, k: &str) -> Result<i64, Error> {
    r.get(k).map_err(|_| Protocol::MalformedStored.into())
}

struct DeviceRow {
    hash: String,
    user_hash: String,
    client: String,
    subject: String,
    revision: i64,
    status: String,
    interval: i64,
    last_poll: Option<i64>,
    expires: i64,
    created: i64,
}
impl DeviceRow {
    fn decode(r: &Row<'_>, cap: i64, p: &DeviceAuthorizationPolicy) -> Result<Self, Error> {
        let bytes = number(r, "scope_bytes")?;
        if bytes < 0 {
            return Err(Protocol::MalformedStored.into());
        }
        if bytes > cap {
            return Err(Protocol::ReadLimitExceeded.into());
        }
        let scopes: Vec<String> =
            serde_json::from_str(text(r, "scopes_json")?).map_err(|_| Protocol::MalformedStored)?;
        if !scopes.is_empty() {
            return Err(Protocol::MalformedStored.into());
        }
        let d = Self {
            hash: text(r, "device_hash")?.into(),
            user_hash: text(r, "user_hash")?.into(),
            client: text(r, "client_id")?.into(),
            subject: text(r, "subject")?.into(),
            revision: number(r, "local_user_revision")?,
            status: text(r, "status")?.into(),
            interval: number(r, "interval_seconds")?,
            last_poll: r
                .get("last_poll_at")
                .map_err(|_| Protocol::MalformedStored)?,
            expires: number(r, "expires_at")?,
            created: number(r, "created_at")?,
        };
        let now = now_micros()?;
        let valid_digest = |s: &str| broker_security::CredentialDigest::parse_sql_hex(s).is_ok();
        if !valid_digest(&d.hash)
            || !valid_digest(&d.user_hash)
            || d.created <= 0
            || d.created > now
            || d.expires.checked_sub(d.created) != Some(p.ttl_micros)
            || d.interval < p.interval_seconds
            || (d.interval - p.interval_seconds) % 5 != 0
            || d.interval > i64::MAX / 1_000_000
            || d.last_poll.is_some_and(|v| v < d.created || v > now)
            || match d.status.as_str() {
                "pending" => !d.subject.is_empty() || d.revision != 0,
                "approved" | "denied" => {
                    !crate::identity::valid_identity_subject(&d.subject, 512) || d.revision < 1
                }
                _ => true,
            }
        {
            return Err(Protocol::MalformedStored.into());
        }
        Ok(d)
    }
}
fn read(
    tx: &Transaction<'_>,
    work: &Work,
    hash: &str,
    by_user: bool,
    a: &OidcAuthorizationPolicy,
    p: &DeviceAuthorizationPolicy,
) -> Result<DeviceRow, Error> {
    let sql = format!(
        "{DEVICE} WHERE {}=?1",
        if by_user { "user_hash" } else { "device_hash" }
    );
    let d = tx
        .query_row(&sql, params![hash, a.limits.json_bytes], |r| {
            Ok(DeviceRow::decode(r, a.limits.json_bytes, p))
        })
        .optional()
        .map_err(|e| ControlError::from(work.sql(e)))?
        .ok_or(Protocol::InvalidGrant)??;
    if (if by_user { &d.user_hash } else { &d.hash }) != hash || d.client != a.cli_client_id {
        return Err(Protocol::MalformedStored.into());
    }
    Ok(d)
}
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
fn consent_row(tx: &Transaction<'_>, work: &Work, hash: &str) -> Result<ConsentRow, Error> {
    tx.query_row(CONSENT, params![hash], |r| {
        Ok((|| {
            Ok(ConsentRow {
                subject: text(r, "subject")?.into(),
                revision: number(r, "local_user_revision")?,
                purpose: text(r, "purpose")?.into(),
                binding: text(r, "binding_hash")?.into(),
                stage: text(r, "stage")?.into(),
                cipher: text(r, "secret_ciphertext")?.into(),
                expires: number(r, "expires_at")?,
                created: number(r, "created_at")?,
            })
        })())
    })
    .optional()
    .map_err(|e| ControlError::from(work.sql(e)))?
    .ok_or(Protocol::InvalidGrant)?
}
fn username(tx: &Transaction<'_>, work: &Work, subject: &str) -> Result<String, Error> {
    tx.query_row("SELECT CASE WHEN typeof(username)='text' AND length(CAST(username AS BLOB))<=128 THEN username END FROM local_users WHERE subject=?1",params![subject],|r|r.get::<_,Option<String>>(0)).optional().map_err(|e|ControlError::from(work.sql(e)))?.flatten().ok_or_else(||Protocol::InvalidGrant.into())
}
fn delete_device(tx: &Transaction<'_>, work: &Work, hash: &str) -> Result<(), Error> {
    affected(
        tx.execute(
            "DELETE FROM oauth_device_codes WHERE device_hash=?1",
            params![hash],
        )
        .map_err(|e| ControlError::from(work.sql(e)))?,
    )
}
const DEVICE: &str = r#"SELECT
 CASE WHEN typeof(device_hash)='text' AND length(CAST(device_hash AS BLOB))<=64 THEN device_hash END AS device_hash,
 CASE WHEN typeof(user_hash)='text' AND length(CAST(user_hash AS BLOB))<=64 THEN user_hash END AS user_hash,
 CASE WHEN typeof(client_id)='text' AND length(CAST(client_id AS BLOB))<=128 THEN client_id END AS client_id,
 CASE WHEN typeof(scopes_json)='text' THEN length(CAST(scopes_json AS BLOB)) END AS scope_bytes,
 CASE WHEN typeof(scopes_json)='text' AND length(CAST(scopes_json AS BLOB))<=?2 THEN scopes_json END AS scopes_json,
 CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=512 THEN subject END AS subject,
 local_user_revision,CASE WHEN typeof(status)='text' AND length(CAST(status AS BLOB))<=16 THEN status END AS status,
 interval_seconds,last_poll_at,expires_at,created_at FROM oauth_device_codes"#;
const CONSENT: &str = r#"SELECT
 CASE WHEN typeof(subject)='text' AND length(CAST(subject AS BLOB))<=512 THEN subject END AS subject,
 local_user_revision,CASE WHEN typeof(purpose)='text' AND length(CAST(purpose AS BLOB))<=32 THEN purpose END AS purpose,
 CASE WHEN typeof(binding_hash)='text' AND length(CAST(binding_hash AS BLOB))<=64 THEN binding_hash END AS binding_hash,
 CASE WHEN typeof(stage)='text' AND length(CAST(stage AS BLOB))<=32 THEN stage END AS stage,
 CASE WHEN typeof(secret_ciphertext)='text' AND length(CAST(secret_ciphertext AS BLOB))<=90 THEN secret_ciphertext END AS secret_ciphertext,
 expires_at,created_at FROM local_auth_challenges WHERE challenge_hash=?1"#;
