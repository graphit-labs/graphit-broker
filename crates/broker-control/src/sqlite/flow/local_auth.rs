use super::{
    SqliteControlStore,
    local_password::{CurrentPassword, PROJECTION},
};
use crate::{
    CompletedLocalLogin, ControlError, LocalAuthError as Error, LocalAuthPolicy,
    LocalAuthStage as Stage, LocalAuthStep, LocalMfaAttemptLimiter, LocalPasswordEngine,
    PendingLocalAuth, VerifiedLocalPassword,
    flow::now_micros,
    identity::{safe_identity_segment, valid_identity_subject},
    local_auth::{ensure_expiry, ensure_time, purpose_sql},
    local_password_admission::PasswordWorkLease,
    service::preserve_federated_request,
    sqlite::executor::{State, Work},
};
use broker_security::{
    CredentialDigest, CredentialDigester, LOCAL_PASSWORD_MAX_BYTES, LocalAuthBinding,
    LocalAuthPurpose, LocalMfaProtector, LocalPasswordError, LocalPasswordHasher,
    LocalRecoveryCodes, TokenKind, new_local_auth_challenge, normalize_local_recovery_code,
    validate_local_auth_challenge,
};
use broker_store::time::TimestampMicros;
use rusqlite::{OptionalExtension, Row, Transaction, params};
use std::{fmt, sync::Arc, time::Instant};
use zeroize::Zeroizing;

const USER: &str = "SELECT CASE WHEN length(CAST(username AS BLOB))<=128 THEN username END,CASE WHEN length(CAST(subject AS BLOB))<=512 THEN subject END,CASE WHEN length(CAST(identity_kind AS BLOB))<=16 THEN identity_kind END,enabled,password_change_required,revision FROM local_users WHERE subject=?1";
const CHALLENGE: &str = "SELECT CASE WHEN length(CAST(challenge_hash AS BLOB))<=64 THEN challenge_hash END,CASE WHEN length(CAST(subject AS BLOB))<=512 THEN subject END,local_user_revision,CASE WHEN length(CAST(purpose AS BLOB))<=32 THEN purpose END,CASE WHEN length(CAST(binding_hash AS BLOB))<=64 THEN binding_hash END,CASE WHEN length(CAST(stage AS BLOB))<=32 THEN stage END,CASE WHEN length(CAST(secret_ciphertext AS BLOB))<=90 THEN secret_ciphertext END,expires_at,created_at FROM local_auth_challenges WHERE challenge_hash=?1";

#[derive(Clone)]
struct Crypto {
    digester: Arc<CredentialDigester>,
    mfa: Arc<LocalMfaProtector>,
    policy: Arc<LocalAuthPolicy>,
}
#[derive(Clone)]
enum Binding {
    Admin,
    OAuth(Zeroizing<Vec<u8>>),
    Device(Zeroizing<Vec<u8>>),
}
impl Binding {
    fn new(crypto: &Crypto, context: LocalAuthBinding<'_>) -> Result<Self, Error> {
        // Enforce the existing digest limits before making an owned worker input.
        crypto.digester.local_auth_binding(context)?;
        Ok(match context {
            LocalAuthBinding::AdminLogin => Self::Admin,
            LocalAuthBinding::OauthAuthorize(v) => Self::OAuth(Zeroizing::new(v.to_vec())),
            LocalAuthBinding::DeviceApprove(v) => Self::Device(Zeroizing::new(v.to_vec())),
        })
    }
    fn context(&self) -> LocalAuthBinding<'_> {
        match self {
            Self::Admin => LocalAuthBinding::AdminLogin,
            Self::OAuth(v) => LocalAuthBinding::OauthAuthorize(v),
            Self::Device(v) => LocalAuthBinding::DeviceApprove(v),
        }
    }
}
#[derive(Clone)]
struct Input {
    crypto: Crypto,
    context: Binding,
    raw: Zeroizing<String>,
    hash: String,
}
impl Input {
    fn new(crypto: &Crypto, raw: &str, context: LocalAuthBinding<'_>) -> Result<Self, Error> {
        validate_local_auth_challenge(raw).map_err(|_| Error::InvalidChallenge)?;
        Ok(Self {
            crypto: crypto.clone(),
            context: Binding::new(crypto, context)?,
            raw: Zeroizing::new(raw.to_owned()),
            hash: crypto
                .digester
                .token(TokenKind::LocalAuthChallenge, raw.as_bytes())?
                .to_sql_hex(),
        })
    }
    fn validate(&self, row: &Challenge) -> Result<(), Error> {
        if row.purpose != purpose_sql(self.context.context().purpose())
            || row.created > now_micros()?
        {
            return Err(Error::InvalidChallenge);
        }
        ensure_expiry(row.expires, now_micros()?)?;
        let digest =
            CredentialDigest::parse_sql_hex(&row.hash).map_err(|_| Error::InvalidChallenge)?;
        self.crypto
            .digester
            .verify_token(TokenKind::LocalAuthChallenge, self.raw.as_bytes(), &digest)
            .map_err(|_| Error::InvalidChallenge)?;
        let digest =
            CredentialDigest::parse_sql_hex(&row.binding).map_err(|_| Error::InvalidChallenge)?;
        self.crypto
            .digester
            .verify_local_auth_binding(self.context.context(), &digest)
            .map_err(|_| Error::InvalidChallenge)?;
        Ok(())
    }
}
#[derive(PartialEq, Eq)]
struct User {
    username: String,
    subject: String,
    revision: i64,
    change: bool,
}
impl User {
    fn decode(row: &Row<'_>) -> Option<Self> {
        let username = row.get::<_, Option<String>>(0).ok()??;
        let subject = row.get::<_, Option<String>>(1).ok()??;
        let kind = row.get::<_, Option<String>>(2).ok()??;
        let enabled: i64 = row.get(3).ok()?;
        let change: i64 = row.get(4).ok()?;
        let revision: i64 = row.get(5).ok()?;
        if !safe_identity_segment(&username, 128)
            || !valid_identity_subject(&subject, 512)
            || kind != "human"
            || enabled != 1
            || !matches!(change, 0 | 1)
            || revision < 1
        {
            return None;
        }
        Some(Self {
            username,
            subject,
            revision,
            change: change == 1,
        })
    }
}
#[derive(PartialEq, Eq)]
struct Challenge {
    hash: String,
    subject: String,
    revision: i64,
    purpose: String,
    binding: String,
    stage: Stage,
    cipher: Zeroizing<String>,
    expires: i64,
    created: i64,
}
impl Challenge {
    fn decode(row: &Row<'_>) -> Result<Self, Error> {
        let invalid = |_| Error::InvalidChallenge;
        let cipher = Zeroizing::new(
            row.get::<_, Option<String>>(6)
                .map_err(invalid)?
                .ok_or(Error::InvalidChallenge)?,
        );
        let text = |n| {
            row.get::<_, Option<String>>(n)
                .map_err(invalid)?
                .ok_or(Error::InvalidChallenge)
        };
        let value = Self {
            hash: text(0)?,
            subject: text(1)?,
            revision: row.get(2).map_err(invalid)?,
            purpose: text(3)?,
            binding: text(4)?,
            stage: Stage::parse(&text(5)?)?,
            cipher,
            expires: row.get(7).map_err(invalid)?,
            created: row.get(8).map_err(invalid)?,
        };
        if !valid_identity_subject(&value.subject, 512)
            || value.revision < 1
            || value.created <= 0
            || value.expires <= value.created
            || !matches!(
                value.purpose.as_str(),
                "admin-login" | "oauth-authorize" | "device-approve"
            )
            || (value.stage == Stage::Enrollment && value.cipher.len() != 90)
            || (value.stage != Stage::Enrollment && !value.cipher.is_empty())
        {
            return Err(Error::InvalidChallenge);
        }
        CredentialDigest::parse_sql_hex(&value.hash).map_err(|_| Error::InvalidChallenge)?;
        CredentialDigest::parse_sql_hex(&value.binding).map_err(|_| Error::InvalidChallenge)?;
        Ok(value)
    }
}
fn sql(work: &Work, e: rusqlite::Error) -> Error {
    ControlError::from(work.sql(e)).into()
}
fn user(tx: &Transaction<'_>, subject: &str, work: &Work) -> Result<Option<User>, Error> {
    tx.query_row(USER, [subject], |r| Ok(User::decode(r)))
        .optional()
        .map(|r| r.flatten())
        .map_err(|e| sql(work, e))
}
fn challenge(tx: &Transaction<'_>, hash: &str, work: &Work) -> Result<Challenge, Error> {
    tx.query_row(CHALLENGE, [hash], |r| Ok(Challenge::decode(r)))
        .optional()
        .map_err(|e| sql(work, e))?
        .ok_or(Error::InvalidChallenge)?
}
fn factor_present(tx: &Transaction<'_>, subject: &str, work: &Work) -> Result<bool, Error> {
    tx.query_row(
        "SELECT 1 FROM local_mfa WHERE subject=?1",
        [subject],
        |_| Ok(()),
    )
    .optional()
    .map(|v| v.is_some())
    .map_err(|e| sql(work, e))
}
fn changed(
    tx: &Transaction<'_>,
    statement: &str,
    p: impl rusqlite::Params,
    work: &Work,
) -> Result<(), Error> {
    if tx.execute(statement, p).map_err(|e| sql(work, e))? != 1 {
        return Err(ControlError::Storage.into());
    }
    Ok(())
}
fn gates(end: Instant, expires: Option<i64>) -> Result<(), Error> {
    ensure_time(end)?;
    if let Some(expires) = expires {
        ensure_expiry(expires, now_micros()?)?;
    }
    Ok(())
}
fn invalidate(
    tx: &Transaction<'_>,
    subject: &str,
    purpose: LocalAuthPurpose,
    now: i64,
    end: Instant,
    work: &Work,
) -> Result<(), Error> {
    invalidate_local_user(
        tx,
        subject,
        matches!(purpose, LocalAuthPurpose::DeviceApprove),
        now,
        end,
        work,
    )
}

pub(super) fn invalidate_local_user(
    tx: &Transaction<'_>,
    subject: &str,
    preserve_device: bool,
    now: i64,
    end: Instant,
    work: &Work,
) -> Result<(), Error> {
    tx.execute("UPDATE local_tokens SET revoked_at=?1 WHERE subject=?2 AND local_user_revision>=1 AND revoked_at IS NULL",params![now,subject]).map_err(|e|sql(work,e))?;
    let mut after: Option<String> = None;
    loop {
        ensure_time(end)?;
        let row:Option<(String,String)>=tx.query_row("SELECT request_hash,request_json FROM oidc_auth_requests WHERE identity_subject=?1 AND (?2 IS NULL OR request_hash>?2) ORDER BY request_hash COLLATE BINARY LIMIT 1",params![subject,after],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|sql(work,e))?;
        let Some((hash, json)) = row else { break };
        let json = Zeroizing::new(json);
        let preserve = preserve_federated_request(&json)?;
        ensure_time(end)?;
        if !preserve {
            changed(
                tx,
                "DELETE FROM oidc_auth_requests WHERE request_hash=?1 AND identity_subject=?2",
                params![&hash, subject],
                work,
            )?;
        }
        after = Some(hash);
    }
    tx.execute(
        "DELETE FROM local_auth_challenges WHERE subject=?1",
        [subject],
    )
    .map_err(|e| sql(work, e))?;
    if !preserve_device {
        tx.execute("DELETE FROM oauth_device_codes WHERE subject=?1", [subject])
            .map_err(|e| sql(work, e))?;
    }
    Ok(())
}
fn advance(
    tx: &Transaction<'_>,
    current: &User,
    factor: bool,
    context: &Binding,
    crypto: &Crypto,
    end: Instant,
    work: &Work,
) -> Result<(LocalAuthStep, Option<i64>), Error> {
    let stage = if current.change {
        Some(Stage::PasswordChange)
    } else if !crypto.policy.required {
        None
    } else if factor {
        Some(Stage::Mfa)
    } else {
        Some(Stage::Enrollment)
    };
    let now = now_micros()?;
    let observed_at = TimestampMicros::new(now).map_err(|_| ControlError::Clock)?;
    let binding = crypto.digester.local_auth_binding(context.context())?;
    let Some(stage) = stage else {
        return Ok((
            LocalAuthStep::Complete(CompletedLocalLogin {
                username: current.username.clone(),
                subject: current.subject.clone(),
                revision: current.revision,
                observed_at,
                purpose: context.context().purpose(),
                binding,
                factor_verified: false,
                recovery_codes: None,
            }),
            None,
        ));
    };
    let ttl =
        i64::try_from(crypto.policy.challenge_ttl.as_micros()).map_err(|_| Error::InvalidPolicy)?;
    let expires = now.checked_add(ttl).ok_or(ControlError::Clock)?;
    let (cipher, enrollment) = if stage == Stage::Enrollment {
        let (cipher, enrollment) = crypto
            .mfa
            .prepare(
                &current.subject,
                &crypto.policy.issuer_label,
                &current.username,
            )?
            .into_parts();
        (cipher, Some(enrollment))
    } else {
        (Zeroizing::new(String::new()), None)
    };
    gates(end, Some(expires))?;
    let raw = new_local_auth_challenge()?;
    let hash = crypto
        .digester
        .token(TokenKind::LocalAuthChallenge, raw.as_bytes())?
        .to_sql_hex();
    tx.execute(
        "DELETE FROM local_auth_challenges WHERE subject=?1 AND purpose=?2",
        params![&current.subject, purpose_sql(context.context().purpose())],
    )
    .map_err(|e| sql(work, e))?;
    changed(
        tx,
        "INSERT INTO local_auth_challenges(challenge_hash,subject,local_user_revision,purpose,binding_hash,stage,secret_ciphertext,expires_at,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            hash,
            &current.subject,
            current.revision,
            purpose_sql(context.context().purpose()),
            binding.to_sql_hex(),
            stage.sql(),
            cipher.as_str(),
            expires,
            now
        ],
        work,
    )?;
    Ok((
        LocalAuthStep::Pending(PendingLocalAuth {
            stage,
            challenge: raw,
            enrollment,
        }),
        Some(expires),
    ))
}

/// SQL-backed LOCAL stages using the actual shared cryptographic owners.
pub struct SqliteLocalAuthService<'a> {
    owner: &'a SqliteControlStore,
    crypto: Crypto,
}
impl fmt::Debug for SqliteLocalAuthService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalAuthService([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_auth_service(
        &self,
        digester: Arc<CredentialDigester>,
        mfa: Arc<LocalMfaProtector>,
        policy: Arc<LocalAuthPolicy>,
    ) -> SqliteLocalAuthService<'_> {
        SqliteLocalAuthService {
            owner: self,
            crypto: Crypto {
                digester,
                mfa,
                policy,
            },
        }
    }
}
impl SqliteLocalAuthService<'_> {
    fn end(&self, original: Instant) -> Result<Instant, Error> {
        self.owner
            .executor
            .deadline(original)
            .map_err(|e| ControlError::from(e).into())
    }
    async fn run<T: Send + 'static>(
        &self,
        end: Instant,
        body: impl FnOnce(&mut State, &Work) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        self.owner
            .executor
            .execute(end, move |owner, work| Ok(body(owner, work)))
            .await
            .map_err(ControlError::from)?
    }
    pub async fn begin(
        &self,
        proof: VerifiedLocalPassword,
        context: LocalAuthBinding<'_>,
        original: Instant,
    ) -> Result<LocalAuthStep, Error> {
        let end = self.end(original)?;
        let context = Binding::new(&self.crypto, context)?;
        let crypto = self.crypto.clone();
        let (result, expiry) = self
            .run(end, move |owner, work| {
                let tx = owner.begin(work).map_err(ControlError::from)?;
                let current = user(&tx, proof.subject(), work)?.ok_or(Error::Unauthenticated)?;
                if current.username != proof.username()
                    || current.subject != proof.subject()
                    || current.revision != proof.revision()
                {
                    return Err(Error::Unauthenticated);
                }
                let factor = factor_present(&tx, &current.subject, work)?;
                let (result, expiry) =
                    advance(&tx, &current, factor, &context, &crypto, end, work)?;
                gates(end, expiry)?;
                work.commit(tx).map_err(ControlError::from)?;
                gates(end, expiry)?;
                Ok((result, expiry))
            })
            .await?;
        gates(end, expiry)?;
        Ok(result)
    }
    pub async fn load(
        &self,
        raw: &str,
        context: LocalAuthBinding<'_>,
        original: Instant,
    ) -> Result<PendingLocalAuth, Error> {
        let end = self.end(original)?;
        let input = Input::new(&self.crypto, raw, context)?;
        let (result, expires) = self
            .run(end, move |owner, work| {
                let tx = owner.begin(work).map_err(ControlError::from)?;
                let row = challenge(&tx, &input.hash, work)?;
                input.validate(&row)?;
                let current = user(&tx, &row.subject, work)?.ok_or(Error::InvalidChallenge)?;
                let factor = factor_present(&tx, &current.subject, work)?;
                if current.revision != row.revision
                    || current.subject != row.subject
                    || current.change != (row.stage == Stage::PasswordChange)
                    || (row.stage == Stage::Mfa && !factor)
                    || (row.stage == Stage::Enrollment && factor)
                {
                    return Err(Error::InvalidChallenge);
                }
                let enrollment = if row.stage == Stage::Enrollment {
                    Some(input.crypto.mfa.load(
                        &current.subject,
                        &row.cipher,
                        &input.crypto.policy.issuer_label,
                        &current.username,
                    )?)
                } else {
                    None
                };
                gates(end, Some(row.expires))?;
                work.commit(tx).map_err(ControlError::from)?;
                gates(end, Some(row.expires))?;
                Ok((
                    PendingLocalAuth {
                        stage: row.stage,
                        challenge: input.raw,
                        enrollment,
                    },
                    row.expires,
                ))
            })
            .await?;
        gates(end, Some(expires))?;
        Ok(result)
    }
    pub async fn complete_password_change(
        &self,
        engine: &LocalPasswordEngine,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
        original: Instant,
    ) -> Result<LocalAuthStep, Error> {
        self.change(engine, raw, context, new_password, original, None)
            .await
    }
    pub(crate) async fn complete_password_change_admitted(
        &self,
        engine: &LocalPasswordEngine,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
        original: Instant,
        lease: Arc<PasswordWorkLease>,
    ) -> Result<LocalAuthStep, Error> {
        self.change(engine, raw, context, new_password, original, Some(lease))
            .await
    }
    async fn change(
        &self,
        engine: &LocalPasswordEngine,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
        original: Instant,
        lease: Option<Arc<PasswordWorkLease>>,
    ) -> Result<LocalAuthStep, Error> {
        let end = self.end(original)?;
        if let Some(lease) = &lease {
            lease.check_work(end)?;
        }
        let input = Input::new(&self.crypto, raw, context)?;
        let initial_input = input.clone();
        let snapshot_lease = lease.as_ref().map(Arc::clone);
        let (initial, password) = self
            .run(end, move |owner, work| {
                let tx = owner.begin(work).map_err(ControlError::from)?;
                // Preserve real admission through an abandoned initial SQL worker.
                let _lease = snapshot_lease;
                let row = challenge(&tx, &initial_input.hash, work)?;
                initial_input.validate(&row)?;
                if row.stage != Stage::PasswordChange {
                    return Err(Error::InvalidChallenge);
                }
                let statement = format!("SELECT {PROJECTION} FROM local_users WHERE subject=?1");
                let password = tx
                    .query_row(&statement, [&row.subject], |r| {
                        Ok(CurrentPassword::decode(r))
                    })
                    .optional()
                    .map_err(|e| sql(work, e))?
                    .flatten()
                    .ok_or(Error::InvalidChallenge)?;
                LocalPasswordHasher::validate_hash(&password.hash)
                    .map_err(|_| Error::InvalidChallenge)?;
                if !password.change_required
                    || password.revision != row.revision
                    || password.subject != row.subject
                {
                    return Err(Error::InvalidChallenge);
                }
                work.commit(tx).map_err(ControlError::from)?;
                Ok((row, password))
            })
            .await?;
        tracing::trace!(target: "broker_control::sqlite::password_change_snapshot", "SQLite password-change snapshot ready");
        if new_password.len() > LOCAL_PASSWORD_MAX_BYTES || new_password.chars().count() < 15 {
            return Err(Error::Password(LocalPasswordError::InvalidPassword));
        }
        password
            .revision
            .checked_add(1)
            .ok_or(Error::InvalidChallenge)?;
        let unchanged = match &lease {
            Some(lease) => {
                engine
                    .verify_for_change(new_password, Some(&password.hash), Arc::clone(lease), end)
                    .await?
            }
            None => {
                engine
                    .verify(new_password, Some(&password.hash), end)
                    .await?
            }
        };
        if unchanged {
            return Err(Error::PasswordUnchanged);
        }
        let new_hash = match &lease {
            Some(lease) => {
                engine
                    .hash_for_change(new_password, Arc::clone(lease), end)
                    .await?
            }
            None => engine.hash(new_password, end).await?,
        };
        gates(end, Some(initial.expires))?;
        let check_lease = lease.as_ref().map(Arc::clone);
        let (result,expiry)=self.run(end,move|owner,work|{
            let tx=owner.begin(work).map_err(ControlError::from)?;
            let row=challenge(&tx,&input.hash,work)?;
            input.validate(&row)?;
            let statement=format!("SELECT {PROJECTION} FROM local_users WHERE subject=?1");
            let current=tx.query_row(&statement,[&row.subject],|r|Ok(CurrentPassword::decode(r))).optional().map_err(|e|sql(work,e))?.flatten().ok_or(Error::InvalidChallenge)?;
            if row!=initial||current!=password||!current.change_required{return Err(Error::InvalidChallenge);}
            let factor=factor_present(&tx,&current.subject,work)?;
            let next=current.revision.checked_add(1).ok_or(Error::InvalidChallenge)?;
            let now=now_micros()?;
            gates(end,Some(row.expires))?;
            if let Some(lease)=&check_lease{lease.check_work(end)?;}
            changed(&tx,"UPDATE local_users SET password_hash=?1,password_change_required=0,revision=?2,updated_at=?3 WHERE subject=?4 AND revision=?5 AND password_change_required=1 AND password_hash=?6",params![new_hash.as_str(),next,now,&current.subject,current.revision,current.hash.as_str()],work)?;
            invalidate(&tx,&current.subject,input.context.context().purpose(),now,end,work)?;
            let current=User{username:current.username,subject:current.subject,revision:next,change:false};
            let (result,expiry)=advance(&tx,&current,factor,&input.context,&input.crypto,end,work)?;
            gates(end,Some(row.expires))?;
            gates(end,expiry)?;
            if let Some(lease)=&check_lease{lease.check_work(end)?;}
            work.commit(tx).map_err(ControlError::from)?;
            gates(end,expiry)?;
            if let Some(lease)=&check_lease{lease.check_work(end)?;}
            Ok((result,expiry))
        }).await?;
        gates(end, expiry)?;
        if let Some(lease) = &lease {
            lease.check_work(end)?;
        }
        Ok(result)
    }
    pub async fn complete_mfa(
        &self,
        limiter: Arc<LocalMfaAttemptLimiter>,
        raw: &str,
        context: LocalAuthBinding<'_>,
        code: &str,
        original: Instant,
    ) -> Result<LocalAuthStep, Error> {
        let end = self.end(original)?;
        if code.len() > 64 {
            return Err(Error::InvalidMfaCode);
        }
        let input = Input::new(&self.crypto, raw, context)?;
        let code = Zeroizing::new(code.to_owned());
        let (result,expires)=self.run(end,move|owner,work|{
            let tx=owner.begin(work).map_err(ControlError::from)?;
            let row=challenge(&tx,&input.hash,work)?;
            input.validate(&row)?;
            if row.stage==Stage::PasswordChange{return Err(Error::InvalidChallenge);}
            let mut current=user(&tx,&row.subject,work)?.ok_or(Error::InvalidChallenge)?;
            if current.change||current.subject!=row.subject||current.revision!=row.revision{return Err(Error::InvalidChallenge);}
            let factor=tx.query_row("SELECT CASE WHEN length(CAST(secret_ciphertext AS BLOB))<=90 THEN secret_ciphertext END,last_totp_step,confirmed_at FROM local_mfa WHERE subject=?1",[&current.subject],|r|Ok((r.get::<_,Option<String>>(0).map(|v|v.map(Zeroizing::new)),r.get::<_,i64>(1),r.get::<_,i64>(2)))).optional().map_err(|e|sql(work,e))?;
            let (cipher,last_step)=match(row.stage,factor){
                (Stage::Enrollment,None)=>{
                    let orphan:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM local_mfa_recovery_codes WHERE subject=?1)",[&current.subject],|r|r.get(0)).map_err(|e|sql(work,e))?;
                    if orphan{return Err(Error::InvalidChallenge);}
                    (row.cipher,-1)
                },
                (Stage::Mfa,Some((Ok(Some(cipher)),Ok(step),Ok(confirmed))))if step>=0&&confirmed>0&&cipher.len()==90=>(cipher,step),
                _=>return Err(Error::InvalidChallenge),
            };
            let mut attempt=limiter.admit(&current.subject)?;
            let now=now_micros()?;
            let seconds=u64::try_from(now/1_000_000).map_err(|_|ControlError::Clock)?;
            let accepted=input.crypto.mfa.verify(&current.subject,&cipher,&code,seconds,last_step)?;
            gates(end,Some(row.expires))?;
            let mut recovery_codes=None;
            let mut verified=accepted.is_some();
            if row.stage==Stage::Enrollment{
                if let Some(step)=accepted{
                    let next=current.revision.checked_add(1).ok_or(Error::InvalidChallenge)?;
                    let cipher=input.crypto.mfa.reencrypt(&current.subject,&cipher)?;
                    let codes=LocalRecoveryCodes::generate()?;
                    changed(&tx,"UPDATE local_users SET revision=?1,updated_at=?2 WHERE subject=?3 AND revision=?4 AND password_change_required=0",params![next,now,&current.subject,current.revision],work)?;
                    changed(&tx,"INSERT INTO local_mfa(subject,secret_ciphertext,last_totp_step,confirmed_at) VALUES(?1,?2,?3,?4)",params![&current.subject,cipher.as_str(),step,now],work)?;
                    for code in codes.iter(){
                        let normalized=normalize_local_recovery_code(code).ok_or(ControlError::Storage)?;
                        let hash=input.crypto.digester.recovery(current.subject.as_bytes(),normalized.as_bytes())?.to_sql_hex();
                        changed(&tx,"INSERT INTO local_mfa_recovery_codes(subject,code_hash,created_at) VALUES(?1,?2,?3)",params![&current.subject,hash,now],work)?;
                    }
                    invalidate(&tx,&current.subject,input.context.context().purpose(),now,end,work)?;
                    current.revision=next;
                    recovery_codes=Some(codes);
                }
            }else if let Some(step)=accepted{
                changed(&tx,"UPDATE local_mfa SET last_totp_step=?1 WHERE subject=?2 AND last_totp_step=?3 AND last_totp_step<?1",params![step,&current.subject,last_step],work)?;
            }else if let Some(normalized)=normalize_local_recovery_code(&code){
                let hash=input.crypto.digester.recovery(current.subject.as_bytes(),normalized.as_bytes())?.to_sql_hex();
                verified=tx.execute("DELETE FROM local_mfa_recovery_codes WHERE subject=?1 AND code_hash=?2",params![&current.subject,hash]).map_err(|e|sql(work,e))?==1;
            }
            if verified{
                if row.stage==Stage::Mfa{changed(&tx,"DELETE FROM local_auth_challenges WHERE challenge_hash=?1 AND local_user_revision=?2",params![&input.hash,current.revision],work)?;}
                gates(end,Some(row.expires))?;
                work.commit(tx).map_err(ControlError::from)?;
                gates(end,Some(row.expires))?;
                let observed_at=TimestampMicros::new(now_micros()?).map_err(|_|ControlError::Clock)?;
                attempt.success()?;
                let binding=input.crypto.digester.local_auth_binding(input.context.context())?;
                Ok((LocalAuthStep::Complete(CompletedLocalLogin{username:current.username,subject:current.subject,revision:current.revision,observed_at,purpose:input.context.context().purpose(),binding,factor_verified:true,recovery_codes}),row.expires))
            }else{
                if row.stage==Stage::Enrollment{attempt.failure()?;}
                let enrollment=if row.stage==Stage::Enrollment{Some(input.crypto.mfa.load(&current.subject,&cipher,&input.crypto.policy.issuer_label,&current.username)?)}else{None};
                gates(end,Some(row.expires))?;
                work.commit(tx).map_err(ControlError::from)?;
                gates(end,Some(row.expires))?;
                if row.stage==Stage::Mfa{attempt.failure()?;}
                Ok((LocalAuthStep::Pending(PendingLocalAuth{stage:row.stage,challenge:input.raw,enrollment}),row.expires))
            }
        }).await?;
        gates(end, Some(expires))?;
        Ok(result)
    }
}
