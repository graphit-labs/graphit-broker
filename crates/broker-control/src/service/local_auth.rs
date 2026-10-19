use super::{
    ConnectionGuard, PostgresControlStore, bounded_deadline, storage_error, timeout_error,
};
use crate::{
    CompletedLocalLogin, ControlError, LocalAuthError, LocalAuthPolicy, LocalAuthStage,
    LocalAuthStep, LocalMfaAttemptLimiter, LocalPasswordEngine, PendingLocalAuth,
    VerifiedLocalPassword,
    flow::now_micros,
    identity::{safe_identity_segment, valid_identity_subject},
    local_auth::{ensure_expiry, ensure_time, purpose_sql},
    local_password_admission::PasswordWorkLease,
};
use broker_security::{
    CredentialDigest, CredentialDigester, LOCAL_PASSWORD_MAX_BYTES, LocalAuthBinding,
    LocalAuthPurpose, LocalMfaProtector, LocalPasswordError, LocalPasswordHasher,
    LocalRecoveryCodes, TokenKind, new_local_auth_challenge, normalize_local_recovery_code,
    validate_local_auth_challenge,
};
use broker_store::time::TimestampMicros;
use sqlx_core::connection::Connection;
use sqlx_postgres::PgConnection;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use zeroize::Zeroizing;

// This borrowed projection decides invalidation; it supplies no authentication.
#[derive(serde::Deserialize)]
struct AuthorizationInvalidation<'a> {
    #[serde(borrow)]
    format: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    phase: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    principal: InvalidationPrincipal<'a>,
}
#[derive(serde::Deserialize)]
struct InvalidationPrincipal<'a> {
    #[serde(borrow)]
    issuer: std::borrow::Cow<'a, str>,
    #[serde(borrow)]
    auth_method: std::borrow::Cow<'a, str>,
    local_user_revision: i64,
}
pub(crate) fn preserve_federated_request(raw: &str) -> Result<bool, LocalAuthError> {
    // Validate all syntax even when the minimal projection has an early shape error.
    let mut syntax = serde_json::Deserializer::from_str(raw);
    <serde::de::IgnoredAny as serde::Deserialize>::deserialize(&mut syntax)
        .map_err(|_| ControlError::Storage)?;
    syntax.end().map_err(|_| ControlError::Storage)?;
    Ok(
        serde_json::from_str::<AuthorizationInvalidation<'_>>(raw).is_ok_and(|p| {
            p.format == "rust-broker-authorization-v1"
                && p.phase == "authorized"
                && p.principal.issuer != "local"
                && crate::oidc_access_grant::canonical(p.principal.issuer.as_ref())
                && p.principal.auth_method == "oidc"
                && p.principal.local_user_revision == 0
        }),
    )
}

const USER_UPDATE: &str = "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,enabled::bigint,password_change_required::bigint,revision FROM public.local_users WHERE subject=$1 FOR UPDATE";
const USER_SHARE: &str = "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,enabled::bigint,password_change_required::bigint,revision FROM public.local_users WHERE subject=$1 FOR SHARE";
type UserRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
);
struct CurrentUser {
    username: String,
    subject: String,
    revision: i64,
    change: bool,
}
impl CurrentUser {
    fn from_row(row: UserRow) -> Option<Self> {
        let (username, subject, kind, enabled, change, revision) = row;
        let username = username?;
        let subject = subject?;
        if !safe_identity_segment(&username, 128)
            || !valid_identity_subject(&subject, 512)
            || kind.as_deref() != Some("human")
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
const CHALLENGE_INITIAL: &str = "SELECT CASE WHEN octet_length(challenge_hash)<=64 THEN challenge_hash END,CASE WHEN octet_length(subject)<=512 THEN subject END,local_user_revision,CASE WHEN octet_length(purpose)<=32 THEN purpose END,CASE WHEN octet_length(binding_hash)<=64 THEN binding_hash END,CASE WHEN octet_length(stage)<=32 THEN stage END,CASE WHEN octet_length(secret_ciphertext)<=90 THEN secret_ciphertext END,expires_at,created_at FROM public.local_auth_challenges WHERE challenge_hash=$1";
const CHALLENGE_FINAL: &str = "SELECT CASE WHEN octet_length(challenge_hash)<=64 THEN challenge_hash END,CASE WHEN octet_length(subject)<=512 THEN subject END,local_user_revision,CASE WHEN octet_length(purpose)<=32 THEN purpose END,CASE WHEN octet_length(binding_hash)<=64 THEN binding_hash END,CASE WHEN octet_length(stage)<=32 THEN stage END,CASE WHEN octet_length(secret_ciphertext)<=90 THEN secret_ciphertext END,expires_at,created_at FROM public.local_auth_challenges WHERE challenge_hash=$1 FOR SHARE";
const CHALLENGE_UPDATE: &str = "SELECT CASE WHEN octet_length(challenge_hash)<=64 THEN challenge_hash END,CASE WHEN octet_length(subject)<=512 THEN subject END,local_user_revision,CASE WHEN octet_length(purpose)<=32 THEN purpose END,CASE WHEN octet_length(binding_hash)<=64 THEN binding_hash END,CASE WHEN octet_length(stage)<=32 THEN stage END,CASE WHEN octet_length(secret_ciphertext)<=90 THEN secret_ciphertext END,expires_at,created_at FROM public.local_auth_challenges WHERE challenge_hash=$1 FOR UPDATE";
const PASSWORD_USER_UPDATE: &str = "SELECT CASE WHEN octet_length(username)<=128 THEN username END,CASE WHEN octet_length(subject)<=512 THEN subject END,CASE WHEN octet_length(identity_kind)<=16 THEN identity_kind END,enabled::bigint,password_change_required::bigint,revision,CASE WHEN octet_length(password_hash)<=512 THEN password_hash END FROM public.local_users WHERE subject=$1 FOR UPDATE";
type PasswordUserRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
    Option<String>,
);
type ChallengeRow = (
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    i64,
);
#[derive(Eq, PartialEq)]
struct ChallengeRecord {
    hash: String,
    subject: String,
    revision: i64,
    purpose: String,
    binding: String,
    stage: LocalAuthStage,
    cipher: Zeroizing<String>,
    expires: i64,
    created: i64,
}
impl ChallengeRecord {
    fn from_row(row: ChallengeRow) -> Result<Self, LocalAuthError> {
        let (hash, subject, revision, purpose, binding, stage, cipher, expires, created) = row;
        let cipher = Zeroizing::new(cipher.ok_or(LocalAuthError::InvalidChallenge)?);
        let hash = hash.ok_or(LocalAuthError::InvalidChallenge)?;
        let subject = subject.ok_or(LocalAuthError::InvalidChallenge)?;
        let purpose = purpose.ok_or(LocalAuthError::InvalidChallenge)?;
        let binding = binding.ok_or(LocalAuthError::InvalidChallenge)?;
        let stage = LocalAuthStage::parse(&stage.ok_or(LocalAuthError::InvalidChallenge)?)?;
        if !valid_identity_subject(&subject, 512)
            || revision < 1
            || created <= 0
            || expires <= created
            || !matches!(
                purpose.as_str(),
                "admin-login" | "oauth-authorize" | "device-approve"
            )
            || (stage == LocalAuthStage::Enrollment && cipher.len() != 90)
            || (stage != LocalAuthStage::Enrollment && !cipher.is_empty())
        {
            return Err(LocalAuthError::InvalidChallenge);
        }
        CredentialDigest::parse_sql_hex(&hash).map_err(|_| LocalAuthError::InvalidChallenge)?;
        CredentialDigest::parse_sql_hex(&binding).map_err(|_| LocalAuthError::InvalidChallenge)?;
        Ok(Self {
            hash,
            subject,
            revision,
            purpose,
            binding,
            stage,
            cipher,
            expires,
            created,
        })
    }
}
/// Borrows owners and explicit policy. Begin consumes real password evidence;
/// load is a non-consuming observation and cannot confirm a factor.
pub struct PostgresLocalAuthService<'a> {
    owner: &'a PostgresControlStore,
    digester: &'a CredentialDigester,
    mfa: &'a LocalMfaProtector,
    policy: &'a LocalAuthPolicy,
}
impl fmt::Debug for PostgresLocalAuthService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostgresLocalAuthService([REDACTED])")
    }
}
impl PostgresControlStore {
    pub fn local_auth_service<'a>(
        &'a self,
        digester: &'a CredentialDigester,
        mfa: &'a LocalMfaProtector,
        policy: &'a LocalAuthPolicy,
    ) -> PostgresLocalAuthService<'a> {
        PostgresLocalAuthService {
            owner: self,
            digester,
            mfa,
            policy,
        }
    }
}
impl PostgresLocalAuthService<'_> {
    pub async fn begin(
        &self,
        proof: VerifiedLocalPassword,
        context: LocalAuthBinding<'_>,
        original: Instant,
    ) -> Result<LocalAuthStep, LocalAuthError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        let binding = self.digester.local_auth_binding(context)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.owner.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            let current = sqlx_core::query_as::query_as::<_, UserRow>(USER_UPDATE)
                .bind(proof.subject())
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?
                .and_then(CurrentUser::from_row)
                .ok_or(LocalAuthError::Unauthenticated)?;
            if current.username != proof.username()
                || current.revision != proof.revision()
                || current.subject != proof.subject()
            {
                return Err(LocalAuthError::Unauthenticated);
            }
            let factor = sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT true FROM public.local_mfa WHERE subject=$1 FOR SHARE",
            )
            .bind(&current.subject)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_error)?
            .is_some();
            let (result, expires) = self
                .advance(&mut tx, &current, factor, context, binding, end)
                .await?;
            ensure_time(end)?;
            if let Some(expiry) = expires {
                ensure_expiry(expiry, now_micros()?)?;
            }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            ensure_time(end)?;
            if let Some(expiry) = expires {
                ensure_expiry(expiry, now_micros()?)?;
            }
            Ok(result)
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }
    /// Changes a current mandatory password and advances LOCAL in one transaction.
    /// The engine must be the shared login engine provisioned with the same pepper.
    /// A pending result confirms no factor, session, consent or OAuth grant.
    pub async fn complete_password_change(
        &self,
        engine: &LocalPasswordEngine,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
        original: Instant,
    ) -> Result<LocalAuthStep, LocalAuthError> {
        self.complete_password_change_impl(engine, raw, context, new_password, original, None)
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
    ) -> Result<LocalAuthStep, LocalAuthError> {
        self.complete_password_change_impl(
            engine,
            raw,
            context,
            new_password,
            original,
            Some(lease),
        )
        .await
    }
    async fn complete_password_change_impl(
        &self,
        engine: &LocalPasswordEngine,
        raw: &str,
        context: LocalAuthBinding<'_>,
        new_password: &str,
        original: Instant,
        lease: Option<Arc<PasswordWorkLease>>,
    ) -> Result<LocalAuthStep, LocalAuthError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        if let Some(lease) = &lease {
            lease.check_work(end)?;
        }
        validate_local_auth_challenge(raw).map_err(|_| LocalAuthError::InvalidChallenge)?;
        let hash = self
            .digester
            .token(TokenKind::LocalAuthChallenge, raw.as_bytes())?
            .to_sql_hex();
        let binding = self.digester.local_auth_binding(context)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.owner.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            let initial = sqlx_core::query_as::query_as::<_, ChallengeRow>(CHALLENGE_INITIAL)
                .bind(&hash).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(LocalAuthError::InvalidChallenge)?;
            let initial = ChallengeRecord::from_row(initial)?;
            self.validate_context(&initial, raw, context)?;
            if initial.stage != LocalAuthStage::PasswordChange { return Err(LocalAuthError::InvalidChallenge); }
            let row = sqlx_core::query_as::query_as::<_, PasswordUserRow>(PASSWORD_USER_UPDATE)
                .bind(&initial.subject).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(LocalAuthError::InvalidChallenge)?;
            let (username, subject, kind, enabled, change, revision, phc) = row;
            let phc = Zeroizing::new(phc.ok_or(LocalAuthError::InvalidChallenge)?);
            LocalPasswordHasher::validate_hash(&phc).map_err(|_| LocalAuthError::InvalidChallenge)?;
            let mut current = CurrentUser::from_row((username, subject, kind, enabled, change, revision)).ok_or(LocalAuthError::InvalidChallenge)?;
            let factor = sqlx_core::query_scalar::query_scalar::<_, bool>("SELECT true FROM public.local_mfa WHERE subject=$1 FOR SHARE")
                .bind(&current.subject).fetch_optional(&mut *tx).await.map_err(storage_error)?.is_some();
            let final_row = sqlx_core::query_as::query_as::<_, ChallengeRow>(CHALLENGE_UPDATE)
                .bind(&hash).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(LocalAuthError::InvalidChallenge)?;
            let challenge = ChallengeRecord::from_row(final_row)?;
            if initial != challenge || !current.change || current.subject != challenge.subject || current.revision != challenge.revision {
                return Err(LocalAuthError::InvalidChallenge);
            }
            self.validate_context(&challenge, raw, context)?;
            if new_password.len() > LOCAL_PASSWORD_MAX_BYTES || new_password.chars().count() < 15 {
                return Err(LocalAuthError::Password(LocalPasswordError::InvalidPassword));
            }
            let next_revision = current.revision.checked_add(1).ok_or(LocalAuthError::InvalidChallenge)?;
            let unchanged = match &lease {
                Some(lease) => engine.verify_for_change(new_password, Some(&phc), Arc::clone(lease), end).await?,
                None => engine.verify(new_password, Some(&phc), end).await?,
            };
            if unchanged { return Err(LocalAuthError::PasswordUnchanged); }
            let new_hash = match &lease {
                Some(lease) => engine.hash_for_change(new_password, Arc::clone(lease), end).await?,
                None => engine.hash(new_password, end).await?,
            };
            ensure_time(end)?;
            ensure_expiry(challenge.expires, now_micros()?)?;
            let now = now_micros()?;
            TimestampMicros::new(now).map_err(|_| ControlError::Clock)?;
            let changed = sqlx_core::query::query("UPDATE public.local_users SET password_hash=$1,password_change_required=0,revision=$2,updated_at=$3 WHERE subject=$4 AND revision=$5 AND password_change_required=1")
                .bind(new_hash.as_str()).bind(next_revision).bind(now).bind(&current.subject).bind(current.revision)
                .execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
            if changed != 1 { return Err(LocalAuthError::InvalidChallenge); }
            invalidate_local_user(&mut tx, &current.subject, matches!(context.purpose(), LocalAuthPurpose::DeviceApprove), now, end).await?;
            current.revision = next_revision;
            current.change = false;
            let (result, expires) = self.advance(&mut tx, &current, factor, context, binding, end).await?;
            ensure_time(end)?;
            ensure_expiry(challenge.expires, now_micros()?)?;
            if let Some(expiry) = expires { ensure_expiry(expiry, now_micros()?)?; }
            if let Some(lease) = &lease { lease.check_work(end)?; }
            commit_started.store(true, Ordering::Relaxed);
            tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            ensure_time(end)?;
            if let Some(lease) = &lease { lease.check_work(end)?; }
            if let Some(expiry) = expires { ensure_expiry(expiry, now_micros()?)?; }
            Ok(result)
        }).await.map_err(|_| timeout_error(&commit_started))?
    }
    /// Confirms a real factor; no consent, session or OAuth grant is issued here.
    pub async fn complete_mfa(
        &self,
        limiter: &LocalMfaAttemptLimiter,
        raw: &str,
        context: LocalAuthBinding<'_>,
        code: &str,
        original: Instant,
    ) -> Result<LocalAuthStep, LocalAuthError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        if code.len() > 64 {
            return Err(LocalAuthError::InvalidMfaCode);
        }
        validate_local_auth_challenge(raw).map_err(|_| LocalAuthError::InvalidChallenge)?;
        let hash = self
            .digester
            .token(TokenKind::LocalAuthChallenge, raw.as_bytes())?
            .to_sql_hex();
        let binding = self.digester.local_auth_binding(context)?;
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(self.owner.pool.acquire().await.map_err(storage_error)?));
            let mut tx = guard.connection()?.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(storage_error)?;
            let initial = sqlx_core::query_as::query_as::<_, ChallengeRow>(CHALLENGE_INITIAL)
                .bind(&hash).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(LocalAuthError::InvalidChallenge)?;
            let initial = ChallengeRecord::from_row(initial)?;
            self.validate_context(&initial, raw, context)?;
            if initial.stage == LocalAuthStage::PasswordChange { return Err(LocalAuthError::InvalidChallenge); }
            let mut current = sqlx_core::query_as::query_as::<_, UserRow>(USER_UPDATE).bind(&initial.subject)
                .fetch_optional(&mut *tx).await.map_err(storage_error)?.and_then(CurrentUser::from_row).ok_or(LocalAuthError::InvalidChallenge)?;
            let factor = sqlx_core::query_as::query_as::<_, (Option<String>, i64, i64)>("SELECT CASE WHEN octet_length(secret_ciphertext)<=90 THEN secret_ciphertext END,last_totp_step,confirmed_at FROM public.local_mfa WHERE subject=$1 FOR UPDATE")
                .bind(&current.subject).fetch_optional(&mut *tx).await.map_err(storage_error)?;
            let final_row = sqlx_core::query_as::query_as::<_, ChallengeRow>(CHALLENGE_UPDATE)
                .bind(&hash).fetch_optional(&mut *tx).await.map_err(storage_error)?.ok_or(LocalAuthError::InvalidChallenge)?;
            let challenge = ChallengeRecord::from_row(final_row)?;
            if initial != challenge || current.change || current.subject != challenge.subject || current.revision != challenge.revision {
                return Err(LocalAuthError::InvalidChallenge);
            }
            self.validate_context(&challenge, raw, context)?;
            let (cipher, last_step) = match (challenge.stage, factor) {
                (LocalAuthStage::Enrollment, None) => {
                    let orphan: bool = sqlx_core::query_scalar::query_scalar("SELECT EXISTS(SELECT 1 FROM public.local_mfa_recovery_codes WHERE subject=$1)")
                        .bind(&current.subject).fetch_one(&mut *tx).await.map_err(storage_error)?;
                    if orphan { return Err(LocalAuthError::InvalidChallenge); }
                    (challenge.cipher, -1)
                },
                (LocalAuthStage::Mfa, Some((cipher, step, confirmed))) if step >= 0 && confirmed > 0 => {
                    let cipher = Zeroizing::new(cipher.ok_or(LocalAuthError::InvalidChallenge)?);
                    if cipher.len() != 90 { return Err(LocalAuthError::InvalidChallenge); }
                    (cipher, step)
                },
                _ => return Err(LocalAuthError::InvalidChallenge),
            };
            let mut attempt = limiter.admit(&current.subject)?;
            let now = now_micros()?;
            let seconds = u64::try_from(now / 1_000_000).map_err(|_| ControlError::Clock)?;
            let accepted = self.mfa.verify(&current.subject, &cipher, code, seconds, last_step)?;
            ensure_time(end)?;
            ensure_expiry(challenge.expires, now_micros()?)?;
            let mut recovery_codes = None;
            let mut verified = accepted.is_some();
            if challenge.stage == LocalAuthStage::Enrollment {
                if let Some(step) = accepted {
                    let revision = current.revision.checked_add(1).ok_or(LocalAuthError::InvalidChallenge)?;
                    let cipher = self.mfa.reencrypt(&current.subject, &cipher)?;
                    let codes = LocalRecoveryCodes::generate()?;
                    let changed = sqlx_core::query::query("UPDATE public.local_users SET revision=$1,updated_at=$2 WHERE subject=$3 AND revision=$4 AND password_change_required=0")
                        .bind(revision).bind(now).bind(&current.subject).bind(current.revision).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                    if changed != 1 { return Err(LocalAuthError::InvalidChallenge); }
                    let changed = sqlx_core::query::query("INSERT INTO public.local_mfa(subject,secret_ciphertext,last_totp_step,confirmed_at) VALUES($1,$2,$3,$4)")
                        .bind(&current.subject).bind(cipher.as_str()).bind(step).bind(now).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                    if changed != 1 { return Err(ControlError::Storage.into()); }
                    for code in codes.iter() {
                        let normalized = normalize_local_recovery_code(code).ok_or(ControlError::Storage)?;
                        let digest = self.digester.recovery(current.subject.as_bytes(), normalized.as_bytes())?.to_sql_hex();
                        let changed = sqlx_core::query::query("INSERT INTO public.local_mfa_recovery_codes(subject,code_hash,created_at) VALUES($1,$2,$3)")
                            .bind(&current.subject).bind(digest).bind(now).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                        if changed != 1 { return Err(ControlError::Storage.into()); }
                    }
                    invalidate_local_user(&mut tx, &current.subject, matches!(context.purpose(), LocalAuthPurpose::DeviceApprove), now, end).await?;
                    current.revision = revision;
                    recovery_codes = Some(codes);
                }
            } else if let Some(step) = accepted {
                let changed = sqlx_core::query::query("UPDATE public.local_mfa SET last_totp_step=$1 WHERE subject=$2 AND last_totp_step=$3 AND last_totp_step<$1")
                    .bind(step).bind(&current.subject).bind(last_step).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                if changed != 1 { return Err(LocalAuthError::InvalidChallenge); }
            } else if let Some(normalized) = normalize_local_recovery_code(code) {
                let digest = self.digester.recovery(current.subject.as_bytes(), normalized.as_bytes())?.to_sql_hex();
                verified = sqlx_core::query::query("DELETE FROM public.local_mfa_recovery_codes WHERE subject=$1 AND code_hash=$2")
                    .bind(&current.subject).bind(digest).execute(&mut *tx).await.map_err(storage_error)?.rows_affected() == 1;
            }
            if verified {
                if challenge.stage == LocalAuthStage::Mfa {
                    let changed = sqlx_core::query::query("DELETE FROM public.local_auth_challenges WHERE challenge_hash=$1 AND local_user_revision=$2")
                        .bind(&hash).bind(current.revision).execute(&mut *tx).await.map_err(storage_error)?.rows_affected();
                    if changed != 1 { return Err(LocalAuthError::InvalidChallenge); }
                }
                ensure_time(end)?;
                ensure_expiry(challenge.expires, now_micros()?)?;
                commit_started.store(true, Ordering::Relaxed);
                tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
                guard.confirmed();
                ensure_time(end)?;
                ensure_expiry(challenge.expires, now_micros()?)?;
                let observed_at = TimestampMicros::new(now_micros()?).map_err(|_| ControlError::Clock)?;
                attempt.success()?;
                Ok(LocalAuthStep::Complete(CompletedLocalLogin { username: current.username, subject: current.subject, revision: current.revision, observed_at, purpose: context.purpose(), binding, factor_verified: true, recovery_codes }))
            } else {
                if challenge.stage == LocalAuthStage::Enrollment { attempt.failure()?; }
                let enrollment = if challenge.stage == LocalAuthStage::Enrollment {
                    Some(self.mfa.load(&current.subject, &cipher, &self.policy.issuer_label, &current.username)?)
                } else { None };
                ensure_time(end)?;
                ensure_expiry(challenge.expires, now_micros()?)?;
                commit_started.store(true, Ordering::Relaxed);
                tx.commit().await.map_err(|_| ControlError::OutcomeUncertain)?;
                guard.confirmed();
                ensure_time(end)?;
                ensure_expiry(challenge.expires, now_micros()?)?;
                if challenge.stage == LocalAuthStage::Mfa { attempt.failure()?; }
                Ok(LocalAuthStep::Pending(PendingLocalAuth { stage: challenge.stage, challenge: Zeroizing::new(raw.to_owned()), enrollment }))
            }
        }).await.map_err(|_| timeout_error(&commit_started))?
    }
    async fn advance(
        &self,
        connection: &mut PgConnection,
        current: &CurrentUser,
        factor: bool,
        context: LocalAuthBinding<'_>,
        binding: CredentialDigest,
        end: Instant,
    ) -> Result<(LocalAuthStep, Option<i64>), LocalAuthError> {
        let stage = if current.change {
            Some(LocalAuthStage::PasswordChange)
        } else if !self.policy.required {
            None
        } else if factor {
            Some(LocalAuthStage::Mfa)
        } else {
            Some(LocalAuthStage::Enrollment)
        };
        let now = now_micros()?;
        let observed_at = TimestampMicros::new(now).map_err(|_| ControlError::Clock)?;
        let Some(stage) = stage else {
            return Ok((
                LocalAuthStep::Complete(CompletedLocalLogin {
                    username: current.username.clone(),
                    subject: current.subject.clone(),
                    revision: current.revision,
                    observed_at,
                    purpose: context.purpose(),
                    binding,
                    factor_verified: false,
                    recovery_codes: None,
                }),
                None,
            ));
        };
        let ttl = i64::try_from(self.policy.challenge_ttl.as_micros())
            .map_err(|_| LocalAuthError::InvalidPolicy)?;
        let expires = now.checked_add(ttl).ok_or(ControlError::Clock)?;
        let (cipher, enrollment) = if stage == LocalAuthStage::Enrollment {
            let (cipher, enrollment) = self
                .mfa
                .prepare(
                    &current.subject,
                    &self.policy.issuer_label,
                    &current.username,
                )?
                .into_parts();
            (cipher, Some(enrollment))
        } else {
            (Zeroizing::new(String::new()), None)
        };
        ensure_time(end)?;
        ensure_expiry(expires, now_micros()?)?;
        let raw = new_local_auth_challenge()?;
        let hash = self
            .digester
            .token(TokenKind::LocalAuthChallenge, raw.as_bytes())?
            .to_sql_hex();
        sqlx_core::query::query(
            "DELETE FROM public.local_auth_challenges WHERE subject=$1 AND purpose=$2",
        )
        .bind(&current.subject)
        .bind(purpose_sql(context.purpose()))
        .execute(&mut *connection)
        .await
        .map_err(storage_error)?;
        let changed = sqlx_core::query::query("INSERT INTO public.local_auth_challenges(challenge_hash,subject,local_user_revision,purpose,binding_hash,stage,secret_ciphertext,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(hash).bind(&current.subject).bind(current.revision).bind(purpose_sql(context.purpose())).bind(binding.to_sql_hex())
            .bind(stage.sql()).bind(cipher.as_str()).bind(expires).bind(now).execute(&mut *connection).await.map_err(storage_error)?.rows_affected();
        if changed != 1 {
            return Err(ControlError::Storage.into());
        }
        Ok((
            LocalAuthStep::Pending(PendingLocalAuth {
                stage,
                challenge: raw,
                enrollment,
            }),
            Some(expires),
        ))
    }
    pub async fn load(
        &self,
        raw: &str,
        context: LocalAuthBinding<'_>,
        original: Instant,
    ) -> Result<PendingLocalAuth, LocalAuthError> {
        let end = bounded_deadline(original, self.owner.budgets.operation_timeout)?;
        validate_local_auth_challenge(raw).map_err(|_| LocalAuthError::InvalidChallenge)?;
        let hash = self
            .digester
            .token(TokenKind::LocalAuthChallenge, raw.as_bytes())?
            .to_sql_hex();
        let commit_started = AtomicBool::new(false);
        tokio::time::timeout_at(end.into(), async {
            let mut guard = ConnectionGuard(Some(
                self.owner.pool.acquire().await.map_err(storage_error)?,
            ));
            let mut tx = guard
                .connection()?
                .begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .map_err(storage_error)?;
            let initial = sqlx_core::query_as::query_as::<_, ChallengeRow>(CHALLENGE_INITIAL)
                .bind(&hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?
                .ok_or(LocalAuthError::InvalidChallenge)?;
            let initial = ChallengeRecord::from_row(initial)?;
            self.validate_context(&initial, raw, context)?;
            let current = sqlx_core::query_as::query_as::<_, UserRow>(USER_SHARE)
                .bind(&initial.subject)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?
                .and_then(CurrentUser::from_row)
                .ok_or(LocalAuthError::InvalidChallenge)?;
            let factor = sqlx_core::query_scalar::query_scalar::<_, bool>(
                "SELECT true FROM public.local_mfa WHERE subject=$1 FOR SHARE",
            )
            .bind(&current.subject)
            .fetch_optional(&mut *tx)
            .await
            .map_err(storage_error)?
            .is_some();
            let final_row = sqlx_core::query_as::query_as::<_, ChallengeRow>(CHALLENGE_FINAL)
                .bind(&hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(storage_error)?
                .ok_or(LocalAuthError::InvalidChallenge)?;
            let current_challenge = ChallengeRecord::from_row(final_row)?;
            if initial != current_challenge
                || current.revision != current_challenge.revision
                || current.subject != current_challenge.subject
                || current.change != (current_challenge.stage == LocalAuthStage::PasswordChange)
                || (current_challenge.stage == LocalAuthStage::Mfa && !factor)
                || (current_challenge.stage == LocalAuthStage::Enrollment && factor)
            {
                return Err(LocalAuthError::InvalidChallenge);
            }
            self.validate_context(&current_challenge, raw, context)?;
            let enrollment = if current_challenge.stage == LocalAuthStage::Enrollment {
                Some(self.mfa.load(
                    &current.subject,
                    &current_challenge.cipher,
                    &self.policy.issuer_label,
                    &current.username,
                )?)
            } else {
                None
            };
            ensure_time(end)?;
            ensure_expiry(current_challenge.expires, now_micros()?)?;
            commit_started.store(true, Ordering::Relaxed);
            tx.commit()
                .await
                .map_err(|_| ControlError::OutcomeUncertain)?;
            guard.confirmed();
            ensure_time(end)?;
            ensure_expiry(current_challenge.expires, now_micros()?)?;
            Ok(PendingLocalAuth {
                stage: current_challenge.stage,
                challenge: Zeroizing::new(raw.to_owned()),
                enrollment,
            })
        })
        .await
        .map_err(|_| timeout_error(&commit_started))?
    }
    fn validate_context(
        &self,
        row: &ChallengeRecord,
        raw: &str,
        context: LocalAuthBinding<'_>,
    ) -> Result<(), LocalAuthError> {
        if row.purpose != purpose_sql(context.purpose()) || row.created > now_micros()? {
            return Err(LocalAuthError::InvalidChallenge);
        }
        ensure_expiry(row.expires, now_micros()?)?;
        let digest = CredentialDigest::parse_sql_hex(&row.hash)
            .map_err(|_| LocalAuthError::InvalidChallenge)?;
        self.digester
            .verify_token(TokenKind::LocalAuthChallenge, raw.as_bytes(), &digest)
            .map_err(|_| LocalAuthError::InvalidChallenge)?;
        let binding = CredentialDigest::parse_sql_hex(&row.binding)
            .map_err(|_| LocalAuthError::InvalidChallenge)?;
        self.digester
            .verify_local_auth_binding(context, &binding)
            .map_err(|_| LocalAuthError::InvalidChallenge)?;
        Ok(())
    }
}

pub(super) async fn invalidate_local_user(
    connection: &mut PgConnection,
    subject: &str,
    preserve_device: bool,
    now: i64,
    end: Instant,
) -> Result<(), LocalAuthError> {
    sqlx_core::query::query(
            "UPDATE public.local_tokens SET revoked_at=$1 WHERE subject=$2 AND local_user_revision>=1 AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(subject)
        .execute(&mut *connection)
        .await
        .map_err(storage_error)?;
    let mut after_hash: Option<String> = None;
    loop {
        ensure_time(end)?;
        // Producer document limits already apply. Keep only one relevant TEXT row alive.
        let row:Option<(String,String)>=sqlx_core::query_as::query_as("SELECT request_hash,request_json FROM public.oidc_auth_requests WHERE identity_subject=$1 AND ($2::text IS NULL OR request_hash>$2) ORDER BY request_hash LIMIT 1 FOR UPDATE")
                .bind(subject).bind(after_hash.as_deref()).fetch_optional(&mut *connection).await.map_err(storage_error)?;
        let Some((hash, json)) = row else { break };
        let json = Zeroizing::new(json);
        let preserve = preserve_federated_request(&json)?;
        ensure_time(end)?;
        if !preserve {
            let changed=sqlx_core::query::query("DELETE FROM public.oidc_auth_requests WHERE request_hash=$1 AND identity_subject=$2")
                    .bind(&hash).bind(subject).execute(&mut *connection).await.map_err(storage_error)?.rows_affected();
            if changed != 1 {
                return Err(ControlError::Storage.into());
            }
        }
        after_hash = Some(hash);
    }
    sqlx_core::query::query("DELETE FROM public.local_auth_challenges WHERE subject=$1")
        .bind(subject)
        .execute(&mut *connection)
        .await
        .map_err(storage_error)?;
    if !preserve_device {
        sqlx_core::query::query("DELETE FROM public.oauth_device_codes WHERE subject=$1")
            .bind(subject)
            .execute(&mut *connection)
            .await
            .map_err(storage_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod invalidation_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn native_invalidation_projection_preserves_valid_nul_and_rejects_malformed_json() {
        let value = json!({"format":"rust-broker-authorization-v1","phase":"authorized","principal":{"issuer":"https://issuer.example","auth_method":"oidc","local_user_revision":0},"state":"state\0","nonce":"nonce\0"});
        assert!(preserve_federated_request(&value.to_string()).unwrap());
        for raw in ["{}", "[]", "null", r#"{"principal":null}"#] {
            assert!(!preserve_federated_request(raw).unwrap());
        }
        for raw in ["{", "{}{}", r#"{"format":1,"ignored":[}"#] {
            assert_eq!(
                preserve_federated_request(raw).unwrap_err(),
                LocalAuthError::Control(ControlError::Storage)
            );
        }
        for (field, replacement) in [
            ("issuer", json!("local")),
            ("issuer", json!("")),
            ("auth_method", json!("local-token")),
            ("local_user_revision", json!(1)),
            ("local_user_revision", json!("0")),
            ("local_user_revision", json!(0.0)),
        ] {
            let mut wrong = value.clone();
            wrong["principal"][field] = replacement;
            assert!(!preserve_federated_request(&wrong.to_string()).unwrap());
        }
        let duplicate = r#"{"format":"rust-broker-authorization-v1","format":"rust-broker-authorization-v1","phase":"authorized","principal":{"issuer":"https://issuer.example","auth_method":"oidc","local_user_revision":0}}"#;
        assert!(!preserve_federated_request(duplicate).unwrap());
    }
}
