//! Fixed-provider HTTPS CAPTCHA admission. Provider data never authenticates a user.
use crate::ControlError;
use broker_security::LocalAuthPurpose;
use reqwest::{Client, redirect::Policy};
use serde::Serialize;
use std::{
    fmt,
    num::NonZeroUsize,
    time::{Duration, Instant},
};
use url::Url;
use zeroize::Zeroizing;

const RESPONSE_BYTES: usize = 64 * 1024;
const PROOF_BYTES: usize = 2048;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LocalCaptchaProvider {
    Turnstile,
    Recaptcha,
}

#[cfg(test)]
#[path = "../tests/support/local_captcha_protocol.rs"]
mod tests;
impl LocalCaptchaProvider {
    fn endpoint(self) -> &'static str {
        match self {
            Self::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            Self::Recaptcha => "https://www.google.com/recaptcha/api/siteverify",
        }
    }
    fn action(self, purpose: LocalAuthPurpose) -> Option<&'static str> {
        match self {
            Self::Turnstile => Some(match purpose {
                LocalAuthPurpose::AdminLogin => "admin-login",
                LocalAuthPurpose::OauthAuthorize => "oauth-login",
                LocalAuthPurpose::DeviceApprove => "device-login",
            }),
            Self::Recaptcha => None,
        }
    }
}
/// Public challenge DATA, not a password, credential or verification proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LocalCaptchaChallenge {
    provider: LocalCaptchaProvider,
    site_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'static str>,
}
impl LocalCaptchaChallenge {
    pub fn provider(&self) -> LocalCaptchaProvider {
        self.provider
    }
    pub fn site_key(&self) -> &str {
        &self.site_key
    }
    pub fn action(&self) -> Option<&'static str> {
        self.action
    }
}
/// Trusted startup input. Disabled admission needs no provider or network client.
pub enum LocalCaptchaConfiguration {
    Disabled,
    Enabled {
        provider: LocalCaptchaProvider,
        site_key: String,
        secret_key: Zeroizing<String>,
        public_url: Url,
        trigger_multiplier: f64,
        verification_timeout: Duration,
    },
}
impl fmt::Debug for LocalCaptchaConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalCaptchaConfiguration([REDACTED])")
    }
}
pub struct LocalCaptcha {
    enabled: Option<EnabledCaptcha>,
}
struct EnabledCaptcha {
    provider: LocalCaptchaProvider,
    site_key: String,
    secret: Zeroizing<String>,
    hostname: String,
    threshold: usize,
    workers: NonZeroUsize,
    saturation_multiplier: NonZeroUsize,
    timeout: Duration,
    client: Client,
}
impl fmt::Debug for LocalCaptcha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalCaptcha([REDACTED])")
    }
}
pub(crate) enum CaptchaFailure {
    Required,
    Control(ControlError),
}
impl LocalCaptcha {
    pub fn new(
        configuration: LocalCaptchaConfiguration,
        workers: NonZeroUsize,
        saturation_multiplier: NonZeroUsize,
    ) -> Result<Self, ControlError> {
        let enabled = match configuration {
            LocalCaptchaConfiguration::Disabled => None,
            LocalCaptchaConfiguration::Enabled {
                provider,
                site_key,
                secret_key,
                public_url,
                trigger_multiplier,
                verification_timeout,
            } => {
                let hostname = public_url.host_str().ok_or(ControlError::Configuration)?;
                let maximum = workers
                    .get()
                    .checked_mul(saturation_multiplier.get())
                    .ok_or(ControlError::Configuration)?;
                if site_key.trim().is_empty()
                    || secret_key.trim().is_empty()
                    || !matches!(public_url.scheme(), "http" | "https")
                    || !public_url.username().is_empty()
                    || public_url.password().is_some()
                    || !trigger_multiplier.is_finite()
                    || trigger_multiplier < 0.0
                    || trigger_multiplier > saturation_multiplier.get() as f64
                    || !(Duration::from_millis(500)..=Duration::from_secs(10))
                        .contains(&verification_timeout)
                {
                    return Err(ControlError::Configuration);
                }
                let threshold =
                    ((workers.get() as f64 * trigger_multiplier).ceil() as usize).max(1);
                if threshold > maximum {
                    return Err(ControlError::Configuration);
                }
                Some(EnabledCaptcha {
                    provider,
                    site_key,
                    secret: secret_key,
                    hostname: hostname.to_owned(),
                    threshold,
                    workers,
                    saturation_multiplier,
                    timeout: verification_timeout,
                    client: Client::builder()
                        .redirect(Policy::none())
                        .build()
                        .map_err(|_| ControlError::Configuration)?,
                })
            }
        };
        Ok(Self { enabled })
    }
    pub fn challenge(&self, purpose: LocalAuthPurpose) -> Option<LocalCaptchaChallenge> {
        self.enabled.as_ref().map(|value| LocalCaptchaChallenge {
            provider: value.provider,
            site_key: value.site_key.clone(),
            action: value.provider.action(purpose),
        })
    }
    pub(crate) fn compatible(&self, workers: NonZeroUsize, saturation: NonZeroUsize) -> bool {
        self.enabled.as_ref().is_none_or(|enabled| {
            enabled.workers == workers && enabled.saturation_multiplier == saturation
        })
    }
    pub(crate) fn required(&self, occupancy: usize) -> bool {
        self.enabled
            .as_ref()
            .is_some_and(|value| occupancy >= value.threshold)
    }
    pub(crate) async fn verify(
        &self,
        purpose: LocalAuthPurpose,
        proof: Option<&str>,
        original: Instant,
    ) -> Result<(), CaptchaFailure> {
        if Instant::now() >= original {
            return Err(CaptchaFailure::Control(ControlError::Deadline));
        }
        let Some(enabled) = &self.enabled else {
            return Ok(());
        };
        let proof = proof
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= PROOF_BYTES)
            .ok_or(CaptchaFailure::Required)?;
        let proof = Zeroizing::new(proof.to_owned());
        let end = Instant::now()
            .checked_add(enabled.timeout)
            .ok_or(CaptchaFailure::Control(ControlError::Configuration))?
            .min(original);
        let operation = async {
            let mut response = enabled
                .client
                .post(enabled.provider.endpoint())
                .form(&[
                    ("secret", enabled.secret.as_str()),
                    ("response", proof.as_str()),
                ])
                .send()
                .await
                .map_err(|_| CaptchaFailure::Required)?;
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|size| size > RESPONSE_BYTES as u64)
            {
                return Err(CaptchaFailure::Required);
            }
            let mut body = Zeroizing::new(Vec::new());
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| CaptchaFailure::Required)?
            {
                if chunk.len() > RESPONSE_BYTES.saturating_sub(body.len()) {
                    return Err(CaptchaFailure::Required);
                }
                body.extend_from_slice(&chunk);
            }
            let value: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| CaptchaFailure::Required)?;
            if value.get("success").and_then(serde_json::Value::as_bool) != Some(true)
                || !value
                    .get("hostname")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|host| host.trim().eq_ignore_ascii_case(&enabled.hostname))
                || enabled.provider.action(purpose).is_some_and(|action| {
                    value.get("action").and_then(serde_json::Value::as_str) != Some(action)
                })
            {
                return Err(CaptchaFailure::Required);
            }
            Ok(())
        };
        let result = tokio::time::timeout_at(end.into(), operation)
            .await
            .map_err(|_| CaptchaFailure::Required)
            .and_then(|result| result);
        if Instant::now() >= original {
            return Err(CaptchaFailure::Control(ControlError::Deadline));
        }
        if Instant::now() >= end {
            return Err(CaptchaFailure::Required);
        }
        result
    }
}
