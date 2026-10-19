use super::{SqliteControlStore, local_bearer};
use crate::{
    ControlError, LocalBearerStateError, LocalBearerVerificationError as Error,
    VerifiedLocalBearer,
    flow::now_micros,
    local_bearer_verifier::{bearer_kind, validate_state},
};
use std::{fmt, num::NonZeroUsize, time::Instant};

/// Authenticate raw LOCAL access/service credentials against current SQLite state.
/// This borrowed verifier supplies observations, never a future authorization lease.
/// ~~~compile_fail
/// fn escape(store: &broker_control::SqliteControlStore) -> broker_control::SqliteLocalBearerVerifier<'static> {
///     store.local_bearer_verifier("explicit",std::num::NonZeroUsize::new(4096).unwrap()).unwrap()
/// }
/// ~~~
pub struct SqliteLocalBearerVerifier<'a> {
    owner: &'a SqliteControlStore,
    audience: &'a str,
    cap: i64,
}
impl fmt::Debug for SqliteLocalBearerVerifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteLocalBearerVerifier([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn local_bearer_verifier<'a>(
        &'a self,
        audience: &'a str,
        json_bytes: NonZeroUsize,
    ) -> Result<SqliteLocalBearerVerifier<'a>, Error> {
        isize::try_from(json_bytes.get()).map_err(|_| LocalBearerStateError::InvalidLimits)?;
        let cap =
            i64::try_from(json_bytes.get()).map_err(|_| LocalBearerStateError::InvalidLimits)?;
        Ok(SqliteLocalBearerVerifier {
            owner: self,
            audience,
            cap,
        })
    }
}
impl SqliteLocalBearerVerifier<'_> {
    pub async fn verify(
        &self,
        raw: &str,
        required_scopes: &[String],
        original: Instant,
    ) -> Result<VerifiedLocalBearer, Error> {
        let end = self
            .owner
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let kind = bearer_kind(raw).ok_or(Error::Unauthenticated)?;
        let hash = self
            .owner
            .digester
            .token(kind.token_kind(), raw.as_bytes())
            .map_err(|_| Error::Unauthenticated)?
            .to_sql_hex();
        let cap = self.cap;
        // The executor alone classifies cancellation and uncertain COMMIT.
        let state = self
            .owner
            .executor
            .execute(end, move |owner, work| {
                let tx = owner.begin(work)?;
                match local_bearer::read(&tx, work, &hash, kind, cap) {
                    Ok(value) => {
                        work.commit(tx)?;
                        Ok(Ok(value))
                    }
                    Err(error) => {
                        work.check()?;
                        Ok(Err(error))
                    }
                }
            })
            .await
            .map_err(ControlError::from)??
            .ok_or(Error::Unauthenticated)?;
        validate_state(&state, self.audience, required_scopes, now_micros()?)?;
        let anchor = Instant::now();
        let mut verified = VerifiedLocalBearer::new(state, now_micros()?, anchor)?;
        verified.finish(now_micros()?)?;
        if Instant::now() >= end {
            return Err(ControlError::Deadline.into());
        }
        Ok(verified)
    }
}
