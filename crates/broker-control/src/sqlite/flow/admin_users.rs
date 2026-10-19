mod data;

use super::{
    SqliteControlStore,
    admin_cookie_session::{CookieObserver, ObservedAdminCookie, cookie_hash},
    admin_local_observer,
    admin_local_observer::LocalProof,
    admin_rbac,
};
use crate::{
    AdminBrokerSessionError as AuthError, AdminCookieSessionError, AdminCookieSessionLimits,
    AdminReadAuthentication, AdminServiceCredentialInput, AdminUserInput, AdminUsersError as Error,
    AdminUsersLimits, AdminUsersRequest, AdminUsersResult, BrokerAccessError, ControlError,
    LocalPasswordEngine, LocalPasswordVerificationError, SqliteControlError, SystemAction,
    UpstreamBearerVerifier, VerifiedBrokerAccess, VerifiedLocalBearer,
    admin_cookie_session::CookieClock,
    admin_local_bearer_session::{check_authentication, verification_error},
    admin_read::{ReadWitness, cookie_authorization},
    service::admin_upstream_session::validate_profile,
    sqlite::executor::Work,
    upstream_oidc::VerifiedUpstreamBearer,
};
use broker_security::CredentialDigester;
use rusqlite::Transaction;
use std::{
    fmt,
    sync::Arc,
    time::{Instant, SystemTime},
};
use zeroize::Zeroizing;

/// Administrative mutations use current action and target observations in SQLite.
/// The actual shared password engine must outlive the producer.
/// ~~~compile_fail
/// use broker_control::{SqliteControlStore, SqliteAdminUsers, LocalPasswordEngine, AdminUsersLimits};
/// fn escape<'a>(store: &'a SqliteControlStore, engine: &LocalPasswordEngine,
///               limits: &'a AdminUsersLimits) -> SqliteAdminUsers<'a> {
///     store.admin_users(engine, limits).unwrap()
/// }
/// ~~~
pub struct SqliteAdminUsers<'s> {
    store: &'s SqliteControlStore,
    engine: &'s LocalPasswordEngine,
    limits: &'s AdminUsersLimits,
}
impl fmt::Debug for SqliteAdminUsers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SqliteAdminUsers([REDACTED])")
    }
}
impl SqliteControlStore {
    pub fn admin_users<'s>(
        &'s self,
        engine: &'s LocalPasswordEngine,
        limits: &'s AdminUsersLimits,
    ) -> Result<SqliteAdminUsers<'s>, ControlError> {
        limits.validate()?;
        Ok(SqliteAdminUsers {
            store: self,
            engine,
            limits,
        })
    }
}
enum OwnedRequest {
    Create(Box<AdminUserInput>),
    Update {
        username: String,
        user: Box<AdminUserInput>,
    },
    Delete(String),
    ResetMfa(String),
    Credentials(String),
    IssueCredential {
        username: String,
        input: AdminServiceCredentialInput,
    },
    RevokeCredential {
        username: String,
        id: String,
    },
}
impl OwnedRequest {
    fn user(v: &AdminUserInput) -> Box<AdminUserInput> {
        Box::new(AdminUserInput {
            username: v.username.clone(),
            subject: v.subject.clone(),
            kind: v.kind.clone(),
            password: v.password.clone(),
            name: v.name.clone(),
            email: v.email.clone(),
            organization: v.organization.clone(),
            teams: v.teams.clone(),
            roles: v.roles.clone(),
            enabled: v.enabled,
            password_change_required: v.password_change_required,
        })
    }
    fn capture(request: AdminUsersRequest<'_>) -> Self {
        match request {
            AdminUsersRequest::Create(v) => Self::Create(Self::user(v)),
            AdminUsersRequest::Update { username, user } => Self::Update {
                username: username.to_owned(),
                user: Self::user(user),
            },
            AdminUsersRequest::Delete { username } => Self::Delete(username.to_owned()),
            AdminUsersRequest::ResetMfa { username } => Self::ResetMfa(username.to_owned()),
            AdminUsersRequest::Credentials { username } => Self::Credentials(username.to_owned()),
            AdminUsersRequest::IssueCredential { username, input } => Self::IssueCredential {
                username: username.to_owned(),
                input: AdminServiceCredentialInput {
                    client_id: input.client_id.clone(),
                    scopes: input.scopes.clone(),
                    expires_in: input.expires_in,
                },
            },
            AdminUsersRequest::RevokeCredential { username, id } => Self::RevokeCredential {
                username: username.to_owned(),
                id: id.to_owned(),
            },
        }
    }
    fn borrow(&self) -> AdminUsersRequest<'_> {
        match self {
            Self::Create(v) => AdminUsersRequest::Create(v),
            Self::Update { username, user } => AdminUsersRequest::Update { username, user },
            Self::Delete(username) => AdminUsersRequest::Delete { username },
            Self::ResetMfa(username) => AdminUsersRequest::ResetMfa { username },
            Self::Credentials(username) => AdminUsersRequest::Credentials { username },
            Self::IssueCredential { username, input } => {
                AdminUsersRequest::IssueCredential { username, input }
            }
            Self::RevokeCredential { username, id } => {
                AdminUsersRequest::RevokeCredential { username, id }
            }
        }
    }
}
#[derive(Clone, Copy)]
enum Cutoff {
    Broker(SystemTime, Instant),
    Opaque(SystemTime, Instant),
    Upstream(Instant),
    Cookie(SystemTime, Instant),
}
impl Cutoff {
    fn end(self, original: Instant) -> Instant {
        original.min(match self {
            Self::Broker(_, mono)
            | Self::Opaque(_, mono)
            | Self::Cookie(_, mono)
            | Self::Upstream(mono) => mono,
        })
    }
    fn check(self) -> Result<(), Error> {
        let expired = match self {
            Self::Broker(utc, mono) | Self::Opaque(utc, mono) | Self::Cookie(utc, mono) => {
                Instant::now() >= mono || SystemTime::now() >= utc
            }
            Self::Upstream(mono) => Instant::now() >= mono,
        };
        if expired {
            return Err(match self {
                Self::Cookie(..) => cookie_authorization(AdminCookieSessionError::Control(
                    ControlError::SessionExpired,
                ))
                .into(),
                _ => AuthError::from(BrokerAccessError::Expired).into(),
            });
        }
        Ok(())
    }
}
// Native proof stays in the async caller. Only this private bounded locator follows
// its worker, as in the existing administrative SQLite writers.
struct CookieActor {
    hash: String,
    limits: AdminCookieSessionLimits,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    clock: CookieClock,
    cutoff: Option<(SystemTime, Instant)>,
    observed: Option<ReadWitness<'static>>,
}
enum Actor {
    Broker {
        username: String,
        subject: String,
        expiry: (SystemTime, Instant),
        digester: Arc<CredentialDigester>,
    },
    Opaque(Box<VerifiedLocalBearer>),
    Upstream(Box<VerifiedUpstreamBearer>),
    Cookie(Box<CookieActor>),
}
impl Actor {
    fn cutoff(&self) -> Option<Cutoff> {
        Some(match self {
            Self::Broker {
                expiry: (utc, mono),
                ..
            } => Cutoff::Broker(*utc, *mono),
            Self::Opaque(proof) => {
                let (utc, mono) = proof.authentication_expiry();
                Cutoff::Opaque(utc, mono)
            }
            Self::Upstream(proof) => Cutoff::Upstream(proof.expires_mono()),
            Self::Cookie(cookie) => match cookie.cutoff {
                Some((utc, mono)) => Cutoff::Cookie(utc, mono),
                None => return None,
            },
        })
    }
    fn end(&self, end: Instant) -> Instant {
        self.cutoff().map_or(end, |cutoff| cutoff.end(end))
    }
    fn check(&self, end: Instant) -> Result<(), Error> {
        check(end)?;
        if let Some(cutoff) = self.cutoff() {
            cutoff.check()?;
        }
        match self {
            Self::Broker { .. } => {}
            Self::Opaque(proof) => check_authentication(proof)?,
            Self::Upstream(proof) => proof.check()?,
            Self::Cookie(cookie) => {
                if let Some(witness) = &cookie.observed {
                    witness.check()?;
                }
            }
        }
        Ok(())
    }
    fn observe(
        &mut self,
        tx: &Transaction<'_>,
        work: &Work,
        limits: &AdminUsersLimits,
        action: SystemAction,
        csrf: Option<&str>,
        end: Instant,
    ) -> Result<(), Error> {
        self.check(end)?;
        match self {
            Self::Broker {
                username,
                subject,
                expiry,
                digester,
            } => {
                admin_local_observer::observe(
                    tx,
                    work,
                    LocalProof::Broker {
                        username,
                        subject,
                        digester: digester.as_ref(),
                        expiry: *expiry,
                    },
                    limits.authorization,
                    action,
                    end,
                )?;
            }
            Self::Opaque(proof) => {
                admin_local_observer::observe(
                    tx,
                    work,
                    LocalProof::Opaque(proof),
                    limits.authorization,
                    action,
                    end,
                )?;
            }
            Self::Upstream(proof) => {
                let subject = format!("{}|{}", proof.issuer(), proof.profile().subject);
                super::admin_upstream_session::observe_roles(
                    tx,
                    work,
                    &subject,
                    proof.claim_roles(),
                    limits.authorization,
                    action,
                    || {
                        if Instant::now() >= end {
                            return Err(ControlError::Deadline.into());
                        }
                        proof.check()
                    },
                )?;
            }
            Self::Cookie(cookie) => {
                let CookieActor {
                    hash,
                    limits,
                    upstream,
                    clock,
                    cutoff,
                    observed,
                } = cookie.as_mut();
                let observation =
                    match CookieObserver::new(*limits, upstream.as_deref(), action, clock, end)
                        .observe(tx, work, hash, cutoff)?
                    {
                        ObservedAdminCookie::Active(observation) => observation,
                        ObservedAdminCookie::Expired(_) => {
                            return Err(cookie_authorization(AdminCookieSessionError::Control(
                                ControlError::SessionExpired,
                            ))
                            .into());
                        }
                    };
                observation
                    .window()
                    .check()
                    .map_err(|e| cookie_authorization(e.into()))?;
                if !matches!(action, SystemAction::UsersRead) && !observation.csrf_matches(csrf)? {
                    return Err(Error::CsrfFailed);
                }
                *observed = Some(observation.into_witness());
            }
        }
        self.check(end)
    }
    fn witness<'a>(
        self,
        native: Option<VerifiedBrokerAccess<'a>>,
    ) -> Result<ReadWitness<'a>, Error> {
        match self {
            Self::Broker { .. } => Ok(ReadWitness::Broker(
                native.ok_or(ControlError::Configuration)?,
            )),
            Self::Opaque(proof) => Ok(ReadWitness::Opaque(*proof)),
            Self::Upstream(proof) => Ok(ReadWitness::Upstream(*proof)),
            Self::Cookie(cookie) => cookie
                .observed
                .ok_or_else(|| ControlError::Configuration.into()),
        }
    }
}
fn check(end: Instant) -> Result<(), Error> {
    if Instant::now() >= end {
        return Err(ControlError::Deadline.into());
    }
    Ok(())
}
fn uncertain<T>(outcome: &Result<T, Error>) -> bool {
    matches!(
        outcome,
        Err(Error::Authorization(AuthError::Control(
            ControlError::OutcomeUncertain
        )))
    )
}
fn native_check(proof: Option<&VerifiedBrokerAccess<'_>>, end: Instant) -> Result<(), Error> {
    check(end)?;
    if let Some(proof) = proof {
        proof.check().map_err(AuthError::from)?;
    }
    Ok(())
}
impl SqliteAdminUsers<'_> {
    async fn transaction(
        &self,
        actor: Actor,
        request: Arc<OwnedRequest>,
        csrf: Option<Zeroizing<String>>,
        hash: Option<Zeroizing<String>>,
        preflight: bool,
        end: Instant,
    ) -> Result<(Actor, data::Output), Error> {
        actor.check(end)?;
        let cutoff = actor.cutoff();
        let wait = actor.end(end);
        let limits = self.limits.clone();
        let digester = self.store.digester.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let observed = self
            .store
            .executor
            .execute(wait, move |owner, work| {
                // The physical SQL thread retains this operation's diagnostic context.
                tracing::dispatcher::with_default(&dispatch, || {
                let mut actor = actor;
                let outcome = (|| -> Result<data::Output, Error> {
                    work.check().map_err(ControlError::from)?;
                    actor.check(end)?;
                    let tx = owner.begin(work).map_err(ControlError::from)?;
                    let request = request.borrow();
                    if !matches!(request, AdminUsersRequest::Credentials { .. }) {
                        admin_rbac::parent(&tx, work).map_err(|e| match e {
                            crate::AdminRbacError::Authorization(e) => Error::Authorization(e),
                            _ => Error::from(ControlError::CorruptRbac),
                        })?;
                    }
                    actor.observe(
                        &tx,
                        work,
                        &limits,
                        request.action(),
                        csrf.as_ref().map(|s| s.as_str()),
                        end,
                    )?;
                    let applied = if preflight {
                        data::preflight(&tx, work, request).map(|()| data::Output::empty(204))
                    } else {
                        data::apply(
                            &tx,
                            work,
                            &digester,
                            &limits,
                            request,
                            hash.as_ref().map(|s| s.as_str()),
                            actor.end(end),
                        )
                    };
                    if uncertain(&applied) {
                        return Err(ControlError::OutcomeUncertain.into());
                    }
                    actor.check(end)?;
                    work.check().map_err(ControlError::from)?;
                    let output = applied?;
                    work.commit(tx).map_err(ControlError::from)?;
                    tracing::trace!(target: "broker_control::sqlite::admin_users_commit_ack", "SQLite administrative transaction committed before result delivery");
                    Ok(output)
                })();
                let outcome = if uncertain(&outcome) {
                    outcome
                } else {
                    actor.check(end).and(outcome)
                };
                Ok((actor, outcome))
                })
            })
            .await;
        if matches!(
            &observed,
            Err(SqliteControlError::OutcomeUncertain)
                | Ok((
                    _,
                    Err(Error::Authorization(AuthError::Control(
                        ControlError::OutcomeUncertain
                    )))
                ))
        ) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        check(end)?;
        if let Some(cutoff) = cutoff {
            cutoff.check()?;
        }
        let (actor, outcome) = observed.map_err(ControlError::from)?;
        actor.check(end)?;
        Ok((actor, outcome?))
    }
    pub async fn execute<'a>(
        &self,
        authentication: AdminReadAuthentication<'a, '_>,
        request: AdminUsersRequest<'_>,
        csrf: Option<&str>,
        original: Instant,
    ) -> Result<AdminUsersResult<'a>, Error> {
        let end = self
            .store
            .executor
            .deadline(original)
            .map_err(ControlError::from)?;
        let mut native = None;
        let mut actor = match authentication {
            AdminReadAuthentication::Broker { verifier, proof } => {
                proof.check().map_err(AuthError::from)?;
                if !proof.owned_by(verifier) {
                    return Err(AuthError::from(BrokerAccessError::InvalidToken).into());
                }
                let username = proof
                    .username()
                    .filter(|u| {
                        crate::identity::safe_identity_segment(
                            u,
                            self.limits.authorization.identity.username_bytes.get(),
                        )
                    })
                    .ok_or(AuthError::Forbidden)?
                    .to_owned();
                let actor = Actor::Broker {
                    username,
                    subject: proof.subject().to_owned(),
                    expiry: proof.authentication_expiry(),
                    digester: self.store.digester.clone(),
                };
                native = Some(proof);
                actor
            }
            AdminReadAuthentication::Opaque {
                raw,
                audience,
                identity_json_bytes,
                required_scopes,
            } => Actor::Opaque(Box::new(
                self.store
                    .local_bearer_verifier(audience, identity_json_bytes)
                    .map_err(verification_error)?
                    .verify(raw, required_scopes, end)
                    .await
                    .map_err(verification_error)?,
            )),
            AdminReadAuthentication::Upstream { raw, verifier } => {
                let proof = verifier.verify(raw, end).await?;
                validate_profile(&proof, self.limits.authorization, end)?;
                Actor::Upstream(Box::new(proof))
            }
            AdminReadAuthentication::Cookie {
                raw,
                limits,
                policy,
                upstream,
            } => {
                let a = limits.authorization;
                let b = self.limits.authorization;
                if a.profile_json_bytes != b.profile_json_bytes
                    || [
                        a.identity.username_bytes,
                        a.identity.subject_bytes,
                        a.identity.role_bytes,
                        a.identity.roles,
                        a.identity.rows,
                    ] != [
                        b.identity.username_bytes,
                        b.identity.subject_bytes,
                        b.identity.role_bytes,
                        b.identity.roles,
                        b.identity.rows,
                    ]
                {
                    return Err(ControlError::Configuration.into());
                }
                self.store
                    .admin_cookie_sessions(limits, policy, upstream.clone())?;
                Actor::Cookie(Box::new(CookieActor {
                    hash: cookie_hash(self.store, raw).map_err(cookie_authorization)?,
                    limits,
                    upstream,
                    clock: CookieClock::capture(),
                    cutoff: None,
                    observed: None,
                }))
            }
        };
        let request = Arc::new(OwnedRequest::capture(request));
        let csrf = csrf
            .filter(|s| s.len() == 43)
            .map(|s| Zeroizing::new(s.to_owned()));
        let borrowed_request = request.borrow();
        let hash = if let Some(password) = borrowed_request.password() {
            let outcome = self
                .transaction(actor, request.clone(), csrf.clone(), None, true, end)
                .await;
            if uncertain(&outcome) {
                return Err(ControlError::OutcomeUncertain.into());
            }
            native_check(native.as_ref(), end)?;
            actor = outcome?.0;
            actor.check(end)?;
            tracing::trace!(target: "broker_control::sqlite::admin_users_before_hash", "SQLite administrative password preflight completed");
            let hashed = self.engine.hash(password, actor.end(end)).await;
            native_check(native.as_ref(), end)?;
            actor.check(end)?;
            Some(hashed.map_err(|e| match e {
                LocalPasswordVerificationError::Control(e) => Error::from(e),
                _ => request.borrow().error(),
            })?)
        } else {
            None
        };
        let outcome = self
            .transaction(actor, request, csrf, hash, false, end)
            .await;
        if uncertain(&outcome) {
            return Err(ControlError::OutcomeUncertain.into());
        }
        native_check(native.as_ref(), end)?;
        let (actor, output) = outcome?;
        actor.check(end)?;
        let result = AdminUsersResult {
            witness: actor.witness(native)?,
            original: end,
            status: output.status,
            body: output.body,
        };
        result.check()?;
        Ok(result)
    }
}
