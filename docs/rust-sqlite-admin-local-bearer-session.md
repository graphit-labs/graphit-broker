---
type: document
title: SQLite administrative session with LOCAL opaque credentials
status: implemented
description: Current administrative identity and RBAC from genuine SQLite LOCAL access and service credentials.
references:
  - target: {type: task, id: tsk-7ac1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-8802, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite administrative session with LOCAL opaque credentials

Broker integrators can read the current administrative session from a genuine
LOCAL access token or service credential against the [private SQLite catalog](rust-sqlite-control.md).
The existing [administrative session wire](rust-admin-local-bearer-session.md)
and [LOCAL cookie transport](rust-sqlite-admin-cookie-session.md) are preserved.
This explicit integration is qualified locally on Linux under tsk-7ac1. This composition does not select
SQLite in the native Server configuration or implement JWT/upstream administrative
admission, CRUD, or browser authorization.

## Compose the existing router

~~~text
sqlite_local_admin_session_router(
    store: Arc<SqliteControlStore>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError>
~~~

The same router serves GET/HEAD /admin/api/v1/session. Supply Some(local_bearer)
for raw LOCAL access/service authentication and Some(cookie) for genuine current
cookie reads. The cookie configuration also mounts POST /admin/auth/logout.
For the [LOCAL password/factor HTTP cycle](rust-sqlite-admin-local-http.md),
None and Some(cookie) preserve the cookie-only configuration. No JWT verifier
or upstream owner is accepted or ignored by this SQLite router.

The LOCAL configuration requires a nonblank administrative audience, an explicit
identity JSON cap and nonblank required scopes. Session/profile/row/role limits
and request timeout remain explicit. Cookie and session authorization limits
must match when both are configured. No new dependency or schema is needed.

A nonempty known graphit_admin_session cookie takes precedence over Bearer.
Any cookie failure terminates the request, including an absent cookie consumer.
An empty known cookie permits Bearer. Duplicate known cookies or multiple Cookie
headers return 401. The mature Authorization parser rejects ambiguous input;
unsupported JWT/upstream credentials cannot fall back to another transport.

## Verify possession and observe current authority

The borrowed SqliteAdminLocalBearerSessions view is obtained with:

~~~text
store.admin_local_bearer_sessions(audience, identity_json_bytes, limits)?
    .read(raw, required_scopes, original).await
~~~

It consumes raw possession through the qualified [SQLite LOCAL verifier](rust-sqlite-local-bearer.md),
including exact gb_at_/gb_sc_ HMAC domains, audience, scopes, expiry, revocation
and current identity eligibility. A supplied profile or role list is never proof.
The genuine VerifiedLocalBearer remains owned through the worker and final result.

A bounded IMMEDIATE transaction then observes current identity, profile, assignments
and role definitions together. Username, raw subject, revision, kind and enabled
state must still match the proof. Humans and services are eligible. The implicit
user role and local|raw-subject assignments supply current SQL permissions;
session.read or wildcard is required. Scopes alone confer no RBAC permission.
Changing current policy changes the next request with the same credential.

Opaque admission does not impose the required-password-change gate. Login and
cookie bindings retain their existing human-only and clear-change-flag gates.
The shared observer distinguishes these typed bindings without copying the SQL
or treating cookie metadata as a bearer proof. Caps apply in SQL before text
allocation, with the existing row sentinel, strict codecs and sorted output.

Success returns current raw subject, username, name, email, organization, normalized
teams, roles and permissions, role_source: database and empty csrf_token. HEAD
keeps status/headers without a body. Bearer reads create neither a cookie nor a
session row. Responses retain no-store, no-cache and X-Request-ID.

## Failure and lifecycle

Invalid authentication, audience/scope/binding, unsupported or failed cookie:
401 admin_unauthorized. Missing current permission: 403 admin_forbidden.
Corrupt/oversized identity or RBAC: 500 authorization_failed. Closed store or
uncertain COMMIT: 503 administration_unavailable. Original/operation deadline:
504 administration_unavailable. Errors omit SQL, credentials and private paths.

The request's Original end and original authentication UTC/monotonic expiry are
retained through SQL and serialization. The current-observation wait is capped
by the earlier of the request end and original bearer expiry. A current revision
change after possession verification denies the observation. No stage renews the budget. Known COMMIT
uncertainty takes precedence over final gates; no outer SQL timeout, automatic
replay or frozen revocation lease is introduced. LOCAL access/service verification
writes no usage metadata, including when a later administrative check denies.

## Validation

~~~text
cargo test --locked --offline -j4 -p broker-control --test sqlite_admin_local_bearer
cargo test --locked --offline -j4 -p broker-presence --test sqlite_admin_local_bearer_http
~~~

The tests use a physical private SQLite file, real HMAC tokens, current SQL state and real TCP HTTP. Cookie coexistence uses the trusted metadata fixture; genuine cookie issuance and password/factor journeys are covered by the affected sqlite_admin_cookie and sqlite_admin_local_http native suites.

Sources: crates/broker-control/src/sqlite/flow/admin_local_bearer_session.rs,
admin_local_observer.rs and the shared AdminLocalBearerSession result;
crates/broker-presence/src/admin_session.rs. Global Server backend selection and
other administrative transports remain separate integration work.
