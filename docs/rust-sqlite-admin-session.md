---
title: SQLite administrative session ingress
doc_type: reference
description: Explicit SQLite composition for current administrative session reads, native and upstream authentication, and confirmed own-cookie logout.
references:
  - target: {type: task, id: tsk-7204, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---

# SQLite administrative session ingress

Backend integrators can compose the [private SQLite control store](rust-sqlite-control.md) with native Broker access JWT, opaque LOCAL bearer, upstream resource bearer F1, and LOCAL or federated administrative cookies. The explicit Presence router serves `GET`/`HEAD /admin/api/v1/session` and optional `POST /admin/auth/logout` using the [existing session wire](rust-admin-session-http.md).

This library API has separate runtime tests; Linux execution does not establish Windows/macOS behavior.

The separately qualified [SQLite administrative browser composition](rust-sqlite-admin-upstream-login.md) supplies H3 and genuine H1→H2→cookie→session/logout journeys. The [administrative readers](rust-sqlite-admin-read.md) also reobserve native JWT, opaque bearer, F1 and cookies against their own current actions. These library compositions do not select SQLite globally in Server or supply administrative CRUD. A successful `session.read` result is not an authorization lease for a subsequent read or mutation.

## Construct the actual producers

The caller supplies a genuine opened store, explicit validated limits, and the configured verifier owners. Factories borrow their store; native and F1 session views also borrow their verifier. Their protected result types retain genuine authentication evidence.

~~~text
SqliteControlStore::admin_broker_sessions<'s, 'v>(
    &'s self, verifier: &'v BrokerAccessVerifier,
    limits: AdminBrokerSessionLimits,
) -> Result<SqliteAdminBrokerSessions<'s, 'v>, ControlError>

SqliteAdminBrokerSessions::read(
    &self, proof: VerifiedBrokerAccess<'v>, original: Instant,
) -> Result<AdminBrokerSession<'v>, AdminBrokerSessionError>  // async

SqliteControlStore::admin_upstream_sessions<'s, 'v>(
    &'s self, verifier: &'v UpstreamBearerVerifier,
    limits: AdminBrokerSessionLimits,
) -> Result<SqliteAdminUpstreamSessions<'s, 'v>, ControlError>

SqliteAdminUpstreamSessions::read(
    &self, raw: &str, original: Instant,
) -> Result<AdminUpstreamSession, AdminBrokerSessionError>  // async

SqliteControlStore::admin_cookie_sessions(
    &self, limits: AdminCookieSessionLimits,
    policy: AdminCookieSessionPolicy,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
) -> Result<SqliteAdminCookieSessions<'_>, ControlError>

SqliteAdminCookieSessions::issue_upstream(
    &self, proof: VerifiedUpstreamLogin, original: Instant,
) -> Result<IssuedAdminCookie, AdminCookieSessionError>  // async
~~~

The complete cookie owner also provides the existing `issue_local`, `read` and `logout` contracts. `None` for its upstream owner means LOCAL only: federated issuance and read are denied. The explicit `local_admin_cookie_sessions` factory and [LOCAL cookie contract](rust-sqlite-admin-cookie-session.md) remain available. No public constructor converts profile JSON, session metadata or SQL rows into authentication proof.

~~~text
sqlite_admin_session_router_with_cookie(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError>
~~~

Every optional argument feeds its concrete producer. Omitting cookie configuration omits logout. The existing explicit LOCAL router and PostgreSQL factories retain their contracts. The router does not issue an upstream cookie from a raw ID token or expose a new login route.

## Read a Broker JWT against current LOCAL authority

1. Obtain a genuine native Broker access JWT from [SQLite code exchange or refresh](rust-sqlite-oidc-local-grants.md). An ID token is not an administrative access credential.
2. Verify it with the configured `BrokerAccessVerifier`, then pass that genuine `VerifiedBrokerAccess` to the borrowed session view. A proof from another verifier owner is invalid.
3. The session producer uses signed `preferred_username` only to locate the current LOCAL row. It binds the signed pseudonymous subject to the domain-15 digest of literal issuer `local` and the current raw SQL subject.
4. In one SQLite IMMEDIATE transaction, it requires an enabled human or service identity and current `session.read` or wildcard permission, projects the current SQL profile and RBAC, and confirms physical COMMIT.

The returned profile replaces stale mint-time attributes; `role_source` is `database` and bearer CSRF is empty. A valid JWT does not acquire a mint-revision check, password-change gate, token-ledger lookup, UserInfo request or immediate revocation on password change. Opaque and LOCAL cookie admission keep their own existing rules.

## Read an upstream resource bearer

F1 uses the [common upstream bearer verifier](rust-admin-upstream-session.md): configured issuer, signature, audience/resource, scopes, predicates and bounded profile claims are verified before SQL authority is consulted. The genuine `VerifiedUpstreamBearer` survives the worker and remains in the result. An external identity is never converted into a LOCAL principal.

Current roles and permission definitions are observed in the same IMMEDIATE transaction:

| Current configuration | Selected roles | Wire provenance |
| --- | --- | --- |
| No OAuth role selector | SQL assignments for literal `issuer|mapped-subject`, plus implicit `user` | `database` |
| OAuth role selector present | Selected claim roles, including `Some([])`, plus implicit `user`; SQL assignments excluded | `claims` |

Both paths use current SQL role definitions and permissions. A role without a definition is inert and contributes no permission; it does not deny another valid authorization. Malformed stored fields, invalid types or unknown stored actions remain errors. Missing `session.read` or wildcard permission denies access. Removing a permission takes effect on the next observation. Verification failure never retries the credential through another authentication mode.

## Issue and read a federated H2 cookie

The [SQLite upstream browser producer](rust-sqlite-oidc-federated.md) completes a genuine HTTPS H1 flow with programmatic `FlowContinuation::Admin`. Its SQL matching consume returns `VerifiedUpstreamLogin`. Pass that proof to `issue_upstream` on a complete cookie owner configured with the same trust/browser owner.

H2 requires Admin purpose and the same `BrowserOwner` retained by the verifier. A different verifier/browser owner or purpose is invalid. This is a trust-owner binding; it does not invent a requirement that H1 and H2 use the same store instance.

Issuance retains the proof and configured owner through physical COMMIT acknowledgement. It uses the earlier caller/proof Original and the proof's UTC/monotonic validity. Profile, external issuer, username, organization, teams and claimed-role provenance come from the proof; the federated LOCAL revision field is zero. Current `session.read` authority and parent/principal insertion occur in one IMMEDIATE transaction.

The cookie and CSRF are independent fallible OS CSPRNG secrets. Raw cookie material is not persisted as SQL authority. Existing metadata caps and lifetime bounds apply. Cookie TTL is independent of the upstream ID-token TTL: issuance does not clamp it to the ID token or renew the proof's clock. Failure, cancellation or uncertain COMMIT acknowledgement returns no issued credential and must not trigger automatic replay.

Subsequent reads validate bounded metadata, the cookie's own expiry and current issuer/authorization policy without upstream network requests. The current **cookie** role selector controls cookie RBAC, independently of the OAuth bearer selector:

| Change after issuance | Existing federated cookie |
| --- | --- |
| Remove or disable issuer | Read denied |
| Remove only browser client | Read remains possible under current issuer/RBAC policy |
| Remove cookie role selector | Stored claim roles ignored; current SQL assignments used |
| Add or change cookie role selector | New login required unless stored selector provenance matches |
| Change role definitions/permissions | Current SQL definitions apply |

LOCAL cookies still require the current human identity, bound revision and password-change rules. Their authority is not replaced by the federated branch.

## Use the session and logout HTTP contracts

A request with one known nonempty `graphit_admin_session` cookie uses that cookie first. Invalid cookie authentication cannot fall through to a valid bearer. Missing cookie, empty value or literal `""` permits bearer dispatch. Ambiguous or duplicated cookie/authorization input is rejected by the existing parsers.

Bearer dispatch selects opaque `gb_at_`/`gb_sc_` when configured, configured upstream F1, or native Broker JWT using the existing explicit selector. It does not probe modes until one accepts.

Successful GET returns the shared JSON fields `subject`, `name`, `email`, `username`, `organization`, `teams`, `roles`, `role_source`, `permissions` and `csrf_token`. Only a cookie observation returns its existing CSRF token. HEAD authenticates and authorizes the same operation with no response body. Neither operation renews a cookie or sends `Set-Cookie`. Responses preserve the validated/generated request ID in JSON where applicable and `X-Request-ID`, with `Cache-Control: no-store` and `Pragma: no-cache`.

To end a known cookie session, POST to `/admin/auth/logout` with that cookie and one `X-CSRF-Token`. CSRF comparison is constant time. Logout reuses the structural own-session implementation: current issuer enablement, roles and `session.read` are not prerequisites for disposing of the caller's known session. Issuer or role removal therefore does not prevent logout. Known absence and expired cleanup retain their existing semantics. Successful logout returns 204 and clears the browser cookie only after its known result; CSRF failure returns 403 without claiming disposal.

| Session failure | Status / code |
| --- | --- |
| Invalid or expired authentication | 401 / `admin_unauthorized` |
| Valid authentication without permission | 403 / `admin_forbidden` |
| Original/authentication deadline | 504 / `administration_unavailable` |
| Closed, unavailable or uncertain store; entropy failure | 503 / `administration_unavailable` |
| Other control failure, including corruption or limits | 500 / `authorization_failed` |

Errors are finite and omit credentials, claims, profile contents and SQL. Transport/configuration policy such as Origin/CORS remains with its existing owner; this factory adds no new policy or token-in-query admission.

## Time, isolation and recovery

The producers use the physical SQLite executor, IMMEDIATE transactions and `Work::commit` acknowledgement. They do not emulate PostgreSQL row/advisory locks. Current profile, assignment and permission observations share a snapshot. SQLite field types and configured identity/profile/role/row/metadata caps are checked before copying or expansion; no new per-entity quota or truncation is introduced.

The effective wait is bounded by the caller's Original and the retained authentication/cookie window. Checks surround SQL work, decoding, projection and commit; HTTP checks also bound response preparation. Captured cutoffs classify late negative results and never substitute for retained proof. An outer or inner `OutcomeUncertain` takes precedence over final clock or semantic errors. There is no successful partial result, automatic retry or outer timeout that abandons a mutation and reports it as known failure.

On an ordinary denied read, repair the current identity, policy or permission and authenticate again as appropriate. On a changed cookie selector, perform a new genuine login. On uncertain acknowledgement, preserve that uncertainty rather than assuming rollback or replaying issuance. Operational reopening/recovery belongs to the physical store contract.

## Evidence and delivery boundaries

Source evidence is `crates/broker-control/src/sqlite/flow/admin_broker_session.rs`, `admin_upstream_session.rs`, `admin_local_observer.rs`, `admin_cookie_session.rs`, and `crates/broker-presence/src/admin_session.rs`. Shared protected proof/result types and pure validations are reused from their existing service modules.

The affected targets are Control `sqlite_admin_ingress` and Presence `sqlite_admin_session_http`, plus their LOCAL consumer regressions.

The temporal fixture preserves the productive minimum cookie TTL of 300s. It issues a genuine H2 cookie with TTL 1800s, then changes only that temporary SQLite session's `expires_at` to create a two-second expiry. A causal queued-job waker delays caller resumption beyond expiry; authentication proofs and clocks are genuine. The first attempt's invalid two-second issuance policy is retained as a failed fixture attempt. The HTTP correction preserves the existing valid, echoed request ID containing spaces rather than imposing an invented 401 rule.

Opaque coexistence uses a controlled persisted credential fixture, following the existing SQLite opaque contract. It exercises real SQL read/verification and HTTP dispatch. It does **not** demonstrate raw opaque issuance end to end. There is no public SQLite raw opaque issuance producer in this leaf; raw issuance, CRUD and Server composition remain separate obligations. The new JWT, F1 and H1→H2 journeys use their genuine producers.

The H3 [browser callback](rust-sqlite-admin-upstream-login.md) and full-channel [administrative readers](rust-sqlite-admin-read.md) have separate tests. Session-ingress tests do not establish CRUD, global Server composition or other-platform behavior.
