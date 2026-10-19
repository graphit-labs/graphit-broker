---
type: document
title: SQLite LOCAL administrative cookies
status: implemented
description: Genuine LOCAL login issuance, current administrative cookie reads and confirmed own-session logout in the private SQLite catalog.
references:
  - target: {type: task, id: tsk-8802, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-d03f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-cbcc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite LOCAL administrative cookies

Backend integrators can consume a genuine [LOCAL login](rust-sqlite-local-auth.md) to issue an administrative cookie on the [private SQLite control store](rust-sqlite-control.md), read its current LOCAL identity and permissions, and confirm own-session logout. This library is qualified on Linux under tsk-8802. It preserves the [native cookie contract](rust-admin-cookie-session.md) and shared protected result types.

The explicit LOCAL factory provides no upstream issuance or authenticated federated read. Server database selection remains separate; the [LOCAL HTTP adapter](rust-sqlite-admin-local-http.md) is qualified. Stored profile or session metadata never supplies issuance authority.

## Borrow the producer

~~~text
SqliteControlStore::local_admin_cookie_sessions(
    &self,
    limits: AdminCookieSessionLimits,
    policy: AdminCookieSessionPolicy,
) -> Result<SqliteLocalAdminCookieSessions<'_>, ControlError>

SqliteLocalAdminCookieSessions::issue_local(
    &self, prepared: PreparedAdminLogin, policy: &LocalAuthPolicy, original: Instant,
) -> Result<IssuedAdminCookie, AdminCookieSessionError>  // async

SqliteLocalAdminCookieSessions::read(
    &self, raw: &str, original: Instant,
) -> Result<AdminCookieReadSession, AdminCookieSessionError>  // async

SqliteLocalAdminCookieSessions::logout(
    &self, raw: &str, csrf: Option<&str>, original: Instant,
) -> Result<AdminCookieLogout, AdminCookieSessionError>  // async
~~~

The view borrows the genuine store, exposes redacted Debug, and has no Clone, Default, serde representation or exported SQL connection. Limits and policy are explicit: the existing TTL range is five minutes through 168 hours, metadata lifetime must cover issuance TTL, and the stored CSRF cap must accept 43 bytes. The shared HTTP-date range guard is retained. This API adds no defaults or quota.

## Issue from the completed login

First retain any one-time recovery codes through the trusted LOCAL consumer. Synchronous PreparedAdminLogin::try_from accepts only a genuine AdminLogin with no pending recovery codes. Its error returns the intact protected login through into_login; issuance neither acknowledges nor discards recovery codes automatically.

The producer verifies the domain-13 AdminLogin binding with its real store digester, a nonfuture completion timestamp and the genuine factor when the supplied trusted LOCAL policy requires it. Password hashing and MFA remain the existing LOCAL producers.

One IMMEDIATE transaction observes current identity, profile, assignments and role definitions before inserting parent/principal metadata. The user must remain human, enabled, at the bound username/raw subject/revision, with no required password change. Current profile data replaces the login snapshot. The observer includes implicit user plus local|raw-subject assignments and requires current session.read or wildcard permission. Profile, text, JSON, row and role limits apply before allocation or delivery; permission strings are strictly typed and outputs sorted/deduplicated.

Cookie and CSRF are independent fallible 256-bit OS CSPRNG draws encoded by the shared base64url SDK. The raw cookie stays outside SQL; SQL stores its domain-1 HMAC digest and protected canonical CSRF metadata. LOCAL inserts issuer local and no claimed-role row. No observer, limit or expiry failure returns an issued credential. Insertion is atomic; late committed effects follow the uncertainty rules below.

## Read current authority

Read validates canonical raw cookie format before HMAC/SQL and loads bounded, strict joined metadata inside the same IMMEDIATE transaction as current authorization. The shared insert/load helpers do not begin or commit another operation. Metadata is data; the public metadata reader is never composed as an authorization lease.

Corrupt metadata is denied and preserved before expiry handling. A valid expired parent is deleted with its children and SessionExpired is returned only after known COMMIT. An active nonlocal session returns Unauthorized. LOCAL claimed-role metadata is invalid for this reader.

Current human/enabled/revision/username/subject/password-change state, profile and SQL permissions are observed again for every read. Missing current identity yields Unauthorized; missing session.read yields Forbidden. The sealed CookieReadProof is constructed only from this genuine observation and retained inside AdminCookieReadSession. It grants no authority for a later administrative write.

Successful reads return current profile, roles and permissions, database role source, protected stored CSRF and the existing absolute authentication expiry. Read neither renews the expiry nor emits a cookie header.

## Confirm own-session logout

Logout loads and validates metadata before classifying expiry. It does not require a current enabled user, role, issuer trust or session.read permission. A valid owner can end a session after those changes deny read.

| Stored state | Required CSRF | Confirmed result |
| --- | --- | --- |
| No matching parent | None, including malformed supplied values | Absent |
| Valid expired metadata | None | Expired after parent DELETE/cascade |
| Valid active metadata | Canonical decoded 32-byte value, compared in constant time | Revoked after parent DELETE/cascade |
| Corrupt metadata | No value can authorize cleanup | Finite error; stored rows retained |

Missing, malformed or wrong active CSRF yields CsrfFailed without deletion. This protected metadata/logout operation also supports stored federated rows, without promising federated issuance or authenticated reads. Unrelated parents and children remain intact.

## Deadlines, uncertainty and transport

One effective Original deadline and captured UTC/monotonic cookie window bound the operation. The existing SQLite executor retains the physical worker, transaction and sensitive owners through completion; cancellation and close use that producer's lifecycle. There is no new outer SQL timeout or automatic replay.

Only known COMMIT and final delivery gates produce IssuedAdminCookie, AdminCookieReadSession or confirmed AdminCookieLogout. OutcomeUncertain takes precedence over a later time cutoff and returns no such output. A durable late COMMIT can require fresh authorized observation or login; uncertainty never proves rollback.

The existing broker_presence::admin_cookie_header accepts the genuine issued owner and checks it through serialization: HttpOnly, SameSite=Lax, Path=/, trusted explicit Secure, SDK Expires and remaining Max-Age. The header never extends stored expiry. No new cookie parser, header serializer, route or transport dispatch is supplied here.

## Sources and qualification

Implementation and affected tests:

- crates/broker-control/src/sqlite/flow/admin_cookie_session.rs
- crates/broker-control/src/sqlite/flow/admin_local_observer.rs
- crates/broker-control/src/sqlite/flow/session.rs shared transaction-local insert/load
- crates/broker-control/tests/sqlite_admin_cookie.rs
- crates/broker-control/tests/sqlite_sessions.rs

~~~text
cargo test --locked --offline -p broker-control --test sqlite_admin_cookie -- --ignored --test-threads=1
cargo test --locked --offline -p broker-control --test sqlite_sessions -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib --test sqlite_admin_cookie --test sqlite_sessions -- -D warnings
~~~

The existing LOCAL gate selects the LOCAL and cookie targets. The physical executor COMMIT/ACK/cancel/close, native LOCAL producers and shared cookie window/header contracts have separate tests. This library API alone does not establish server backend integration or other-platform support.

The [explicit SQLite LOCAL administrative HTTP consumer](rust-sqlite-admin-local-http.md) is qualified on Linux. It composes the genuine password/factor runtime with this producer for existing login, continuation, current session and confirmed logout paths; final Server configuration and backend dispatch remain separate.

The shared current LOCAL observer also serves [opaque administrative bearer reads](rust-sqlite-admin-local-bearer-session.md) with a distinct typed binding. That path admits humans and services without adding a password-change gate; cookie/login bindings retain their existing human-only and clear-change-flag requirements.
