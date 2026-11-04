---
title: Rust federated administrative cookies
doc_type: reference
references:
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9548, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-06cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-d03f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-a729, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Rust federated administrative cookies

The explicit [SQLite administrative ingress](rust-sqlite-admin-session.md) supplies `SqliteAdminCookieSessions` through `store.admin_cookie_sessions(limits, policy, upstream)`, where `upstream` is `Option<Arc<UpstreamBearerVerifier>>`. It consumes a genuine H1 Admin proof from the same configured trust/browser owner. Issuance, current read and own logout use the existing SQLite physical executor and require known COMMIT. Cookie reads use current cookie-role selector policy and never fetch upstream identity over the network. This producer does not add the administrative browser HTTP callback or select SQLite globally in Server.

For server integrators using the Rust `broker-control` PostgreSQL implementation.
The [upstream browser producer](rust-upstream-browser-login.md) authenticates an
OIDC identity; this consumer turns its genuine Admin proof into a stored cookie,
reads current trust and permissions, and confirms own-session logout. Native
the [native browser HTTP/configuration adapter](rust-admin-upstream-login.md)
connects this producer to the existing HTML and callback. This library itself
adds no route, OP grant or compatibility importer.
The native [cookie transport](rust-admin-cookie-session.md) and
[LOCAL HTTP login](rust-admin-local-login.md) retain their existing boundaries.

## Borrow the configured owner

Use the same `UpstreamBearerVerifier` instance that produced the login proof:

```rust,ignore
let cookies = store.admin_cookie_sessions(limits, policy, Some(&verifier))?;
let issued = cookies.issue_upstream(completed_upstream_login, original).await?;
issued.check()?;
let current = cookies.read(issued.secret(), original).await?;
current.check()?;
cookies.logout(issued.secret(), Some(current.csrf_token()), original).await?;
```

`completed_upstream_login` must come from a real matching SQL flow and mature OIDC
code exchange. `VerifiedUpstreamLogin` cannot be cloned, deserialized, defaulted or
constructed from profile metadata. It is consumed by value and must have Admin
purpose. A different verifier with identical issuer/client strings fails the
private physical owner check. An OAuth continuation cannot issue an Admin cookie.

The common factory takes `(limits, policy, upstream)` with independent borrowed
store/verifier lifetimes. `None` explicitly supplies LOCAL-only read/issuance;
LOCAL callers use `issue_local` with their genuine protected LOCAL login. Presence
borrows its existing optional common owner. Runtime/configuration preparation
continues to prepare and transfer that owner once.

## Issue only after current SQL authorization

Selector provenance preserves the exact compiled key, including whitespace. An
empty or missing selected role list is a stored claims snapshot with only implicit
`user`; it does not fall back to SQL assignments. Current SQL permission is still
mandatory.

The principal is `issuer|mappedsubject`: `mappedsubject` is the protected producer's
`profile.subject`. The validated raw OIDC `sub` binds ID, access and UserInfo
sources, and is not substituted for the configured mapped identity. The stored
external principal has `local_user_revision = 0`; it grants no LOCAL identity.
Profile, username, organization, teams and any role-selector/claim-role snapshot
come exclusively from the genuine proof.

One READ COMMITTED transaction observes current assignments or protected claim
roles, implicit `user`, current SQL role definitions, and `session.read` or `*`,
then inserts parent and principal metadata. The shared bounded observer checks the
caller's validity gate for every row. Profile, role, row, list and serialized JSON
limits remain explicit. No current permission means Forbidden and no issued cookie.

Cookie and CSRF are independent fallible 256-bit OS draws encoded by the mature
base64url SDK. The cookie is a canonical 43-byte native secret; only its domain-1
HMAC enters SQL. The stored CSRF is recoverable protected metadata. The existing
cookie policy defaults to eight hours in native configuration and accepts five
minutes through 168 hours. Typed library callers supply their policy explicitly.
Stored metadata accepts at most 168 hours. The cookie owns a captured UTC/monotonic
window; its lifetime is independent of ID-token expiry and is never clamped to it.

The producer proof, binding, immutable Original and expiry must remain live before
SQL, before COMMIT and after known COMMIT. Awaiting SQL uses the minimum of the
existing operation deadline, producer Original, cookie window and producer expiry, without re-anchoring
the proof. Only acknowledged COMMIT and final gates return `IssuedAdminCookie`.
An uncertain COMMIT returns no credential or automatic replay instruction, even
when the INSERT is already visible to another SQL connection. It takes precedence
over a later expiry. The [cookie header serializer](rust-admin-cookie-session.md)
accepts this protected owner and preserves its time gates.

## Read current trust and permissions

Read validates the canonical cookie/HMAC and bounded joined SQL metadata before
constructing a closed LOCAL or federated `CookieReadProof`. The public
`AdminCookieReadSession` projects only authenticated data and holds its captured
expiry and Original through SQL/serialization. It is a current session-read
observation, not authority for a later write.

LOCAL read retains the user-before-parent lock order and current human, enabled,
revision and password-change checks. Federated read requires the issuer in the
current common configured owner. Removing/disabling that issuer denies read;
removing only its browser client leaves existing-cookie issuer trust intact.
This is a pure configuration lookup: no discovery, JWK refresh, UserInfo,
introspection or issuer request occurs during cookie read.

| Current role selector | Stored snapshot | Read behavior |
|---|---|---|
| Same selector | Matching protected selector/roles | Use stored roles and current SQL definitions; `role_source` is `claims`. |
| Added or changed selector | Absent or different | Unauthorized; complete a fresh login. |
| Removed selector | Any old claim-role snapshot | Ignore old claim roles and use current canonical SQL assignments; `role_source` is `database`. |

Every branch includes implicit `user` and requires current `session.read` or `*`.
SQL changes take effect at the next read. Lowering issuance TTL does not shorten a
stored cookie. GET/HEAD emits no Set-Cookie, renews no expiry, and returns the same
session wire and protected CSRF through the existing transport. The issuer's ID
token may expire after issuance without ending this independent cookie session.

## Log out and recover

Own-session logout matches the stored cookie, validates structural metadata, and
compares decoded CSRF bytes with `subtle` before confirmed DELETE/cascade. It does
not add current issuer trust or `session.read` checks. Removal of issuer/roles may
deny read while valid own-session CSRF still permits logout. External metadata is
never authenticated as a fictitious LOCAL principal.

Known active sessions require canonical CSRF. Expired valid sessions need known
cleanup and do not require CSRF. Unknown canonical secrets require confirmed SQL
absence; malformed/absent browser credentials retain the transport's guest-clear
behavior. Corruption is denied and preserved. A browser clear header is never
proof that SQL revocation succeeded. Concurrent logout observes one Revoked and
one Absent result. Cancellation or unconfirmed transactions close their physical
connection rather than returning it for reuse.

Wrong owner/purpose, cookie or current trust/selector yields Unauthorized; missing
current permission yields Forbidden; SQL/corrupt metadata yields finite Control
errors. Proof expiry remains `Control(Expired)`, stored expiry is
`Control(SessionExpired)`, and elapsed Original is `Control(Deadline)`. An uncertain
COMMIT is `Control(OutcomeUncertain)`. Existing read/logout HTTP mappings remain
as described in the [cookie transport reference](rust-admin-cookie-session.md).
No upstream browser callback error mapping is delivered by this library.

## Source and executable verification

The owner is `crates/broker-control/src/service/admin_cookie_session.rs`; its
sealed projections are exposed by `crates/broker-control/src/admin_cookie_session.rs`.
The private shared observer remains in `service/admin_upstream_session.rs` and
F1 continues to retain its genuine resource-token proof. Presence uses the existing
common owner and delegates cookie `role_source()`.

Run the real TLS issuer, PostgreSQL NOSUPERUSER and actual COMMIT-ACK contracts:

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_admin_federated_cookie -- --ignored --exact postgres_admin_federated_cookie_contract --test-threads=1
cargo test --locked --offline -j4 -p broker-control --test postgres_admin_federated_cookie -- --ignored --exact postgres_admin_federated_cookie_uncertainty_contract --test-threads=1
```

These exact phases belong to the active xtask qualification sequence. Its adversarial
runner executes an actual failing Rust contract and verifies that later phases
are not reached. Full migration integration and other platform execution remain
separate coordinator outcomes; library verification does not prove browser HTTP,
OP grants or the migration complete.
