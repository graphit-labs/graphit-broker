---
title: Read administrative data from SQLite
description: Action-specific SQLite projections through native Broker JWT, opaque LOCAL, upstream bearer and LOCAL or federated cookie authentication.
doc_type: reference
tags: [rust, sqlite, administration, authorization]
references:
  - target: {type: task, id: tsk-0dff, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-3daa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-8802, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7ac1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Read administrative data from SQLite

This reference covers the native library vertical for administrators and HTTP
compositors using a genuine private `SqliteControlStore`. The complete reader
accepts native Broker JWT, opaque LOCAL bearer, upstream resource bearer F1,
and LOCAL or federated administrative cookies. Every read authorizes its own
action and projects data in the same SQLite IMMEDIATE transaction.

This library covers full-channel administrative reads. Global Server composition and Windows/macOS execution require separate validation.

This library does not install the complete SQLite Server administration block,
H3 browser callback or administrative writes. The [PostgreSQL read contract](rust-admin-read.md)
remains active. The [session ingress delivery](rust-sqlite-admin-session.md)
supplies the shared genuine authentication producers; a session result never
authorizes a later read.

## Authenticate and read one action

`store.admin_reads(AdminReadLimits)` validates the limits and returns a borrowed
`SqliteAdminReads<'_>`. Its complete entry point is:

```text
read<'a>(
    authentication: AdminReadAuthentication<'a, '_>,
    request: AdminReadRequest<'_>,
    original: Instant,
) -> Result<AdminReadResult<'a>, AdminReadError>  // async
```

The common redacted `AdminReadAuthentication` input retains the actual configured
owners and genuine factors:

| Input | Authentication and current authority |
|---|---|
| `Broker { verifier, proof }` | Genuine borrowed proof from that Broker verifier; current LOCAL profile, enabled identity, domain-15 subject binding and action RBAC |
| `Opaque { raw, audience, identity_json_bytes, required_scopes }` | Existing real LOCAL human/service possession verification and current SQL identity/RBAC |
| `Upstream { raw, verifier }` | Raw F1 verified by the borrowed configured upstream verifier; owned proof retained through SQL/ACK/result, with current SQL role definitions |
| `Cookie { raw, limits, policy, upstream }` | Genuine cookie metadata and current LOCAL or federated authority; `upstream` is `Option<Arc<UpstreamBearerVerifier>>` |

Only bounded Broker locator/subject/expiry data and the actual store digester
cross into its worker; the borrowed proof stays in the caller/result and is
rechecked. The F1 verifier stays borrowed at the call boundary while its genuine
owned verification result crosses the worker. The cookie branch retains the
configured upstream Arc for current trust and selector checks inside the worker.
No profile, stored metadata or caller-built witness can manufacture authority.

Each branch authorizes `request.kind().action()` and projects the response under
the same transaction. It never calls `session.read` first or requires an extra
`session.read` permission. JWT profile claims do not replace current SQL LOCAL
identity; existing JWT revision/password-change semantics remain unchanged.

### Current federated policy

F1 verifies the real issuer/signature/audience/resource/scopes/predicates through
the common upstream verifier. Its OAuth role selector uses selected claim roles,
including `Some([])`, plus implicit `user`; without that selector it uses current
assignments for literal `issuer|mapped-subject`, plus `user`. Both paths resolve
current SQL definitions and the exact requested action. A role without a SQL
definition is inert, contributes no permission and does not invalidate another
real authorization. Invalid stored actions/types remain errors.

Federated cookies instead use the current cookie-role selector. Removing or
disabling the issuer denies the read. Adding or changing the selector requires
matching stored provenance; removing it ignores old claims and uses assignments.
Removing only the browser client does not revoke an existing cookie. These
checks and the requested action occur after genuine metadata loading and before
projection in the same transaction; cookie read makes no upstream network call.
Without the optional configured upstream owner, federated cookie admission is
denied. LOCAL cookies retain their current human/revision/password-change rules.

### Retained LOCAL producer

`store.local_admin_reads(AdminReadLimits)` returns a borrowed
`SqliteLocalAdminReads<'_>` after validating the configured limits. Call either:

```text
read_opaque(raw, audience, identity_json_bytes, required_scopes, request, original)
read_cookie(raw, cookie_limits, cookie_policy, request, original)
    -> Result<AdminReadResult<'static>, AdminReadError>
```

`raw` is actual possession, `original` is the caller's existing finite `Instant`,
and `request` is an `AdminReadRequest`. No transport is selected implicitly.
The opaque verifier checks genuine LOCAL human or service access, then retains
the non-cloneable factor through the worker and final result. Current SQL
identity, revision, binding, profile and roles are observed again for the exact
requested action. Opaque access does not require a clean password-change flag.
Cookie reads require a genuine HMAC-protected LOCAL human session, valid
metadata, current revision and a clean password-change flag.

Each route requires only the following action or the existing wildcard. A
previous `session.read` result, profile, hint, role list or catalog is DATA and
does not authorize this read. `session.read` alone cannot read any of these routes.

| GET/HEAD route under `/admin/api/v1/` | Current action | Complete result |
|---|---|---|
| `projects` | `projects.read` | `{projects,all_projects,authorization_revision,provider_command}` |
| `roles` | `roles.read` | `{roles,actions}` |
| `role-assignments` | `roles.read` | `{assignments,bootstrap_only}` |
| `local-users` | `users.read` | `{users}` |
| `principals` | `grants.read` | `{principals}` |
| `grants` | `grants.read` | `{v:1,revision,updated_at,rules}` and the same revision ETag |
| `config` | `configuration.read` | `{source:"deployment",restart_required:true,yaml}` |

## Compose the HTTP consumer

The single complete SQLite HTTP factory mirrors the PostgreSQL argument order:

```text
sqlite_admin_read_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    config: AdminReadHttpConfig,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError>
```

The former LOCAL-only HTTP factory/backend is removed; the complete factory
serves both the existing LOCAL consumers and the additional channels. Control's
`local_admin_reads` remains a real producer reused by the complete opaque branch.
Optional configurations feed their concrete producers; no verifier is fabricated.
Validate and
capture the caller's typed redacted deployment projection as
`AdminReadHttpConfig.configuration_yaml` before constructing the router. It is
server-provided DATA, never YAML accepted from a request. This factory neither
creates a SQLite deployment builder nor serializes a raw configuration owner.

A nonempty administrative cookie has precedence. An invalid cookie returns
401 even when a valid bearer is also supplied. An empty administrative cookie
permits bearer dispatch: configured opaque `gb_at_`/`gb_sc_`, upstream F1 when
the configured selector chooses it, then native Broker JWT. A failed selected
mode never falls through to another. Duplicate/malformed credential
headers follow the existing parsers. GET/HEAD needs no CSRF input, never renews
the cookie and emits no `Set-Cookie`. Successful and failed read responses,
including native method rejection, carry `Cache-Control: no-store` and
`Pragma: no-cache`. HEAD preserves response metadata and emits no body.
The normal administrative responses retain the finite `request_id` and
`X-Request-ID` correlation convention. Other methods return 405.

| Condition | HTTP result |
|---|---|
| Invalid/expired factor or current binding | 401 `admin_unauthorized` |
| Missing requested action | 403 `admin_forbidden` |
| Corrupt current identity/authorization SQL | 500 `authorization_failed` |
| Projects projection failure | 503 `projects_read_failed` |
| Other projection failure | 500 with that projection's existing finite code |
| Original deadline | 504 `administration_unavailable` |
| Closed store or uncertain physical outcome | 503 `administration_unavailable` |

Authentication errors never include token, SQL, profile or secret text. When a
read fails, do not treat the response as an empty list or substitute a previous
session result. Correct the expired factor, action assignment, bounds or stored
data indicated by the finite error before making a new request.

## Snapshot, limits and data integrity

Authorization for the action and all its SQL projections share one physical
IMMEDIATE transaction. Projects and grants load the ACL through the transaction's
`observe_snapshot`, rather than opening a second reader transaction. Read-only
logical operations still require a known physical COMMIT acknowledgement.
`OutcomeUncertain` has priority over final expiry/deadline/semantic errors.

Broker, F1 and opaque worker waiting ends at the smaller of Original and the
genuine factor's captured monotonic expiry; available UTC and monotonic cutoffs
also classify late errors. Broker borrowed proof and owned F1/opaque proof remain
retained and are rechecked rather than replaced by those cutoffs.
Cookie processing captures its clock once, validates metadata before expiry and
uses the actual window. Expired cookie cleanup requires a known COMMIT. Gates
surround SQL, decoding, encoding, commit and HTTP header preparation. Cancellation,
expiry or a closed owner cannot release a late positive body. The protected
result is neither a reusable SQL lease nor proof that a disconnected client
received the response.

All existing identity/profile caps must agree between read/session/cookie
configuration; mismatches are `Configuration` errors. Positive representable
`grants_json_bytes` and `response_json_bytes` bound complete aggregates before
driver copying and final JSON encoding. A response may also fail because its
complete intermediate user aggregate exceeds the response bound, even when its
final principal hints would be smaller. Lists fail as a whole: no truncation or
partial success. These bounds do not bound SQLite's internal aggregation memory
or add per-entity quotas; actor `rows`/`roles` still bound the authorization join.

Projection rules match the maintained PostgreSQL codec:

- Projects require principal and a capability pattern matching `hub` in the same
  complete eligible rule. LOCAL uses current raw subject/profile, not a stored
  pseudonym. IDs and literal capabilities are unique and sorted. Eligible empty
  project lists or `*` set `all_projects` without registry enumeration. The
  provider command is returned literally, never executed.
- Roles include empty/custom/builtin definitions and the nine supported actions;
  `*` is a permission, not another action. Assignment subjects remain literal,
  untrimmed DATA of at most 512 Unicode characters. `bootstrap_only` means the
  complete assignment list is empty.
- Users are ordered by username, retain kind/flags/revision/UTC timestamps and
  effective roles including `user`. Principal hints include anonymous,
  authenticated and all LOCAL users, including disabled users. SQL never selects
  password PHCs, MFA ciphertext or recovery codes; `mfa_enabled` reports presence.
- Grants preserve raw wire `access`, optional selector omission and exact quoted
  decimal revision ETag. Reading grants does not compile them into read authority
  or implement write CAS. Invalid SQLite types, actions, timestamps and JSON fail
  closed, rather than becoming defaults.

## Verify this vertical

Full-channel tests use the existing `sqlite_admin_reads` and `sqlite_admin_read_http` targets and genuine shared ingress fixtures. The LOCAL HTTP contract uses the complete factory while retaining its assertions.

The Control selectors cover per-action projections without a SessionRead lease,
current external roles/cookie trust, and causal Original/proof-expiry precedence.
The HTTP selectors cover all four ingress paths with per-action admission and
cookie precedence, plus the migrated genuine LOCAL cookie/opaque contract.

The causal Control case first confirms a real projection failure. Holding a
physical IMMEDIATE lock with a 150ms JWT caller Original returns Deadline before
that projection failure. A genuinely verified upstream bearer signed with a
two-second expiry expires while waiting on the real lock; it returns Expired.
A fresh upstream bearer returns the baseline projection failure again. It adds
no fake clock or proof. Physical uncertain-ACK behavior reuses the qualified
3daa/9569 evidence; it is not claimed as a new execution in these five cases.

The saved `SQLITE_LOCAL_AUTH` phase selects both read targets with `--ignored` and no exact test filter, so it includes all ignored cases in those targets.

The two targeted fixtures use physical SQLite, genuine opaque possession and
native password login/cookie issuance; the HTTP fixture opens real TCP. Run the
portable commands from the project root using the coordinated Broker target:

```text
cargo test --locked --offline -p broker-control --test sqlite_admin_reads -- --test-threads=1
cargo test --locked --offline -p broker-control --test sqlite_admin_reads -- --ignored --test-threads=1
cargo test --locked --offline -p broker-control --lib sqlite::flow::admin_read::tests -- --test-threads=1
cargo test --locked --offline -p broker-presence --test sqlite_admin_read_http -- --ignored --test-threads=1
```

The private unit verifies the factor before taking the physical writer lock, then verifies that its smaller expiry bounds the admin observation. Other cases cover all seven independent actions, two owners and a coherent ACL snapshot, full bounds/types/errors, retained factors, cookie precedence, GET/HEAD and redacted configuration DATA. Physical commit-ACK behavior and LOCAL producers have separate tests. Source existence alone is not runtime validation; a Linux execution does not establish Windows, macOS or CI behavior.

Sources: [Control reader](../crates/broker-control/src/sqlite/flow/admin_read.rs),
[complete authentication reader](../crates/broker-control/src/sqlite/flow/admin_read/full.rs),
[SQL aggregates](../crates/broker-control/src/sqlite/flow/admin_read/rows.rs),
[HTTP reader](../crates/broker-presence/src/admin_read.rs),
[Control focal](../crates/broker-control/tests/sqlite_admin_reads.rs) and
[HTTP focal](../crates/broker-presence/tests/sqlite_admin_read_http.rs).
