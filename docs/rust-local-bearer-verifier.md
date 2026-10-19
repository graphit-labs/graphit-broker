---
title: PostgreSQL local opaque bearer verifier in Rust
doc_type: technical
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-cdd7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7442, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# PostgreSQL local opaque bearer verifier in Rust

The [SQLite LOCAL verifier and PROJECT HTTP composition](rust-sqlite-local-bearer.md)
reuse these codecs and credential rules with a bounded private SQLite projection.
The PostgreSQL API below remains available unchanged.

This reference is for server integrators using broker-control. The verifier
requires the raw local access or service bearer and checks current PostgreSQL
state. It returns a private successful credential observation. It does not
provide resource grants, an authorization lease or HTTP endpoints. Current
[resource authorization](authorization.md) must follow authentication for every
consequential operation. JWT, external OIDC and the OP are separate producers.

## Inputs and API

PostgresControlStore::local_bearer_verifier(audience: &str, json_bytes:
NonZeroUsize) builds a borrowed PostgresLocalBearerVerifier. The explicit audience
and store must outlive that view. There is no audience or JSON-cap default.
The JSON cap and codec are the [SQL reader contract](rust-local-bearer-state.md).

The asynchronous method is:

```text
verify(
    &self,
    raw: &str,
    required_scopes: &[String],
    deadline: std::time::Instant,
) -> Result<VerifiedLocalBearer, LocalBearerVerificationError>
```

The raw string is never trimmed. Case-exact gb_at_ selects LocalAccess; gb_sc_
selects ServiceCredential. Refresh, unknown prefixes and JWT strings are denied;
this method has no alternative authentication fallback. The existing explicit
[credential digest](rust-credentials.md) token byte limit bounds input.
It hashes the entire raw string with the selected Rust credential domain and
store-owned pepper. This uses the Rust persistence format, without Go hash
compatibility or import.

The configured audience is trimmed only for comparison. Stored SQL audience
remains literal and case-sensitive. Explicit empty audience remains an input
value; it is not supplied as a default. Server startup must provide its intended
audience policy separately.

Required scopes are trimmed and empty requirements skipped. Each remaining
requirement must equal a raw SQL scope string. Duplicates do not change the
result. Only after this check are output scopes trimmed, empties removed,
sorted and deduplicated. Stored " presence:read " cannot satisfy required
"presence:read". "a,b" is a single scope, never CSV.

## Current identity and successful output

The reader joins the opaque token and current local user in one statement
snapshot. It enforces local issuer, subject/revision bindings, enabled current
identity, and access/human or service/service kind. Missing or unavailable state
is denied. Stored principal attributes cannot replace current user attributes.
Password/MFA values and role data are not selected.

Revocation with any present timestamp denies. Expiry must be strictly after UTC
wall clock, with no leeway. The verifier observes wall clock after reading state
and again immediately before returning. Equality and expiry during SQL waits
both deny. UTC microsecond conversion reuses TimestampMicros; callers
cannot supply a stale time to authenticate. The monotonic caller deadline
bounds the whole read and final check through the existing store
operation timeout.

VerifiedLocalBearer exposes current_local_user(), kind(), audience(), scopes(),
auth_method(), expires_at(), verified_at() and authentication_expiry(). Methods are local-token or
service-credential, derived from verified kind rather than stored auth_method.
Current issuer is literal local and subject is the raw local identity subject,
not an OIDC issuer or pseudonymous JWT subject. Raw bearer and digest are not
retained. Debug is redacted. No public constructor, Clone, Default or Deserialize
can turn client data or a LocalBearerState into this result.

This result records a successful credential observation, not continuing
validity. It does not freeze SQL revocation or authorize a later effect. Verify
the bearer for each consequential operation and then read its current ACL.
Administrative roles/permissions remain the separate
[current identity/RBAC reader](rust-postgres-identity.md). Neither stale token
roles nor Hub/admin status implicitly confer presence capabilities.

## Read-only verification, failures and recovery

LOCAL access/service verification only reads current token and identity state.
It does not update `last_used_at` or maintain a replacement usage counter. A
concurrent row writer therefore does not make the verifier wait for an UPDATE;
locks that block its SELECT still obey Original, cancellation and the store
operation budget. No authenticated result is returned after a failed read or
final expiry/deadline check.

The shared schema column remains available to the separate OAuth refresh,
UserInfo and introspection protocols; their lifecycle behavior is unchanged.
The administrative service-credential inventory does not expose a last-use metric.

| Error | Internal meaning and recovery |
| --- | --- |
| Unauthenticated | Uniform credential denial: prefix/input/domain, unavailable identity/token, audience, required scopes, expiry or revocation. No partial principal. |
| State(InvalidLimits) | Fix the explicit reader-cap configuration. |
| State(ReadLimitExceeded) | Applicable JSON exceeds the cap; no truncated authentication. |
| State(MalformedStored) | Invalid typed SQL state; repair through an authorized management operation, never automatic normalization. |
| Control(error) | Finite store/deadline/clock failure, including failed read-COMMIT confirmation; no authenticated result. |

Display/Debug errors contain no token, digest, JSON, database-driver message or
identity attributes. These are server-internal diagnostics; external HTTP error
mapping belongs to the endpoint contract. Neither SQL waits nor final checks
renew expiry. The PostgreSQL state reader returns storage errors or Deadline
when its read-only COMMIT cannot be confirmed; no authenticated result or
automatic replay follows. This metadata read has no persistent application effect.

## Qualification

Run from the Broker workspace:

```text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test postgres postgres_local_bearer_verifier_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
git diff --check
```

Unit checks cover exact prefix selection, raw-match-before-clean and exact expiry.
External compile-fail rustdocs cover inaccessible fields/constructor, cloning
and deserialization. The focused native test uses real pinned PostgreSQL with
TLS and an ordinary NOSUPERUSER owner, synthetic SQL fixtures and the mature
Rust digester. It exercises raw access/service authentication, current attrs,
wrong prefix/domain/pepper, audience/scopes/expiry/revocation/current-user denial,
malformed and oversized state, column-only identity access without UPDATE
permission, unchanged complete token/user state for access and service, a
concurrent row writer, real SELECT lock/deadline/cancellation, pool recovery,
expiry during a blocked SELECT, closed store and reopen.

On 2026-10-11, the focused native command passed on Linux with Docker in
9.476 seconds (one test). The affected suite passed 45 fast tests and 15
rustdocs; formatting, strict broker-control Clippy, diff checks and all 19
relative links in the three affected pages passed. Tracker review found no
remaining material issue. Earlier fixture compilation and SQL-delimiter failures
are retained in the qualification history; the corrected fixture was rerun.
No HTTP/ACL/presence product or Windows/macOS qualification is implied.
At that historical qualification, read-only COMMIT disconnect and usage
autocommit ACK-loss were not injected;
cancellation does not imply rollback beyond the blocked fixture observation.

Sources: crates/broker-control/src/local_bearer_verifier.rs,
src/service/local_bearer_verifier.rs and tests/postgres.rs in broker-control.

The [local presence authorizer](rust-presence-authorization.md) composes raw local
bearer verification and fresh same-rule project ACL. Its qualification and
transport limits are recorded separately.

The [authentication expiry observer](rust-authentication-expiry.md) returns the actual UTC/monotonic pair captured after SQL, without discounting SQL latency or renewing it in later finish checks.
