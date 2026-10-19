---
title: PostgreSQL local bearer state in Rust
doc_type: technical
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-7442, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-74a7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# PostgreSQL local bearer state in Rust

The [SQLite LOCAL verifier and PROJECT HTTP composition](rust-sqlite-local-bearer.md)
reuse these codecs and credential rules with a bounded private SQLite projection.
The PostgreSQL API below remains available unchanged.

This reference describes the SQL metadata reader in `broker-control`. It reads an
opaque local token and the current local user from one PostgreSQL statement
snapshot. It supports the future server bearer verifier and resource
authorization. Qualification of this reader is tracked by `tsk-7442`.

A `CredentialDigest` is data: it can be constructed from SQL hexadecimal
metadata. Receiving a digest or a `LocalBearerState` does not prove possession
of a bearer. The server verifier must compute the correct HMAC domain from the
raw bearer and enforce audience, exact required scopes, expiry, revocation and
current identity before producing an authenticated principal. Resource grants
must then be read for the consequential operation. See [security](security.md)
and [resource authorization](authorization.md).

## API and caller input

`PostgresControlStore::local_bearer_states(json_bytes: NonZeroUsize)` returns a
borrowed `PostgresLocalBearerStates` reader or `LocalBearerStateError`. The
explicit JSON byte limit must fit `isize` and `i64`; there is no default.
It applies independently to `principal_json`, `scopes_json` and
`teams_json`. SQL length checks and CASE projections keep oversized JSON
payloads out of the client. An oversize payload fails; it never produces a
truncated successful state.

The asynchronous read has this signature:

```text
read(
    &self,
    digest: &CredentialDigest,
    kind: LocalBearerKind,
    deadline: std::time::Instant,
) -> Result<Option<LocalBearerState>, LocalBearerStateError>
```

`LocalBearerKind::Access` corresponds to stored `access` and digest domain
`TokenKind::LocalAccess`. `ServiceCredential` corresponds to stored
`service` and `TokenKind::ServiceCredential`. The caller supplies the kind;
the reader does not infer or authenticate a raw token prefix.

## Returned metadata and current attributes

The immutable state exposes kind, audience, raw scope strings, expiry,
optional revocation timestamp and `current_local_user()`. The current user
exposes username, subject, identity kind, name, email, organization, teams and
revision. Local issuer is the literal `local`, validated against stored
principal binding; it is distinct from the public OIDC issuer or pseudonymous
JWT subject.

All local attributes come from the current `local_users` row. Stored
principal name, username, email, organization, teams and roles do not replace
current attributes. Roles and permissions remain the separate
[current identity/RBAC reader](rust-postgres-identity.md); this query does not
load password or MFA fields.

Local username and subject reuse the qualified identity helpers: username is
canonical ASCII up to 128 bytes, subject is nonempty, already trimmed and at
most 512 bytes, and revision is positive. Stored identity kind must be
`human` or `service`; enabled must be exactly 0 or 1. No missing kind is
filled with a creation default. Name, email and organization retain literal
values and their natural SQL character limits, including empty values and
Unicode.

A returned state can be **expired or revoked**. Those timestamp fields are
metadata, not successful authentication. Timestamps use the existing
nonnegative `TimestampMicros` contract. Debug for state, current user and
borrowed reader is redacted.

## JSON and binding

The Rust principal codec requires string fields `issuer`, `subject`,
`username` and `auth_method`. Its optional fields retain absence as
`Option`: string name/email/organization/role_claim_selector, arrays of
strings teams/scopes/roles, boolean roles_from_claim and integer
local_user_revision. Wrong types, duplicate recognized fields and unknown
fields fail. This defines new Rust persistence and includes no importer or
compatibility reader.

The local branch requires a present positive JSON local_user_revision equal
to the token revision column, and JSON subject equal to the token subject
column. This opaque-token rule must not be applied to the separate JWT grant
reader, whose active contract differs.

SQL scopes and teams are JSON arrays of strings; JSON null is not an array.
Teams are trimmed, empties removed, sorted and deduplicated. A string such as
`a,b` remains one team, never CSV.

Scopes remain **exactly as stored** for required-scope matching. For example,
`" presence:read "` does not satisfy required `"presence:read"`.
The verifier checks required values against the raw array before cleaning
the outgoing principal's scopes. Cleaning first would widen acceptance.

## Availability, errors and lifecycle

`Ok(None)` means no usable local metadata for this lookup: missing token,
different kind, nonlocal issuer, mismatched principal binding, absent or
disabled local user, changed revision, or access/service kind incompatible
with the current human/service identity. It does not mean anonymous access.

| Error | Meaning |
| --- | --- |
| `InvalidLimits` | The explicit JSON cap cannot be represented safely. |
| `ReadLimitExceeded` | An applicable JSON payload exceeds that cap. |
| `MalformedStored` | Selected stored types, JSON, local identity or timestamps are invalid. |
| `Control(error)` | Existing storage, closed-store or original-deadline failure. |

A single SELECT joins token to local user by its unique subject under
READ COMMITTED. Both rows and attributes share that statement's snapshot;
separate token/user reads cannot create a mixed snapshot. The transaction
is read-only and changes neither last_used_at nor token/user metadata.

The caller deadline is bounded by the owner's existing operation timeout.
Confirmed COMMIT precedes both state and None returns. Error or cancellation
discards the unfinished transaction connection; confirmed success returns
it to the pool. This SELECT-only transaction has no persistent application effect.
COMMIT errors use the existing storage mapping; expiration while awaiting its
ACK returns `Control(Deadline)`. Neither failure releases state or None, and
neither triggers automatic replay. Missing confirmation is not a write outcome.

## Verification

From the Broker workspace:

```text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test postgres postgres_local_bearer_state_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
git diff --check
```

The focused native fixture uses pinned real PostgreSQL with TLS and an ordinary
NOSUPERUSER owner. It covers current attributes, Unicode, raw scopes, expired
and revoked metadata, empty/missing/disabled/revised identities, opaque binding,
human/service separation, atomic writer visibility, malformed/oversized JSON,
column permissions, SELECT denial, table-lock deadlines, task cancellation,
pool recovery, closed store and reopen. It uses synthetic SQL data and the
mature credential digester; it does not substitute for bearer authentication
or an HTTP/ACL integration test.

On 2026-10-11, the exact focused native command passed on Linux with Docker
in 23.891 seconds. The affected fast suite passed 43 tests and 11 doctests;
formatting and strict broker-control Clippy also passed. That historical run
did not inject read-only COMMIT disconnect; its earlier uncertainty mapping
was inspected in the reused guard lifecycle and is superseded by the
SELECT-only error contract above.

The server verifier, current resource grants, registration HTTP endpoint,
JWT/upstream/OP behavior and live presence remain separate work. Windows/macOS
and broad integration are not qualified by this reader.


On 2026-10-18, the focused real TLS test
`postgres_readonly_commit_failures_preserve_state` passed all three PostgreSQL
metadata readers against both a retained COMMIT ACK and a physical relay
closure (one test, six cases, 54.21 s). Retained ACK through the original
deadline returned Deadline; disconnect returned Storage. No observation was
released and all rows/columns in ten relevant tables stayed identical. The
timeout case recovered through the same two-connection pool; disconnect
recovery used a newly opened store. These recovery checks demonstrate
availability, not reaping of a particular backend. Connection ownership and
cleanup are unchanged by this error-classification correction. The existing
CommitRelay was reused without a production hook or new fixture framework:

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_admin_local_bearer_session postgres_readonly_commit_failures_preserve_state -- --ignored --exact --test-threads=1
```

The affected reader contracts and the existing Admin LOCAL consumer also
passed separately with real TLS on 2026-10-18. The Admin operation's own COMMIT
uncertainty remains covered and unchanged. Focused strict Clippy, formatting
and whitespace checks passed; this does not qualify a new installed binary or
broad product integration.

This correction changes only these SELECT-only PostgreSQL readers. Writers,
other operations and backends keep their own error contracts; missing ACK
never turns an unconfirmed observation into authentication or authorization.

Implementation: `crates/broker-control/src/local_bearer.rs`,
`src/service/local_bearer.rs` and the focused native test in
`crates/broker-control/tests/postgres.rs`. The owner and schema lifecycle are
documented in [PostgreSQL control persistence](rust-postgres-control.md).

## Server verifier

The [local opaque bearer verifier](rust-local-bearer-verifier.md) requires the raw
bearer and performs audience, required raw scopes, expiry and revocation checks
before producing a private authenticated observation. This reader continues to
return metadata only; its digest/DTO input cannot construct that result.
