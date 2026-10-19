---
title: PostgreSQL resource grant snapshots in Rust
doc_type: technical
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7604, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-463c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# PostgreSQL resource grant snapshots in Rust

This server reference describes the broker-control reader of current normalized
SQL grants. It returns typed metadata from one PostgreSQL statement snapshot.
It does not authenticate callers, interpret selectors, make an authorization
decision or provide an authorization lease. The server must verify its current
principal and evaluate fresh grants for each consequential operation; see
[resource authorization](authorization.md) and the
[local bearer verifier](rust-local-bearer-verifier.md).

## API and data

PostgresControlStore::resource_grants(json_bytes: NonZeroUsize) returns a borrowed
PostgresResourceGrants view. Its asynchronous read(deadline: Instant) returns
Result<ResourceGrantSnapshot, ResourceGrantReadError>. The explicit total JSON
byte limit must fit isize and i64; there is no default, grant quota or row-reservation
framework. The view cannot outlive its store.

The immutable snapshot exposes revision(), updated_at() and rules(). Every rule
exposes id(), name(), access_kind(), principal(), s3_route(), capabilities(),
projects(), s3_operations(), s3_prefixes(), created_at() and updated_at(). Strings
and array members remain exactly as stored. No trim, CSV split, case folding,
selector default or capability inference occurs. Arrays are ordered by literal
UTF-8 value; parents are ordered by ID. Revision is positive and timestamps use
the existing nonnegative TimestampMicros type. Debug for snapshots, rules and
the reader is redacted.

The SQL projection includes resource_acl_state ID 1, resource_grants and the four
normalized capability/project/S3-operation/S3-prefix child tables. Startup seeds
ACL revision 1 through the existing schema initializer. A missing ACL-state row
is malformed state, not an empty policy. An empty rules array is valid metadata;
it does not grant anything. Likewise, empty project arrays have no authorization
meaning in this reader. Only an explicit capability grant evaluated by the policy
producer may use the agreed Any-project selector.

Raw unknown access kinds, malformed selector syntax or noncanonical project
strings can be returned as data. The separate policy producer must validate its
Rust rules before making an active decision; receiving this snapshot never makes
an invalid rule valid. Administrative roles are orthogonal to resource grants.
No magic global project alias, Go configuration importer or compatibility reader
is introduced by this API.

## Coherence, limits and failures

One SELECT under READ COMMITTED READ ONLY reads the state revision and all grant
parents/children. PostgreSQL nested aggregates produce the ordered raw arrays
within that statement snapshot, without client-side per-rule queries or a
cartesian parent/child result. Literal COLLATE C order agrees with Rust string
ordering. Readers observe either the old committed policy or the new committed
policy during an atomic replacement; no parent/child revision mixture is returned.
The reader does not lock writers or freeze authorization after returning.

The projected JSON is measured with octet_length. A CASE projection keeps an
oversize document out of the client; ReadLimitExceeded returns no partial or
truncated snapshot. This limits transfer and client decoding, not PostgreSQL's
aggregate working memory. SQL widths and normalized keys/FKs retain their
[schema contract](rust-sql-schema.md).

The private Serde codec requires every projected field with its exact type,
including arrays of strings and integer timestamps. Null arrays, wrong types,
unknown or duplicate fields fail. Parent/child ordering must be strict and unique;
negative timestamps or nonpositive revision fail. The reader performs no repair,
normalization or retry.

| Error | Meaning and recovery |
| --- | --- |
| InvalidLimits | Correct the explicit, representable JSON byte cap. |
| ReadLimitExceeded | Increase an intentionally configured cap or reduce the policy through an authorized management operation; no partial policy is usable. |
| MalformedStored | Missing state, invalid codec/order/revision/timestamp. Diagnose and repair through an authorized writer; never treat it as Any or anonymous success. |
| Control(error) | Existing finite store, original-deadline or closed-store failure, including failed COMMIT confirmation. No snapshot is returned. |

Confirmed COMMIT precedes return, including an empty snapshot. Error or
cancellation discards the incomplete transaction connection; confirmed success
returns it to the pool. The caller's original monotonic deadline is bounded by
the existing store operation timeout. This SELECT-only transaction has no
persistent application effect. COMMIT errors use the existing storage mapping;
expiration while awaiting its ACK returns `Control(Deadline)`. Neither failure
releases a snapshot or triggers automatic replay. Errors contain no
policy content, principal attributes or database-driver text.

## Qualification

From the Broker workspace:

```text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test postgres postgres_resource_grants_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
git diff --check
```

The focused native fixture uses real pinned PostgreSQL with TLS and an ordinary
NOSUPERUSER owner. It covers all four child arrays, literal/raw values and Unicode,
empty policy, atomic old/new visibility, missing state, malformed revision/time,
JSON byte caps, normalized FKs, privileges on every child, table-lock deadlines,
actual task cancellation, pool recovery, closed store and reopen. Unit tests
exercise the private typed codec and strict ordering. This is SQL metadata
qualification; authorization and HTTP/presence tests need their own producers.

Linux qualification passed under tsk-7604: 46 fast tests, 15 rustdoc tests,
formatting, strict Clippy and the final native PostgreSQL fixture (121.079 s).
The final fixture uses the 1280-byte Unicode cap. Bounded Tracker review found
no residual fault; 14 maintained relative documentation links resolve.
The earlier native fixture also passed (217.430 s) with its previous 768-byte
cap; the final rerun, rather than that earlier result, qualifies current source.
Those historical runs did not inject read-only COMMIT disconnect. Their
earlier uncertainty mapping is superseded by the SELECT-only contract above.
Windows/macOS and broad final integration remain separate evidence boundaries.


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

Sources: crates/broker-control/src/resource_grants.rs,
src/service/resource_grants.rs and tests/postgres.rs in broker-control.

The [local presence authorizer](rust-presence-authorization.md) composes raw local
bearer verification and fresh same-rule project ACL. Its qualification and
transport limits are recorded separately.

The [local logical PROJECT authorizer](rust-project-authorization.md) checks explicit
module/action capabilities using current opaque local Auth and the shared policy
matcher. Logical PROJECT permission and storage authority remain separate.

[Hub project storage admission](rust-hub-storage-admission.md) composes this current
snapshot with actual Native or opaque authentication and literal Hub roots.
Raw snapshot metadata remains DATA, independently of that private authorization.
