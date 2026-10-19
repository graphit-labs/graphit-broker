---
references:
  - target: {type: task, id: tsk-56ac, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-795b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-6e9e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-5870, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust inventory candidates in PostgreSQL

Audience: Broker server integrators building authorized inventory listing.
This SQL API reads one complete candidate's durable inventory. It returns data,
including the literal owner; the consumer must authenticate and authorize
before disclosure. The [own-inventory reader](rust-instance-inventory-read.md)
has separate ownership and ALL-project rules. Candidate reading does not
implement the partial-project business projection or GET /v1/instances.
Use the [local authenticated lister](rust-instance-list.md) for partial Read
projection, cumulative filters and visible-only page cursors.

## API and order

Use the existing shared PostgresControlStore:

~~~text
store.instance_inventory_candidates(json_bytes: NonZeroUsize)
  -> Result<PostgresInstanceInventoryCandidates<'_>, InstanceReadError>
reader.read_next(after: Option<&str>, original_deadline: Instant)
  -> Result<Option<StoredInstanceInventory>, InstanceReadError>
~~~

The view borrows its store; it creates no pool/runtime and has redacted Debug.
Supply an explicit complete-payload cap representable in isize and i64; there
is no default or candidate batch size.

after None begins the scan. Some(after) uses the exact
[registration ID grammar](rust-broker-instances.md): 1–128 ASCII bytes, with
alphanumeric first/last bytes and only alphanumeric or ._- inside. Invalid
input fails before SQL. Values are neither trimmed nor interpolated into SQL.

The SELECT chooses the least ID strictly greater than after, ordered by
instance_id COLLATE "C" ASC. The cursor need not name a stored parent.
For example, stored IDs A, A-1, A.1, A_1, Z, a are returned in that order;
after A-0 selects A-1. This is the storage scan position, not a public HTTP
cursor. An authorized list consumer must expose only its own visible cursor.

Some contains the complete validated StoredInstanceInventory from the
[existing data decoder](rust-instance-read.md): canonical inventory, literal
owner, and creation/update UTC microseconds. A stored parent with no versions
returns Some with projects empty. None is real SQL EOF observed in that
statement, returned only after confirmed COMMIT.

## Snapshot and failure

Selection of the parent and aggregation of all its children share one MVCC
statement. The parent CTE selects at most one row before payload aggregation.
Versions retain project order COLLATE "C" and contiguous positions; the
existing strict decoder rejects invalid identities, owner, timestamps,
positions, version order and contents. It never sorts malformed stored rows
into validity or repairs them.

The cap covers the complete JSON parent, owner, timestamps and version rows.
PostgreSQL measures octet_length and CASE withholds both the oversized payload
and the separately selected ID.
ReadLimitExceeded fails that candidate; the API does not skip it, truncate it
or pretend it reached EOF. UTF-8 bytes count, including Unicode owner and
versions. This bounds transfer/decode, not PostgreSQL aggregate RAM.

The original caller deadline is bounded by the store's operation budget.
The transaction uses READ COMMITTED READ ONLY and the existing connection
guard. Some and None require confirmed COMMIT. An incomplete transaction on
failure, timeout or task cancellation discards its connection; successful
reads return it to the existing pool. There is no automatic retry.

| Error | Meaning |
| --- | --- |
| InvalidLimits | Explicit payload cap does not fit supported sizes. |
| InvalidInstanceId | after violates canonical ID grammar. |
| ReadLimitExceeded | Complete candidate payload exceeds the cap. |
| MalformedStored | Selected ID or complete stored data violates the decoder contract. |
| Control(Storage/Closed/Deadline) | SQL/storage, closed pool or original/budget deadline failure. |
| Control(OutcomeUncertain) | Read-only COMMIT was started but its confirmation is missing. |

Messages and Debug contain no owner, inventory, SQL or driver text.
No user, token or resource grants are required by this DATA API. It performs
no authentication, authorization, token telemetry or write.

Successive calls observe independent statement snapshots. Concurrent changes
can affect later candidates; this is not an atomic page or a stable snapshot
lease. A later insertion behind after can be absent from that scan. Durable
inventory is distinct from online presence; disconnect does not remove it.

## Verification

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test instance_candidates postgres_instance_inventory_candidates_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
~~~

Linux qualification passed: 56 Control fast tests (final 0.218 s), 28
rustdocs (11.435 s), fmt (0.259 s), strict Clippy (0.404 s), and the complete
native fixture (207.794 s). The affected broker-presence consumer passed six
fast tests (5.777 s) and two rustdocs (0.384 s). Static impact review found no
remaining fault; all 27 affected documentation links resolve. Cargo/Lock and
the existing decoder remain unchanged.

The native fixture uses real pinned PostgreSQL over TLS with an ordinary
NOSUPERUSER role. It covers canonical C ordering,
exclusive/nonexistent cursors and injection rejection, empty/EOF, complete
Unicode data and exact byte caps, coherent committed/uncommitted snapshots,
malformed stored values without repair, SELECT denial, original deadline,
observed SQL lock followed by real task abort and pool recovery, Closed/reopen
and connection cleanup. It compares SQL before and after reads.

The first compilation failed (24.423 s) because a fixture count query used
dynamic SQL rejected by the pinned SDK. Counts and REVOKE/GRANT pairs now use
static literals. The first native run failed (157.743 s) when the fixture
tried to change a previously seeded owner; the writer correctly rejected it.
The fixture now creates the Unicode parent with its original Unicode owner
and removes its intentionally corrupted candidate before the recovery/reopen
scenario. Production behavior was not relaxed. Failures and successful reruns
are retained in .build/rust-instance-candidates-2026-10-11/.

The existing codec and guard fast tests are reused; the new rustdoc checks
the borrowed view's lifetime. Windows/macOS, MySQL, native read-only COMMIT-loss
injection, authenticated partial listing, HTTP LIST and full Broker integration
are separate qualifications. This leaf does not complete N6/N7/N9 or the migration.

Sources: crates/broker-control/src/service/instance_candidates.rs,
crates/broker-control/tests/instance_candidates.rs and the unchanged
crates/broker-control/src/instance_read.rs decoder.
See [PostgreSQL control](rust-postgres-control.md) for startup, budgets and shutdown.
