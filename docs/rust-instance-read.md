---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-173d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-6e9e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5870, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust durable inventory read

The [SQLite reader companion](rust-sqlite-instance-read.md) reuses this data
decoder and explicit transfer bound over the private SQLite owner. Its writer
wait and own qualification are documented there; the PostgreSQL results below
retain their original scope.

Audience: Broker server integrators implementing authenticated reconciliation.
The PostgreSQL API reads one durable installation inventory. Its result is
storage data; the caller must authenticate and authorize before disclosing it.
The separate own-inventory GET requires the literal current owner and Read for
every project, or explicit Any Read for an empty inventory. This SQL API does
not make that decision or list other installations.

## Read one ID

Use the existing shared PostgresControlStore:

~~~text
store.instance_inventories(json_bytes: NonZeroUsize)
  -> Result<PostgresInstanceInventories<'_>, InstanceReadError>
reader.read(instance_id: &str, deadline: Instant)
  -> Result<Option<StoredInstanceInventory>, InstanceReadError>
~~~

Supply a useful explicit nonzero byte cap that fits isize and i64 and the
original operation deadline. The reader borrows its store, creates no new pool
or runtime, and has no default cap. Invalid IDs fail before SQL; use the
[registration identity contract](rust-broker-instances.md), without trimming.

None means no parent was stored in the selected statement snapshot.
Some with an empty projects slice means a registered parent whose inventory is
empty. These states are distinct. StoredInstanceInventory has no public
constructor or Clone. Its getters expose inventory, literal owner and
creation/update UTC microseconds, with redacted Debug. Owner data is never
identity proof.

The one SELECT reads parent and ordered versions in one MVCC statement.
Projects must be canonical nonzero ULIDs; version rows must have contiguous
one-based positions and strictly ascending unique meaningful versions.
The decoder rejects malformed order before constructors could sort it.
Stored owner limits and nonnegative timestamps match the writer. It does not
repair, truncate or silently discard invalid rows.

## Limits, failure and recovery

The JSON byte cap covers the complete parent, owner, timestamps and version
rows. PostgreSQL measures octet_length and returns no payload above the cap;
the client does not receive or decode an oversized payload. This is a transfer
bound, not a promise to bound PostgreSQL aggregate memory. Unicode limits use
UTF-8 bytes here; owner column validation uses Unicode character counts.

| Error | Meaning |
| --- | --- |
| InvalidLimits | Explicit cap does not fit supported sizes. |
| InvalidInstanceId | ID violates the registration identity contract. |
| ReadLimitExceeded | Complete stored JSON exceeds the explicit cap. |
| MalformedStored | Stored JSON/schema/order/identity/stamps are invalid. |
| Control(Storage/Closed/Deadline) | Corresponding SQL/store/original time failure. |

Messages and Debug disclose no SQL, driver text, owner or inventory.
The reader uses READ COMMITTED READ ONLY and the existing bounded caller
deadline. It returns Some or None only after confirmed COMMIT.
Failure or cancellation discards the connection through the existing guard;
confirmed success returns it to the shared pool. COMMIT errors use the existing
storage mapping; expiration while awaiting its ACK returns Control(Deadline).
This SELECT-only transaction has no persistent application effect. Neither
failure releases Some/None or triggers automatic replay.
This API performs no mutation, authentication, grant lookup or token telemetry.
Concurrent writes can change a later read; there is no ongoing snapshot lease.
Durable inventory is not online presence and disconnect does not remove it.

Use [PostgreSQL control](rust-postgres-control.md) for startup, budgets and
shutdown, and [authenticated registration](rust-instance-registration.md) for
publishing and uncertain-write recovery. Business and HTTP read integration
are separate leaves.

## Qualification

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test instance_read postgres_instance_inventory_read_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
~~~

Linux qualification passed: affected Control fast suite (1.273 s), 22 rustdocs
(6.358 s), fmt (0.316 s), strict Clippy (0.494 s) and the complete native fixture
(50.613 s). The affected broker-presence consumer passed 3 fast tests
(19.273 s) and 1 rustdoc (0.336 s). Static impact review found and fixed per-row project validation
before grouping, with a composed empty-project regression; the final review
found no residual fault. Twenty-two affected local documentation links resolve.

The first native attempt failed after 281.141 s while observing the cancellation
lock. The fixture now clears the transaction statistics snapshot before each
poll, following [PostgreSQL monitoring documentation](https://www.postgresql.org/docs/current/monitoring-stats.htm),
and still requires the actual SQL lock, pending job, confirmed task cancellation
and pool recovery. No production rule or deadline was relaxed. Earlier fixture
compilation failures (SQLx static SQL lifetime, 8.290 s and 7.120 s) and an
initial cargo invocation that did not execute are preserved in separate logs.
Logs and results are retained in .build/rust-instance-read-2026-10-11/.

The native fixture uses pinned real
PostgreSQL over TLS and an ordinary NOSUPERUSER role. It covers writer-to-reader,
absence/empty, Unicode and 70KB versions/caps, concurrent committed snapshots,
reopen, malformed rows without repair, permission failure, original deadline,
actual task abort and pool recovery, store close and shutdown.
Unit/rustdoc checks cover strict private schema and lifetime/construction
boundaries. Those historical runs did not inject read-only COMMIT loss; the
earlier uncertainty mapping is superseded by the SELECT-only contract above.
This leaf does not qualify Windows/macOS, MySQL, full Broker integration,
authenticated GET/list/live/Now or completion of N6/N7/N9/the migration.


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

Sources: crates/broker-control/src/instance_read.rs,
service/instance_read.rs and tests/instance_read.rs.

Use the [authenticated own-inventory reader](rust-instance-inventory-read.md)
for current local Auth, literal ownership and complete Read permission.

Read complete candidates in C ID order through the [SQL candidate reader](rust-instance-candidates.md).
