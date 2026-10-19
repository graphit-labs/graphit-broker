---
title: SQLite bounded durable inventory reads
doc_type: reference
description: Coherent durable SQLite inventory data with a complete JSON byte bound.
tags: [rust, sqlite, inventory, persistence]
references:
  - target: {type: task, id: tsk-173d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6e9e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e69e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite bounded durable inventory reads

Broker storage consumers can read one persisted inventory through the [private SQLite store](rust-sqlite-control.md), after authenticating and authorizing disclosure. This reader uses the shared [inventory decoder and data contract](rust-instance-read.md) and consumes the [SQLite inventory writer](rust-sqlite-instances.md).

~~~text
SqliteControlStore::instance_inventories(json_bytes: NonZeroUsize)
    -> Result<SqliteInstanceInventories<'_>, InstanceReadError>

reader.read(instance_id: &str, caller: std::time::Instant)
    -> Result<Option<StoredInstanceInventory>, InstanceReadError>
~~~

The cap is explicit, positive and must fit isize and i64. There is no default.
The view borrows the original store, exposes no connection or SQL and redacts
Debug. Invalid canonical instance IDs fail before SQL, without trimming.
None means no matching parent; Some with no projects means an existing empty
registration. These states remain distinct.

## Coherent statement and bounded transfer

The existing BEGIN IMMEDIATE owner transaction serializes against a writer.
A pending read waits for that writer to commit or roll back, subject to its
original deadline. It then observes one coherent parent and complete ordered
version set. This backend does not promise PostgreSQL's old statement snapshot
while an uncommitted writer is open, or an ongoing snapshot lease.

One SQL statement constructs the complete JSON parent, owner, timestamps and
ordered version rows. SQLite measures its UTF-8 byte length and returns payload
only when it fits the supplied cap, before Rust fetches or decodes it.
ReadLimitExceeded returns no snapshot. This is a transfer bound; it does not
promise bounded SQLite aggregate memory. It adds no writer version quota.

Wrong stored scalar types become null in the private JSON representation and
are rejected by the strict shared decoder; BLOBs are not coerced into identity
or version strings. The decoder validates literal owner character limits,
nonnegative timestamps, canonical project/instance IDs, contiguous one-based
positions and strictly increasing unique meaningful versions before constructors
could sort anything. Corruption is never repaired, truncated or skipped.
All reads leave durable state unchanged.

StoredInstanceInventory retains its private construction, redacted Debug and
non-Clone data boundary. Its owner, inventory and timestamp getters convey
data, not authentication, authorization or live Presence.

## Lifecycle and errors

A single bounded original end covers admission, statement and COMMIT.
The existing executor owns cancellation, worker retention, shutdown and known
acknowledgement. Some and None are delivered only after known COMMIT.
Missing acknowledgement yields Control(OutcomeUncertain) without automatic
retry. The API adds no post-acknowledgement clock gate or cleanup mutation.

The finite errors are InvalidLimits, InvalidInstanceId, ReadLimitExceeded,
MalformedStored and Control(ControlError). Public errors contain no SQL,
driver text, owner values or paths. Recover from uncertain operations by fresh
authorized observation, without inferring a partial snapshot or replaying a
write.

## Verification and integration limits

~~~text
cargo test --locked --offline -p broker-control --test sqlite_instance_read -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib --test sqlite_instance_read -- -D warnings
~~~

Physical files and the real writer exercise absence/empty/full, reopen, literal
Unicode ownership, 70 KB versions, exact JSON byte caps, malformed stored types
and values without repair, coherent commit/rollback observations, blocked
deadline, cancellation, shutdown and recovery. A third writer is retained while
the actual read future is polled Pending; no production witness or fault API is
added for the test.

The unchanged shared decoder/library/rustdoc and SQLite executor acknowledgement
proofs are reused explicitly. The existing Control all-targets phase selects
the fast target; no additional general phase or broad replay is added.
This library does not provide authenticated inventory HTTP/list/Presence or
complete SQLite configuration/server dispatch. Linux results do not qualify
native Windows/macOS runtime behavior.

Sources: [reader](../crates/broker-control/src/sqlite/flow/instance_read.rs),
[physical tests](../crates/broker-control/tests/sqlite_instance_read.rs).
