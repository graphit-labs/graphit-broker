---
title: SQLite durable instance inventory replacement
doc_type: reference
description: Atomic durable instance inventory data over the private SQLite owner.
tags: [rust, sqlite, inventory, persistence]
references:
  - target: {type: task, id: tsk-e69e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5870, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite durable instance inventory replacement

For Broker storage consumers, this is the SQLite implementation of the shared [durable inventory model and writer contract](rust-broker-instances.md). It uses the [private SQLite owner](rust-sqlite-control.md) and existing schema.

## API and data boundary

~~~text
SqliteControlStore::replace_instance_inventory(
    &self, owner: &InstanceOwner, inventory: &InstanceInventory,
    caller: std::time::Instant
) -> Result<RegistrationResult, InstanceRegistryError>
~~~

The asynchronous method accepts the existing immutable data types. Constructors
and data do not authenticate or authorize. A consumer derives the literal owner
from verified identity and authorizes publication for every project, including
the existing explicit policy for an empty inventory, before calling this writer.

Issuer and subject stay separate and literal: no trimming, case folding or URL
normalization. The existing limits count Unicode characters (1024 and 512),
reject empty/NUL values, and allow multibyte values up to those character limits.
Instance and project identifiers retain the shared canonical validation.
Versions are nonempty, already trimmed and contain no controls; projects and
versions are sorted and unique. The shared contract accepts a 70,000-byte
Unicode version. This backend adds no version-byte/count quota or default version.

## Atomic replacement and stored validation

A single BEGIN IMMEDIATE transaction serializes independent writers. It inserts
the parent only when absent, validates its stored owner and timestamps, then
compares every current child before replacing anything. A different owner gets
OwnerConflict without takeover or inventory changes.

The cursor validates canonical project/version values, strictly ordered
projects and versions, and contiguous positions starting at one per project.
Only the preceding stored version is retained; the stored inventory is not
collected into a second complete copy. Finite owner/project projections are
bounded before decoding. Owner byte bounds follow the maximum UTF-8 size of
their existing character bounds. Version text keeps its existing unbounded
contract.

Malformed stored data returns MalformedStored and remains unchanged. Creation
and update times must be nonnegative; the contract does not require update time
to be greater than creation time. Values are never repaired silently.

Changed children, their exact row counts and the parent's update timestamp are
committed together. The first owner and creation timestamp remain immutable.
An identical inventory returns Unchanged with both timestamps unchanged.
An empty replacement deletes children and retains the parent and owner.
New registration returns Created; a changed existing registration returns Updated.

## Lifecycle, errors and recovery

One original end, bounded by the caller and the existing operation budget,
covers preparation, admission, SQL and COMMIT. The private executor retains its
actual connection and worker until native work finishes. Precommit cancellation
or failure rolls back; shutdown closes admission.

RegistrationResult is delivered only after known COMMIT acknowledgement.
A missing acknowledgement returns Control(OutcomeUncertain) without a confirmed
change result or automatic replay. Observe current state through an authorized
consumer before deciding whether to retry. Known acknowledgement is not
reclassified by an added postcommit clock gate.

The closed errors are InvalidOwner, InvalidInventory, OwnerConflict,
MalformedStored and Control(ControlError). Shared error messages contain no
driver SQL, owner values, paths or other private data. The result contains the
instance ID, change and timestamps, with no owner or authority.

## Verification and limits

~~~text
cargo test --locked --offline -p broker-control --test sqlite_instances -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib --test sqlite_instances -- -D warnings
~~~

The physical-file tests cover reopen, no-op/empty/changed inventories, literal
Unicode owner and large versions, corruption preservation, nonnegative timestamp
ordering, cancellation/deadline/shutdown and independent creators/replacements.
Concurrency holds a third connection's write transaction until both actual
operations have been submitted; it checks equal and different owners and whole
child sets. No production event or fault API is added solely for this oracle.

The unchanged executor's physical rollback/COMMIT acknowledgement evidence is
reused explicitly. The writer composes all SQL through that same transaction
and Work::commit; no artificial schema/trigger fault is required.
The saved Control all-targets phase already selects this fast target.
Unchanged shared library/rustdoc proofs are reused; broad integration belongs
to the final integration owner.

The source is [instances.rs](../crates/broker-control/src/sqlite/flow/instances.rs);
the physical tests are [sqlite_instances.rs](../crates/broker-control/tests/sqlite_instances.rs).
This library writer does not provide an authenticated inventory reader,
HTTP endpoint, live Presence or complete SQLite server backend. Native
Windows/macOS runtime behavior is not qualified by Linux results.

Read the stored data through the [bounded SQLite inventory reader](rust-sqlite-instance-read.md), after authenticating and authorizing disclosure.
