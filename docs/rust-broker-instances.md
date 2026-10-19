---
references:
  - target: {type: task, id: tsk-5870, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-463c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-795b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-c471, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e69e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# Rust instance registration schema

The [SQLite writer companion](rust-sqlite-instances.md) implements the same data
contract over the private SQLite owner. Its own receipt delimits qualification;
the PostgreSQL results below retain their original scope.

Audience: Broker storage integrators and maintainers. This contract describes the
structural producer in `broker-store`, format `rust-broker-v1`, epoch 2, and the
PostgreSQL inventory writer in `broker-control`. Bearer authentication, project
authorization, the MySQL writer, live Now publication and instance-list tools are
separate producers. Neither these tables nor the SQL writer authenticate a caller
or make an installation online.

## Durable model

The [single typed SQL declaration](rust-mysql-catalog.md) renders this structure
for SQLite, PostgreSQL and MySQL. Timestamps use the [UTC-microsecond contract](rust-sql-schema.md).

| Table / field | Type and constraint | Meaning |
| --- | --- | --- |
| `broker_instances.instance_id` | VARCHAR(128), explicit NOT NULL, primary key | Stable installation identity supplied by the installation; data, not authority. |
| `owner_issuer` | VARCHAR(1024), NOT NULL | Literal principal issuer binding supplied by the authenticated server caller. |
| `owner_subject` | VARCHAR(512), NOT NULL | Authenticated subject binding; kept separately from issuer. |
| `created_at`, `updated_at` | BIGINT, NOT NULL | Creation and last effective inventory change. |
| `broker_instance_project_versions.instance_id` | VARCHAR(128), NOT NULL, cascading FK to instance | Parent registration identity. |
| `project_id` | VARCHAR(26), NOT NULL | Canonical nonzero project ULID validated by the PostgreSQL writer. |
| `position` | BIGINT, NOT NULL, CHECK > 0 | Internal one-based ordering of a project's version list. |
| `version` | LONGTEXT/MySQL; TEXT/PostgreSQL/SQLite, NOT NULL | Version value without an invented VARCHAR quota. |

The child primary key is `(instance_id, project_id, position)`. Version text is
not indexed, hashed into a new identifier, or exposed through a wire position.
Deleting the parent cascades to its project/version rows. Removing all child
rows leaves the registration intact. Fresh startup installs no instance rows.
The whole schema contains 25 tables and 138 columns.

SQL guarantees non-null fields, parent identity, ordinal uniqueness and positive
positions. It does not enforce canonical ULIDs, sorted unique version lists,
contiguous positions or text-content validation. Those checks belong in the
registration reader/writer; an SQL INSERT alone is not a supported registration API.

## Registration and authority boundary

The agreed writer contract derives the owner tuple from server authentication,
never caller JSON, and compares issuer/subject exactly without case or whitespace
normalization. Another owner cannot take over an existing installation identity.
Project IDs are canonical nonzero ULIDs. Version strings are nonempty, trimmed,
and contain no control characters; inventory is canonicalized into sorted unique
project/version lists. An empty inventory retains the installation row.

The PostgreSQL writer locks the parent and atomically replaces the normalized
child set. An identical inventory is a no-op that preserves `updated_at`. The
schema library alone does not enforce these application rules. Authorization must govern project visibility and publication independently
of registration. Durable inventory neither proves live presence nor records Now
activity. A socket disconnect must not delete registration history.

## PostgreSQL inventory replacement

The SQL-only asynchronous method on `PostgresControlStore` has this signature:

```text
pub async fn replace_instance_inventory(
    &self,
    owner: &InstanceOwner,
    inventory: &InstanceInventory,
    deadline: std::time::Instant,
) -> Result<RegistrationResult, InstanceRegistryError>
```

Construct immutable data with `InstanceOwner::new`, `InstanceProjectVersions::new`
and `InstanceInventory::new`. None of these constructors is an authentication
factory. The server caller must derive owner from the verified principal's literal
issuer/subject, which can differ from the JWT envelope issuer/sub, and authorize
**every** project before writing. These values must not be accepted as caller JSON
proof of identity or permission.

Owner fields are nonempty and fit their SQL limits in Unicode characters, not
UTF-8 bytes: issuer 1024 and subject 512. They are preserved exactly; NUL is
rejected because PostgreSQL text cannot store it. URL and other principal policy
belongs to authentication. Owner Debug is redacted.

Installation input is the already canonical `InstallationId.as_str()` value:
1–128 ASCII bytes, alphanumeric first/last byte, with only letters, digits,
`._-` internally. The writer does not trim or generate an ID. Project IDs use
the mature `ulid =3.0.0` parser/formatter and must be canonical nonzero ULIDs.
Each declared project has at least one version, matching Core inventory. Versions
are nonempty, already trimmed and contain no controls; there is no artificial
version-text size limit or default version. Projects and versions are sorted;
duplicate projects or versions are rejected rather than silently merged. Zero
projects is a valid replacement and retains the parent.

The transaction inserts a parent only if absent and then locks that parent with
`FOR UPDATE`. The first creator wins; another literal owner receives
`OwnerConflict` without taking over or changing the inventory. Concurrent writes
from the same owner produce one complete inventory or the other, never a mixture.
Current children are streamed to validate canonical IDs/versions, contiguous
one-based positions and strictly ordered unique versions before comparison. A
malformed stored set is rejected and is not repaired or overwritten silently.
Stored creation/update timestamps must also satisfy the existing nonnegative
`TimestampMicros` contract; negative values return `MalformedStored` without repair.
Only one preceding version is retained while reading; the writer does not collect
a second full inventory. A real change replaces children and updates the parent
inside the same transaction. Creation timestamps are server-generated; later
changes preserve `created_at`.

`RegistrationResult` is returned after confirmed COMMIT. Its borrowing getters
expose instance ID, UTC-microsecond creation/update timestamps and
`RegistrationChange::{Created, Updated, Unchanged}`, with no owner or authority.
`Unchanged` preserves the exact previous update timestamp.

| Error | Meaning and caller action |
| --- | --- |
| `InvalidOwner` | Owner data does not fit the storage contract. |
| `InvalidInventory` | Noncanonical ID/version, duplicate input or project without versions. |
| `OwnerConflict` | The installation is already bound to another literal owner. |
| `MalformedStored` | Stored identity/inventory cannot be interpreted; stop without repair. |
| `Control(error)` | Existing storage, closed-store, clock or deadline failure. |
| `Control(OutcomeUncertain)` | COMMIT began but its result is unknown; do not replay automatically. |

The caller deadline is bounded by the existing operation timeout and is never
renewed. Cancellation or failure before COMMIT discards the transaction's
connection; known success returns it to the pool. A timeout or disconnect after
COMMIT begins returns uncertainty. SQL/driver values are absent from public error
messages. This API does not list installations, remove parents, publish presence,
make authorization decisions or provide an HTTP endpoint.

From the Broker workspace, the focused native check is:

```text
cargo test --locked -j1 -p broker-control --test postgres postgres_instance_registry_contract -- --ignored --test-threads=1
```

The test uses the pinned real PostgreSQL TLS fixture for registration, reread,
reopen, 70,000-byte versions, exact owner binding, no-op/empty inventories, races,
constraint/trigger rollback, malformed stored rows, parent-lock deadline/cancel,
pool recovery and a real disconnect during COMMIT. On 2026-10-11, the exact
focused command above passed on Linux with Docker in 86.044 seconds
(`tsk-5870`). The affected fast suite passed 40 tests and 11 doctests;
workspace formatting and strict broker-control Clippy also passed.
The disconnect fixture observed rollback, but the API reported
`OutcomeUncertain`: that one observed state is not a guarantee for other
uncertain commits. No automatic retry occurred. Windows/macOS, other native
backends, the broad integration suite and future Auth/ACL/HTTP consumers are
not qualified by this PostgreSQL writer result. The structural qualification
below remains the separate `tsk-463c` result.

## Development database lifecycle

The existing control services initialize the full current schema only in an empty
database. They validate exact table inventory and the format/epoch marker before
using an existing database. Epoch 1, missing instance tables and future epochs are
rejected; startup does not add the missing tables or upgrade stored data.

For a disposable development database, explicitly recreate only that database
through the chosen database engine's normal operations, then initialize the Rust
service. Keep configuration and credentials separately. No automatic reset,
old-format converter, importer or compatibility reader is part of this producer.

## Verification

From the Broker workspace:

```text
cargo test --locked -j1 -p broker-store --all-targets
cargo test --locked -j1 -p broker-store --doc
cargo test --locked -j1 -p broker-store --test sql_servers -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test postgres postgres_runtime_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test mysql_control mysql_control_runtime_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test mysql_control mysql_instance_schema_epoch_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test mysql_control mysql_inbound_authority_service_contract -- --ignored --test-threads=1
```

The SQLite contract and pinned real-server fixtures exercise orphan/duplicate
rejection, invalid positions, deletion cascade, empty child inventory and exact
reread of owner values and a 70,000-byte Unicode version. The native control
fixtures check fresh initialization, restart and rejection of incompatible schemas;
the MySQL inbound-authority case retains real overflow beyond the new catalog
minimum. Ignored tests require Docker and are not counted by the fast suite.
Qualification results are recorded under `tsk-463c`; historical schema artifacts
retain their original epoch and evidence.

## Qualification of the structural producer

`tsk-463c` qualified this source on Linux with Docker and the pinned PostgreSQL/MySQL images. The store fast suite passed 12 contracts and two doctests; the control fast suites passed 36 tests and 11 doctests; xtask passed six tests. Ignored native tests are counted separately: both store servers passed, followed by a focused PostgreSQL TCP-readiness run; PostgreSQL control runtime, MySQL control runtime, the MySQL epoch contract and the MySQL inbound-authority/overflow contract each passed. The overflow fixture created and counted 139 real foreign keys against a capture cap of 138. Formatter, strict Clippy for the affected crates, diff whitespace and local documentation links passed.

The first store attempt failed with MySQL socket error 2002; its exact underlying cause was not established. Native store readiness now uses TCP loopback for both engines, excluding their image entrypoint temporary socket-only servers. Later inbound-authority attempts failed at fixture startup and at a setup SQL deadline; their exact underlying cause was not established. Those failures remain in the qualification history; the final unchanged-deadline run passed. No product deadline, capture cap, durability setting or authentication behavior was relaxed to obtain that result. Other platforms and Registry CRUD/Auth/ACL/live integrations have not been qualified by this leaf.

Source owners: `crates/broker-store/src/schema.rs`,
`crates/broker-store/tests/schema_contract.rs`,
`crates/broker-store/tests/sql_servers.rs`, and the affected PostgreSQL/MySQL
control fixtures. This leaf does not qualify end-to-end N6/N7/N9 behavior.

Authenticated ALL-project registration and empty-inventory ownership are provided
by [local instance registration](rust-instance-registration.md). This operation
composes current raw local Auth, fresh Publish grants and the SQL inventory writer.

Read one durable inventory through the [Rust SQL data reader](rust-instance-read.md).
