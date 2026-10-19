---
title: SQLite current identity, role definitions and ACL snapshots
type: reference
status: qualified-library-linux
updated: 2026-10-17
references:
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implemented_by
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite identity, role definitions and resource ACL

This reference is for Control library consumers. It covers three data primitives on the existing private, file-backed `SqliteControlStore`. Library tests do not establish complete SQLite server configuration/dispatch or administrative HTTP integration.

Open the store using the explicit path and startup/operation/shutdown budgets in
[SQLite Control](rust-sqlite-control.md). Each operation takes its original caller
deadline; the existing executor also applies the configured operation budget.
Borrowed views retain the store lifetime and redact Debug. They expose no SQL or
connection. Callers authenticate and authorize before consuming these data APIs.

## Current local identity

`local_identities(IdentityReadLimits)` validates explicit positive limits and returns
`SqliteLocalIdentities<'_>`. Its async `read(&LocalIdentityReference, Instant)` returns
the shared `LocalIdentityRead`. A reference is data supplied by an already
authenticated consumer, not a credential.

The read observes username, subject, human/service kind, enabled state, revision,
current role assignments and strict `SystemPermission` values in one transaction.
The canonical assignment subject is `local|<subject>`; the official `user` role is
implicit. Returned roles and deduplicated permissions are sorted. Password hashes,
profile data and teams JSON are not part of this projection.

Unavailable results remain distinct: Missing, Disabled, SubjectChanged and
RevisionChanged. Invalid references fail before SQL. Corrupt identity fields produce
CorruptIdentity; malformed role/action data produces CorruptRbac. Row/role ceilings
produce IdentityLimitExceeded without returning a truncated snapshot. The SQL
projection bounds text bytes before moving fields to Rust. Its field-cap behavior
matches the shared PostgreSQL reader: an inadmissible stored field produces the
corresponding corruption error. Unrepresentable row-limit-plus-one is Configuration.

Construct `IdentityReadLimits` explicitly. Username, subject and role byte limits
are capped at the shared schema bounds of 128, 512 and 128; role capacity must still
admit `user`. A snapshot describes the observed rows. It does not freeze later
assignments or produce a continuing authorization lease.

## Replace one role definition

The async `set_role(&str, &[SystemPermission], Instant) -> Result<(), ControlError>`
uses the shared role normalizer. Names are trimmed and remain case-sensitive,
ASCII identifiers of at most 128 bytes, starting with an alphanumeric character.
Remaining characters may also contain dot, underscore or hyphen. Custom bundles
must be nonempty; typed permissions are deduplicated and sorted.

Exact `admin` and `user` names always retain the official bundles, including when
the input is empty or contains All. The admin bundle has the nine system actions;
user retains projects.read and session.read. Replacement inserts a missing role,
preserves an existing created_at and atomically replaces its permission rows.
Independent owners of the same physical database serialize through SQLite's
IMMEDIATE transaction. No partial bundle is a successful result.

This primitive does not assign/revoke roles, change local identity revisions or
modify grants. Authenticated AdminRbac, last-admin checks and HTTP/CSRF remain with
their later consumers.

## Read raw resource ACL

`resource_grants(NonZeroUsize)` returns `SqliteResourceGrants<'_>` with an explicit
snapshot JSON byte ceiling representable by both isize and i64. Its async
`read(Instant)` returns the shared `ResourceGrantSnapshot` through the existing
closed `decode_snapshot` codec.

The id=1 ACL state is required, with positive revision and nonnegative timestamp.
Parents and capabilities/projects/S3 operations/S3 prefixes are ordered literally
by UTF-8 value and preserve stored strings. The reader does not trim, casefold,
split comma-separated values or infer capabilities. Invalid dynamic SQLite types
become codec errors, rather than coerced policy values. The complete JSON length
is checked in SQL before an oversized payload can cross into Rust.

An absent/malformed state is MalformedStored; it never means an empty policy.
A valid empty snapshot contains no grants. InvalidLimits rejects an unrepresentable
ceiling and ReadLimitExceeded rejects excess bytes. Under a concurrent atomic writer,
a result contains a complete old or new snapshot with coherent revision/children.
Evaluating the raw selectors still belongs to the actual policy consumer.

## Lifecycle and errors

All three operations reuse the private executor, its original deadline,
cancellation/close signal, exact file checks and `State::begin` transaction. Reads
also return only after known commit. The native owner remains retained through
quiescence; a cancelled caller cannot lend its connection to a successor early.
Known domain failures retain the shared finite errors, while physical failures map
through the closed SQLite-to-Control conversion without SQL, driver text, paths or
credentials. A commit without confirmed acknowledgement remains OutcomeUncertain;
never replay that write automatically.

There is no new pool, lock lifetime, global quota, schema or compatibility importer.
The physical SQLite producer and its original qualification remain in
[SQLite Control](rust-sqlite-control.md). This unit does not configure Presence,
server dispatch or project/storage authorization to use SQLite.

## Sources and verification

- `crates/broker-control/src/sqlite/flow/{identity,roles,resource_grants}.rs`: data APIs.
- `identity.rs`, `resource_grants.rs` and `service/roles.rs`: shared types, codec and role policy.
- `crates/broker-control/tests/sqlite_identity_acl.rs`: actual file, independent owners,
  invalid/capped data, atomic snapshots and deadline/caller-drop/close cases.

Run the affected target with `cargo test --locked -p broker-control --test sqlite_identity_acl`.
The two new view-lifetime rustdocs are selected by SqliteLocalIdentities and
SqliteResourceGrants; the unchanged broader library/rustdoc suites retain their
existing evidence. Quality uses Clippy for the library and new integration target,
plus `cargo fmt --package broker-control -- --check`. The existing CONTROL_TEST all-targets command already includes
this new target. Linux execution proves Linux; compilation does not qualify native
Windows/macOS runtime.

The new lifecycle cases retain a real competing writer, exercise deadlines and
discard pending futures for all three APIs, then verify recovery and the previous
role bundle. They also exercise shutdown and closed admission. They do not assert
that SQL had begun or that cancellation occurred after DELETE. Role replacement
uses the existing SQLite transaction through every delete/insert and known commit;
the producer's separate physical mutation/rollback, cancellation and COMMIT/ACK
proofs are reused. Concurrent role replacements still verify complete old/new
bundles through the actual identity reader.
