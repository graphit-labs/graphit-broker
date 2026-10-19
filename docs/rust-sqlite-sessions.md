---
title: SQLite administrative session metadata
type: reference
status: qualified-library-linux
updated: 2026-10-17
references:
  - target: {type: task, id: tsk-cbcc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# SQLite administrative session metadata

This library stores, reads and revokes administrative session metadata on the private file-backed [SQLite Control store](rust-sqlite-control.md). Configuration, Presence/server dispatch, cookies, login, CSRF comparison and current issuer/user/RBAC authorization are separate consumers. Reading metadata does not grant authority or establish a lease until its expiry.

The [shared session reference](rust-admin-sessions.md) defines `SessionLimits`,
`NewAdminSession`, `AdminSession`, profile/principal/claims DTOs, canonical lists and
finite errors. Its `AdminSessions` wrapper remains PostgreSQL-specific.

## API and explicit limits

`SqliteControlStore::admin_sessions(SessionLimits)` validates the explicit policy
and returns `SqliteAdminSessions<'_>`. The borrowed view exposes:

```text
create_session(&str, &NewAdminSession, Instant) -> Result<(), ControlError>
session(&str, Instant) -> Result<AdminSession, ControlError>
revoke_session(&str, Instant) -> Result<SessionRevocation, ControlError>
```

These methods are async. The view is redacted in Debug, borrows the store and
exposes no SQL, connection or digester. There are no default limits or lifetime.
Limits cover UTF-8 bytes, Unicode field widths, list counts, encoded JSON and
maximum lifetime, with shared checked arithmetic. The factory rejects impossible
capacities or a zero/sub-microsecond lifetime. Creation revalidates the input
against the view policy before HMAC and field copies: a permissive constructor
does not authorize a stricter view.

The [credential digester](rust-credentials.md) uses `TokenKind::AdminSession`,
credential domain 1. Only the hex64 digest enters SQL. The raw token is not stored
or logged. CSRF remains recoverable in private storage and its Rust owner is
`Zeroizing<String>`; this does not promise erasure of every driver or SQL copy.

## Atomic creation and coherent reads

One existing IMMEDIATE transaction inserts `admin_sessions`, the required
`admin_session_principals` child and optional `admin_session_claim_roles`. Each
INSERT must affect exactly one row. A duplicate parent is SessionExists and
preserves the existing three-table state. All statements remain inside the same
transaction until `Work::commit`; failure before commit rolls it back.

Creation observes server UTC after acquiring the physical owner and beginning the
transaction. Expiry must follow creation and fit the view's maximum lifetime. A
fresh check before commit rejects expiry reached during creation. Expiry is the
original absolute timestamp and is never renewed.

The reader joins the parent and both children in one transaction. SQL CASE clauses
check storage types and cap every text/JSON field before transferring it to Rust.
Separate child-presence markers distinguish a missing principal from a field
rejected by its byte cap. Missing parent is SessionUnavailable; missing principal
is CorruptSession. Missing claims are valid `None`. `Some([])` is distinct and
retains the literal configured selector, including whitespace. Unknown claimed
roles are metadata; this API performs no permission lookup or assignment fallback.

The shared closed decoder checks JSON arrays of strings, canonical lists, raw
bytes and Unicode widths, revision, timestamps and lifetime. A future creation
timestamp is corrupt. Invalid stored values are never normalized or repaired.
Complete corruption checks precede expiry evaluation and leave all rows intact,
including malformed expired sessions.

## Expiry, revocation and lifecycle

Equality is expired. Once a clock observation sees expiry, a later backwards
clock movement cannot revive that observation. A valid expired session deletes
only its parent and foreign-key children, then returns SessionExpired after known
commit. A valid read preserves its rows; a subsequent revocation may follow.

Revocation deletes directly by the session-domain digest without decoding stored
metadata, so it also handles corrupt sessions. Zero affected rows is confirmed
Absent; one is confirmed Revoked. More is Storage and rollback. The result is
returned only after known commit. Other sessions are preserved.

Each operation captures the existing effective monotonic deadline before its
input work and carries it through the physical executor and commit. It is never
renewed between SQL statements. Deadline/caller-drop/close use the existing native
interrupt and retain the worker/owner through quiescence. A commit started without
confirmed acknowledgement is OutcomeUncertain, with no confirmed result or
automatic replay. A known acknowledgement is not reclassified by a later clock
tick. Errors expose no driver message, SQL, path, token or identity data.

## Verification

The ordinary `sqlite_sessions` target exercises real private SQLite files,
independent owners, three-table roundtrip and duplicate preservation, HMAC-domain
separation, strict view limits, raw token absence, corruption/types/caps, optional
claims, expiry/cascades, concurrent create/read/revoke and writer-blocked lifecycle.
Expiry wait cases retain a real SQLite writer and cross the original expiry;
sleep is not their only concurrency oracle.

The new pending-future cancellation cases do not claim SQL had started or that
cancellation occurred after a staged write. Inspection verifies the three INSERTs
share one mature transaction. Physical rollback of mutations, cancellation and
COMMIT/ACK proofs are separately reused from tsk-6ebc. There is no new trigger,
schema fault, witness, mock clock or production fault harness.

Run the affected checks from Broker on supported hosts:

```text
cargo test --locked --offline -p broker-control --test sqlite_sessions -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib --test sqlite_sessions -- -D warnings
cargo fmt --package broker-control -- --check
```

The new lifetime rustdoc is selected with `cargo test --locked --offline -p broker-control --doc SqliteAdminSessions`.
Existing unchanged library/rustdoc and
physical executor evidence is reused. CONTROL_TEST already includes this ordinary
target through `--all-targets`; no duplicate gate is added. Linux runtime proves
Linux. No native Windows/macOS execution or complete SQLite backend is claimed by
this library unit.
