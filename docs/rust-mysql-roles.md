---
title: Rust MySQL role definition persistence
references:
  - target: {type: task, id: tsk-84fa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7b3e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-14f5, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1e59, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-5ca4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-cd0d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-d609, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# MySQL role definitions

Audience: Broker maintainers composing the administrative server. This SQL producer implements definition replacement under tsk-14f5; its three native cases passed on Linux. It borrows the existing [MySQL control store](rust-mysql-control.md).

The caller must authenticate, revalidate current identity and policy, require `roles.write`, and verify CSRF for a cookie mutation. Stored session metadata and identity snapshots do not authorize a write. The HTTP authority producer remains a separate delivery; see [Administration](administration.md).

## API and definition rules

```rust
use broker_control::{SystemAction, SystemPermission};

store.set_role(
    "auditor",
    &[SystemPermission::Action(SystemAction::ConfigurationRead)],
    deadline,
).await?;
```

`MySqlControlStore::set_role` returns `Result<(), MySqlControlError>`. It borrows the store, name and typed permission slice until its future completes. It exposes no raw SQL, connection or credentials.

Names are trimmed, case-sensitive ASCII identifiers of at most 128 bytes: an initial alphanumeric character, followed by alphanumeric characters, dot, underscore or hyphen. Invalid names and empty custom bundles return the static, redacted `InvalidRole` error before admission or SQL.

Custom bundles use the existing nine system actions and literal `All` wildcard (`*`). The method deduplicates and orders codes, retaining only distinct catalogue entries during normalization. The exact names `admin` and `user` always persist their official bundles, including when supplied permissions are empty or request a wildcard. Admin retains the nine supported actions; user retains `projects.read` and `session.read`.

## SQL and provisioning

One READ COMMITTED transaction inserts a role or performs a no-op update on its existing name, locks the role row with `FOR UPDATE`, and replaces its permissions. Writers of one role serialize. Existing creation timestamps remain unchanged; new timestamps are captured internally. SQL errors roll back the whole bundle. The next [current identity/RBAC read](rust-mysql-identity.md) observes the committed permissions.

Provision the SQL account for these statements:

| Object | Required privileges |
| --- | --- |
| `roles` | INSERT on name/created_at, SELECT(name), UPDATE(name) |
| `role_permissions` | INSERT on role/action, DELETE, SELECT(role) |

The no-op upsert requires UPDATE(name) even though it preserves the stored value. SELECT(role) supports the DELETE predicate. See the MySQL manuals for [INSERT privileges](https://dev.mysql.com/doc/refman/8.4/en/insert.html), [DELETE privileges](https://dev.mysql.com/doc/refman/8.4/en/delete.html), and [InnoDB locks](https://dev.mysql.com/doc/refman/8.4/en/innodb-locks-set.html). The implementation uses bound values and the configured, observed database identifier. It does not suppress errors with INSERT IGNORE or replace existing rows.

The method uses the existing TLS connection, settings/context observation, admission, transaction and commit machinery. The server enforces current SQL permissions on those actual statements. Flow and identity consumers keep their existing catalogue validation; this writer does not introduce another operation/proof catalogue. `MysqlCatalogLimits` bounds the existing settings/context capture and catalogue consumers. Role DML templates and inserts are not added to the catalogue probe counter: their domain is the finite typed action catalogue, with the existing database identifier validation and shared operation deadline.

Assignments, local identities, their revisions and resource grants are unchanged. Role definitions have no revision/CAS column. Last-administrator protection belongs to assignment and local-user mutations; this operation retains the fixed admin bundle.

## Deadlines and failures

The original caller deadline is bounded by the store's operation budget. Connection acquisition, TLS setup, statements, row locks and commit share it. Cancellation drops the private connection and releases its admission permit; remote transaction cleanup is eventual.

`Denied` reports a native permission rejection. `Denied(Insert)` identifies the upsert/insertion operation, including a denial of its UPDATE privilege. `Storage` reports other precommit SQL failures. An expired precommit operation returns `Deadline`; shutdown prevents new valid operations with `Closed`. Clock, connection and context failures retain the existing finite errors.

Only a known COMMIT returns success. A failed or timed-out COMMIT returns `OutcomeUncertain`; the server may already have committed. Do not replay automatically or infer rollback from that error.

## Verification

From the Broker workspace:

```text
cargo fmt --all --check
cargo clippy --locked -p broker-control -p xtask --all-targets --all-features -- -D warnings
cargo test --locked -p broker-control --all-targets
cargo test --locked -p broker-control --doc
cargo test --locked -p xtask --all-targets
cargo test --locked -p broker-control --test mysql_control mysql_role_ -- --ignored --test-threads=1
```

The three cases reuse the existing pinned MySQL 8.4.11 TLS fixture and ordinary account: definitions/current RBAC; real SQL rollback, concurrency and row locks; permission denial, deadline, abort, observed COMMIT uncertainty and shutdown. The existing MYSQL_CONTROL gate already includes this file. Ignored native cases in the fast command do not count as executed passes.

On 2026-10-10, all three native cases passed on Linux with MySQL 8.4.11 in 111.10 seconds. The affected fast control tests passed (36), documentation tests passed (11), and xtask tests passed (6), including the real formatter-failure guardrail. Formatting, strict Clippy and whitespace checks passed. The lock observer uses actual requesting records from `performance_schema.data_lock_waits` correlated to the ordinary writer and the roles table. Linux results do not establish other platforms or full server integration.

## Role assignments

MySqlControlStore::assign_role(subject, role, deadline) returns Result<(), MySqlControlError>. The same caller authentication, current policy, roles.write and CSRF boundary above applies. Pass the stable issuer|subject or local|subject identity; the primitive does not look up a user or canonicalize a username/email.

Both strings are trimmed and preserve case. Subjects must be nonempty and contain at most 512 Unicode characters, matching VARCHAR(512); the assignment API adds no byte quota or separator requirement. Role names follow the same ASCII 128 rule as definitions. Invalid input returns InvalidAssignment before admission/SQL. A missing role returns RoleNotFound, leaving assignments unchanged.

One READ COMMITTED transaction locks the existing parent role with FOR UPDATE, inserts the pair using bound values and an internally captured timestamp, and performs a no-op update when the pair already exists. Duplicates preserve created_at. The parent lock shares the order used by SetRole and assignment revocation. Only a known COMMIT returns success; the deadline, cancellation, Closed, Denied, Storage and OutcomeUncertain behavior above also applies. Denied(Insert) covers either INSERT or the required duplicate-path UPDATE privilege. No automatic replay follows uncertainty.

Provision SELECT(name)/UPDATE(name) on roles for the parent locking read and INSERT(subject,role,created_at)/UPDATE(subject) on role_assignments, in addition to the existing store/Lease requirements. AssignRole does not insert or update a role definition, identity, revision or resource grant. The next current SQL identity/RBAC read observes committed assignments. The caller remains responsible for authenticating an external identity; an assignment string is not an authentication proof.

Run the existing native fixture for this leaf:

~~~text
cargo test --locked -j1 -p broker-control --test mysql_control mysql_assignment_ -- --ignored --test-threads=1
~~~

The three cases exercise inputs and current RBAC, timestamp-preserving duplicates, 512 Unicode characters with more than 512 bytes, explicit role absence, real trigger rollback and denied permissions, concurrent duplicate pairs, observed parent-row waits, deadline/abort/shutdown, and actual COMMIT observation followed by relay disconnect or response timeout. For tsk-7b3e on Linux, all three native cases passed with MySQL 8.4.11/TLS in 253.62 seconds. The affected fast control tests passed (36), documentation tests passed (11), and xtask tests passed (6), including the formatter-failure guardrail. Formatting, strict Clippy, whitespace checks and links passed; impact review found no static faults. The definition results above remain qualified separately. These results establish the tested Linux assignment primitive; other platforms and full server integration remain separate. RevokeRole and local-user mutations are subsequent deliveries, including protection of the last explicitly assigned administrator.

## Revoking assignments and protecting the last administrator

MySqlControlStore::revoke_role(subject, role, deadline) returns Result<(), MySqlControlError> after the caller satisfies the same authentication, roles.write/current-policy and CSRF boundary. It trims both strings and deletes only that exact pair; an absent pair or role succeeds without changing other assignments. It adds no general input validation or identity revision/CAS update to deletion. Pair presence, candidate exclusion and DELETE share the same binary subject/role equality, refining native equality so PAD SPACE cannot turn the target itself into another administrator. Native equality predicates retain indexed lookup where applicable.

The method first locks the parent role in the same READ COMMITTED transaction and order as SetRole/AssignRole. For literal admin and a present target, it requires another explicitly assigned eligible administrator. An assignment whose subject does not start literally with local| counts as external without an issuer/configuration lookup. Local| with a capital L is an external prefix under this literal rule. An external administrator permits an immediate decision without reading local identities; OIDC claim roles and custom roles with equivalent permissions do not count as explicit admin assignments.

If no other external admin exists, one JOIN selects at most one enabled local candidate. The candidate username, subject, kind, enabled and revision must satisfy the existing Rust identity invariants: ASCII username up to 128 bytes, nonempty subject up to 512 bytes without outer whitespace or NUL, human/service kind, enabled=1 and revision>=1. Its stored assignment must equal local| plus the stored identity subject byte for byte. Native JOIN equality may encounter a padded row; validation returns CorruptIdentity before allowing DELETE. It never trims/canonicalizes stored identity data to make it eligible. The identity byte invariant differs from the assignment input limit of 512 Unicode characters. A malformed selected candidate fails closed even if another valid local candidate exists; no global list or per-user N+1 lookup is performed.

Disabled or missing local users do not count. The target user's enabled state is not consulted, so a disabled target remains protected if no other eligible admin exists. No eligible alternative returns LastAssignedAdmin and rolls back. Missing targets remain idempotent. Successful removal changes current SQL RBAC without modifying identity revisions or timestamps of remaining assignments.

Provision SELECT(name)/UPDATE(name) on roles for the parent locking read, SELECT(subject,role) and DELETE on role_assignments, and SELECT(username,subject,identity_kind,enabled,revision) on local_users for the local admin guard, plus the existing Lease requirements. A native SELECT/DELETE denial remains Denied; it does not become an absent candidate or successful no-op. Deadline, abort, Closed, known COMMIT and OutcomeUncertain behavior above applies.

Future local-user disable/delete producers must share the roles.admin parent lock and ordering to compose the same protection across mutation types. This primitive's serialization guarantee covers cooperating SetRole/AssignRole/RevokeRole writers; it does not claim protection from external writers that ignore the protocol.

~~~text
cargo test --locked -j1 -p broker-control --test mysql_control mysql_revocation_ -- --ignored --test-threads=1
~~~

The three existing-fixture cases cover current RBAC and idempotency, local/external eligibility and malformed/PAD SPACE identities, concurrent revocation preserving one administrator, actual DELETE-trigger rollback and denied capabilities, deadline/abort/shutdown, and observed COMMIT followed by relay disconnect or response timeout with an independent SQL oracle. For tsk-84fa on Linux, all three native cases passed with MySQL 8.4.11/TLS in 327.73 seconds. The affected fast control tests passed (36), documentation tests passed (11), and xtask tests passed (6), including the actual formatter-failure guardrail. Formatting, strict Clippy, whitespace checks and links passed; impact review found no static faults. The first native run recorded two passes and a DELETE-denial fixture failure because revoking DELETE also removed the parent locking-read privilege. The corrected fixture retains UPDATE(name) on roles, proves AssignRole still works, and verifies Denied(Delete) at the intended assignment DELETE. Previous SetRole/AssignRole results above remain qualified separately. These results establish the tested Linux revocation primitive; other platforms and full server integration remain separate.

The parent SELECT FOR UPDATE needs SELECT plus a locking privilege. UPDATE(name) on roles supplies that privilege without deleting definitions; an already provisioned DELETE or LOCK TABLES privilege is an alternative. See the [MySQL 8.4 locking-read privilege contract](https://dev.mysql.com/doc/refman/8.4/en/innodb-locking-reads.html). Native denial tests preserve the parent locking privilege while revoking assignment DELETE, so they exercise the intended statement.
