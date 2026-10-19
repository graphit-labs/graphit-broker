---
title: Rust MySQL local identity and system roles
description: Bounded current local identity and SQL RBAC snapshots in the existing MySQL control owner.
tags: [rust, mysql, identity, authorization]
references:
  - target: {type: task, id: tsk-cd0d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-1e59, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-1c24, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Rust MySQL local identity and system roles

Audience: Broker server maintainers and future authenticated administrative consumers. This implementation candidate adds a bounded read of current local identity and SQL role data to the [MySQL control owner](rust-mysql-control.md). The four identity tests and the complete 23-case MySQL suite passed on Linux. The cleanup also passed all four affected identity cases. The prior [MySQL administrative session qualification](rust-mysql-sessions.md) remains evidence for its own snapshot.

A consumer must authenticate a local caller before using this API to decide a request. `LocalIdentityReference` contains expected username, subject and revision; constructing it does not authenticate credentials. Public session metadata and schema seeds likewise confer no permission. The read returns a fetched snapshot. Repeat it on the next request; it is not a lease proving identity or permissions stayed unchanged after fetching.

This read selects username, subject, human/service kind, enabled state, revision and SQL role/permission fields. It does not select or copy the password PHC, profile attributes, teams JSON, password-change state or MFA data. Credential authentication, KDF/MFA, HTTP login, upstream issuer/claim policy, identity mutations and last-administrator serialization remain separate deliveries. PostgreSQL/SQLite identity, resource grants, the complete OAuth/OIDC provider and gateway integration remain necessary.

## API and caller sequence

```text
IdentityReadLimits { username_bytes, subject_bytes, role_bytes, roles, rows: NonZeroUsize }
IdentityReadLimits::validate() -> Result<(), IdentityInputError>
LocalIdentityReference::new(username: &str, subject: &str, revision: i64,
    limits: &IdentityReadLimits) -> Result<LocalIdentityReference, IdentityInputError>
MySqlControlStore::local_identities(limits: IdentityReadLimits)
    -> Result<MySqlLocalIdentities<'_>, MySqlControlError>
MySqlLocalIdentities::read(reference: &LocalIdentityReference, caller: Instant)
    -> Result<LocalIdentityRead, MySqlControlError>
LocalIdentityRead = Current(LocalIdentitySnapshot) | Unavailable(LocalIdentityUnavailable)
LocalIdentityUnavailable = Missing | Disabled | SubjectChanged | RevisionChanged
```

All limits are mandatory; there is no default deployment policy. The borrowed view shares the existing owner's configuration, admission and native lease. It exposes neither an independent pool nor raw SQL/connection/native proof. Snapshot fields have readonly getters for username, subject, kind, revision, roles and permissions. The reference, snapshot, result and view redact Debug; they do not serialize or clone identity data through convenience derives.

1. Authenticate a local human or service caller through the appropriate credential flow.
2. Supply its exact expected username, immutable subject and positive persisted revision. Local identities always use SQL assignments, never claimed roles cached in a browser session.
3. Read with the original monotonic caller deadline. Invalid input/limits fail before admission or network I/O.
4. Only `Current` permits the caller to inspect this request's SQL permission snapshot. `Missing`, `Disabled`, `SubjectChanged` and `RevisionChanged` require the consumer's authentication/refresh handling. Do not turn infrastructure or corruption errors into a successful empty role set.
5. Apply the requested typed system action only under the authenticated consumer's policy. `allows(SystemAction)` tests this fetched permission set; it neither authenticates the reference nor grants access to projects, S3 or AI resources.

Lookup uses username, matching the existing administrative consumer. Renaming invalidates the old username; disabling or deleting the row invalidates the reference; subject/revision mismatches are distinct unavailable reasons. Stored identity corruption is rejected before these outcomes. Human and service rows remain supported. No cookie, HTTP response or credential is emitted here.

## Bounded inputs and corruption

Username must match the existing safe ASCII identifier grammar: an initial alphanumeric character followed by alphanumeric characters, dot, underscore or hyphen, at most 128 bytes. Subject must be nonempty UTF-8, NUL-free, already trimmed and at most 512 bytes. Revision is positive. The reader never normalizes identity. Original limit arithmetic/conversions are validated before taking physical minima; role capacity must fit the four-byte implicit role `user`.

Effective username/subject/role capacities are the smaller of the explicit limits and 128/512/128 octets respectively. Read rows are bounded by the explicit row limit and the existing owner's catalog-row limit; roles have their explicit cardinality cap. A single closed SELECT uses `CASE` and `OCTET_LENGTH` before owned text copies. Presence markers distinguish an absent permission from a present oversized value. The query requests at most the row cap plus one: excess rows or distinct roles produce `IdentityLimitExceeded`, never a truncated successful result. The existing aggregate Work budget still applies; measured native field bytes are charged before copying. This does not bound the driver's network allocations or establish a hard process memory peak.

Stored kind must be `human` or `service`, enabled must be exactly zero or one, and revision must be positive. Stored usernames/subjects and repeated identity fields across joined rows must satisfy their exact bounded contracts. Malformed identity data produces `CorruptIdentity`; malformed role/action data produces `CorruptRbac`. Fields outside the projection are not decoded by this operation.

| Condition | Finite result |
|---|---|
| Invalid original limits | `IdentityInputError::InvalidLimits`; view construction maps it to existing `Configuration` |
| Invalid reference or view input bounds | `IdentityInputError::InvalidReference`; read maps it to `InvalidIdentity` |
| Stored identity or role corruption | `CorruptIdentity` or `CorruptRbac` |
| SQL row sentinel or distinct role count exceeds its cap | `IdentityLimitExceeded` |
| Existing aggregate Work budget exceeded | Existing `Unproven(Truncated)` |
| Native capability/proof/storage/lifecycle failure | Existing typed finite MySQL error, never an unavailable identity substitute |

Error messages contain no identity, roles, credentials, SQL or driver text.

## Current SQL roles and wildcard

The identity key for local assignments is literal `local|` plus subject, never username or email. Effective roles are the distinct union of SQL assignments with `user`. An existing role with no permissions is valid; an unknown role adds no permission; no assignments still produce the implicit role name. Permission rows are read from SQL, including those of `user`. Removing actual permission rows does not cause the reader to fabricate seed grants.

`SystemPermission` represents either one of the nine existing typed `SystemAction` values or the literal wildcard `All` (`*`). Results are deduplicated and sorted deterministically. An exact action or `*` permits that typed action within the fetched set. Unknown stored action text fails closed as `CorruptRbac`; it is not a new action grant. Resource grants are evaluated independently by their proper consumer.

A 512-byte ASCII subject yields a 518-byte canonical SELECT bind. This read does not write an assignment, truncate the bind, reduce subject capacity to 506, alter the schema or invent a grant. No matching assignment yields only the implicit role and its actual SQL permissions. A Unicode subject can occupy 512 UTF-8 bytes while its canonical identity fits the producer's VARCHAR(512) character capacity. Future assignment writers must enforce their actual character capacity separately; the read does not solve that mutation contract by silently changing identifiers.

## Snapshot and transaction behavior

The read performs one nonlocking consistent SELECT over `local_users`, derived assigned roles union `user`, `roles` and `role_permissions`. READ COMMITTED gives that statement its own coherent read view. Separate user/role queries could mix snapshots; the candidate instead fetches them together. The [MySQL 8.4 consistent-read contract](https://dev.mysql.com/doc/refman/8.4/en/innodb-consistent-read.html) explains the engine mechanism; the native concurrency fixture exercises an atomic writer and checks the old and subsequent current snapshots.

The operation opens the existing private native lease and revalidates the complete 23-table catalog/current settings on the same ordinary verified-TLS handle. A closed EXPLAIN of the same projection proves selected capabilities without DML. There are no new row locks, permission booleans, owner pools or deadlines. The original caller deadline intersects the existing operation budget and covers admission, proof, query, unchanged-context check and COMMIT.

After fetching, an external identity/role writer may commit new data. That does not change the already fetched snapshot. The next read observes the current revision/roles. Catalog proof and constant progress trace events do not establish a policy lease or authorize execution. `Current` and unavailable outcomes are returned only after a confirmed COMMIT ACK. Loss of that ACK after COMMIT is sent produces existing `OutcomeUncertain`, including this readonly operation; do not replay automatically. Precommit cancellation/deadline discards the private native handle and preserves read-only SQL state. Admission and shutdown remain shared with flows and sessions. No fallible await follows a known successful ACK.

## Tests and integration status

Run the affected native identity tests with Docker available:

```text
cargo test --locked -p broker-control --test mysql_control mysql_identity_ -- --ignored --test-threads=1
```

The four cases cover current RBAC and unavailable identities, long canonical binds,
stored corruption and useful bounds, coherent snapshots during an atomic SQL writer,
cancellation and shared shutdown, current SELECT permissions, and real COMMIT
confirmation loss. The concurrency fixture pauses the connection after fetching,
commits identity and permission changes through an independent SQL connection,
and checks both the fetched snapshot and the next read. The ACK-loss fixture holds
the response after the server completes COMMIT; the caller receives
`OutcomeUncertain`, and an independent read confirms that no identity data changed.
Both fixtures use normal operation deadlines and the existing connection lifecycle.

Normal tests, compile-fail doctests, formatting and strict Clippy cover the public
API and Rust implementation. Existing hooks execute the library's checks and native
SQL suites; identity uses the ordinary fail-fast hook regression and library checks.

Before this cleanup, all four focused identity cases and the complete affected
MySQL suite passed: 23 passed, zero failed, zero ignored and zero filtered. Normal
broker-control tests (34), compile-fail doctests (10), xtask library tests (5),
formatting, strict Clippy and the advisory audit also passed. After cleanup, the four native cases passed again (4 passed, zero failed,
19 filtered). Normal tests (34), compile-fail doctests (10), xtask checks (6),
formatting and strict Clippy also passed. Windows/macOS
and broad server integration belong to final integration and have not run here.

The full native command, used for integration when wider changes justify it, is:

```text
cargo test --locked -p broker-control --test mysql_control -- --ignored --test-threads=1
```
