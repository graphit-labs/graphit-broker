---
title: PostgreSQL local identity and current SQL roles
description: Current local identity and SQL RBAC snapshots borrowed from the PostgreSQL control owner.
tags: [rust, postgresql, identity, authorization]
references:
  - target: {type: task, id: tsk-74a7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-cd0d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9a45, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# PostgreSQL local identity and current SQL roles

Audience: Broker server maintainers and authenticated administrative consumers. This PostgreSQL reader is implemented under tsk-74a7. All four native identity scenarios passed together on Linux through the existing prepush PostgreSQL phase. Its control target and the administrative-session target with corrected COMMIT-fault synchronization also passed. The active MySQL reader supplies its shared data types and behavior; see [MySQL identity](rust-mysql-identity.md).

A consumer that has already authenticated a local caller supplies a LocalIdentityReference with expected username, raw local subject and revision. Constructing this reference does not verify credentials or confer permissions. A fetched LocalIdentitySnapshot contains username, subject, human/service kind, revision, role names and typed SQL system permissions. It contains no password verifier, profile, teams JSON, credential, session or authorization lease.

The [native Admin session endpoint](rust-admin-session-http.md) is a separate authenticated consumer: it binds signed username and pseudonymous subject through the store's native domain-15 derivation, then reads current SQL profile and `session.read` permission in one statement. It does not manufacture a LocalIdentityReference from a JWT subject or compare a nonexistent JWT mint revision. This reader and its data-only contract remain unchanged.

## Reading and revalidation

PostgresControlStore::local_identities(limits) returns a view borrowing its store. PostgresLocalIdentities::read(reference, deadline) fetches the current database row and roles. It returns Current only for the matching enabled username, subject and revision. Missing, Disabled, SubjectChanged and RevisionChanged identify ordinary unavailability. Invalid original limits map to Configuration; invalid read references to InvalidIdentity. Malformed identity and role/action data use CorruptIdentity and CorruptRbac respectively. Exceeding the useful row or role cap returns IdentityLimitExceeded. Messages are static and redacted. Callers must handle these outcomes before applying fetched permissions to the already authenticated request.

Role membership combines assignments for canonical local|subject with implicit user. Roles and permissions are deduplicated and sorted. Valid roles without permissions do not grant actions; custom and unknown role names do not imply authority. The permission set uses the existing nine typed SystemAction values and literal *; unrecognized stored actions fail closed. allows(action) tests only this fetched permission set. A subsequent call reads current SQL again; the snapshot is not a lease for future requests.

## Limits and SQL

IdentityReadLimits supplies explicit username/subject/role byte bounds and role/row count bounds. The established identity contract caps safe ASCII username/role segments at128 bytes and raw subjects at512 bytes. Subjects are nonempty and contain no leading/trailing whitespace or NUL; revision is positive. Implicit user requires a role bound of at least4 bytes. No deployment default is introduced.

The single closed parameterized SELECT uses public-qualified identity/role tables and SQL-side octet_length/CASE bounds before decoding text. Native presence booleans distinguish an absent permission from a present action rejected by the byte-bound CASE. The latter remains corrupt data, never a silently empty permission set. A limit+1 result detects row overflow; an original row cap whose sentinel cannot fit signed PostgreSQL LIMIT is Configuration. Strings are borrowed from each native PgRow during validation and allocated when retained in the result. Password/profile/JSON columns are absent from the projection.

Canonical local|subject can require518 bytes for the SELECT bind, while role_assignments.subject retains the schema producer's VARCHAR512 character width. This read-only interface adds no durable role-assignment write and does not claim a518-character canonical value fits that stored column. A512-byte raw subject remains a valid identity input; no506-byte input cap or schema change is introduced. Later assignment mutations must reconcile their own durable identifier contract.

## Transactions, deadlines and cleanup

The reader uses the existing SQLx pool with an explicit read-only READ COMMITTED transaction. One SELECT gives identity and roles one coherent statement snapshot. Connection acquisition, query and COMMIT share the minimum of the caller's absolute monotonic deadline and the configured operation budget.

A successful result is returned after a known COMMIT. Timeout or driver failure once COMMIT starts returns OutcomeUncertain with no identity payload. The API does not infer rollback or replay the operation. Before COMMIT, the established finite Deadline/Closed/Storage outcomes apply. The existing ConnectionGuard discards failed/cancelled leased connections with close_on_drop; confirmed completion returns the connection to the pool. Shutdown closes admission and waits under the existing store lifecycle contract.

## Validation

The native fixture uses the existing pinned PostgreSQL image, TLS, dynamically assigned loopback ports and owned temporary files/containers. Its named Fixture guard exists before Docker create/start; the helper uses normal Command.output() drain/reap and named RAII removal with volumes. Native cases cover reference changes/current RBAC, useful bounds and malformed data, real atomic writer/snapshot consistency, SELECT denial, deadlines/cancellation/shutdown and a precisely described backend disconnect. The SELECT-denial scenario opens as a non-superuser schema owner with startup privileges, then revokes SELECT after a healthy read and restores it for recovery. A backend kill is not described as proof of a confirmed COMMIT with lost ACK.

Run affected checks from the Broker workspace:

```text
cargo fmt --all --check
cargo clippy --locked -p broker-control --all-targets --all-features -- -D warnings
cargo test --locked -p broker-control --all-targets
cargo test --locked -p broker-control --doc
cargo test --locked -p broker-control --test postgres_identity -- --ignored --test-threads=1
```

Re-run affected existing PostgreSQL control/session native cases when their shared service or fixture changes:

```text
cargo test --locked -p broker-control --test postgres --test postgres_sessions -- --ignored --test-threads=1
```

The existing prepush PostgreSQL phase runs the control and identity native targets together:

```text
cargo test --locked -p broker-control --test postgres --test postgres_identity -- --ignored --test-threads=1
```

The native identity cases passed on Linux. The initial fixture failures remain failed historical attempts, followed by the passing runs; they are not counted as successful qualification. Other platforms and broad system integration remain with the migration coordinator.

The HTTP authentication/authorization boundary, identity mutations, password/MFA flows, OIDC provider and storage gateways remain their own deliveries. This reader does not complete the Broker server migration or establish another platform's runtime qualification.

Native password evidence is a separate producer; see [LOCAL password verification](rust-local-password.md). The identity projection above still selects no PHC and authenticates no caller.
