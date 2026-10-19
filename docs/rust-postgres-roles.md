---
title: Rust PostgreSQL role definition persistence
references:
  - target: {type: task, id: tsk-d609, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-74a7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9a45, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# PostgreSQL role definitions

Audience: Broker maintainers composing the administrative server. This SQL producer implements role definition replacement under tsk-d609; its three native PostgreSQL cases passed on Linux. It uses the existing [PostgreSQL control store](rust-postgres-control.md) and the shared system permission catalogue. It does not authenticate callers or supply an authorization decision. The HTTP authentication and authorization producer remains a separate delivery.

Before invoking this method from an administrative endpoint, authenticate the caller, revalidate the current identity and policy, require `roles.write`, and verify CSRF for a cookie-based mutation. Identity snapshots and stored session metadata alone do not authorize a write. See [Administration](administration.md) for the administrative journey.

```rust
store.set_role(
    "auditor",
    &[SystemPermission::Action(SystemAction::ConfigurationRead)],
    deadline,
).await?;
```

The method borrows `PostgresControlStore`, the name and permission slice until the future completes. It returns `Result<(), ControlError>`; creation time is captured internally. It exposes no pool, driver error, raw SQL or credential.

## Definition rules

Names are trimmed, remain case-sensitive, and must be ASCII identifiers of at most 128 bytes: an alphanumeric initial character followed by alphanumeric characters, dot, underscore or hyphen. Invalid names and an empty custom bundle return the finite, redacted `InvalidRole` error before acquiring a connection.

Custom bundles use the existing typed `SystemPermission` catalogue: the nine supported `SystemAction` values and the literal wildcard `All` (`*`). Duplicate permissions are removed and codes are ordered. Temporary normalization stores only distinct catalogue entries; no generic quota or new arbitrary input default is introduced.

The exact built-in names `admin` and `user` always persist their official `BuiltinRole` bundles, even when the supplied bundle is empty or requests a wildcard. Admin retains all supported actions; user retains `session.read` and `projects.read`. Built-ins cannot be narrowed or broadened through this operation.

## Transaction and failure behavior

A parameterized transaction inserts the role if absent, locks that role row with `FOR UPDATE`, then replaces its permission rows. Writers of the same role serialize; creation time remains unchanged when an existing definition is replaced. A failed transaction does not expose a partial bundle. The next [current identity/RBAC read](rust-postgres-identity.md) sees the new committed permissions.

This operation does not alter assignments, identities, their revisions or resource grants. There is no role-definition revision or compare-and-swap column. Last-administrator protection belongs to assignment and local-user mutations; these definitions retain the fixed admin bundle and do not remove its assignments.

The original deadline is bounded by the existing operation budget. Normal SQLx RAII closes failed or cancelled connections. `Storage` covers SQL failure before commit; `Deadline` covers an operation that times out before commit; pool shutdown returns `Closed`. A clock error is finite. Successful acknowledgement requires a known COMMIT. Failure or timeout during COMMIT returns `OutcomeUncertain`; do not replay automatically. No response grants an authentication or policy lease.

## Verification

Run affected checks from the Broker workspace:

```text
cargo fmt --all --check
cargo clippy --locked -p broker-control -p xtask --all-targets --all-features -- -D warnings
cargo test --locked -p broker-control --all-targets
cargo test --locked -p broker-control --doc
cargo test --locked -p xtask --all-targets
cargo test --locked -p broker-control --test postgres_roles -- --ignored --test-threads=1
```

The existing prepush PostgreSQL phase also includes `postgres_roles`; it remains one phase. Native cases verify definition replacement, fixed built-ins and fresh RBAC reads, SQL rollback and concurrent writers, real SQL permission denial, cancellation, COMMIT uncertainty and shutdown. On 2026-10-10, all three native cases passed in 98.78 seconds. The affected fast control suite passed 36 tests, documentation passed 11 tests, xtask passed six tests, and strict Clippy passed. Linux results do not establish other platforms or full server integration.

This producer introduces no migration, importer or conversion of legacy Go data, schemas, configuration or formats. It uses the Rust store and its current data contracts. OP, HTTP authority, identity mutations, STS and the full Broker migration remain their own deliveries.
