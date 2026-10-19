---
references:
  - target: {type: task, id: tsk-7f74, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6e9e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-70b2, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust authenticated own-inventory read

Audience: Broker server integrators implementing reconciliation after publishing.
This operation returns the complete own inventory only after current local Auth,
literal ownership and Read permission for every project. It is separate from
a list of other installations that projects only their readable projects.

## Call the shared store

~~~text
store.local_instance_inventory_reader(
  audience, identity_json_bytes, grants_json_bytes, inventory_json_bytes
) -> Result<PostgresLocalInstanceInventoryReader<'_>, InstanceInventoryReadError>
reader.read(raw, required_scopes, instance_id, original_deadline)
  -> Result<Option<AuthorizedInstanceInventory>, InstanceInventoryReadError>
~~~

Audience, scopes and three nonzero JSON byte caps are explicit integration
settings. The borrowed reader creates no new pool/runtime and has no defaults.
Use the existing [raw local verifier](rust-local-bearer-verifier.md),
[SQL inventory reader](rust-instance-read.md) and
[presence authorization](rust-presence-authorization.md) contracts.

The raw Access/Service bearer authenticates the current local user, with current
audience/scopes, enabled state, revision binding, revocation and strictly future
expiry. No caller owner or principal is accepted. After the SQL snapshot read,
the literal stored issuer/subject must equal the verified current issuer/raw
subject. Matching username, Publish, admin role or Hub permission cannot take
over another owner's inventory.

A nonempty own inventory requires explicit Read permission for every project.
Each project checks principal/capability/project in the same rule; different
rules can cover different projects, but cannot combine half of a grant.
The whole fresh policy compiles before any allow, including unrelated rules.
An empty own parent requires an explicit matching Any-project Read rule
(projects [] or *). Versions are data, not permission.

None means no parent at the selected SQL snapshot, after authentication is
still unexpired and the original deadline still valid. This absence path does
not read grants. Some exposes only inventory and creation/update microseconds;
the result has no public factory, owner getter, Clone, Deserialize or Default,
and redacts Debug. One denied project denies the whole read; no partial result
is returned by this own-inventory operation.

## Errors, deadlines and recovery

| Error | Meaning |
| --- | --- |
| Authorization(Authentication(...)) | Current local bearer is invalid/unavailable; no inventory returned. |
| Authorization(Forbidden) | Own inventory lacks ALL-project Read or explicit Any Read for empty. |
| OwnerConflict | Stored literal owner differs; no inventory returned. |
| Authorization(InvalidPolicy/Grants(...)) | Current whole grant policy is invalid or unavailable. |
| Inventory(...) | ID, SQL snapshot, complete JSON cap, stored corruption or SQL failure from the data reader. |
| Nested Control(Deadline/Closed/OutcomeUncertain) | Original time/store/COMMIT confirmation failure; classification is preserved. |

One bounded end time is passed to raw Auth, inventory SQL and grants SQL.
The SQL inventory call is direct; no outer timeout masks COMMIT confirmation.
Expiry/deadline are checked after SQL, before foreign-owner conflict or None,
and again immediately before successful output after ACL waits. No automatic
retry, repair, invented global project or authentication/ACL freeze is added.

Auth, inventory and ACL are separate current observations. A later call sees
committed changes; this result is not a lease against concurrent revocation or
an ongoing shared SQL snapshot. The operation does not mutate inventory, owner,
users or grants. Existing verifier token usage telemetry remains best effort
under the original deadline and can precede a later denial. Failure/cancellation
uses the producers' existing guards to discard incomplete connections.

Use [authenticated registration](rust-instance-registration.md) for publishing
and uncertain-write recovery. The own GET HTTP adapter and list/live/Now
remain separate work; this business API does not qualify those transports.

## Qualification

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test instance_inventory_read postgres_local_instance_inventory_read_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
~~~

Linux qualification passed: Control all-targets (22.388 s), 27 rustdocs
(0.288 s), fmt (0.871 s) and strict Clippy (20.589 s). The native contract
passed once (209.871 s), with no failed attempt in this leaf. The affected
broker-presence suite passed: three fast tests (4.617 s) and one rustdoc
(0.346 s). The bounded Tracker review found no fault; the new page and three
linked contract surfaces match the implementation in both directions, all
28 local links resolve, and the five existing-file deltas are restricted to
exports and navigation. No manifest or lockfile changed.

The native fixture uses real pinned PostgreSQL TLS,
an ordinary NOSUPERUSER role, real raw Access/Service verification and current
SQL users/tokens/grants. It covers ALL/Any/literal ownership, absence, current
identity/attributes/policy changes, all three caps, corruption and permissions,
causal expiry during ACL wait, original deadline, actual abort/pool recovery,
store close/reopen and unchanged inventory. Fast/rustdoc checks cover finite
nested errors, private construction/traits and borrowed lifetime.

Windows/macOS, MySQL, readonly COMMIT-loss injection, GET/list/live/Now and full
Broker migration are not qualified by this leaf.

Sources: crates/broker-control/src/instance_inventory_read.rs,
service/instance_inventory_read.rs and tests/instance_inventory_read.rs.

Use the [own-inventory HTTP reader](rust-instance-inventory-read-http.md)
for GET reconciliation and explicit PUT+GET router composition.

Use the separately selected [Native own-inventory reader](rust-broker-instance-inventory-read.md)
for a signed Broker JWT and literal Native owner. Its fresh whole policy precedes
missing/foreign decisions and absence returns finite NotFound.
