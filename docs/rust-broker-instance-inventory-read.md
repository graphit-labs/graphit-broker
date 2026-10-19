---
references:
  - target: {type: task, id: tsk-2372, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1137, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6e9e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-5f69, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Broker own-inventory read

Broker server integrators can reconcile an installation after registration by
reading its entire own inventory with a verified Native access JWT. The API
requires the literal signed owner and current Read for every registered project.
It returns no partial inventory. Use the independently selected
[opaque local API](rust-instance-inventory-read.md) for raw local bearers.

## API and permission

~~~text
store.broker_instance_inventory_reader(
  &verifier, grants_json_bytes, inventory_json_bytes
) -> Result<PostgresBrokerInstanceInventoryReader<'_>, BrokerInstanceInventoryReadError>
reader.read(raw, required_scopes, instance_id, original_deadline)
  -> Result<AuthorizedBrokerInstanceInventory<'_>, BrokerInstanceInventoryReadError>
~~~

The verifier, positive whole-grant and whole-inventory JSON caps, required
OAuth scopes, canonical instance ID and absolute caller `Instant` are explicit.
There is no caller-provided principal, owner, default, authentication fallback
or additional pool. The reader borrows its store and verifier; the returned
private output retains the real verifier borrow. It exposes only `inventory()`,
`created_at_micros()`, `updated_at_micros()` and `policy_revision()`. Neither owner
nor credential is exposed. The output has no public construction, Clone, Default
or Deserialize and redacts Debug.

Signature, configured issuer, audience, optional resource, access type, scope
and expiry come from the [Native verifier and policy](rust-broker-presence-authorization.md).
Scopes and signed roles do not imply `presence:read`. The literal signed
`(issuer, subject)` must equal the two stored owner columns. Matching username
or raw subject under another issuer cannot take over an installation.

Nonempty inventories require current `presence:read` for **all** project IDs.
Each matching rule independently matches principal, capability and project;
different complete rules can cover different projects. An empty parent requires
an explicit matching Any Read rule, with an empty project selector or `*`.
A finite selector does not authorize empty data. One denied project denies the
whole result; partial projection belongs to a separate list operation.

The existing [SQL reader](rust-instance-read.md) validates the complete
one-instance snapshot, literal meaningful versions, canonical project ordering
and nonnegative microsecond stamps. Registration and atomic replacement are
provided by the [Native registrar](rust-broker-instance-registration.md).
Version data does not grant authority.

## Observation boundary and recovery

The operation bounds the caller's original deadline by the store budget once.
It verifies the actual JWT; reads current complete SQL grants and compiles every
rule; reads one validated inventory snapshot; computes absence, owner conflict
or ALL/Any Read; then checks JWT expiry and the deadline again before returning
any logical decision. Invalid unrelated rules fail closed, including for a
missing or foreign installation. Missing data returns finite `NotFound`,
not an Option. Each SQL reader owns its transaction and COMMIT confirmation;
there is no outer timeout or automatic replay.

The signed identity window remains valid until actual JWT expiry. Disabling a
local user, revoking an SQL token or deleting a dynamic client cannot remap that
identity. The next operation still reads current ACLs. Grant and inventory
transactions are separate observations; the result is not a global atomic
snapshot or a reusable authorization lease. Data getters do not renew or
recheck authorization. The reader does not write inventory, identities or ACLs.

| Error | Meaning |
| --- | --- |
| Authorization(Authentication(...)) | Invalid Native signature, claims, purpose or expired signed identity. |
| Authorization(Forbidden) | Own inventory lacks ALL Read or empty Any Read. |
| Authorization(InvalidPolicy/Grants(...)) | Whole current policy is invalid, malformed or exceeds its cap. |
| NotFound | No parent at the inventory observation, after final authentication/time checks. |
| OwnerConflict | Literal stored owner differs; no inventory returned. |
| Inventory(...) | Invalid ID, inventory cap, stored corruption or SQL reader failure. |
| Nested Control(Deadline/Storage/Closed/OutcomeUncertain) | Producer failure preserves its grant-read or inventory-read origin. |

Display messages are finite and static. Cancellation uses the existing SQL
connection guards, and incomplete connections are discarded. `OutcomeUncertain`
is retained even for readonly COMMIT acknowledgement failure. Reconcile an
uncertain write with a new authorized read before deciding whether to retry;
this API does not retry or repair it automatically.

This business API supplies the producer for the subsequent Native HTTP GET
adapter. It does not qualify Native HTTP, list, live WS, STS or the entire
Broker migration.

## Verification

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test broker_instance_inventory_read -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test instance_inventory_read postgres_local_instance_inventory_read_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The focused test uses actual Ed25519 JWTs, the qualified Native registrar and
the pinned PostgreSQL TLS fixture with a NOSUPERUSER application role. Whole
inventory SQL oracles check rejection and cancellation; cases cover ALL/Any,
partial and cross-rule denial, literal owners, current ACL revision and
committed version removal, unchanged Native identity after SQL disable/revoke,
invalid purpose, caps, policy corruption and storage privileges. Causally
observed ACL and inventory locks test expiry before allowed, denied, missing,
foreign and empty verdicts, original deadline, abort and pool recovery.
Closed-store/reopen behavior is checked. Rustdocs verify private construction,
traits and lifetimes. Unit tests preserve both COMMIT uncertainty origins;
network ACK-loss injection and non-Linux platforms are not qualified here.

Qualification artifacts: `.build/rust-broker-native-instance-read-2026-10-11/`.

Linux qualification passed: 99 ordinary Control tests (65 Native tests remain
ignored in the ordinary suite), 99 Control rustdocs, 17 Presence ordinary tests
and 4 Presence rustdocs. The focused Native contract passed in 216.57 s test
runtime; the affected opaque own-read contract passed in 181.36 s test runtime.
Strict all-target/all-feature Clippy and workspace fmt passed. All eight
commands exited zero without a failed compile/test attempt in this leaf. Wall
times and Cargo queue waits are retained in receipts, rather than treated as
isolated CPU costs. The bounded Source/documentation Tracker review found no
fault. Sixteen protected files retain their prior SHA256, three existing-file
deltas reverse exactly to the captured baseline, and all ten local document
links resolve. This evidence does not qualify the pending Native HTTP adapter,
Windows/macOS or full integration.

Sources: `crates/broker-control/src/broker_instance_inventory_read.rs`,
`src/service/broker_instance_inventory_read.rs` and
`tests/broker_instance_inventory_read.rs`.

Use the [Native inventory HTTP router](rust-broker-instance-inventory-http.md)
for explicitly configured PUT and own GET with finite statuses and no-store responses.
