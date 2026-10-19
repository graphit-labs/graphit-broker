---
references:
  - target: {type: task, id: tsk-5f69, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1137, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-5870, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Broker instance registration

The native server registrar accepts a signed Broker access JWT through the
configured `BrokerAccessVerifier`. It reads current whole SQL grants before
calling the existing atomic inventory writer. The
[opaque local registrar](rust-instance-registration.md) remains an independently
selected API. A native registrar never probes the opaque token store or remaps
the JWT subject to a local user.

## API and authority

`PostgresControlStore::broker_instance_registrar(&verifier, grants_json_bytes)`
returns a borrowed `PostgresBrokerInstanceRegistrar`. Its
`register(raw, required_scopes, &InstanceInventory, original)` takes an absolute
caller `Instant` and returns `RegistrationResult` or
`BrokerInstanceRegistrationError`. The verifier and store must outlive it;
there is no default, clone, caller-supplied principal or owner parameter.
Grant capacity is an explicit positive byte limit. Required OAuth scopes bind
the token purpose; they do not grant inventory permissions.

Every nonempty inventory requires current `presence:publish` permission for
**all** its canonical project IDs. Each matching rule must independently match
principal, capability and project. Empty inventories require an explicit Any
Publish rule, whose project selector is empty or contains `*`; a finite project
list does not permit clearing or creating an empty inventory. `presence:read`,
roles, Hub, S3 and project module capabilities do not imply Publish.

Native policy uses verified signed identity attributes. Missing optional user,
organization or team attributes do not invent a local identity. The owner is
the literal signed `(issuer, subject)` pair, kept as two SQL columns. A local
owner or a different native pair cannot be taken over. All existing validated
inventory ordering, literal version values, atomic replacement and immutable
first-owner semantics are supplied by the
[SQL inventory writer](rust-broker-instances.md).

## Operation boundary and errors

The operation deadline is bounded by the original caller deadline and the
store budget. Processing verifies JWT signature, issuer, audience, optional
resource, access type, scope and expiry; reads fresh complete SQL grants;
compiles the whole policy; evaluates ALL or Any; then checks JWT expiry and
the deadline again **before either denying or entering the writer**. Invalid
unmatched policy rules and oversized/malformed grant snapshots fail closed.
No inventory write occurs after a prewrite rejection.

The signed JWT identity window lasts until its actual expiry. Disabling a
local SQL user, revoking a stored token or removing a dynamic client does not
rewrite that signed identity. Current ACL changes are observed on the next
operation. Entry checks do not freeze authorization throughout the writer or
promise to undo a committed write after token expiry.

`BrokerInstanceRegistrationError` retains two finite failure origins:
`Authorization(BrokerPresenceAuthorizationError)` and
`Registry(InstanceRegistryError)`. Authentication failures, forbidden policy,
grant failures, deadline, storage and closed-store conditions retain their
qualified native error classifications. Read COMMIT uncertainty and writer
COMMIT uncertainty remain distinguishable by origin. Debug output for the
registrar is redacted; Display errors contain static messages.

The unchanged writer owns transaction cancellation and COMMIT uncertainty.
There is no outer timeout around the write or automatic replay after
`OutcomeUncertain`. Dropping/aborting the registration future cancels the real
operation; the caller must reconcile an uncertain outcome using an authorized
read before deciding whether to retry. Created and changed inventories retain
the first creation timestamp; identical replacement preserves both timestamps.
Empty replacement retains the parent and owner.

This leaf supplies the native business registration API. Native authorized
own reads and HTTP PUT/GET are subsequent deliveries; it does not supply a
native list endpoint, WS runtime, STS route or complete Broker migration.

## Verification

Run these repository-relative commands through Cargo:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test broker_instance_registration -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test postgres postgres_local_instance_registration_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The focused native test uses actual Ed25519 signatures and the pinned
PostgreSQL TLS fixture with an ordinary NOSUPERUSER application role. SQL
oracles compare the entire inventory before and after rejected operations.
It checks ALL, empty Any, same-rule matching, signed attributes, literal
ownership, created/updated/no-op replacement, fresh committed ACLs, the native
JWT window, invalid purpose/input, policy and grant limits. Causally observed
ACL locks prove expiry is rechecked for both allowed and denied requests,
original deadline/cancellation has no prewrite effect, and the pool recovers.
Closed/reopen behavior preserves the inventory. Unit tests retain both COMMIT
uncertainty origins; this leaf does not claim an injected network ACK-loss test.
The affected opaque native test qualifies the shared private Any predicate.

Artifacts are retained in
`.build/rust-broker-native-registration-2026-10-11/`.
Linux qualification passed: 106 ordinary Control tests, 95
rustdocs, the focused Native registrar test (105.08 s test runtime), the
affected opaque registrar test (34.77 s wall), 17 Presence ordinary tests
and 4 Presence rustdocs. Strict Clippy and workspace fmt passed. The
bounded Tracker review found no fault; nine protected sources/manifests match
their prior SHA256 and four existing files have exact minimal reversible
hunks. Seven affected document links resolve. The first compile attempt
found two missing String conversions in the test builder; the corrected final
suites passed. Linux evidence does not qualify Windows/macOS or full product
integration.

Sources: `crates/broker-control/src/service/broker_instance_registration.rs`,
`src/broker_instance_registration.rs`, the private ResourcePolicy Any helper,
and `tests/broker_instance_registration.rs`. Writer and verifier are reused
without changing their contracts.

Use the [Native inventory HTTP router](rust-broker-instance-inventory-http.md)
for explicitly configured PUT and own GET with finite statuses and no-store responses.
