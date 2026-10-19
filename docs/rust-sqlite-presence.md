---
title: SQLite Native Presence integration
doc_type: reference
status: qualified-locally-linux
updated: 2026-10-17
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-44aa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e69e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-173d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite Native Presence integration

For Broker integrators composing Native JWT inventory HTTP and Now WebSocket
routers over `SqliteControlStore`. The integration consumes the existing
[SQLite owner](rust-sqlite-control.md), [whole ACL reader](rust-sqlite-identity-acl.md),
[inventory writer](rust-sqlite-instances.md) and
[bounded inventory reader](rust-sqlite-instance-read.md). Inventory and channel
DTOs convey data; actual JWT verification and current policy produce authority.
The standalone server's final configuration and dispatch remain separate under
tsk-8069. These routers do not establish a complete SQLite server backend.

## Construct the actual consumers

All three views borrow the actual store and trusted `BrokerAccessVerifier`:

| Factory on `SqliteControlStore` | View and operations |
| --- | --- |
| `broker_instance_registrar(verifier, grants_json_bytes)` | `SqliteBrokerInstanceRegistrar::register` |
| `broker_instance_inventory_reader(verifier, grants_json_bytes, inventory_json_bytes)` | `SqliteBrokerInstanceInventoryReader::read` |
| `broker_now_channel_authorizer(verifier, grants_json_bytes, inventory_json_bytes)` | `SqliteNowChannelAuthorizer::{authorize_publish, authorize_read, authorize_subscriber_project}` |

The verifier's configuration owner supplies issuer, audiences/resource, trusted
keys and token cap. Authentication uses the signed JWT within its existing expiry
window. SQL profile/client/token metadata does not replace that signed identity.
Each operation reads and compiles the complete fresh policy, including unrelated
rules. One rule must match principal, capability and project; a policy revision
is an observation, never a future permission lease.

Registration derives the literal issuer/subject owner and requires Presence
Publish for every submitted project. An empty inventory requires an explicit
matching Any Publish rule. After the final JWT/deadline check, the real atomic
writer decides Created, Updated or Unchanged. Its COMMIT/ACK result is preserved;
a late consumer gate cannot reclassify a known commit or replay an uncertain one.

Own reads require the exact literal owner and Presence Read for every registered
project, or Any Read for an existing empty inventory. The complete coherent
snapshot is authorized together. Missing and empty remain distinct. JWT/deadline
checks precede every logical result, including absence, conflict and denial.
No partially authorized inventory is returned.

The shared `SqliteResourceGrants::read` and `SqliteInstanceInventories::read`
observations execute SELECTs only in a coherent DEFERRED transaction, allowing
another WAL owner to commit without waiting for that snapshot. They release it by
checked rollback, retaining the Original and physical file/schema checks without
entering the executor's write-COMMIT phase. A missing read acknowledgement can
therefore report Deadline or Closed, never write `OutcomeUncertain`. A failed
rollback still fails closed and an owner left in a transaction is quarantined.
This does not change registration writes or their uncertain COMMIT/ACK outcome.

## Now proof and transport boundaries

The [Now authorizer contract](rust-now-channel-authorization.md) is unchanged.
A channel operation reloads the complete inventory and checks its exact project
and version. Publisher admission additionally requires the literal owner.
Channel Read requires a matching registration; project subscriber admission can
produce an empty online view without fabricating a registry entry. The
ALL-project Publish rule belongs to registration; Now authorizes the exact channel.

The existing private `AuthorizedNowPublisher`, `AuthorizedNowSubscriber` and
`AuthorizedNowProjectSubscriber` hold genuine verified identity and policy/storage
observations. Their current masks preserve Task including Sessions, and independent
Memory and Knowledge access. The unchanged `RealtimeHub` consumes these proofs.
There is no new public proof constructor or callback authority.

Select the Native SQLite factories explicitly:

```text
sqlite_broker_instance_inventory_router(
    Arc<SqliteControlStore>, Arc<BrokerAccessVerifier>,
    BrokerPublishHttpConfig, BrokerOwnReadHttpConfig
)
sqlite_broker_realtime_router(
    Arc<SqliteControlStore>, Arc<BrokerAccessVerifier>,
    RealtimeHttpConfig, &RealtimeServerRuntime
)
```

The first serves PUT and own GET `/v1/instances/{id}/inventory`; the second
serves GET upgrades at `/v1/realtime`. PostgreSQL factory signatures and opaque
LOCAL PostgreSQL remain intact. A private closed backend choice belongs only to
the Native branch; there is no token/backend detection, optional store or fallback.

The existing [Native inventory HTTP wire](rust-broker-instance-inventory-http.md) and
[WSv1 contract](rust-realtime-ws.md) remain authoritative for strict objects,
Bearer admission, caps, full snapshots, filters and finite failures. HTTP errors
retain their nested `error.code` envelope and no-store behavior. Existing WS
`closed` uses Close 1000; `authorization_unavailable` uses 1011. The SQLite
integration preserves those current policies. Supply nonblank scopes, positive
byte caps and explicit representable operation/heartbeat budgets; no defaults,
new quotas or version limits are introduced.

## Renewal, timing and cleanup

Only an accepted complete publication renews its live heartbeat. Publisher
`heartbeat` is not a protocol operation. Ping/Pong never renews DATA. Subscriber
heartbeat and invalidation obtain fresh project/channel proofs and full replay.
Publisher and subscriber masks intersect. The actual connection's UTC/monotonic
authentication bounds cannot be extended by these observations.

One original end, bounded by the existing operation budget, flows through ACL,
inventory and write work. The two SELECT-only DATA readers use DEFERRED snapshots;
operations that may mutate state retain IMMEDIATE and may wait for a writer.
There is no outer SQL timeout, budget renewal, authorization cache or automatic retry that
hides COMMIT uncertainty. Native cancellation, acknowledgement and SQL-owner
retention use the already qualified producer.

Retain `RealtimeServerRuntime` while serving its routers. Its shutdown closes
admission and joins connection tasks and Hub maintenance. The application owns
HTTP listener shutdown/join separately, then the real SQL owner. Closing a socket
removes live Hub state and preserves durable SQL registration.

## Qualification and limits

The new ordinary `sqlite_presence_http_ws` target uses private physical SQLite,
real Ed25519 JWTs, owned Axum/Hyper HTTP and the actual WebSocket client SDK.
Five distinct journeys are qualified across a four-case pass and the remaining
exact-case retry. They cover full-policy HTTP registration/renewal/own reads,
owner/Any/partial denial, full and intersected masks, exact channels, committed
ACL/registration withdrawal, positive publication renewal beyond its initial
heartbeat, Ping/Pong expiry, original/SQL deadline and closed-store errors,
active owned runtime shutdown, durable registry preservation and reopening.

```text
cargo test --locked --offline -p broker-presence --test sqlite_presence_http_ws -- --test-threads=1
cargo test --locked --offline -p broker-control --lib sqlite::executor::tests:: -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib -- -D warnings
cargo clippy --locked --offline -p broker-presence --lib --test sqlite_presence_http_ws -- -D warnings
cargo test --locked --offline -p broker-control --doc SqliteBrokerInstanceRegistrar
cargo test --locked --offline -p broker-control --doc SqliteBrokerInstanceInventoryReader
cargo test --locked --offline -p broker-control --doc SqliteNowChannelAuthorizer
cargo fmt --package broker-control --package broker-presence -- --check
```

Executor regressions separately cover read acknowledgement withheld past the
deadline or shutdown, cancellation followed by owner reuse, and a DEFERRED
snapshot that remains coherent while a second WAL owner commits. The write
missing-ACK case must still report `OutcomeUncertain`. The Native finite-outcome
journey verifies a successful own GET during an external pending writer, then
HTTP 504 and WS `deadline`/1011 after Welcome when a real write occupies the shared
SQL owner. Heartbeat-only expiry remains `closed`; takeover remains `superseded`.

Existing PG/opaque/SDK and unchanged physical reader/writer/driver evidence is
reused. These consumer tests add no native SQL-start witness, staged-write fault
or missing-ACK experiment. Linux fixture execution qualifies this composition;
it does not prove final binary dispatch, native Windows/macOS behavior or the
complete SQLite migration.

The distinct [SQLite LOCAL inventory and Now consumers](rust-sqlite-local-presence-now.md) serve configured opaque human/service possession, own inventory and partial authorized LIST with current LOCAL policy. Native JWT owners and LOCAL owners remain distinct; neither library mode alone activates the executable SQLite backend.
