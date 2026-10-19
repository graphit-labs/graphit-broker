---
title: Rust realtime Hub
doc_type: reference
references:
  - target: {type: task, id: tsk-dbe6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b9ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-cab0, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Rust realtime Hub

The `broker-presence` library keeps authorized Now channels online in memory,
notifies project subscribers when that view changes, and derives full authorized
replays. The Hub does not register instances in SQL; the [WebSocket server](rust-realtime-ws.md) composes its proofs and lifecycle.
[Channel authorization](rust-now-channel-authorization.md) supplies actual Native
or opaque proofs. [Snapshot DATA](rust-now-snapshot-data.md) supplies strict typed
input; a snapshot or channel identifier alone cannot admit a publication.

## Configure and own maintenance

Call `RealtimeHub::new(heartbeat_timeout, broadcast_capacity)` with an explicit
positive `Duration` and `NonZeroUsize`. Zero/unrepresentable timing and a capacity
outside Tokio broadcast's representable range return `InvalidConfiguration`.
There is no inferred timeout, payload limit, connection quota or memory reserve.
The decoder and [WebSocket command configuration](rust-realtime-ws.md) own input byte limits.
Live memory scales with published channels and retained replay views.

Construction creates state only. In an active Tokio runtime, call
`hub.run_maintenance()` once and retain the returned `RealtimeHubMaintenance`.
The serving owner must run a runtime with time enabled. Admission, subscription
and replay fail closed before maintenance starts; a second maintenance owner is
rejected. `maintenance.shutdown().await` closes the Hub, wakes publishers and
subscribers, and joins its actual task. Dropping the guard closes state and aborts
the retained task. Cancellation during shutdown also retains the handle for
abort. The task captures state, never its maintenance owner. A closed Hub cannot
restart; construct a new explicitly configured Hub for a new serving lifecycle.

```rust
# async fn example() -> Result<(), broker_presence::RealtimeHubError> {
use broker_presence::RealtimeHub;
use std::{num::NonZeroUsize, time::Duration};
let hub = RealtimeHub::new(Duration::from_secs(30), NonZeroUsize::new(32).unwrap())?;
let maintenance = hub.run_maintenance()?;
maintenance.shutdown().await?;
# Ok(()) }
```

## Publish and remove activity

`open_publisher(proof, snapshot)` consumes an actual `AuthorizedNowPublisher`
and strict `NowSnapshotData`. It checks the proof's operation deadline and
actual authentication expiry, filters DATA with the publisher's current read
mask, and binds the exact project/instance/version to its registered literal
issuer and subject. `handle.publish(fresh_proof, full_snapshot)` consumes a new
proof for each consequential update. A handle is a publication identity, not
permission for later updates. The composer must authenticate and load current
SQL grants and registration again through the actual channel authorizer.

A full accepted publication refreshes the explicit heartbeat deadline. Caller
`generated_at` records the observation and does not set activity time. The Hub
accepts the same valid full DATA with that timestamp unchanged, using a fresh
proof and applying its current read mask. Repetition does not renew authority,
authentication expiry or the age of the observation, and no increasing timestamp
or wire sequence is required. The [consumer recomposition contract](rust-realtime-ws.md#heartbeats-deadlines-and-cleanup)
limits this use to the last genuine snapshot of the same channel while one real
recomposition is pending; it does not authorize indefinite renewal after a
terminal failure or cancellation. The Hub itself does not schedule client work
or recapture corpus contents.

Liveness requires all three bounds:
current UTC before actual authentication UTC expiry, current monotonic time
before actual authentication monotonic expiry, and current monotonic time
before the accepted publication's heartbeat deadline. Clock rollback cannot
extend the monotonic authentication bound. An expired handle cannot revive an
old publication; open a new authorized publication.

Replacement creates a private `Arc` identity. An old publish or drop cannot
modify a replacement, including after remove/reopen; no numeric generation,
wire counter or tombstone is retained. Dropping the current handle removes only
its activity. `check_active()` observes that identity; `wait_inactive().await`
returns the actual `RealtimeHubError` on replacement, expiry, removal or closure
without granting publish rights. A Tokio watch channel retains that publication's
first terminal cause even if no waiter exists when the slot is removed. After
validation of a fresh proof, publish observes the same cause as `check_active()`
and a later waiter; dropping an old handle
or closing the Hub cannot overwrite it. No separate Hub tombstone is added.
Heartbeat-only expiry returns `Closed`; authentication expiry returns
`AuthenticationExpired`, including when heartbeat has also expired. Replacing a
live publication returns `Superseded`. Expired handles cannot publish again:
recovery requires a new authorized publication and genuine full snapshot.
Maintenance waits for the nearest real bound and removes expired activity even
without another API call. SQL registration remains intact.

## Subscribe and replay

`subscribe(&actual_project_proof)` returns only per-project unit invalidations.
`recv().await` reports `Lagged` or `Closed` directly from Tokio broadcast. Signals
are not snapshots or authorization. A consumer must obtain fresh project and
channel proofs for each replay; after lag, reconnect and obtain a full replay.
Dropping the receiver prunes an unused empty project group. No offline journal
or retention timeout is maintained.

Crate-private `candidates(&project_proof)` returns exact channel metadata only,
so the WebSocket composer can authorize each candidate outside the Hub mutex.
`replay(project_proof, channel_proofs)` consumes and privately retains both proof
classes. Wrong projects or duplicate channels return `InvalidContext`. A live
channel's actual registered publisher owner must equal the stored publisher;
otherwise replay returns `OwnerConflict`. Missing/inactive memory entries are
omitted. SQL authorization, missing registry, corrupt data or storage errors
while obtaining proofs remain actual errors, never a fabricated empty replay.
An authorized project with no online channels legitimately has `instances: []`.

The output implements `Serialize`, has metadata observers `project_id()` and
`instances()` (instance ID/version only), and exposes no raw snapshot getter.
`check()` retains the project and every channel proof's Original operation
window. Serialization checks those proofs before encoding and after projection.
The serving composer must check again immediately before its bounded send.
These checks observe the captured operation, not a new SQL read or rollback of
bytes already sent. Concurrent activity can change after a replay observation.

Output has exactly `project_id` and literal-sorted `instances`, each with
`instance_id`, `version` and `now` matching the strict snapshot schema. A future
WebSocket frame adds its `type: snapshot` envelope. No owner, token, revision,
progress, sequence or private path is emitted.

Each section is allowed only by **project proof mask AND channel proof mask AND
already publisher-filtered DATA**. Tasks and Sessions use the same Task read
permission; Memory and Knowledge are independent. Denial is exactly:

```json
{"availability":"failed","items":[],"total":null,"has_more":null,"error":"forbidden"}
```

Typed borrowed Serde views preserve allowed DATA without adding `Clone` to the
snapshot or encoding/decoding it to filter. Broader channel rights cannot widen
a narrower project view, and broader readers cannot restore publisher-denied
DATA. `registered_owner()` identifies the publisher, not the reader. The Hub
makes no same-reader identity claim; the WebSocket composer must obtain the
proofs from the same bearer/factory request. Neither mask DATA nor serde input
can construct the private authorization, publication, subscription or replay.

## Errors and verification

`RealtimeHubError` preserves actual `NowChannelAuthorizationError` inside
`Authorization`, including Native, opaque, inventory, deadline and uncertain
outcome origins. The other finite errors are `InvalidConfiguration`,
`InvalidContext`, `OwnerConflict`, `AuthenticationExpired`, `Superseded`, `Closed`
and `Unavailable`.
Display strings and Debug output do not reflect policy, identity or driver data;
errors expose no source chain. No SQL/network/encoding/await or consumer callback
runs while the state mutex is held.

Implementation: `crates/broker-presence/src/realtime_hub.rs`. The real contract
suite is `crates/broker-presence/tests/realtime_hub.rs`, including the existing
PostgreSQL TLS support read-only. Run the project hook for fast formatting and
strict affected checks; qualify this delivery with:

```text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo clippy --locked -j1 -p broker-control -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo test --locked -j1 -p broker-presence --test realtime_hub -- --ignored --exact realtime_hub_postgres_contract --test-threads=1
```

The focused suite uses real PostgreSQL TLS with a NOSUPERUSER owner, Ed25519
JWTs, opaque token digests, actual registrars and actual owned Tokio timers.
Compilation/unit/rustdoc checks cover representability, clock arithmetic,
maintenance lifetime and non-forgeable API boundaries. Task records retain
executed receipts and failures. Library verification does not establish TCP
WebSocket behavior, Root corpus integration, non-Linux execution or completion
of the Rust Broker migration.

The [Rust realtime WebSocket server](rust-realtime-ws.md) composes these contracts with explicit runtime ownership, fresh authorization and full project views.
