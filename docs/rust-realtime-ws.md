---
title: Rust realtime WebSocket server
doc_type: reference
references:
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-44aa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e381, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-13a3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-dbe6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-795b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-cab0, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Rust realtime WebSocket server

The explicit [SQLite Native inventory and realtime composition](rust-sqlite-presence.md) supplies the same WSv1 wire and owned runtime using real JWT, current whole ACL, registered channels and existing private proofs. The explicit [SQLite LOCAL composition](rust-sqlite-local-presence-now.md) also supplies current opaque authentication through `sqlite_local_realtime_router(Arc<SqliteControlStore>, local_config, &runtime)`. It shares the existing configs and WSv1 wire; PostgreSQL factories retain their signatures. Current-identity expiry or authorization loss sends the controlled error frame and Close 1008 under the existing cleanup deadline; no new token lifetime is inferred. The existing `closed` control code uses Close 1000, including closed SQL storage; `authorization_unavailable` uses 1011. Final standalone server SQLite configuration/dispatch remain separate.

For Broker integrators and WSv1 clients. `broker-presence` serves authenticated
Now publications and full project views at `GET /v1/realtime`. The application
supplies the shared PostgreSQL control store, listener and transport TLS. Select
Native JWT or current opaque access/service authentication explicitly. The
[registry HTTP router](rust-broker-instance-inventory-http.md) registers contexts;
this WebSocket does not create or erase SQL registrations.

## Configure and own the server

In a Tokio runtime with time enabled, create and retain
`RealtimeServerRuntime::new(heartbeat_timeout, broadcast_capacity)`. Both arguments
are explicit: a positive representable `Duration` and `NonZeroUsize` in the
[Hub's supported range](rust-realtime-hub.md). This owner starts Hub maintenance
and a supervisor whose `JoinSet` owns socket connection tasks. Construction has
no inferred quota, timeout, token lifetime or resource reserve.

`RealtimeHttpConfig` supplies `required_scopes`, positive `grants_json_bytes`,
`inventory_json_bytes`, `command_bytes`, `outbound_bytes` and a positive
representable `operation_timeout`. `LocalRealtimeHttpConfig` additionally supplies
`audience`, `identity_json_bytes` and this common `realtime` config. Caps use
`NonZeroUsize`; command/output caps must fit `isize`. Blank scopes, invalid
producer configuration and unavailable runtime construction fail. These configs
have no `Default`; their Debug representations are redacted.

```rust
# async fn example(store: std::sync::Arc<broker_control::PostgresControlStore>,
# verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>) -> Result<(), broker_presence::RealtimeServerError> {
use broker_presence::{RealtimeHttpConfig, RealtimeServerRuntime, broker_realtime_router};
use std::{num::NonZeroUsize, time::Duration};
let cap = NonZeroUsize::new(65536).unwrap();
let runtime = RealtimeServerRuntime::new(Duration::from_secs(30), NonZeroUsize::new(32).unwrap())?;
let routes = broker_realtime_router(store, verifier, RealtimeHttpConfig {
    required_scopes: vec!["presence-sdk".into()],
    grants_json_bytes: cap, inventory_json_bytes: cap,
    command_bytes: cap, outbound_bytes: cap, operation_timeout: Duration::from_secs(4),
}, &runtime)?;
// Supply routes to the application's listener while retaining runtime.
drop(routes);
runtime.shutdown().await?;
# Ok(()) }
```

The Native factory accepts the configured `BrokerAccessVerifier`; it owns issuer,
audience, optional resource and trusted JWKs. The separate
`local_realtime_router(store, local_config, &runtime)` selects current SQL opaque
authentication. There is no token-format probing, fallback or query-token input.
Both factories return `Result<axum::Router, RealtimeServerError>`. Routers retain a
weak runtime handle. A late upgrade callback after closure drops its socket and
credential rather than spawning work.

`runtime.shutdown().await` closes admission, cancels and joins connection tasks,
then closes and joins Hub maintenance. Cancellation during shutdown retains the
supervisor handle for abort; dropping the owner closes admission and aborts the
supervisor and maintenance guards. Tokio's `JoinSet` drop aborts its socket tasks.
The application separately shuts down and joins its HTTP listener. HTTP graceful
shutdown alone does not own these upgraded sockets. Hyper/Axum's internal
pre-upgrade futures remain SDK-owned; this runtime owns actual socket connections.

## Authenticate and send the first command

Supply exactly one `Authorization: Bearer …` header. Authentication runs before
101 under one operation deadline, with real Native crypto or current opaque SQL.
Native invalid/expired and opaque authentication failures return 401 with a
Bearer challenge. Native insufficient scope returns 403 with
`Bearer error="insufficient_scope"`; opaque insufficient scope follows its 401
producer contract. Storage/configuration failures return 503 and deadlines 504.
No live publication exists merely because the connection upgraded.

Send the first Text command immediately after upgrade. Do not wait for welcome:
welcome is sent only after the command has passed actual project/channel
admission. A publisher sends a complete snapshot and exact immutable context:

```json
{"op":"publish","instance_id":"station","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","version":"main","snapshot":{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","generated_at":"1000000","sections":{"tasks":{"availability":"available","total":0,"items":[],"has_more":false,"error":null},"sessions":{"availability":"available","total":0,"items":[],"has_more":false,"error":null},"memories":{"availability":"available","total":0,"items":[],"has_more":false,"error":null},"knowledge":{"availability":"available","total":0,"items":[],"has_more":false,"error":null}}}}
```

A subscriber sends a canonical project and optional independent exact filters:

```json
{"op":"subscribe","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","instance_id":"station"}
```

`instance_id` and `version` may each be omitted independently. Explicit null,
empty or malformed values fail; omit an absent optional field in client JSON.
Filters compare literal values, including case and branch characters; they are
not wildcards. The first role and context remain fixed for the connection.
Unknown/duplicate fields, root arrays, invalid strict nested
[snapshot DATA](rust-now-snapshot-data.md), Binary and role/context changes fail.
Axum's mature frame/message decoder enforces the command cap, and Serde decodes
object-only commands with its strict map/enum machinery.

Successful admission sends only:

```json
{"type":"welcome","heartbeat_timeout_ns":"30000000000"}
```

The decimal nanosecond string comes from this runtime's actual explicit heartbeat
setting. A subscriber then receives a full view. A publisher receives no
additional publication ACK after later updates; every later update still has the
whole `publish` shape, including all context fields and full snapshot.

## Permissions, freshness and full views

Publish requires fresh Presence Publish and the literal registered issuer/subject
owner for the exact instance/project/version. Reader identity does not replace
the publisher owner. Publication stores DATA already restricted by the publisher's
current PROJECT read mask. Subscription requires fresh project Presence Read,
including when no channel is online. Each selected online candidate also needs
fresh channel Read and a current matching registered publisher owner.

Every command/event operation obtains current Auth/ACL/registry observations via
[channel authorization](rust-now-channel-authorization.md) outside the Hub mutex.
Native signed identity stays within its local JWT window; opaque authentication
reads current token/user state. Neither format promises quiet immediate ACL
revocation notification. Missing/withdrawn registration, forbidden/corrupt policy
and storage failures remain failures, rather than successful empty snapshots.
An authorized project with no online selected channels legitimately returns:

```json
{"type":"snapshot","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","instances":[]}
```

Nonempty `instances` are sorted by literal `instance_id`, then `version`, and each
contains exactly `instance_id`, `version`, `now`. The `now` value is the strict
DATA shape above, restricted by publisher mask AND fresh project mask AND fresh
channel mask. Task Read controls both Tasks and Sessions; Memory and Knowledge
Read are independent. A denied section is failed/forbidden with empty items and
null total/has_more. All four denied sections remain a valid authorized view.
No owner, credential, sequence, revision or internal path is emitted.

Subscribe, reconnect, subscriber `{"op":"heartbeat"}` and valid project
invalidations send complete replacements, never deltas. One loop writes each
socket. Broadcast lag closes with 1013; reconnect for the current full view.
Input and complete output caps are independent. Output serialization uses a
bounded `std::io::Write` and fails the whole frame without truncating DATA.

## Heartbeats, deadlines and cleanup

A full accepted publication renews only the explicit publication heartbeat.
The existing wire accepts the same valid full snapshot again, with its original
`generated_at`; no increasing timestamp or wire sequence is required. This
renews activity, not the observation time or the authority to publish. There is
no separate publisher heartbeat command: `{"op":"heartbeat"}` belongs only to
subscribers. Ping/Pong is transport activity and never a presence heartbeat.

The consumer contract permits resending only the last genuine snapshot of the
same project/instance/version while one real recomposition is pending. Each
send requires fresh authorization and current masks; retained DATA carries no
authority. Preserve `generated_at` as the time of that observation, then publish
the new observation when composition finishes. Current masks can remove denied
sections but do not recapture changed or deleted corpus content. The consumer
must preserve existing partial-result semantics and stop renewing previous DATA
on terminal composition failure or cancellation, joining the owned work. This
contract adds no TTL, observation-age limit, longer cadence or generic cache.
It is a consumer composition rule; the Broker does not perform recomposition or
start client renewal jobs.

Scheduled Hub maintenance removes activity at its nearest heartbeat/authentication
bound; old publication guards cannot erase or update a replacement.
Dropping/closing a socket removes its live publication, not the SQL registry.
Heartbeat-only expiry reports the existing JSON `closed` notice followed by
Close 1000, allowing an established continuous owner to use its existing recovery
path. Authentication expiry reports `unauthenticated` with Close 1008, including
when both bounds have expired; takeover remains `superseded` with Close 1008.
The first publisher startup remains failfast. Recovery must obtain fresh
admission and publish a new full snapshot; an expired handle cannot revive DATA.

Receiving a publish command does not renew activity. The server first awaits
current authorization, checks the proof and applies its masks, then prunes and
requires the same live publication identity before updating snapshot and heartbeat.
A command delayed in authorization can therefore lose its publication; its late
DATA is rejected with the retained termination cause rather than reopening it.

The connection retains the actual Native/opaque
[UTC and monotonic authentication pair](rust-authentication-expiry.md) sampled by
the producer. Subsequent observations intersect these bounds and cannot extend
this connection's window. First-command reception and admission share a single
Original. Later Text captures Original before JSON decoding; signal operations
capture it when processing that event. Current proof checks run before/after
whole serialization and send; network waits are limited by Original and both
actual authentication bounds. SQL producers keep their own timeout/transaction
outcome responsibilities. There is no outer SQL timeout or automatic replay of
an uncertain effect. Bytes already sent cannot be rolled back.

When the retained connection window is checked, expiry of either authentication
bound takes precedence over an elapsed operation deadline: simultaneous expiry
reports `unauthenticated` with Close 1008. This check does not renew either bound
or reclassify errors returned by SQL or authorization producers.

Terminal messages contain only finite public control data
`{"type":"error","code":"…"}`. Best-effort error/Close cleanup uses the configured
operation budget without extending a protected DATA operation. A peer disconnect
or failed transport can prevent delivery of these notices. If a DATA send is
incomplete or times out, the socket is dropped without another write: error
cleanup must not flush unsent protected DATA from the SDK buffer. Invalid input,
authentication/policy, missing registration, owner conflict and superseded
publication close with 1008; oversize with 1009; storage/deadline/uncertainty with
1011; broadcast lag with 1013; normal closure with 1000. Codes are
`invalid_data`, `too_large`, `unauthenticated`, `forbidden`, `not_registered`,
`owner_conflict`, `deadline`, `authorization_unavailable`, `closed`,
`outcome_uncertain`, `superseded`, `backpressure`. Superseded means a newer
publication replaced that live identity; heartbeat-only expiry is `closed`. Driver causes and raw
credentials are never reflected. Raw bearer ownership is confined to the
connection in `Zeroizing`, without Debug/serde/persistence.

## Verification scope

The unit test `realtime::tests::window_check_prioritizes_authentication_expiry`
checks UTC, monotonic and simultaneous authentication expiry against an expired
operation deadline, as well as an expired operation with valid authentication
and a fully valid window.

`crates/broker-presence/tests/realtime_ws.rs` exercises real TCP WebSockets using
the mature client SDK, PostgreSQL TLS with a NOSUPERUSER serving role, Ed25519
signatures, opaque access/service tokens and Native PUT/GET registration. The
focused command is:

```
cargo test --locked -j1 -p broker-presence --test realtime_ws -- --ignored --exact realtime_ws_postgres_contract --test-threads=1
```

The focused integration tests exercise an opaque pre101 SQL lock against a token that remains valid through upgrade/admission and expires quietly afterwards. Heartbeat, Ping without presence renewal, socket abandonment, Runtime Drop, shutdown and a real slow-peer send under the original deadline are also covered. Library/router tests do not establish other-platform or daemon/CLI/MCP composition.
