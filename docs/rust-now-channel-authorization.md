---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b9ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5e58, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-1137, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-5401, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Rust Now channel authorization

For Broker server integrators. `PostgresNowChannelAuthorizer` produces actual
Native or opaque Auth/ACL observations for a registered channel. It uses the
existing verifiers, whole current SQL policy and one-ID inventory reader. This
library does not implement a Hub, HTTP/WS transport, Runtime subscription or
online lease. Those consumers must authenticate and load current policy and
registry again before consequential operations and heartbeats.

## Configure one explicit mode

`store.broker_now_channel_authorizer(&BrokerAccessVerifier, grants_json_bytes,
inventory_json_bytes)` borrows the actual Native verifier and store.
`store.local_now_channel_authorizer(audience, identity_json_bytes,
grants_json_bytes, inventory_json_bytes)` uses the qualified current opaque SQL
verifier. All byte caps are `NonZeroUsize`, with the SQL producers' checked
configuration bounds. Audience and trusted Native verifier come from the owner;
there is no token mode probe, fallback, default audience or synthesized grant.

```rust
use broker_control::{BrokerAccessVerifier, NowChannelAuthorizationError,
    PostgresControlStore, PostgresNowChannelAuthorizer};
use std::num::NonZeroUsize;

fn configured<'a>(store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier, grants: NonZeroUsize,
    inventory: NonZeroUsize,
) -> Result<PostgresNowChannelAuthorizer<'a>, NowChannelAuthorizationError> {
    store.broker_now_channel_authorizer(verifier, grants, inventory)
}
```

`PresenceChannel::new(instance_id, project_id, version)` applies the same
canonical installation/project/version validators as the durable registry.
Channel DATA exposes those three literal values and can be cloned. It carries
no authentication or permission.

`authorize_publish(raw, required_scopes, &channel, original)` returns
`AuthorizedNowPublisher`; `authorize_read` has the same inputs and returns
`AuthorizedNowSubscriber`. `authorize_subscriber_project(raw, required_scopes,
project_id, original)` returns `AuthorizedNowProjectSubscriber` even when the
project's online view is empty, without inventing a registry entry. Each result
retains the actual private verified principal. Native results borrow the actual
verifier through their lifetime. Authorized results have no public construction,
Clone, Default, Serialize or Deserialize, and Debug omits their contents.

## Admission and current policy

The authorizer bounds the supplied original deadline once. It authenticates,
reads all current SQL grants and compiles the whole policy, including unmatched
rules. An invalid rule fails the entire observation. Presence permission matches
principal, capability and project within the same rule. Separate partial rules
are never combined to authorize an operation.

A denied Presence permission receives a final authentication/time check before
Forbidden and never queries the registry. An allowed channel reads its actual
one-ID SQL registry observation. Publisher requires `presence:publish`, exact
literal stored issuer/raw subject ownership and registered project/version.
Foreign ownership takes precedence over a missing version. Subscriber requires
`presence:read` and exact registered project/version; it may read a channel
owned by someone else. Missing registration/project/version is NotRegistered.
Authentication and original deadline are checked again before these negative
results or success. Neither grants nor inventory reads receive a new outer
SQL timeout/replay; each qualified producer retains its error classification.
The three SELECT-only PostgreSQL metadata readers return storage errors or Deadline if COMMIT cannot
be confirmed; no channel proof is released and no persistent application effect
is involved.

Grants and registry are separate observations, not one globally atomic read or
a freeze against concurrent withdrawal/revocation. The Native verifier retains
its signed until-exp window: disabling a SQL identity, revoking the stored OIDC
token or deleting its client does not remap that verified JWT. ACL still comes
from fresh SQL. Opaque authentication checks current token/identity state on
every new authorize call. A prior result does not create instant revocation
notification or authority for future operations.

## Mask owned DATA

Every result exposes `project_id()`, `read_mask()`, `policy_revision()`,
`authentication_expiry()`, `check()` and
`filter_snapshot(snapshot: broker_now_wire::NowSnapshotData)`. Channel results
also expose `channel()` and `registered_owner()`. Stored owner and revision are
observation DATA, not an authentication factory. Project results have no fake
channel/owner. Read-mask fields are private; its boolean getters are
`task_read()`, `memory_read()` and `knowledge_read()`.

The mask derives from `task:read`, `memory:read`, `knowledge:read` in the same
whole policy. Task Read controls both tasks and sessions. Presence, Write and
Hub permissions do not imply module Read. Filter checks the actual proof and
project before and after calling the [pure consuming DATA operation](rust-broker-now-wire.md#consume-data-to-remove-selected-sections).
The snapshot only carries project; its instance/version are established by the
channel/registry, not fabricated as DATA fields.

The returned owned snapshot contains no denied rows: denied sections are
exactly failed/forbidden, empty items, null total and null has_more. Permitted
sections retain literals, ordering, counts, failures and allocations. All four
denied sections remain valid DATA for an otherwise authorized identity/channel.
No JSON roundtrip, alternative decoder or new byte cap is introduced. The
transport owns input/output byte budgets and must store the masked snapshot,
rather than the original incoming rows. DATA never attests corpus scans, EOF,
admission or active installed version.

## Authentication bounds and errors

`authentication_expiry()` returns `(SystemTime, Instant)`: actual UTC expiration
and its captured monotonic bound. Native and opaque copy both values stored by
their real verifier. The opaque producer captures its pair after read-only SQL with
monotonic time immediately before its final UTC observation. The channel
composer checks the proof and copies that pair; it never reconstructs a bound
from later verified_at metadata or another UTC observation. Final checks do not
renew that bound. Consumers use these authentication bounds for online expiry, not the
original operation deadline as heartbeat TTL.

`check()` checks captured UTC/mono and the original operation deadline. It does
not reload SQL ACL or identity. `filter_snapshot` also cannot renew those
observations. Subsequent consequential effects require a new authorize call.
The Hub/WS consumer must carry the actual proof rather than rebuilding authority
from the channel tuple, owner, mask booleans or snapshot.

`NowChannelAuthorizationError` has finite Native and Local Presence wrappers,
Inventory errors, InvalidChannel, InvalidProject, NotRegistered, OwnerConflict
and SnapshotProjectMismatch. Display/Debug errors contain finite codes, without
input, raw token, database message or parser cause; `Error::source` is None.
Native/Local wrappers preserve authentication, policy, grants and control
failures; Inventory preserves its separate storage origin. Deadline, Closed,
Storage and OutcomeUncertain remain distinct when their producers emit them.
The three SELECT-only PostgreSQL readers do not emit OutcomeUncertain. This
authorizer does not replay a failed observation. Fix invalid input/policy at its
producer, refresh current registration for a missing version, reauthenticate an expired credential, and
recover the actual store for Closed/Storage. HTTP/WS mappings are owned by their
transport delivery.

## Checks

From the Broker checkout, using the owner's normal Cargo resource queue:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo test --locked -j1 -p broker-control --test now_channel -- --ignored --exact postgres_now_channel_authorization_contract --test-threads=1
~~~

The focused ignored test uses real PostgreSQL TLS, NOSUPERUSER admission,
Ed25519 signatures, actual Native/opaque registrars and the qualified opaque
access/service-token SQL model. It exercises masks, exact owner/version,
current ACL, cross-rule denial, whole invalid policy, scope/format failures,
withdrawal, storage caps/privileges/corruption, causally observed SQL waits for
expiry/Original, abort/recovery and registry read oracles. A unit test captures
expiry from an actual verifier-produced Native principal and checks rollback
boundaries without changing the OS clock. Artifacts belong to
`.build/rust-now-channel-authorization-2026-10-11/`. Actual command outcomes are
recorded there; library tests cannot qualify Hub/WS/Runtime, another platform,
remote CI, lost COMMIT acknowledgments or the migration as a whole.


Linux qualification passed: 101 Control ordinary tests (66 native tests remain
ignored in that ordinary invocation), 117 Control rustdocs, 19 Presence
ordinary tests (9 ignored), 5 Presence rustdocs, strict all-target/all-feature
Clippy and formatting. The isolated real Native+opaque PostgreSQL TLS channel
test passed in 204.01 s (204.49 s command wall time). This separately executes
the new ignored scenario; ignored results from ordinary suites are not counted
as integration passes.

The first test compilation failure from temporary SQL strings, interrupted
owned chains during the clock/test review, and their logs are retained in
qualification.json and the interruption records. That qualification used the
same verified_at confirmed by opaque finish; the temporal observer delivery now
copies the verifier's stored pair instead. Static SQL privilege commands
replace runtime SQL strings. Final Tracker found no remaining static fault.
The scope audit proves four new files plus the ceded minimal hunks: exact
Native-helper/service/Cargo reversal, minimal lib exports and normal lock
resolution adding only the Control→wire edge. All other package pins/blocks,
17 protected hashes and 9 affected local links remain intact. No wide migration
suite, other platform, lost COMMIT acknowledgment or Runtime/WS journey is
inferred from this library result.

The [Rust realtime Hub](rust-realtime-hub.md) consumes actual channel proofs and strict snapshot DATA for ephemeral publication, project invalidations and authorized replay.

Authentication windows copy the [actual verifier expiry pair](rust-authentication-expiry.md). Opaque finish metadata does not reanchor or renew the stored monotonic expiry.

The [Rust realtime WebSocket server](rust-realtime-ws.md) composes these contracts with explicit runtime ownership, fresh authorization and full project views.
