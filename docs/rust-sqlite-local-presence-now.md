---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---

# SQLite LOCAL inventory and Now

Audience: Broker integrators maintaining inventory and live project views with
`presence.authentication.type=local_opaque`. This page describes the Rust SQLite
business APIs and explicit Axum factories. Server configuration, discovery and
global activation are a separate integration boundary.

The received opaque credential is verified by the current LOCAL verifier. This
consumer does not issue credentials, translate LOCAL owners into Native owners,
or create authorization from registration ownership. See the
[LOCAL verifier](rust-local-bearer-verifier.md),
[project authorization](rust-presence-authorization.md) and
[SQLite identity boundary](rust-sqlite-local-auth.md).

## Register, retrieve and list

Start with an open `Arc<SqliteControlStore>` whose current LOCAL identities,
tokens and resource ACL were created through their owning APIs. Supply the
explicit audience, required scopes, byte caps and operation timeout using
`InstanceRegistryHttpConfig`, `InstanceInventoryReadHttpConfig` and
`InstanceInventoryListHttpConfig`. Compose:

```rust,ignore
let inventory = sqlite_instance_inventory_router(
    store.clone(), registration_config, read_config, list_config,
)?;
```

The exports are in `broker_presence`. Separate composition may use
`sqlite_instance_registry_router` or `sqlite_instance_inventory_read_router`.
There is no backend probing or fallback to another implementation.

1. An authorized publisher sends `PUT /v1/instances/station/inventory` with a
   Bearer header and an inventory. The path supplies the instance ID; the body
   contains only `projects`, each with `project_id` and `versions`.
2. The verifier checks current token possession, user state, revision, audience,
   scopes and expiration. Every declared project must grant `presence:publish`.
   An empty inventory requires that capability on any authorized project.
3. The writer derives the literal LOCAL owner from that identity. Creation
   returns 201; an update or unchanged repeat returns 200. Responses contain
   `instance_id`, `change`, `created_at` and `updated_at`. The owner cannot be
   replaced by another credential, even one with project publish access.
4. The owner retrieves the complete inventory with GET or HEAD on the same path.
   `presence:read` is required on all declared projects, or any project for an
   empty inventory. Missing inventory returns 404; a different owner gets 409.
5. A reader uses `GET /v1/instances` to discover the projects it may read.
   Unlike ownGET, this route projects permitted projects from other owners.
   Empty inventories are visible only to their owner with Any Read authority.

For example, with an explicitly illustrative canonical project ID:

```json
{"projects":[{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","versions":["main"]}]}
```

The list response is `{"items":[...],"next_after":...}`. Its closed query accepts
only `limit`, `after`, `instance_id`, `project_id` and `version`. The HTTP default
limit is 50 and maximum is 100. Unknown or duplicate fields and invalid UTF-8 or
percent escapes return 400. The cursor is the last returned item, not the last
invisible item examined. Candidate IDs use binary ordering and advance strictly
past `after`, including when that ID is absent. Each record is capped before
payload copying and decoded with the maintained SQLite inventory decoder. There
is no corpus quota or whole-corpus allocation.

The opaque PUT wire validates header presence, syntax and uniqueness before
reading the body. A syntactically valid Bearer header with invalid JSON returns
400 `invalid_json`; genuine credential verification follows body decoding and
always precedes registration effects. An invalid credential with a valid body
returns 401. This ordering is the existing opaque HTTP contract; it differs from
claiming cryptographic verification precedes malformed JSON.

## Publish and observe Now

Create the existing `RealtimeServerRuntime` with its explicit heartbeat and
capacity, then merge `sqlite_local_realtime_router(store,
LocalRealtimeHttpConfig, &runtime)` with the inventory router. The route is
`GET /v1/realtime`. It verifies the actual credential before HTTP 101. Use the
existing [WebSocket protocol](rust-realtime-ws.md), including its initial full
publish or subscribe command and welcome frame.

A publisher needs the exact registered instance/project/version, the literal
registration owner, current `presence:publish` and the current section read
masks. A subscriber needs `presence:read` for its requested project; an authorized
view may contain no instances. Task access includes Sessions; Memory and
Knowledge have independent masks. The visible Now payload is the permitted
intersection, reevaluated against current policy and registration state.

Only a successful authenticated full publication renews the DATA heartbeat.
Transport Ping/Pong does not. Replacement publishers supersede the old handle;
registration withdrawal and fresh ACL changes affect live views. The existing
runtime owns sessions and joins them on shutdown. Runtime shutdown does not
erase the durable registration and rejects new upgrades.

Authentication has both UTC and monotonic cutoffs. A quiet subscriber whose
credential expires reports `unauthenticated` and Close 1008. A publisher whose
Hub handle becomes inactive follows the `superseded` / Close 1008 path; there is
no promised priority between concurrent publisher inactivity and authentication
cutoff. No protected DATA may be emitted after its authorization cutoff. A
policy error requires its finite error frame and explicit Close code; connection
reset is not a substitute for that protocol outcome. A closed store uses the
existing `closed` / Close 1000 path. See the protocol reference for other errors.

## Failure and recovery boundaries

The business methods share the caller's Original deadline and the actual SQLite
executor. They do not wrap a COMMIT in a second outer timeout or manufacture an
ACK. A candidate read uses a deferred, read-only snapshot and checks the
original deadline before returning data or EOF. Corruption and byte-cap
failures remain errors rather than empty inventories.

For 401, obtain a current credential through its owner and check configured
audience/scopes. For 403, check the current same-rule capability/project ACL.
For 409, use the actual registration owner; project permission does not transfer
ownership. For input or cap errors, repair the request before retrying. An
uncertain write requires an authorized reread to establish the observed state;
do not assume a timeout means no registration committed.

The shared ACL and own-inventory DATA readers (`SqliteResourceGrants::read` and
`SqliteInstanceInventories::read`) perform SELECTs only in a DEFERRED transaction
that does not reserve the WAL writer. They end their coherent snapshot
with checked rollback and Original checks, without entering write-COMMIT state.
If their acknowledgement is lost to deadline or shutdown, they report Deadline
or Closed rather than write `OutcomeUncertain`. Physical/schema validation and
transaction-owner quarantine remain enforced. This distinction does not change
LOCAL authentication, candidate cleanup, registration writes or their existing
COMMIT acknowledgement requirements.

## Implementation and validation scope

The four SQLite flows are `local_instance_registration`, `local_inventory_read`,
`local_inventory_list` and `instance_candidates` under
`crates/broker-control/src/sqlite/flow/`. The LOCAL variant of
`broker_now_channel.rs` consumes real verifier and policy proofs. Presence uses
private backends in `inventory_read.rs`, `inventory_list.rs` and `realtime.rs`;
the shared PUT adapter remains in `lib.rs`.

The focal native targets are `sqlite_local_presence_now` in `broker-control` and
`sqlite_local_presence_now_http` in `broker-presence`. The latter uses real TCP
HTTP and WebSocket clients. The LOCAL fixtures exercise possession verification
against real SQLite state; they do not prove human or service credential
issuance. Existing Native, writer, verifier and consumer qualifications remain
separate reusable evidence. Linux library/router results do not qualify an
installed host, Windows/macOS, or the complete Broker server. Consult
[SQLite Native Presence](rust-sqlite-presence.md) for that distinct mode.
