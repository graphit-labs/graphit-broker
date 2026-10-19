---
references:
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f253, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-0022, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0137, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-5c850, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e52a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust Inventory integration fixture

Audience: Runtime integration developers exercising the real Broker Inventory
HTTP contract with their captured installation, project and version identifiers.

The Rust example starts a disposable PostgreSQL container with generated TLS
certificates, opens the native store as a non-superuser and serves the actual
PUT, own GET and partial LIST router on a loopback ephemeral port. Docker must
be available to the current user. It reuses the pinned PostgreSQL image and
private test support; it does not connect to an operator's database.

Run from the Broker project:

~~~text
cargo run --locked -j1 -p broker-presence --example inventory_fixture
~~~

Keep stdin open while testing. Write one JSON object per line. Stdout contains
only protocol events and flushes each line; stderr contains finite error
messages. Cargo's build messages go to stderr. Capture stdout privately: Ready
contains synthetic raw credentials for this disposable fixture. Do not copy
Ready into logs, receipts or shared Task records.

## Start with captured identifiers

The first command supplies the consumer's actual captured identifiers:

~~~json
{"command":"start","instance_id":"station","projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main","release"]}]}
~~~

There is no installation/project/version default. The native Inventory
constructors validate and order identifiers and versions, reject duplicates,
and accept an empty projects array. Missing, duplicate, unknown or mistyped
fields, invalid native identifiers and trailing JSON fail before startup.
EOF before Start exits successfully without starting PostgreSQL.

Ready contains exactly:

| Field | Value |
|---|---|
| event | ready |
| endpoint | HTTP base URL with loopback ephemeral port |
| instance_id, projects | Validated, ordered inventory seeded through the native SQL writer |
| audience | inventory-fixture |
| read_scopes, publish_scopes | Arrays containing presence:read and presence:publish respectively |
| access_bearer, service_bearer | Raw opaque credentials; prepend Bearer when making HTTP requests |
| subject, username | Local human identity for Access, owner of the seeded inventory |
| service_subject, service_username | Separate local service identity for Service |

Use the returned Access credential and identity in the consumer's temporary
Auth setup. The fixture provides neither an Auth authority factory nor a mock
HTTP response. Runtime still owns its original request, captured installation
and cancellation/lifetime controls.

Access and Service correspond to different native identity kinds. Service
authenticates, but its own GET/PUT of the human-owned installation returns 409 owner_conflict.
Its explicit Read grants permit partial LIST. This preserves literal ownership;
the fixture does not fabricate a common principal for both token kinds.

The fixture gives both principals explicit Read and Publish Any grants, with
no role-to-resource promotion. Its local credentials expire one hour after
startup. HTTP fixture settings are explicit: identity JSON 4096 bytes; grants, body
and inventory JSON 16384 bytes; LIST query 1024 bytes; request timeout four
seconds. These are synthetic fixture settings, not Broker production defaults
or JWT signing/trust rules.

## Exercise the protocol and current SQL authorization

Use the returned endpoint plus the [own GET and PUT path](rust-instance-inventory-read-http.md),
or the [partial LIST route](rust-instance-inventory-list-http.md). A successful
GET contains instance_id, projects, created_at and updated_at exactly; the
timestamps are native SQL microseconds.

Subsequent commands have only a command field:

| Command | Confirmed effect |
|---|---|
| deny_read | Remove both fixture Read capabilities and advance the SQL ACL revision; Publish remains |
| allow_read | Restore those Read capabilities and advance the SQL ACL revision |
| revoke_access | Mark only the fixture's local Access token revoked; Service remains independent |
| restore_access | Clear that local Access revocation |
| delete_inventory | Delete the seeded installation and its versions; own GET becomes 404 and PUT can recreate it |
| shutdown | End the protocol and gracefully stop the fixture |

Shutdown Ack is emitted only after the listener, store and container have
finished normal cleanup. Other successful commands emit after SQL confirmation:


~~~json
{"event":"ack","command":"deny_read","ok":true}
~~~

Wait for Ack before checking the resulting HTTP behavior. Repeating Start,
unknown commands, extra fields or malformed JSON produce a static stderr
error and nonzero exit, followed by normal cleanup. SQL or HTTP serving errors
also produce finite failure messages; no SQL error details or credentials are
printed. A missing Ack is not evidence that a SQL mutation rolled back.

These controls exercise opaque local Inventory behavior. They are not JWT
blacklist or revocation compensation: JWT authentication remains local until
access expiration, while PROJECT permission is a separate current SQL check.

## Finish and verify

Shutdown or stdin EOF stops the listener, closes the store/control connection
and explicitly removes the disposable container before ShutdownAck. The consumed
shared fixture cleanup must confirm success of the real Docker removal command;
a failure produces a finite error and cannot produce a successful shutdown Ack.
RAII remains available for cleanup on failure and removes temporary TLS files.
EOF follows the same cleanup without Ack. Cleanup after SIGKILL is not promised.
HTTP is loopback plaintext in
this test tool; PostgreSQL uses verified TLS.

~~~text
cargo test --locked -j1 -p broker-presence --example inventory_fixture
cargo test --locked -j1 -p broker-presence --example inventory_fixture -- --ignored --test-threads=1
~~~

The native test exercises real PostgreSQL and TCP HTTP, current ACL changes,
opaque revocation and owner isolation, deletion/recreation and normal cleanup.
Qualification also runs the actual example binary over stdin/stdout. Runtime
consumer integration is a separate delivery; passing this producer does not
qualify the complete Broker, JWT provider, realtime Now or supported platforms.

## Historical producer qualification — tsk-0022

The original producer qualification, before the explicit cleanup correction,
passed on Linux with fourteen unique fast tests, three rustdocs, fmt and
strict Clippy, one real PostgreSQL/TCP test (84.09 seconds), and three runs of
the actual binary: shutdown, EOF and invalid command after startup. The binary
runs confirmed HTTP/SQL effects, listener closure and removal of the disposable
container. Receipts contain only sanitized results; Ready was not recorded.

## Explicit cleanup correction — tsk-5c850

This correction consumes the confirmed cleanup helper qualified by tsk-e52a.
Linux qualification on 2026-10-11 passed 17 current Presence fast tests,
formatting and strict Clippy, the affected native PostgreSQL/TCP contract
(69.098 seconds), and four rebuilt public binary IPC cases. The happy case
performed six actual HTTP calls covering own GET/PUT, Service LIST and independent
Service ownership conflicts, then observed ShutdownAck and exit 0. EOF produced
only Ready and exit 0; invalid input produced a static error and exit 1 without
Ack; initial EOF produced no setup or output. Live cases confirmed listener
closure and no owned-container cleanup failure. Shutdown and EOF success depend
on the consumed real Docker removal result. The four current Presence rustdocs
from tsk-e52a are reused because crate APIs/rustdocs are unchanged by this example
cleanup change.

The prebuilt public executable was rebuilt and verified executable after the
source change for the Runtime consumer. Sanitized receipts are under
.build/rust-inventory-fixture-cleanup-2026-10-11/. The original producer receipts
remain historical; Runtime integration and the full migration remain separate.

## Optional realtime composition

To serve the production WebSocket router at `/v1/realtime` alongside Inventory,
add `realtime` to Start. Omit it for the existing Inventory-only scenario.
Ready, the control commands and acknowledgment shapes are unchanged. Explicit
null, positional values, unknown, duplicate or missing realtime fields fail;
invalid capacities, scopes and operation/heartbeat durations fail before startup.
There are no WebSocket defaults in this fixture.

The object has seven required fields:

| Field | Contract |
| --- | --- |
| heartbeat_timeout_ms | Positive representable heartbeat duration, negotiated by the actual Welcome |
| broadcast_capacity | Positive channel capacity accepted by the existing realtime Hub |
| required_scopes | Token scopes required for both subscriber and publisher admission; separate from SQL capabilities |
| command_bytes, outbound_bytes | Positive representable WebSocket encoding limits |
| operation_timeout_ms | Positive representable operation budget |
| task_read | Explicit boolean; true adds a real `task:read` SQL grant, false retains presence-only grants |

For example, the following is an explicit functional scenario, not production
policy or implicit defaults:

~~~json
{"heartbeat_timeout_ms":60000,"broadcast_capacity":32,"required_scopes":["presence:read"],"command_bytes":65536,"outbound_bytes":65536,"operation_timeout_ms":30000,"task_read":true}
~~~

The LOCAL token already contains `presence:read`; no scope conversion is needed.
Task grants are separate from Presence Any: they apply to the explicit human
and service principals and exactly the project IDs in Start.projects. Empty
Start.projects creates no Task rule. Token identity kinds and ownership remain distinct.
Audience and identity limits (LOCAL), grants and inventory limits use the same
configuration already supplied for this fixture. Both routers use the same
PostgreSQL store and a single retained `RealtimeServerRuntime` and Hub. The
fixture implements no WebSocket protocol or authority factory of its own.

Register a second captured Core installation ID with the public Inventory PUT,
using its real captured project IDs and versions, then publish/subscribe via
the public client. The same legitimate principal may own two installations;
there is no `second_instance` IPC field or second credential requirement.
LOCAL credentials still have their separate literal owners. To reconnect,
close the subscriber and open a new authenticated subscription.

`task_read:true` grants only Task read for the fixture principals and projects.
It does not grant Memory or Knowledge. The Now authorizer verifies the configured
transport scopes and independently computes the content mask from current SQL
capabilities. `task:read` is not an additional token scope unless explicitly
listed in `required_scopes`. It is not implied by `presence:read`.

Shutdown, EOF and IPC errors after startup stop admission and await the realtime
owner's connection and maintenance tasks before closing SQL and removing the
container. Shutdown Ack follows that cleanup. The fixture tests exercise real
Inventory registration, publishers and subscribers, Task versus forbidden
content masks (including a project outside Start.projects), and cleanup while WebSockets remain open. Their synthetic DATA
validates the fixture composition only. Runtime owns the separate two-process
integration and Now updates produced by actual MCP records; this support does
not qualify that delivery.

## Observe startup before Ready

For an owned startup investigation, set `GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS=1`
in the fixture process environment. The shared PostgreSQL test helper then emits
static phase labels before/after each Docker verb and SQL/TLS readiness, with
relative elapsed milliseconds and finite completion status, only on stderr.
It emits no Docker arguments, container identifiers, credentials, configuration
values or raw subprocess diagnostics. A begin without its matching end locates
the current wait; a container's `created` state alone does not establish which
command returned. For `docker create` only, separate spawn and wait-output
labels distinguish process creation from draining/reaping the child. On Linux,
a finite identity label says whether the spawned executable matches the
canonical `/usr/bin/docker`; it never prints resolved paths or environment
values. No new timeout or retry is applied.

The default is silent and stdout remains the exact JSONL protocol. Drain both
pipes and keep Ready/credentials private. This diagnostic mode does not prove
consumer or protocol success; evaluate the actual Ready and shutdown Ack using
the existing contract. Rebuild only the affected normal example binaries after a
causal helper change, then pass those exact binaries to the consumer.
