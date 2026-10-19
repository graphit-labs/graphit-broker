---
references:
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f253, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
---
# Warm Native inventory integration fixture

The Rust example [native_inventory_fixture.rs](../crates/broker-presence/examples/native_inventory_fixture.rs)
starts a real PostgreSQL TLS store, an Ed25519 Broker access issuer and verifier,
and the [Native inventory HTTP router](rust-broker-instance-inventory-http.md).
It lets a separate consumer exercise warm Native access, current SQL grants and
recovery after an inventory response is lost.

Discovery metadata has the shape required by the SDK's warm verification
journey. This tool does not implement or qualify authorization-code login,
refresh, UserInfo or a complete production OpenID Provider. The metadata's
authorization and token URLs are fixture data; no synthetic OAuth handler is
installed. Tests require zero token and UserInfo requests in the warm journey.

## Run and provision

Docker, PostgreSQL fixture TLS support and the Broker Rust toolchain are
required. Run from the Broker project root:

~~~text
cargo run --locked -p broker-presence --example native_inventory_fixture
~~~

Use a private process pipe for JSON-lines stdin/stdout. Send this first line;
every field is required, and the numbers below are explicit test configuration,
not production defaults:

~~~json
{"command":"start","api_audience":"broker-api","resource":"https://resource.example.test/v1","client_id":"native-client","subject":"native-subject","scope":"openid fixture","redirect_uri_path":"/auth/callback","access_ttl_seconds":600,"instance_id":"Station._-1","projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main"]}],"seed_inventory":false,"grant_project_ids":["01D39ZY06FGSCTVN4T2V9PKHFZ"],"read_required_scopes":["fixture"],"publish_required_scopes":["fixture"],"token_bytes":8192,"grants_json_bytes":65536,"inventory_json_bytes":65536,"body_bytes":65536,"request_timeout_ms":3000}
~~~

Root and project entries must be JSON objects. Missing, duplicate, unknown,
positional or trailing fields are rejected. Capacities, TTL and request timeout
must be positive and representable; the scope contains the literal token
`openid`. Instance/project/version data uses the public inventory validators.
Grant project IDs are canonical ULIDs or `*`; an explicit empty array retains
the existing matcher's Any semantics. The tool adds independent read and
publish grants for the actual issuer/subject principal and commits ACL revisions.
It creates a non-superuser store owner. The fixture operator's separate
administrative connection is used only for its explicit controls.

`seed_inventory:false` leaves the inventory absent. A true value calls the
actual Native registrar with the signed access token, supplied publish scopes
and supplied inventory; it does not insert an authenticated owner by hand.

The process binds an ephemeral `127.0.0.1` port before creating its issuer.
Its single Ready object has exactly these fields:

| Field | Meaning |
| --- | --- |
| event | Literal `ready` |
| endpoint, issuer, inventory_endpoint | The same actual HTTP base origin, with no inventory path |
| instance_id | Supplied instance ID |
| api_audience, resource, client_id, subject, scope, redirect_uri_path | Supplied configuration |
| expires_at | Unsigned Unix UTC seconds, matching the access JWT `exp` |
| access_bearer | Synthetic access JWT signed by the actual fixture issuer |
| read_required_scopes, publish_required_scopes | Supplied required-scope arrays |

Keep Ready and its bearer inside the private IPC/profile provisioning path.
Do not copy the bearer into logs, documentation, Task evidence or receipts.
The example does not emit an ID token or persist tokens. Signing DER and owned
bearers use zeroizing storage. The actual verifier rechecks the access token
after setup and before emitting Ready; startup that outlives an explicit short
TTL fails and cleans up without a Ready response.

A Code consumer provisions its Native profile/binding/token through its own
Auth SDK. It explicitly enables `allow_loopback_http:true` for this fixture;
the foreground production default is unchanged. Supply the base
`inventory_endpoint`: the consumer appends
`/v1/instances/{instance_id}/inventory` once.
Broker source must not edit or bypass the consumer's profile storage.

## Actual HTTP surface

All responses use `Cache-Control: no-store`.

- `/.well-known/graphit-broker` has string `"version":"1"`,
  the actual issuer and the OIDC authentication fields required by the SDK.
- `/.well-known/openid-configuration` uses the actual issuer and JWKS URL.
  Its fixture arrays are authorization_code/refresh_token, S256, none and
  EdDSA for grant types, challenge methods, token authentication and signing.
- `/jwks` returns the public JWK set of the same signing key used for Ready.
- Native GET/PUT use the unchanged production inventory router and current
  SQL authorization. See its linked HTTP contract for statuses and schemas.
- OAuth flow endpoints have no handler added by this fixture; unsupported
  requests take the existing router fallback. Token/UserInfo counters observe
  requests even when they take that fallback.

## Controls, acknowledgment and recovery

After Ready, send one object per line. Non-Start controls do not accept extra
fields. Every successful control except stats returns exactly
`{"event":"ack","command":"<command>","ok":true}`.
Stats emits only its Stats object. Shutdown emits Ack only after cleanup.

| Command | Effect before acknowledgment |
| --- | --- |
| deny_read / allow_read | Remove/restore the independent real read grant and commit ACL revision |
| deny_publish / allow_publish | Remove/restore the independent real publish grant and commit ACL revision |
| delete_inventory | Delete this inventory's children and parent in one administrative transaction |
| replace_with_foreign_owner | Requires a nonblank, different `subject`; reads registry DATA, signs a real foreign token, installs a temporary publish grant, re-registers through the actual Native registrar, then removes the grant |
| lose_next_successful_put_response | Arm one response-body delivery failure after an actual Native PUT produces confirmed 200/201 |
| stats | Return cumulative HTTP and response-loss counters |
| shutdown | Stop and join the HTTP task, shut down the store, close the control connection and remove the PostgreSQL fixture |

The ownership replacement is a fixture operator control, not a consumer
permission or a new authority constructor. Read and publish withdrawal remain
independent. An absent registry entry makes replacement fail; it is not
invented from Start data.

The loss control survives denied or otherwise unsuccessful PUTs. On the next
successful PUT the middleware first receives the real registrar's confirmed
result, then fails body delivery. A fresh own GET can recover the persisted
inventory; a later PUT responds normally. This proves causal TCP ambiguity
and persisted recovery. It does not simulate a lost SQL COMMIT acknowledgment,
qualify SQL OutcomeUncertain, or establish Code's NetworkEffect classification.
The separate consumer integration must exercise that API itself.

Stats contains exactly `event:stats` plus unsigned counters:
`broker_metadata_requests`, `oidc_metadata_requests`, `jwks_requests`,
`token_requests`, `userinfo_requests`, `put_success_responses` and
`put_response_losses`. No token or private signing material is included.

EOF after Ready and control failures also clean up resources. EOF before Start
emits nothing and starts nothing. Invalid initial non-Start commands fail.
Shutdown timeout aborts and joins the owned server and attempts the remaining
cleanup; it returns failure rather than a false acknowledgment.

Failure exits unsuccessfully, emits no JSON error on stdout and uses one finite
stderr line: invalid command, input/output/setup/storage/server/shutdown failed,
or the panic guard's generic fixture failure. Causes, panic payloads and
bearers are not printed.

## Qualification

The example's tests are colocated with its source. Ordinary checks include the
strict IPC and invalid-configuration cases. Run affected checks:

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo test --locked -j1 -p broker-presence --example native_inventory_fixture -- --ignored --exact tests::native_inventory_fixture_postgres_contract --test-threads=1
~~~

The isolated test uses real PostgreSQL TLS, a non-superuser store owner, TCP,
issuer/JWKS/signature verification, discovery metadata, create/update/no-op,
current read/publish grant withdrawal, foreign-owner rejection, causal response
loss followed by own GET, zero token/UserInfo requests, shutdown, EOF and
malformed-control cleanup. It does not substitute for the separate Code SDK
integration, live WS, STS, full OAuth integration or final migration acceptance.

Linux qualification passed: 21 ordinary Presence tests (10 real integration
tests remain ignored in that suite), 5 rustdocs, strict all-target/all-feature
Clippy and workspace fmt. The isolated Native test passed in 118.44 s runtime,
including the actual expired-token Ready regression. Artifacts are retained in
`.build/rust-native-inventory-fixture-2026-10-11/`; final commands and earlier
attempts are distinguished in its qualification and execution records. The
earlier Clippy failure was corrected by boxing Start configuration, preserving
the IPC schema. Sixteen protected files retain their prior SHA256; the only
existing document edit is the fixture backlink. Five new document links resolve.
This does not establish Windows/macOS, remote CI or consumer integration.

Related contracts: [Native registrar](rust-broker-instance-registration.md),
[own inventory reader](rust-broker-instance-inventory-read.md) and
[Broker access issuer](rust-broker-access-issuer.md).

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

For this example, include the literal token `presence:read` in Native Start.scope
and use coherent required-scope arrays for the other HTTP operations. The tool
does not repair scopes or replace the configured token. Task grants use the
existing `grant_project_ids` selection and actual issuer/subject principal.
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
Inventory registration, two publishers and a subscriber, Task versus forbidden
content masks, and cleanup while WebSockets remain open. Their synthetic DATA
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
