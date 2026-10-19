---
references:
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-cc7e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7f74, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-074c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust own-inventory HTTP read

Audience: Broker server integrators and clients reconciling a published inventory.

## Supply the shared store and explicit settings

Use `instance_inventory_read_router(store, InstanceInventoryReadHttpConfig)`
for GET alone. Use `instance_inventory_router(store, publish_config, read_config, list_config)`
to serve PUT and GET on the inventory path plus the [partial LIST route](rust-instance-inventory-list-http.md). Read and Publish audiences and required
scopes are independent explicit settings. Both factories share the existing
`Arc<PostgresControlStore>`; the application provides its listener and shutdown.

For SQLite LOCAL, use `sqlite_instance_inventory_read_router(store, read_config)` or `sqlite_instance_inventory_router(store, publish_config, read_config, list_config)` with the shared `Arc<SqliteControlStore>`. These mature factories use the same explicit configs, DTOs, query rules and current opaque authority as the PostgreSQL routes above. See the [SQLite LOCAL composition](rust-sqlite-local-presence-now.md). Own GET retains whole-inventory ownership/Read checks; LIST remains a partial projection.

The Read config requires audience, required_scopes, identity_json_bytes,
grants_json_bytes, inventory_json_bytes and request_timeout. Caps are nonzero and
validated by the real producers. Blank audience/scope items, zero or overflowing
duration and invalid caps fail construction with a finite configuration error.
An empty required-scopes vector adds no inferred scope; business Read permission
still applies. There are no config defaults, new runtime, pool or policy cache.

The combined factory maps an invalid Read, Publish or List config to
`InstanceInventoryReadHttpConfigurationError`. The existing
`instance_registry_router` preserves its PUT API, configuration error and wire.

PUT and GET MethodRouters are combined and LIST is added before installing one JSON 404/405
fallback. Do not merge the two completed standalone Routers: the installed
[Axum Router contract](https://docs.rs/axum/latest/axum/struct.Router.html#method.merge)
allows only one explicit fallback; MethodRouter has the same restriction.
The own-inventory handlers use the fixed Axum 0.8.9 SDK. The separate LIST
parser uses its two approved SDK pins and explicit raw query cap.

## Read a complete own inventory

~~~text
GET /v1/instances/station/inventory
Authorization: Bearer <raw local Access or Service credential>
~~~

~~~json
{
  "instance_id": "station",
  "projects": [
    {
      "project_id": "01D39ZY06FGSCTVN4T2V9PKHFZ",
      "versions": ["main", "release"]
    }
  ],
  "created_at": 1000000,
  "updated_at": 2000000
}
~~~

The response contains exactly these four fields; each project contains only
project_id and versions. Timestamps are creation/update microseconds preserved
from storage. Owner, change, principal, token and policy are never returned.

The handler calls the real [authenticated own-inventory reader](rust-instance-inventory-read.md).
It verifies the current local identity, literal issuer/raw-subject ownership,
and explicit Read for every project; an empty inventory requires explicit Any
Read. A denied project denies the whole own GET. This differs from the [partial LIST operation](rust-instance-inventory-list-http.md),
which projects readable projects of other installations.

Exactly one Authorization value must decode through the headers SDK. Invalid,
missing or duplicate headers fail with 401 and WWW-Authenticate: Bearer. The
SDK preserves raw token bytes; refresh credentials and JWT-shaped strings are
not accepted by this local route. No owner or authority is accepted from a body.
HEAD uses Axum's GET handling and authentication with its response body removed.

## Errors, time and recovery

The finite JSON envelope is `{"error":{"code":"finite_static"}}`.

| Status / code | Meaning |
| --- | --- |
| 200 | Complete authorized own inventory. |
| 404 / not_found | Authenticated absence, or an unmatched route. |
| 409 / owner_conflict | Literal stored owner differs; no inventory returned. |
| 403 / forbidden | Required ALL-project or empty Any Read missing. |
| 400 / invalid_inventory | Rejected path or noncanonical instance ID. |
| 401 / unauthenticated | Invalid headers or current local bearer. Includes Bearer challenge. |
| 503 / authentication_unavailable | Identity/token read cap, corruption or storage failure. |
| 503 / authorization_unavailable | Grant read cap or storage failure. |
| 503 / invalid_policy | Whole current policy is malformed, including unrelated rules. |
| 503 / inventory_unavailable | SQL snapshot cap, malformed stored data or storage failure. |
| 503 / closed | Shared control store is closed. |
| 503 / outcome_uncertain | Nested SQL COMMIT confirmation is uncertain. |
| 504 / deadline | Original request/store deadline exceeded. |
| 405 / method_not_allowed | Matched path has no handler for this method. |

One deadline is admitted in the handler and passed directly to the business API.
The sequence is deadline, header validation, path extraction and real raw Auth.
Path rejection can precede SQL authentication. The store may reduce the end
time by its own budget; the handler never restarts or enlarges that budget.

There is no outer timeout around the business/SQL call, so even readonly COMMIT
uncertainty retains its classification. There is no automatic retry or repair.
A bearer expiring during the real grant wait cannot produce a successful body.
Current Auth, inventory and ACL are separate observations, with the producer's
final expiry/deadline check before output; this is no ongoing lease or freeze
against concurrent changes. Reads leave inventory untouched; existing token
usage telemetry remains best effort under the same deadline.

For publishing and uncertain-write reconciliation see
[registration HTTP](rust-instance-registration-http.md). This GET transport
does not implement list/live/Now, JWT/OIDC, MySQL or the full server bootstrap.

## Qualification

The following costs and counts record the original tsk-cc7e delivery. The current
four-argument composer and its affected native regression are qualified separately
in [HTTP LIST](rust-instance-inventory-list-http.md), tsk-1a3a.

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-presence --test inventory_read_http inventory_read_http_postgres_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
~~~

The bounded Tracker review found no fault. The new page and three linked
surfaces agree with Source in both directions; 27 local links resolve. The four
existing-file deltas contain only the private route extraction/exports and
three navigation additions; no Cargo/Lock/Control/shared-support edits.

The focused native fixture uses a real TCP
Axum/Hyper listener and pinned PostgreSQL TLS with an ordinary NOSUPERUSER
role, real Access/Service credentials and current users/tokens/grants. It covers
full wire/stamps, ALL/Any, owners/absence, malformed path/Auth headers, current
changes, three caps, policy/data corruption, SELECT permission, causal expiry
during ACL lock, original deadline, unchanged SQL inventory, combined
PUT201/200+GET200 and JSON404/405, authenticated HEAD body removal and close/reopen.

Linux is the available environment. Windows/macOS, MySQL, TLS on the HTTP
listener, readonly COMMIT-loss injection, list/live/Now and full migration are
not qualified by this leaf.

Sources: crates/broker-presence/src/inventory_read.rs, the private route
composition in src/lib.rs and tests/inventory_read_http.rs.

For Runtime integration with captured identifiers, use the [Rust Inventory fixture](rust-inventory-fixture.md).
