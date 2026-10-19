---
references:
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-1a3a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-795b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-d37e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-cc7e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust HTTP inventory list

Audience: Broker server integrators and clients finding readable maintained
inventories. This HTTP route uses the real [local authenticated business LIST](rust-instance-list.md).
It returns a partial Read projection; it does not require ownership or Read ALL
of nonempty inventories.

## Configure the existing composer

~~~text
instance_inventory_router(
  store: Arc<PostgresControlStore>,
  registration_config: InstanceRegistryHttpConfig,
  own_read_config: InstanceInventoryReadHttpConfig,
  list_config: InstanceInventoryListHttpConfig
) -> Result<Router, InstanceInventoryReadHttpConfigurationError>
~~~

The SQLite LOCAL `sqlite_instance_inventory_router(store: Arc<SqliteControlStore>, registration_config, own_read_config, list_config)` takes the same explicit configs and shares the DTO, query and partial projection contracts below. See the [SQLite LOCAL composition](rust-sqlite-local-presence-now.md). The PostgreSQL composer above retains its signature.

The existing composer takes four explicit arguments and serves PUT/GET
/v1/instances/{id}/inventory plus GET /v1/instances. PUT and GET own-inventory
standalone factories retain their signatures. There is no separate LIST
standalone factory or second global composer.
Read, Publish and List audiences/scopes/caps/timeouts remain independent settings.

InstanceInventoryListHttpConfig requires audience, required_scopes,
identity_json_bytes, grants_json_bytes, inventory_json_bytes, request_timeout and
query_bytes. Byte caps use NonZeroUsize. The raw query cap must fit isize; JSON
caps are validated by the real business producers. Audience must be nonblank;
scope items must be nonblank. An empty scope vector adds no inferred scope.
request_timeout must be positive and representable by the monotonic clock.
No config defaults or framework size quota are supplied. Config Debug is redacted.
Any invalid config maps to the existing finite inventory HTTP configuration error.

The application provides its listener and shutdown and shares the existing
Arc<PostgresControlStore>. The composer builds default MethodRouters, combines
PUT+GET own-inventory and adds LIST before installing one finite JSON404/405
fallback. Do not merge standalone routers with custom fallbacks.
Axum [method fallback applies to previously registered routes](https://docs.rs/crate/axum/0.8.9/source/src/docs/routing/method_not_allowed_fallback.md).

## Query contract

~~~text
GET /v1/instances?limit=50&after=station-001&project_id=01D39ZY06FGSCTVN4T2V9PKHFZ&version=main
Authorization: Bearer <raw local Access or Service credential>
~~~

| Parameter | When omitted | Supplied value |
| --- | --- | --- |
| limit | 50 | ASCII unsigned decimal digits representing 1–100; leading zeros allowed. |
| after | Start of byte-order scan | Canonical instance ID; exclusive and need not exist. |
| instance_id | Scan candidates | One canonical instance ID. |
| project_id | Any readable project | Canonical nonzero uppercase ULID. |
| version | All versions of matching projects | Meaningful nonempty, control-free version with exact trim. |

Only these five decoded names are accepted and each may occur once.
limit=1 and %6cimit=2 together are duplicates. Names are case-sensitive.
limit=01 represents 1. Empty, signs, whitespace, non-ASCII digits, overflow and
out-of-range limits are invalid. Query absence or empty query uses default50.

Before decoding, raw query bytes are bounded by the explicit query_bytes cap.
Exact cap is allowed; above it returns 413/QUERY_TOO_LARGE.
The cap applies to actual raw URL query input, including percent encoding,
rather than the decoded size or the PUT body.

Pinned [form_urlencoded 1.2.2](https://docs.rs/form_urlencoded/1.2.2/form_urlencoded/fn.parse.html)
parses pairs and percent-decodes names and values, with plus as space.
A strict boundary first rejects malformed percent triplets and validates decoded
UTF-8 through [percent-encoding decode_utf8](https://docs.rs/percent-encoding/latest/percent_encoding/fn.percent_decode.html).
It never accepts lossy replacement characters as a repair. The SDK convention
for empty separators is retained. No handwritten decoder is used.
For a literal plus, use %2B; for an internal version space, plus or %20 works.
Other values pass through the business Query constructor without corrective trim.

## Partial projection, page and wire

~~~json
{
  "items": [
    {
      "instance_id": "station",
      "projects": [
        {"project_id": "01D39ZY06FGSCTVN4T2V9PKHFZ", "versions": ["main"]}
      ],
      "created_at": 1000000,
      "updated_at": 2000000
    }
  ],
  "next_after": null
}
~~~

Only these fields are returned. Timestamps are stored signed microseconds.
Owner, principal, grants, change, count, total and reusable authority are absent.

For each nonempty inventory, projects require presence:read in the same matching
principal/capability/project rule. Publish and administrative/Hub roles supply
no implicit Read. A foreign inventory can appear with just its readable
projects. project_id and version filters are cumulative. version without a
project may match any readable project; only matching versions are returned.
Projects with no matching versions and inventories with no visible projects are
omitted. Valid nonexistent filters return 200 with items[] and next_after null.

Actually stored empty inventories require literal current owner issuer/raw
subject plus Any Read, and are excluded when project_id or version is supplied.
Filtering a nonempty inventory to zero projects never converts it into an empty
owned inventory. [Own GET](rust-instance-inventory-read-http.md) retains literal
ownership and Read ALL for its complete response.

IDs are ordered by bytes/C collation. Hidden candidates advance only an internal
scan cursor. next_after is the last visible ID actually returned, only when one
more visible item exists. A full page followed only by hidden rows returns null.
An exact instance filter at/before after returns empty after current Auth and
whole policy validation. There is no global count or atomic whole-page snapshot.
Concurrent inventory/ACL changes may affect later observations and pages.

## Errors, time and recovery

The response envelope is exactly {"error":{"code":"finite_static"}}.

| Status / code | Meaning |
| --- | --- |
| 400 / INVALID_QUERY | Invalid percent/UTF-8, name, duplicate, limit, cursor or business filter. |
| 413 / QUERY_TOO_LARGE | Raw query exceeds the explicit query byte cap. |
| 401 / unauthenticated | Invalid/missing/duplicate Authorization header or current local bearer; includes Bearer challenge. |
| 503 / authentication_unavailable | Current identity/token cap, malformed state or storage failure. |
| 503 / authorization_unavailable | Grant snapshot cap or storage failure. |
| 503 / invalid_policy | Whole fresh policy is malformed, including unrelated rules. |
| 503 / inventory_unavailable | Selected inventory cap, malformed data or SQL failure. |
| 503 / closed | Shared control store is closed. |
| 503 / outcome_uncertain | A nested SQL COMMIT outcome cannot be confirmed. |
| 504 / deadline | Original request or bounded store deadline expired. |
| 404 / not_found | Unmatched route. Matching LIST absence is a successful empty page. |
| 405 / method_not_allowed | Known path has no handler for that method. |

One original deadline is admitted, then Authorization header decoding precedes
query validation, followed by business raw Auth. Query errors can precede SQL
authentication. The headers SDK preserves raw token bytes and requires exactly
one header. Refresh credentials and JWT-shaped tokens are rejected by this local
route. GET has no added body or Accept contract.
HEAD uses the same GET authentication/operation and removes the response body.

The handler awaits business directly, with no outer business/SQL timeout,
retry, repair, own SQL or enlarged budget. The producer verifies current Auth
and a fresh whole policy per page and rechecks expiry with fresh UTC plus the
original bounded deadline before output. This expiry check does not reread SQL
revocation or freeze concurrent ACL changes. Corrupt/oversized hidden candidates
fail the scan rather than being skipped. Existing token usage telemetry remains
best effort; read phases leave inventory unchanged. See the business contract
for coherent per-candidate snapshots and transaction outcome classification.

## Qualification and boundaries

Sources: [handler/parser/config](../crates/broker-presence/src/inventory_list.rs),
[composer](../crates/broker-presence/src/inventory_read.rs),
[route helpers](../crates/broker-presence/src/lib.rs),
[native LIST contract](../crates/broker-presence/tests/inventory_list_http.rs),
[own-GET regression](../crates/broker-presence/tests/inventory_read_http.rs).

The native fixture uses real TCP Axum/Hyper,
pinned PostgreSQL TLS, an ordinary NOSUPERUSER role, actual current Access/Service
users/tokens/grants and the inventory writer. It checks 55+ visible items,
default50 and hidden-ID cursor privacy, partial foreign reads, cumulative filters,
plus/UTF-8/query boundaries, exact wire/stamps, current Auth/fresh ACL, malformed
whole policy, three caps, corruption and SELECT denial, causal expiry during an
observed inventory SQL lock with statistics snapshot clear, original deadlines,
pool recovery, close/reopen and owned cleanup. SQL inventory stays unchanged
outside the explicit PUT phase. The existing own-GET native suite is rerun
because its composer changed.

~~~text
cargo metadata --format-version 1 --offline
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-presence --test inventory_list_http inventory_list_http_postgres_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --test inventory_read_http inventory_read_http_postgres_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
~~~

The two direct SDK pins were approved; normal Cargo metadata resolves their
existing package references, without manual lockfile edits. No package/version
upgrade, shared Control source, root manifest or fixture change is part of this
route. Metadata --no-deps alone does not resolve the lockfile.
Linux is the available qualification environment. Windows/macOS, MySQL LIST,
JWT/external OIDC, HTTP listener TLS, remote Now/WebSocket, full bootstrap and
whole Broker migration remain separate outcomes. The broad suite belongs to
final integration.
