---
references:
  - target: {type: task, id: tsk-44aa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-adca, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5f69, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-2372, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Broker inventory HTTP

An explicit [SQLite Native inventory and realtime composition](rust-sqlite-presence.md) now consumes the real JWT, whole current ACL, durable writer and bounded reader with the same PUT/own-GET wire. The PostgreSQL constructor below and separate opaque LOCAL PostgreSQL factories retain their signatures. Final standalone SQLite server configuration and dispatch remain separate.

Broker server integrators can select a Native PUT/own-GET router backed by the
shared control store and a configured access-JWT verifier. The application
supplies its listener, transport security and shutdown. This router delegates
registration and reconciliation to the qualified
[Native registrar](rust-broker-instance-registration.md) and
[Native own reader](rust-broker-instance-inventory-read.md).
The [opaque router](rust-instance-inventory-read-http.md) is selected separately.
There is no token-format probing or fallback.

## Configure and serve

Call `broker_presence::broker_instance_inventory_router(store, verifier,
publish_config, read_config)`. It returns `Result<axum::Router,
BrokerInventoryHttpConfigurationError>` and owns no separate runtime or SQL pool.
The two configs explicitly supply independent settings:

| Config | Fields |
| --- | --- |
| `BrokerPublishHttpConfig` | `required_scopes`, `grants_json_bytes`, `body_bytes`, `request_timeout` |
| `BrokerOwnReadHttpConfig` | `required_scopes`, `grants_json_bytes`, `inventory_json_bytes`, `request_timeout` |

Caps are positive `NonZeroUsize` values. Timeouts are positive `Duration` values
that must fit an `Instant`; blank required scopes and invalid producer caps
reject router construction. Neither config provides Default or inferred limits,
scopes or audience. Debug is redacted. The supplied verifier owns issuer,
audience, optional resource and signing-key trust; no audience or SQL identity
cap is added to the Native configs. Required scopes bind token purpose, while
current ACLs independently grant Read and Publish.

A compiled factory example is maintained in
`crates/broker-presence/src/broker_inventory.rs`. Set scopes and limits from the
serving application's explicit integration configuration.

## PUT and GET wire

Both methods use `/v1/instances/{id}/inventory`. Supply exactly one mature SDK
Bearer Authorization header with a valid signed Native access JWT. Query,
cookie or JSON token values do not substitute for it. Missing, malformed,
wrong-signature, expired or opaque credentials return 401 with a Bearer
challenge. A valid JWT lacking required scope returns 403 `insufficient_scope`
with `Bearer error="insufficient_scope"`.

PUT accepts this complete replacement body:

~~~json
{"projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main","release.1"]}]}
~~~

The root and each project row must be JSON objects. Positional arrays, missing,
duplicate or unknown fields, wrong types and trailing JSON are rejected by the
SDK decoder. Canonical instance/project IDs and meaningful, unique, literal
versions are checked by the existing inventory constructors. Versions with
surrounding whitespace are rejected rather than normalized. Empty projects
are valid replacement data. No caller owner or timestamp is accepted.

Created returns 201; updated and identical replacement return 200:

~~~json
{"instance_id":"station","change":"created","created_at":1,"updated_at":1}
~~~

The example stamps illustrate the wire shape; real stamps come from the writer.
GET returns the complete own inventory, with no owner or ACL revision:

~~~json
{"instance_id":"station","projects":[{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","versions":["main","release.1"]}],"created_at":1,"updated_at":1}
~~~

The signed literal `(issuer, subject)` must own the installation. Nonempty PUT
requires Publish for every project; GET requires Read for every project. Empty
PUT and empty GET require explicit matching Any Publish and Any Read,
respectively. One denied project denies the whole own GET. Version data and
signed admin roles do not imply permission. GET absence returns 404 after the
producer checks current whole policy and final JWT expiry/deadline. HEAD uses
the same authenticated GET and removes the response body. This Native router
does not expose a list endpoint.

All Native responses carry `Cache-Control: no-store`, including successes,
errors, HEAD and the finite JSON 404/405 fallbacks. Error bodies contain only
`{"error":{"code":"..."}}`, without credentials, owners, SQL causes or policy
content.

## Errors and operation boundary

| Status / code | Meaning |
| --- | --- |
| 400 `invalid_json` | Body is not the complete strict object schema. |
| 400 `invalid_inventory` | Path decoding or inventory values are invalid. |
| 401 `unauthenticated` | Bearer or Native authentication failed; Bearer challenge. |
| 403 `insufficient_scope` | Signed token lacks required scope; scope challenge. |
| 403 `forbidden` | Current whole ACL lacks required ALL or Any capability. |
| 404 `not_found` | Own parent is absent, or no route matches. |
| 405 `method_not_allowed` | The selected route does not accept the method. |
| 409 `owner_conflict` | Another literal owner owns the parent; no inventory returned. |
| 413 `body_too_large` | Actual Native PUT body exceeds the configured cap. |
| 503 `authentication_unavailable` | Native verifier configuration failure. |
| 503 `invalid_policy` | Whole current policy is invalid, including unmatched rules. |
| 503 `authorization_unavailable` | Grant snapshot/storage is unavailable or exceeds its cap. |
| 503 `inventory_unavailable` | Complete inventory snapshot is corrupt, oversized or unavailable. |
| 503 `registration_unavailable` | The qualified writer is unavailable. |
| 503 `closed` / `outcome_uncertain` | Store is closed, or producer COMMIT confirmation is uncertain. |
| 504 `deadline` | Original body or producer operation deadline expired. |

The handler captures its absolute original deadline once, before Bearer/path/
body processing. The PUT body extractor alone has an input timeout. The native
business call receives that same deadline directly; no outer timer can mask
SQL COMMIT confirmation, and no automatic retry renews the budget.

Native identity remains the signed JWT window until actual expiry; disabling
an SQL user, revoking a stored token or deleting a dynamic client does not remap
it. Every business operation still reads current complete SQL grants. Grant
and inventory observations remain separate transactions, not an atomic lease
against subsequent ACL changes. GET checks expiry/deadline before any logical
verdict; Publish checks them before entering the existing atomic writer.

A lost response or `outcome_uncertain` can follow a committed PUT. Perform a
fresh authorized GET, compare the inventory and only then decide whether to
retry. A TCP client disconnect does not promise the HTTP framework cancelled
the producer or rolled back a write. Original deadlines and the qualified SQL
guards retain their existing responsibilities. This router's GET cannot mutate
the registry. The server owner must finish its normal graceful shutdown and
join its serving task.

## Verification

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-presence --test broker_inventory_http -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --test registration_http registration_http_postgres_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --test inventory_read_http inventory_read_http_postgres_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The focused Native contract uses actual TCP Axum/Hyper, Ed25519 JWTs,
PostgreSQL TLS and a NOSUPERUSER application role. It checks strict object
requests, Bearer negatives, finite statuses/challenges, exact confidential
wire, current ALL/Any policy, registration replacement/no-op, ownership,
corruption, privileges, byte caps and signed identity after SQL revocation.
Causally observed ACL/inventory locks check expiry and Original deadlines;
a real client disconnect and subsequent GET check recovery and unchanged
readonly state. Slow body input checks the original extraction budget. The
fixture joins its owned servers and checks closed/reopened reconciliation.
Affected opaque TCP tests retain their existing contracts, including their
independent body-limit status. Fast tests retain finite nested COMMIT error
origins; network ACK-loss injection is outside this qualification.

Artifacts: `.build/rust-broker-native-inventory-http-2026-10-11/`.

Final Linux qualification passed: 19 ordinary Presence tests (9 Native tests
remain ignored in that suite), 5 Presence rustdocs, 99 ordinary Control tests
and 99 Control rustdocs. The real Native TCP contract passed in 101.24 s test
runtime; affected opaque PUT passed in 35.98 s and own GET in 68.71 s. Strict
all-target/all-feature Clippy and workspace fmt passed. The nine final commands
and all earlier attempts are retained separately in `qualification.json` and
`receipts.json`; wall times include Cargo queue waits.

Earlier attempts exposed two fixture assumptions: a positive version with
surrounding spaces, and unconditional HTTP connection success after a pending
body received 504. The corrected helper admits only SDK streaming body plus
504 plus `IncompleteMessage`; all other connection errors still fail. During
concurrent fixture runs, Native expiry returned 504 instead of expected 401
and opaque PUT recovery returned 503 instead of 200. Both contracts then
passed individually without changing production or opaque sources. This does
not establish the physical cause of those earlier failures or claim a passing
concurrent run. Failed attempts remain in the artifacts.

The bounded Source/fixture/documentation review found no remaining fault.
Nineteen protected files retain their prior SHA256, all four existing-file
deltas reverse exactly to their captured baselines, and eleven local document
links resolve. Shared manifests, lockfiles, SQL/Auth producers and opaque
algorithms are unchanged.

This delivery does not qualify live WS, STS, Runtime/CLI/MCP consumers,
Windows/macOS, remote CI or full Broker migration.

The [warm Native inventory fixture](rust-native-inventory-fixture.md) exercises this router with real issuer/JWKS and current SQL authorization.

The [Rust realtime WebSocket server](rust-realtime-ws.md) composes these contracts with explicit runtime ownership, fresh authorization and full project views.
