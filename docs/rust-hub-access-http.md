---
references:
  - target: {type: task, id: tsk-4f6e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-81ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9606, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7616, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-0257, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-d75f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-b788, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---
# Hub access HTTP in Rust

`broker-presence` exposes `POST /v1/hub/access/resolve` by composing the
[current SQL Hub resolver](rust-hub-access.md). The application supplies its
listener, shared `Arc<PostgresControlStore>` and shutdown lifecycle. This router
does not advertise discovery or configure an OP/client/storage backend.

The explicit [SQLite SQL and HTTP composition](rust-sqlite-hub-access.md)
uses the same Hub policy, protected result and metadata reader with its physical
SQLite owner. Its separate receipt records qualification progress. The PostgreSQL
configuration and transaction details on this page remain specific to that backend;
global Server SQLite selection remains under tsk-8069.

## Choose an explicit ingress

- `broker_hub_access_router(store, Arc<BrokerAccessVerifier>, HubAccessHttpConfig)`
  uses the configured native JWT verifier. The config has
  `grants_json_bytes: NonZeroUsize` and `request_timeout: Duration`.
- `local_hub_access_router(store, LocalHubAccessHttpConfig)` uses current opaque
  SQL access/service credentials. The config has an explicit `audience: String`,
  `identity_json_bytes: NonZeroUsize`, `grants_json_bytes: NonZeroUsize` and
  `request_timeout: Duration`. Audience semantics follow the SQL producer.

Both return `Result<axum::Router, HubAccessHttpConfigurationError>`, validate the
producer limits and require a positive representable timeout. Configuration
Debug and error Display are redacted. Native trust, token cap and optional
resource binding remain in `BrokerAccessVerifier`. Required Hub scopes are `[]`;
there is no scope or audience default and no token-format detection or fallback.
Mount the selected factory as the configured ingress for this route.

The handler captures the deadline before interpreting Authorization and passes
it through authentication and SQL reads without an outer timeout around COMMIT.
The SQL producer also bounds it by the store's operation timeout.

## Request and response

No request body or Content-Type is required. The handler ignores the body,
including arbitrary non-JSON bytes. Caller-supplied identity headers or body
fields do not change authorization.

```http
POST /v1/hub/access/resolve HTTP/1.1
Authorization: Bearer <credential for the configured ingress>
```

Omit Authorization to request anonymous access. One trim-empty header also
selects anonymous. A nonempty malformed/invalid credential receives 401.
Multiple Authorization values receive 401 even when they are all empty.
Nonempty headers use the existing mature Bearer parser. A JWT supplied to the
opaque ingress or an opaque credential supplied to the native ingress is denied.

Success is 200 JSON with `Cache-Control: no-store`:

```json
{"v":1,"authorization_revision":"42","subject":"anonymous|anonymous","selectors":[{"id":"01D39ZY06FGSCTVN4T2V9PKHFZ"},{"all":true}]}
```

Revision and canonical subject are strings. Selectors retain the SQL producer's
first-value deduplication/order; IDs remain alongside `all`, with no NamePrefix.
An empty list is a successful observation. The handler calls the retained
result's `check()` immediately before JSON emission, including empty results.
Native identities remain bound by JWT expiry; opaque identity is read from
current SQL state. Each call reads fresh grants, so committed revision/removal
affects the next response. This response is discovery data; issuing storage
credentials or authorizing a later storage action requires its own boundary.

## Error contract

Errors are finite JSON `{"error":{"code":"unauthenticated"}}`, without raw
bearers, SQL payloads or driver diagnostics. Branch on the code:

| Condition | HTTP / code |
|---|---|
| Invalid, expired, ambiguous or wrong-ingress credential | 401 / `unauthenticated`, `WWW-Authenticate: Bearer`. |
| Propagated native scope denial | 403 / `insufficient_scope`, corresponding Bearer challenge. |
| Deadline during authentication, SQL or final check | 504 / `deadline`. |
| Closed store | 503 / `closed`. |
| Uncertain SQL COMMIT | 503 / `outcome_uncertain`. |
| Invalid native configuration or malformed/over-limit local authentication state | 503 / `authentication_unavailable`. |
| Invalid Hub policy, grant cap/metadata or SQL storage failure, including local identity SQL | 503 / `authorization_unavailable`. |
| Wrong method on the route | 405 / `method_not_allowed`. |
| Unknown path | 404 / `not_found`. |

An error never becomes anonymous access or a successful empty/all response.
Correct the credential/configuration/policy through its owner before a new call;
restore SQL availability for storage failures. An uncertain COMMIT is not proof
of success or an automatic retry instruction. Only success has the no-store
response header under this contract.

## Verification and source

[Router implementation](../crates/broker-presence/src/hub_access.rs) uses the
existing private HTTP error/Bearer helpers.
[Focused integration test](../crates/broker-presence/tests/hub_access_http.rs)
serves real TCP axum listeners and uses the existing Hyper client with PostgreSQL
TLS under a `NOSUPERUSER` owner. It exercises the separate native Ed25519 and
opaque SQL ingress, anonymous/duplicate headers, ignored bodies, exact wire,
current revision/removal, invalid policy/privileges, actual SQL lock deadline and
JWT expiry, client cancellation and joined listener/fixture shutdown. Cancellation
of a client connection is not a claim of instantaneous server query cancellation.
Lost COMMIT acknowledgments are not simulated as network proof.

From the Broker checkout with Docker available, run
`cargo test --locked -j1 -p broker-presence --test hub_access_http -- --ignored --test-threads=1`.
Affected ordinary tests use `cargo test --locked -j1 -p broker-presence --lib --test hub_access_http`;
documentation tests use `cargo test --locked -j1 -p broker-presence --doc`.
Execution evidence and platform limitations live with the delivery. This router
does not establish an App/Auth consumer deployment, STS issuing or completion of
the entire Broker migration.


## Available PROJECT metadata catalog

The productive server also mounts `GET /v1/hub/catalog/projects` when storage is
enabled. `hub_catalog_router` composes native JWT and opaque SQL ingress with the
same configured audience and stores: `gb_at_`/`gb_sc_` selects opaque exactly
once; other nonempty credentials select the native verifier, with no fallback.
Anonymous access still requires an actual matching anonymous/global Hub rule.
This is a metadata-only operation, separate from issuing S3 credentials and from
PROJECT, Presence or administrative ProjectsRead authorization.

Optional `id` and `name_prefix` are mutually exclusive; `limit` defaults to 100
and accepts 1..1000, and `cursor` resumes a page. Unknown/duplicate query fields
are rejected. Success is no-store JSON:

```json
{"v":1,"subject":"https://broker.example|subject","authorization_revision":"42","projects":[{"id":"01D39ZY06FGSCTVN4T2V9PKHFZ","name":"example"}],"next_cursor":null}
```

The canonical document is `{base}/v1/projects/{id}/hub/metadata/project.json`,
strict v1 `{project:{id,name,status:"active"}}`. Rust FILE/Native publishers create
this metadata from the actual local PROJECT under their own HubWrite and PROJECT
admissions and a real storage grant. The metadata reader uses the same matching
Hub rules' `s3_route`, or the configured default. Overlapping Hub rules selecting
different routes for one PROJECT are an error; it never chooses an alternative
route, grant name, instance registry or SQL-derived friendly name.

AWS reuses configured SDK credential/provider caches through object_store's
paginated delimiter API; filesystem uses confined nofollow access. Only PROJECT
candidate directories and bounded metadata documents are read, without traversing
corpus contents. Exact IDs do not enumerate the universe. Pagination retains only
a page; cursors hold a binding plus the last returned ID, no names of unauthorized
PROJECTs or backend continuation tokens. Each request rereads SQL authority.
Changed query/identity/revision/routes return 409 `catalog_restart_required`;
this is pagination, not an immutable snapshot. Restart the query explicitly.

The finite catalog errors are 400 `invalid_query`/`invalid_cursor`, 409
`catalog_restart_required`, 403 `conflicting_routes`, 401 `unauthenticated`,
502 `invalid_project_metadata`, 503 `catalog_unavailable`, and 504 `deadline`.
Authentication/SQL failures preserve the existing Hub error mapping. Missing
metadata is a genuinely absent project; malformed metadata/backend errors never
become empty success. A canceled HTTP exchange drops its storage future; it does
not claim instantaneous cancellation of synchronous filesystem calls or SQL.

Source: [metadata reader](../crates/broker-storage/src/hub_catalog.rs),
[HTTP composition](../crates/broker-presence/src/hub_catalog.rs), and the focused
[real two-route test](../crates/broker-presence/tests/hub_access_http/catalog.rs).
The existing [process fixture](rust-hub-storage-fixture.md) also mounts this route
and permits the PROJECT metadata root in its actual STSv3 publishing grant.
Qualification and platform limits belong to tsk-81ba; these contracts do not
complete separate App/CLI/Web catalog consumers.


### Catalog qualification scope

The two `catalog::` cases in `hub_access_http` pass in 26.33s (26333ms wall):
`hub_catalog_current_metadata_routes_pages_and_authority` exercises real SQL/HTTP
and two confined filesystem volumes; `hub_catalog_s3_short_truncated_page_continues_after_prefix_skip`
uses the actual object_store client against a controlled short/truncated S3 page,
then reaches the matching later PROJECT and EOF. This distinguishes continuation
from a false EOF inferred from the number of common prefixes. These cases cover
native JWT/opaque and Hub-specific authority, query/revision restart, names,
route conflict, invalid metadata/identity, wrong audience/expiry and Original.
The server composition compiles (17.53s); strict compilation of storage/control/
presence/server libraries passes (8.07s). Compilation costs are separate from the
26.33s of test execution. The three affected App journeys also pass in 114.75s
(114764ms wall, 36g): projects CLI reads metadata created by actual FILE
publication, FILE CLI/MCP creates and conditionally renames metadata, and Native
publication distinguishes first/duplicate effects and rejects a foreign ID.
Three STS policy tests pass in 0.03s (36e), preserving exact resources, staging
DELETE and the 2048-byte boundary after removing inherited permission redundancy.
Broader application/CLI (tsk-0257), shared MCP/HTTP adapters (tsk-d75f) and React/
browser journeys (tsk-b788) remain open; these results do not qualify their whole
scope or migration-wide completion. App/Source strict passes in 34.41s (36j),
and affected Broker library/test strict passes in 6.49s (36k), both with Rust
`-D warnings`. Historical 35a/35b/35c remains distinguished from 36g.

When composing this router with the credentials router, retain a single global
fallback: the productive server uses
`credentials_router.merge(catalog_router.reset_fallback())`. Both standalone
routers install JSON fallbacks, so merging them directly would panic in Axum.
This fix was identified after the compilation-only 35b result; the filesystem
focal now builds both actual routers together and passes in 12.12s (12126ms
wall, 35h). The affected server strict compilation passes in 10.13s (10229ms
wall, 35h). The actual process fixture main builds in 2.22s (2273ms wall, 35f);
this build is distinguished from a test harness executable. Unchanged reader/S3
boundaries retain their 35a evidence. The current process fixture main rebuild
passes in 15.69s (36f), and its real publishing/catalog consumers pass in 36g.
Historical policy-too-large failures remain in the producer receipt.
