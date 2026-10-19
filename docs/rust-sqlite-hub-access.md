---
references:
  - target: {type: task, id: tsk-4f6e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7ac1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# SQLite Hub access and metadata catalog

This guide is for integrators composing Hub discovery with an explicitly opened
`SqliteControlStore`. It covers the Control resolvers and Presence routers;
global Server backend selection remains a separate integration. Use the existing
[SQLite configuration and lifecycle](rust-sqlite-control.md) and retain the store,
verifier, listener and metadata reader for the lifetime of their consumers.

## Select the actual identity ingress

`SqliteControlStore` exposes the same explicit factories as the
[Hub resolver contract](rust-hub-access.md):

- `broker_hub_access_resolver(&BrokerAccessVerifier, grants_json_bytes)` returns
  `SqliteBrokerHubAccessResolver<'_>`. The verifier supplies the actual signed
  token trust, issuer, audience and explicit optional resource binding.
- `local_hub_access_resolver(audience, identity_json_bytes, grants_json_bytes)`
  returns `SqliteLocalHubAccessResolver<'_>` and consumes the current SQLite
  [opaque bearer verifier](rust-sqlite-local-bearer.md) directly. Hub requires
  scopes `[]`; it does not inherit administrative session permission.

Factories return `Result`, borrow their owners and accept positive `NonZeroUsize`
byte caps. Call asynchronous `resolve(raw: Option<&str>, original: Instant)`.
`None` selects anonymous. `Some`, including an empty or malformed credential,
authenticates through the chosen ingress and never falls back to anonymous or
the other verifier.

Each resolution bounds the original caller deadline by the existing SQL
operation budget, authenticates and reads a fresh complete ACL snapshot with a
known COMMIT acknowledgement. Shared `HubResourcePolicy` derives selectors and
catalog routes from that same snapshot. There is no outer timeout around SQL
COMMIT and no automatic replay after `OutcomeUncertain`.

Only Hub capabilities contribute. Principals match literal values; project IDs
and `all` retain first occurrence order and deduplication. An empty project rule
or `*` selects all; NamePrefix is not a discovery selector. Missing matching rules
produce an empty successful result. Invalid policy, cap violations, corruption,
closed SQL and uncertain outcomes remain errors. Committed changes apply to the
next resolution. A retained result's `check()` rechecks its actual proof and
expiry/deadline; it does not reread ACL or renew authority. Discovery selectors
are data and cannot authorize storage credential issuance.

## Compose HTTP resolve

Use `sqlite_broker_hub_access_router(Arc<SqliteControlStore>,
Arc<BrokerAccessVerifier>, HubAccessHttpConfig)` or
`sqlite_local_hub_access_router(Arc<SqliteControlStore>,
LocalHubAccessHttpConfig)`. Both return
`Result<Router, HubAccessHttpConfigurationError>`. Config structs and positive,
representable timeout requirements are shared with the
[existing HTTP contract](rust-hub-access-http.md).

`POST /v1/hub/access/resolve` ignores body and Content-Type. Omitted Authorization
or one trim-empty value selects anonymous; duplicates, malformed credentials and
wrong ingress return 401. Caller identity headers and body fields grant nothing.
Success is checked immediately before emission, including empty selections:

```json
{"v":1,"authorization_revision":"42","subject":"anonymous|anonymous","selectors":[{"id":"01D39ZY06FGSCTVN4T2V9PKHFZ"}]}
```

Only success carries `Cache-Control: no-store` in this contract. Authentication,
SQL and policy errors retain the shared finite mapping: 401 unauthenticated,
403 propagated insufficient scope, 504 deadline, and 503 closed,
outcome_uncertain, authentication_unavailable or authorization_unavailable.
405/404 retain their existing method/path codes. Correct the actual credential,
policy or SQL availability before a new request; an uncertain response does not
establish success or authorize a blind retry. Errors expose no tokens or SQL
driver diagnostics.

## Read PROJECT metadata

`sqlite_hub_catalog_router(store, verifier, reader, HubCatalogHttpConfig)` retains
the real `Arc<HubCatalogReader>` and configured volumes. It does not create a
storage authorizer, issue credentials or use the SQL instance registry as a
catalog. `gb_at_`/`gb_sc_` chooses opaque ingress once; other nonempty tokens choose
the native verifier. Anonymous reads still require an actual Hub rule.

`GET` and `HEAD /v1/hub/catalog/projects` reuse the shared bounded query and wire
contract. `id` and `name_prefix` are mutually exclusive, `limit` defaults to 100
and accepts 1–1000, and `cursor` resumes a page. Unknown or duplicate fields are
400. Successful JSON contains `v`, `subject`, `authorization_revision`,
`projects: [{id,name}]` and `next_cursor`, with no-store; HEAD has no response body.

The reader opens canonical active v1 metadata at
`<base>/v1/projects/<id>/hub/metadata/project.json` through its existing confined
filesystem or configured object-store reader. Missing metadata means absence;
malformed metadata is 502 `invalid_project_metadata`, backend failure is 503
`catalog_unavailable`. Overlapping conflicting routes return 403
`conflicting_routes`; the reader never chooses a more permissive alternative.
Cursors bind query, identity, revision and routes. A changed binding returns 409
`catalog_restart_required`; explicitly restart pagination. Cursors confer no
authority. Authentication, SQL and deadline errors retain their causal mapping.

## Validate this composition

From the Broker checkout, run the two focused targets:

```text
cargo test --locked --offline -j4 -p broker-control --test sqlite_hub_access -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_hub_access_http -- --ignored --test-threads=1
```

The Control target uses private file-backed SQLite, signed Ed25519 JWTs and actual
human/service credential digests. The TCP target serves real Axum listeners with
joined Hyper clients and listener shutdown. Its catalog prepares physical
metadata in temporary volumes and reads through the actual confined reader with
SQLite authority. These documents are fixture data, not a storage grant,
publication/import path or STS proof. Fixture mutations occur between awaited
requests and do not qualify concurrent publication.

The COMMIT-delivery case pauses the real executor's post-COMMIT observation before its caller acknowledgement. It verifies finite uncertainty and owned cleanup; it does not simulate physical network acknowledgement loss. Executor cancellation/rollback and join have separate tests. Linux execution does not establish native Windows/macOS runtime behavior.

Source: [SQLite resolvers](../crates/broker-control/src/sqlite/flow/hub_access.rs),
[resolve adapters](../crates/broker-presence/src/hub_access.rs),
[catalog adapter](../crates/broker-presence/src/hub_catalog.rs), and the
[metadata reader](../crates/broker-storage/src/hub_catalog.rs).
