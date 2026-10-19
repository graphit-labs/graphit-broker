---
references:
  - target: {type: task, id: tsk-44aa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-074c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8632, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust instance registration HTTP

The explicit [SQLite Native inventory and realtime composition](rust-sqlite-presence.md) supplies real JWT-authenticated PUT/own GET and Now WebSocket consumers. The PostgreSQL factories below retain their signatures and wire; opaque LOCAL PostgreSQL remains separate, and global server SQLite dispatch is not completed by these routers.

Audience: Broker server integrators and installation publishers. This route
registers a complete installation inventory through the shared PostgreSQL control
store. The Rust Router is implemented in broker-presence; a standalone full
Broker server bootstrap, list API, live presence and Now remain separate work.

## Publish an inventory

Send PUT /v1/instances/{id}/inventory with exactly one Authorization: Bearer
header and Content-Type: application/json. The raw credential must authenticate
the current local user, match the configured audience and required scopes, and
have current Publish grants for every submitted project. Read
[authenticated registration](rust-instance-registration.md) for ownership,
ALL-project permissions and the explicit Any-project rule for an empty inventory.

~~~json
{
  "projects": [
    {"project_id": "01D39ZY06FGSCTVN4T2V9PKHFZ", "versions": ["main", "release"]}
  ]
}
~~~

The path supplies the validated installation ID. Body objects reject unknown,
duplicate or missing fields, wrong types, null and trailing data. No body owner,
principal, timestamp or authority field is accepted. Project IDs are canonical
nonzero ULIDs; versions are meaningful, already-trimmed unique strings. Repeated
projects and versions fail validation.

A successful first registration returns 201; updated or unchanged inventories
return 200. The response has only these four fields:

~~~json
{"instance_id":"station","change":"created","created_at":1,"updated_at":1}
~~~

Timestamps in this example are illustrative microsecond values. Real timestamps
come from the server. Equal canonical inventories return "unchanged" with stable
timestamps. An empty projects array creates or clears an owned parent only with
a matching explicit Any-project Publish grant; clearing retains the parent and
its creation timestamp. Another authenticated owner cannot take over an ID.

## Errors and recovery

Every handled route error returns JSON with one finite static code, for example
{"error":{"code":"owner_conflict"}}. No owner, principal, raw credential, SQL or
driver message is exposed. No request ID is fabricated.

| Status | Codes | Meaning |
| --- | --- | --- |
| 400 | invalid_json, invalid_inventory, body_too_large | Correct media type, strict body, IDs/versions or configured body size. |
| 401 | unauthenticated | Supply exactly one valid local bearer matching current identity, audience and scopes. WWW-Authenticate is Bearer. |
| 403 | forbidden | Current grants do not allow ALL projects or the empty-inventory operation. |
| 409 | owner_conflict | The ID belongs to a different literal issuer/subject. |
| 503 | invalid_policy | Repair a malformed grant policy before it can activate. |
| 503 | authentication_unavailable, authorization_unavailable, registration_unavailable, closed | The corresponding current data/store is unavailable; no internal details are returned. |
| 503 | outcome_uncertain | COMMIT confirmation is uncertain. Do not automatically replay or assume no write occurred. |
| 504 | deadline | The original body/Auth/ACL/SQL operation deadline was exceeded before a confirmed result. |
| 404 / 405 | not_found / method_not_allowed | Use the defined URL and PUT method. |

Header format and uniqueness are checked first, then path/body/schema, then
actual raw authentication, fresh authorization and SQL. A malformed body can
therefore fail before database authentication even with a correctly formatted
but invalid bearer. Credential parsing uses the headers SDK without trimming
the extracted raw token in application code.

The handler computes one deadline at admission. The body Json extractor uses the
configured byte limit and that deadline. Authentication and SQL receive the same
end time; their own budgets may shorten it, never extend it. The route has no
outer transaction timeout or replay layer: the SQL writer retains its
OutcomeUncertain classification after COMMIT starts. Identity and grants are
current observations, not a policy freeze during COMMIT. Best-effort token usage
telemetry can precede a later denial.

Dropping an incomplete-body client's connection cannot register that unfinished
inventory. This is not a promise that an HTTP disconnect rolls back an operation
whose COMMIT has already started. Callers must treat loss of the response as
uncertain and reconcile stored state before a further consequential attempt;
the reconciliation/list endpoint is separate work.

## Integrate the shared Router

instance_registry_router accepts Arc<PostgresControlStore> plus
InstanceRegistryHttpConfig with explicit audience, required_scopes,
identity_json_bytes, grants_json_bytes, body_bytes and request_timeout.
It creates no new SQL pool or runtime. Configuration has no Default; reject blank audiences, zero
or unrepresentable timeouts, blank required-scope entries and invalid registrar
configuration. The configured scope vector does not replace Publish ACL checks.

~~~rust
fn routes(
    store: std::sync::Arc<broker_control::PostgresControlStore>,
) -> Result<axum::Router, broker_presence::RegistryHttpConfigurationError> {
    broker_presence::instance_registry_router(store, broker_presence::InstanceRegistryHttpConfig {
        audience: "explicit-audience".into(),
        required_scopes: vec!["presence:publish".into()],
        identity_json_bytes: std::num::NonZeroUsize::new(4096).unwrap(),
        grants_json_bytes: std::num::NonZeroUsize::new(16384).unwrap(),
        body_bytes: std::num::NonZeroUsize::new(4096).unwrap(),
        request_timeout: std::time::Duration::from_secs(2),
    })
}
~~~

These are example integration settings, not product defaults. The serving
application supplies its listener, transport security and normal shutdown.
Use [PostgreSQL control](rust-postgres-control.md) for the shared store.

The implementation uses [Axum 0.8.9](https://docs.rs/axum/0.8.9/axum/) and
[headers 0.4.2](https://docs.rs/headers/0.4.2/headers/).
Native TCP tests use Hyper 1.12.0, hyper-util 0.1.21 and http-body-util 0.1.5;
no application HTTP or Bearer parser is implemented.

## Qualification

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-presence --test registration_http registration_http_postgres_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
~~~

Linux qualification passed: 3 HTTP fast tests (8.470 s), 1 rustdoc (0.395 s),
fmt (0.245 s), strict Clippy (10.142 s) and the final native fixture (169.018 s).
The affected broker-control suite passed 52 fast tests (0.301 s) and 19 rustdocs
(0.291 s). An earlier corrected native version passed in 39.142 s; the final
version additionally verifies identity/grant read-cap propagation over TCP.
Two failed native attempts remain recorded separately: blank-audience factory
validation (119.308 s), fixed in the HTTP factory, and the test client demanding
a fully completed HTTP/1 request after an incomplete streaming body received a
deadline response (218.481 s). That fixture now accepts only unknown-size body,
actual 504 response and the SDK incomplete-message classification; other errors
remain failures. No production deadline, cap or authorization rule was relaxed.
Static impact review found no fault, including these two corrections.
Twenty affected local documentation links resolve. The lockfile retains every
old package version/source/checksum; 27 package blocks were added including the
new crate, and seven old blocks only disambiguate existing dependency labels.
Logs are retained in .build/rust-instance-registration-http-2026-10-11/.

The fixture runs
the real Router over loopback TCP and a pinned PostgreSQL image over TLS, with an
ordinary NOSUPERUSER application role, actual Access/Service credentials and
fresh SQL grants. It covers create/update/no-op/empty/foreign-owner outcomes,
strict input/header/body limits, current authentication failures, malformed
policy and unavailable data, explicit identity/grant read caps, slow-body and writer-lock deadlines, incomplete
client-body disconnect, pool recovery, store close and graceful server shutdown.
Unit error mappings cover OutcomeUncertain at every nested boundary; actual
writer COMMIT disconnect qualification is in the linked inventory contract and
is not claimed as an injected HTTP failure here.

Windows/macOS, full Broker bootstrap/packaging, HTTP TLS deployment, list/read
reconciliation and live/Now integrations have not been qualified by this leaf.
The route alone does not complete N6/N7/N9 or the migration.

Sources: crates/broker-presence/src/lib.rs and
tests/registration_http.rs::registration_http_postgres_contract.

Use the [own-inventory HTTP reader](rust-instance-inventory-read-http.md)
for GET reconciliation and explicit PUT+GET router composition.
