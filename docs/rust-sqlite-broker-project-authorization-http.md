---
title: SQLite Broker JWT PROJECT authorization over HTTP
type: reference
status: qualified-locally-linux
updated: 2026-10-17
references:
  - target: {type: task, id: tsk-b532, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c091, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-5df1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# SQLite Broker JWT PROJECT authorization

This integration combines genuine [Broker access JWT verification](rust-broker-access-jwt.md),
the [current SQLite ACL reader](rust-sqlite-identity-acl.md), the shared PROJECT
policy and the existing [PROJECT HTTP contract](rust-broker-project-authorization-http.md).
It provides an explicit library/router
composition; the standalone server's configuration and global dispatch remain
PostgreSQL and are separate work under tsk-8069.

## Construct the real producer and router

Open the private file-backed store with explicit path and budgets as documented
in [SQLite Control](rust-sqlite-control.md). The configuration/key owner supplies
the actual `BrokerAccessVerifier`, including issuer, API/resource audiences,
trusted Ed25519 keys and token byte cap.

`SqliteControlStore::broker_project_authorizer(&BrokerAccessVerifier, NonZeroUsize)`
returns `SqliteBrokerProjectAuthorizer<'_>`, borrowing both owners. Call its async
`authorize(raw, required_scopes, module, action, project_id, original)` for a genuine
`AuthorizedBrokerProjectAccess`. No identity DTO or public proof constructor is
accepted. Debug redacts the authorizer and proof.

Use the explicit HTTP constructor:

```rust
fn routes(
    store: std::sync::Arc<broker_control::SqliteControlStore>,
    verifier: std::sync::Arc<broker_control::BrokerAccessVerifier>,
    config: broker_presence::BrokerProjectAuthorizationHttpConfig,
) -> Result<axum::Router, broker_presence::ProjectAuthorizationHttpConfigurationError> {
    broker_presence::sqlite_broker_project_authorization_router(store, verifier, config)
}
```

Supply `required_scopes`, `grants_json_bytes`, `body_bytes` and `request_timeout`
explicitly. Scope entries must be nonblank and contain no ASCII space. An empty
scope list infers no requirement or permission. Invalid limits/timeouts reject
construction. The application owns listener, request admission and shutdown.

Existing PostgreSQL factories retain their signatures. The opaque local factory
accepts only PostgreSQL. A private PG/SQLite enum belongs only to the Broker-JWT
branch; there is no backend detection from token format, SQL pool substitution,
opaque SQLite path or fallback.

## Fresh authorization for nine explicit operations

| Module | Read capability | Write capability |
| --- | --- | --- |
| task | task:read | task:write |
| memory | memory:read | memory:write |
| knowledge | knowledge:read | knowledge:write |
| ast | ast:read | ast:write |
| hub | hub | Invalid operation |

Hub write is rejected before JWT verification or SQL. Project IDs must be
canonical nonzero ULIDs. Scopes, administrator roles, Presence and S3 permissions
do not grant PROJECT access. Hub read does not imply another module's permission.

After operation/project validation, the producer verifies the JWT locally and
reads the complete current ACL snapshot through the existing SQLite reader. It
compiles the whole shared resource policy, including unrelated rules, and requires
one rule to match principal, capability and project. Rules cannot combine their
partial matches. Empty policy denies; malformed policy fails closed.

The principal comes from the signed issuer/subject and supported signed attributes.
User/token/client SQL records do not replace or revoke that signed identity for
this operation. Account/profile/client changes may take until signed JWT expiry
to be observed. This constructor sets no access-token lifetime and performs no
UserInfo, introspection, blacklist or per-request identity-table lookup.

Every invocation rereads committed ACL state. Removing a grant affects the next
call with the same still-valid JWT. The observed revision and proof describe one
operation, not a permission lease or Core Records admission.

## Shared wire, errors and timing

The constructor serves the same exact `POST /v1/project/access/authorize` route.
The strict JSON body is exactly `project_id`, `module`, `action`; the exact 200
body is `subject: {issuer, subject}`, `authorization_revision`, `project_id`,
`module`, `action`. Subject values come from the verified JWT, not SQL profile
metadata. The shared handler rejects malformed/duplicate/unknown fields, nonempty
queries and ambiguous Bearer headers. Body limits cover fixed and chunked input;
content type, JSON extraction and 404/405/HEAD handling use the existing framework.

The [shared HTTP error table](rust-broker-project-authorization-http.md) remains
authoritative. Invalid/expired JWT is 401 unauthenticated with Bearer challenge;
missing required scope is 403 insufficient_scope with its challenge. A valid
principal without a matching rule is 403 forbidden. Malformed policy is 503
invalid_policy; ACL state/cap/storage failures are 503 authorization_unavailable.
The existing closed/outcome_uncertain/deadline mappings remain 503/503/504, without
SQL, driver, path, policy or credential details in the response.

HTTP admits one original deadline before headers/body. Only body extraction has
an enclosing timeout. The authorizer captures the existing store deadline once
and passes the same end to the ACL reader; no outer SQL timeout, renewed budget
or retry replaces native COMMIT classification. SQLite reads use the producer's
IMMEDIATE transaction. JWT validity is checked again after SQL for both an allow
and a deny, so a token expiring while waiting cannot authorize or become an
ordinary policy denial.

Shutdown and cancellation retain the physical owner until native work finishes.
A closed store fails through the existing finite mapper. Reopening the same
private file uses the real producer and its schema checks. This router creates no
new database lifecycle or background task.

## Qualification and limits

The new ordinary `sqlite_broker_project_authorization_http` target uses real
private SQLite files and SDK Ed25519 verification. Three tests use owned Axum
TCP listeners and Hyper requests; one directly exercises the real authorizer API
to control the expiry barrier. A separate rusqlite connection commits ACL changes; it is a test-only
dependency, not an exposed SQL seam. Cases cover nine operation pairs, whole-policy
decisions, signed identity versus changed SQL metadata, wire samples and lifecycle.

Expiry tests retain an independent SQLite writer before minting a short-lived
JWT, prove the real API future is pending and cross that same expiry before
releasing the writer. They check both allow and deny. Pending-future cancellation
and recovery do not claim SQL had begun, a staged write was rolled back or peer
EOF proved rollback. Shutdown/reopen in this target is quiescent; the native join
during active work is reused from the physical producer qualification. Native executor/COMMIT/ACK and unchanged reader proofs are
separately reused from tsk-6ebc/tsk-7bd3. There is no production witness, schema
fault, mock authority, new gate or general qualification campaign.

Run the affected target and shared wire units from Broker:

```text
cargo test --locked --offline -p broker-presence --test sqlite_broker_project_authorization_http -- --test-threads=1
cargo test --locked --offline -p broker-presence --lib project_authorization::tests -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib -- -D warnings
cargo clippy --locked --offline -p broker-presence --lib --test sqlite_broker_project_authorization_http -- -D warnings
cargo test --locked --offline -p broker-control --doc SqliteBrokerProjectAuthorizer
cargo fmt --package broker-control --package broker-presence -- --check
```

Select only the new `SqliteBrokerProjectAuthorizer` lifetime rustdoc and format
the affected packages. Existing PostgreSQL/opaque producers, JWT suites and the
broader library/rustdoc proofs are reused where unchanged. The ordinary Presence
all-targets gate already includes the new target. Linux execution proves Linux;
no native Windows/macOS result or full standalone SQLite backend is implied.
