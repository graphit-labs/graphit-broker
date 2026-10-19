---
title: Rust Broker JWT PROJECT authorization
description: Authenticate signed Broker access tokens locally and evaluate current SQL permissions for each PROJECT operation.
references:
  - target: {type: task, id: tsk-b532, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5406, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target:
      type: task
      id: tsk-c091
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-bf2f
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: supports
  - target:
      type: task
      id: tsk-5401
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: supports
---

# Authorize a PROJECT operation with a Broker JWT

An explicit [SQLite authorizer and HTTP router](rust-sqlite-broker-project-authorization-http.md) also use the genuine verified principal and a fresh whole ACL snapshot. The PostgreSQL API below retains its signature; the SQLite composition has its own constructor and qualification. Standalone server configuration and global dispatch still select PostgreSQL.

The server combines [local access JWT authentication](rust-broker-access-jwt.md)
with a fresh SQL permission snapshot for one explicit project, module and action.
The JWT identifies the signed canonical Broker issuer and subject. Current
permissions determine whether that caller may perform this particular operation.

Use the new PostgresControlStore::broker_project_authorizer API with the
configuration owner's actual BrokerAccessVerifier and an explicit finite grant
payload byte limit. The authorizer borrows the store and verifier; it does not
accept an identity DTO or build an opaque local user from JWT claims.

~~~rust
use broker_control::{
    BrokerAccessVerifier, BrokerProjectAuthorizationError,
    PostgresBrokerProjectAuthorizer, PostgresControlStore,
};
use std::num::NonZeroUsize;

fn configured<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants_json_bytes: NonZeroUsize,
) -> Result<PostgresBrokerProjectAuthorizer<'a>, BrokerProjectAuthorizationError> {
    store.broker_project_authorizer(verifier, grants_json_bytes)
}
~~~

Call authorize(raw_bearer, required_scopes, module, action, project_id,
original_deadline). A successful AuthorizedBrokerProjectAccess exposes the
verified principal, project, module, action, exact capability and observed
policy_revision. Its constructor and fields are private; it has no Clone,
Default or Deserialize, and its Debug redacts identity material.

This is an observation for one operation. Authenticate and consult current SQL
grants again for subsequent operations. Retaining this object creates no
permission lease or Records admission factory.

## Explicit logical capabilities

Reuse ProjectResourceModule and ProjectResourceAction from
[local PROJECT authorization](rust-project-authorization.md):

| Module | Read | Write |
| --- | --- | --- |
| Task | task:read | task:write |
| Memory | memory:read | memory:write |
| Knowledge | knowledge:read | knowledge:write |
| Ast | ast:read | ast:write |
| Hub | hub | Not admitted |

Write does not imply read. Hub has only its Read pair, using the existing hub
capability. Hub Write is rejected as InvalidOperation before authentication or
SQL; the typed mapping returns None for that pair. Presence, S3 operations,
prefixes, routes and administrator roles grant none of these capabilities.
Hub read does not authorize the other four modules. A JWT scope only passes
the explicit token-purpose requirement; it never creates a SQL permission.

The requested project must be an exact canonical nonzero ULID. Wildcard, global,
zero and lowercase project identifiers are invalid request inputs. A policy
rule may explicitly use Any, represented by an empty project list or ["*"].

For an exact project, an operator can create a SQL resource rule with these
logical fields:

~~~json
{
  "access_kind": "subject",
  "principal": "https://broker.example.test|broker-subject",
  "capabilities": ["task:read"],
  "projects": ["01D39ZY06FGSCTVN4T2V9PKHFZ"]
}
~~~

This example describes rule fields, not an HTTP mutation endpoint. The operator
must use the actual signed Broker pair. It does not import or remap upstream or
opaque local identities. Subject matching accepts the signed subject alone or
the signed issuer|subject pair using the existing case-sensitive anchored byte
glob semantics.

## Signed attributes and current whole policy

The private [shared matcher](../crates/broker-control/src/resource_policy.rs)
derives a borrowed view from the legitimate VerifiedBrokerAccess. Existing
LocalBearerUser callers retain their actual local identity and public behavior.

User selectors match signed preferred_username, team selectors match signed
groups, and organization selectors match signed organization. Missing or null
username/organization and missing groups do not match their selectors, including
a wildcard. An empty username is treated as absent; a signed empty organization
remains a present empty string and can match a wildcard under the existing glob
semantics. No fallback string or profile lookup fills an absent attribute.

Global and authenticated selectors operate only after successful authentication;
anonymous selectors never match this authenticated path. For an allow, a single
rule must match the principal, exact logical capability and requested project.
The authorizer never assembles an allow from different rules.

Every call reads the current ResourceGrantSnapshot through
[the existing SQL producer](rust-resource-grants.md), including its revision.
It compiles the entire policy before deciding. An unrelated malformed selector,
capability pattern or invalid policy project fails the request closed, even when
another rule would allow it. Empty policy denies. No cached authorization,
implicit grants or policy repair runs during the request.

## Authentication expiry and SQL freshness

JWT authentication checks trusted keys, signature, issuer, API/resource audience,
claims, purpose, required scopes and expiry locally. It performs no UserInfo,
introspection, token/user/client SQL lookup, revocation polling or blacklist.
The issuer's signed client identifier remains its issuance attestation until
expiry, even if the SQL registration later disappears.

Account disablement, token revocation or changed profile claims may take until
the access token expires to change authentication. The verifier enforces the
signed expiry; this authorizer changes neither the observed OP default of ten
minutes nor its configured one-minute-to-one-hour range.

PROJECT grants are read freshly and can change immediately. Removing a capability
or changing its project/selector affects the next call with the same still-valid
JWT. The reported policy revision belongs to the observed SQL snapshot.

The request uses the earlier of its original deadline and the store's operation
timeout, without renewal. The existing read-only SQL producer owns acquisition,
cancellation and COMMIT classification. No enclosing business timeout hides an
uncertain COMMIT result. After a successful policy read/evaluation, the
authenticated proof and request deadline are checked again before returning
either allow or Forbidden. A token that expires while waiting for SQL is rejected
before either decision. SQL read errors retain the producer's classification.

## Errors and recovery

| Error | Meaning and next action |
| --- | --- |
| InvalidOperation | Choose a supported pair; Hub admits Read only |
| InvalidProject | Supply an exact canonical nonzero project ULID |
| InvalidPolicy | Repair the malformed whole SQL policy through its owning control path |
| Forbidden | The authenticated caller has no matching current rule for this operation |
| Authentication(BrokerAccessError) | Reject the invalid, expired or insufficient-scope bearer using the finite local verifier result |
| Grants(ResourceGrantReadError) | Handle the actual payload-limit or malformed stored snapshot failure |
| Control(ControlError) | Respect deadline, Closed, storage or uncertain-outcome classification; do not invent an allow |

JWT deadline errors and nested SQL control errors are folded into Control.
Errors expose no raw bearer, decoded profile, SQL text or driver diagnostics.
Close/reopen uses the existing store lifecycle; a canceled read must not leave
its connection reusable with an active transaction.

## Qualification and integration boundary

[Native tests](../crates/broker-control/tests/broker_project_authorization.rs)
use real SDK-signed Ed25519 JWTs and the existing pinned TLS PostgreSQL fixture
with an ordinary NOSUPERUSER owner. They exercise all eight pairs, same-rule
denials, signed profile matching and absence, grant removal/revision with the
same JWT, and successful local authentication after prior authentication metadata
is changed and SELECT on user/token/client tables is denied.

The fixture also exercises invalid policy, actual SQL privilege errors, read
payload caps, missing state, observed ACL SQL locks, expiry before both allow and
deny, the captured request deadline, cancellation/pool recovery and close/reopen.
The existing opaque PROJECT native contract and shared matcher regressions
protect current local callers.

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-control --test broker_project_authorization postgres_broker_project_authorization_contract -- --ignored --exact --nocapture
cargo test --locked -j1 -p broker-control --test project_authorization postgres_local_project_authorization_contract -- --ignored --exact --nocapture
~~~

Run the affected commands serially with one Cargo job in a shared checkout.
Only actual successful runs establish behavior on their executed host; pending
or ignored native tests do not establish SQL qualification.

The [existing HTTP PROJECT page](rust-project-authorization-http.md) describes
the opaque local endpoint. The JWT HTTP producer and Auth Web PROJECT/Records
admission integration remain subsequent deliveries. This SQL library does not
complete that bridge, the OP or the wider Broker migration.

## Hub read for one project

POST the same endpoint with this body and an authenticated bearer:

```json
{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"hub","action":"read"}
```

One current SQL rule must match the verified principal, capability `hub` and
that project. Missing membership or capability returns 403 even while the JWT
is valid. Separate rules cannot contribute different parts of the allow.
Removing the grant affects the next call; the response remains the existing
`subject`, `authorization_revision`, `project_id`, `module`, `action` shape.
A SQL hub rule with projects [] or * retains its existing Any-project meaning;
a separate Global Hub admission cannot replace this PROJECT decision.
This is logical PROJECT access for Hub source records; global Hub metadata
and S3 storage operations retain their separate admission. It does not by itself
qualify the Code LiveSource consumer or a complete OAuth Web session.
