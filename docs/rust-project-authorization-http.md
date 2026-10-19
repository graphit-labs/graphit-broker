---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5406, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-c153, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5401, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Local PROJECT authorization over HTTP

An explicit [SQLite LOCAL PROJECT service and HTTP factory](rust-sqlite-local-bearer.md)
uses the same opaque credential and whole-policy contracts. The PostgreSQL
constructors below retain their signatures; final server database dispatch is separate.

Audience: Broker server integrators and clients using opaque local Access or
Service credentials. The route evaluates one logical project operation using
the [real current SQL authorizer](rust-project-authorization.md).

## Supply explicit configuration

Call broker_presence::project_authorization_router(shared_store, config), where
shared_store is the existing Arc<PostgresControlStore> and config is
ProjectAuthorizationHttpConfig. The application supplies its listener and normal
shutdown. The router creates no runtime, SQL pool or policy cache.

Supply audience, required_scopes, identity_json_bytes, grants_json_bytes,
body_bytes and request_timeout. Byte caps are NonZeroUsize. Blank audience or
scope items, zero or overflowing duration and invalid producer caps reject
construction with ProjectAuthorizationHttpConfigurationError. Config Debug is
redacted. An empty required_scopes vector adds no inferred scope; it still
requires the explicit logical capability.

This factory serves one complete standalone route with finite JSON fallbacks.
The existing inventory composer retains its four arguments. A future application
composer must combine routes before installing one explicit fallback; merging
two completed standalone Routers with explicit fallbacks is unsupported by the
[Axum Router contract](https://docs.rs/axum/0.8.9/axum/struct.Router.html#method.merge).
This leaf does not provide the full server bootstrap or discovery metadata.

## Authorize one exact project operation

~~~text
POST /v1/project/access/authorize
Authorization: Bearer <current opaque local Access or Service credential>
Content-Type: application/json
~~~

~~~json
{
  "project_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "module": "task",
  "action": "read"
}
~~~

The body must be an object containing exactly these three fields. project_id is
one canonical nonzero ULID. module is exactly task, memory, knowledge, ast or
hub. The first four modules admit read or write; hub admits only read. Hub write
returns 400 invalid_request even with a broad grant. Duplicate, unknown or missing fields, wrong
types, case aliases, enum objects, root arrays, invalid UTF8 and trailing JSON
are rejected. Nonempty query strings are rejected. project_version and claimed
subject/issuer fields cannot supply authority.

Exactly one Authorization value must decode through the headers SDK. Invalid,
missing or duplicate headers fail with a Bearer challenge. Local refresh
credentials, JWT-shaped strings and unissued opaque values do not authenticate.
JSON extraction uses the configured raw body cap, including chunked bodies,
and the SDK content-type checks.

An explicit operator rule must match the verified current principal, exact
logical capability and project in the same rule. Read and write are independent.
A hub grant authorizes only Hub read for matching projects. Presence, S3 and
roles do not grant logical PROJECT access, and Knowledge cannot substitute for
Hub. Read the
[capability and native pattern contract](rust-project-authorization.md) before
creating grants; no auto-grant or legacy conversion runs on this route.

~~~json
{
  "subject": {
    "issuer": "local",
    "subject": "current-sql-subject"
  },
  "authorization_revision": 7,
  "project_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "module": "task",
  "action": "read"
}
~~~

A 200 response contains exactly these fields. subject is the literal issuer/raw
SQL subject of the successfully verified current local principal, not a
caller-supplied identity or a concatenated subject. authorization_revision is
the current SQL grant snapshot revision observed for this decision. The project,
module and action are the exact operation authorized. The response contains no
credential, digest, username, scopes, grant rules or selectors.

## Errors, freshness and lifecycle

The finite envelope is {"error":{"code":"static_code"}}.

| Status / code | Meaning |
| --- | --- |
| 200 | Current local principal has the explicit operation on this project. |
| 400 / invalid_request | Invalid strict body, project or nonempty query. |
| 413 / body_too_large | Raw fixed or chunked body exceeded its configured cap. |
| 415 / unsupported_media_type | The SDK did not accept the JSON content type. |
| 401 / unauthenticated | Invalid headers or current bearer. Includes WWW-Authenticate: Bearer. |
| 403 / forbidden | No same-rule principal/capability/project match. |
| 503 / authentication_unavailable | Non-Control identity/token state error, such as cap or corruption. |
| 503 / authorization_unavailable | Grant state failure or generic Control SQL failure from any producer phase. |
| 503 / invalid_policy | Whole current policy invalid, including unrelated rules. |
| 503 / closed | Shared control store closed. |
| 503 / outcome_uncertain | Preserved mapping for producers that emit OutcomeUncertain; the three SELECT-only PostgreSQL metadata readers do not emit it. |
| 504 / deadline | Original admitted request/store deadline exceeded. |
| 404 / not_found | Unmatched route. |
| 405 / method_not_allowed | Matched path with a method other than POST. |

GET, HEAD, PUT, PATCH and DELETE on the path return 405. HEAD has its response
body removed by the SDK. The path with a trailing slash is unmatched. Errors
never include driver text, stored principal data, patterns or raw credentials.

The authorizer folds generic Control errors without retaining their Auth/ACL
phase. A generic SQL failure during authentication therefore also returns
503 authorization_unavailable. Only non-Control AuthState errors use
503 authentication_unavailable. Deadline, Closed and OutcomeUncertain retain
their exact causes; the transport neither invents a phase nor runs a second
Auth query to distinguish one.

The handler admits one monotonic end before headers, query and body. It applies
a timeout only to body extraction and passes the same end to the real authorizer.
The store can shorten this end by its operation budget; body completion does not
start a new budget. There is no enclosing SQL timeout, retry or repair that
could replace the producer's error classification. For the three SELECT-only
PostgreSQL metadata readers, failed COMMIT confirmation produces a storage
error (503 authorization_unavailable) or Deadline (504 deadline), never an
authorization result. Their transaction has no persistent application effect.

Every call verifies current local enabled state, revision, audience, scopes,
revocation and expiry and reads fresh whole SQL grants. The authorizer checks
expiry/deadline again before both allowed and forbidden outcomes. Auth and ACL
remain separate observations. This response is an observation for one operation,
not a cacheable authority lease or a freeze against concurrent revocation.
Incomplete SQL readers use existing guard cleanup. A dropped transport discards
its response; do not infer an ongoing permission from an earlier response.
LOCAL verification and PROJECT evaluation change no token usage metadata, ACL,
user, inventory or policy revision. The HTTP SQL oracle compares complete token
rows without excluding a usage timestamp.

## Identity and integration boundary

This local route does not verify Web JWT access tokens. Its subject pair cannot
be compared to an incoming Broker JWT subject as though they were the same
identity. The separate [Broker JWT HTTP factory](rust-broker-project-authorization-http.md)
verifies the signed canonical Broker iss/sub directly through the actual
[JWT PROJECT authorizer](rust-broker-project-authorization.md), without a local
user conversion or upstream binding lookup. ID tokens, registered client IDs and
session cookie IDs alone do not supply backend permission.

Core/Auth Records admission, JWT/OIDC server verification, storage authorization,
discovery and full application composition have separate deliveries. Version
binding is outside this local project operation. Completion of this endpoint
does not complete the Broker or the migration.

## Qualification

Run from the Broker workspace:

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-control --test project_authorization postgres_local_project_authorization_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --test project_authorization_http project_authorization_http_postgres_contract -- --ignored --test-threads=1
~~~

Native fixtures use TCP Axum/Hyper and ordinary NOSUPERUSER PostgreSQL TLS with actual Rust digests, Access/Service state and SQL grants. They exercise all eight pairs, independent read/write, current revision/revocation, malformed and oversized HTTP input, real SQL denied reads, caps, corruption, slow body plus original SQL deadline, live-token expiry during an observed SQL lock and transport cancellation/pool recovery. The nested OutcomeUncertain mapping test preserves the transport contract for producers that report it; it does not imply that SELECT-only PostgreSQL readers emit that cause. These HTTP tests do not inject read-only COMMIT disconnect.

Tracker found that generic derived Serde enums and structs also accept enum
objects and root arrays. The route now uses the SDK map-only visitor and
string-only enum decoding, with unit and real HTTP regressions. No manual JSON
tokenizer or compatibility decoder was added.

Linux execution does not qualify Windows/macOS or the integrations excluded above.
Sources: crates/broker-presence/src/project_authorization.rs and
tests/project_authorization_http.rs; shared auth/finite error helpers remain in
src/lib.rs. The [PostgreSQL store](rust-postgres-control.md) and
[PROJECT authorizer](rust-project-authorization.md) own SQL/security behavior.

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
