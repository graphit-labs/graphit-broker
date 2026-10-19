---
references:
  - target: {type: task, id: tsk-b532, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5406, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5df1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-c091, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-bf2f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Broker JWT PROJECT authorization over HTTP

The explicit [SQLite Broker JWT PROJECT router](rust-sqlite-broker-project-authorization-http.md) serves this same wire contract using the real SQLite authorizer and fresh ACL reader. The PostgreSQL constructor below and separate opaque local constructor retain their signatures. Global standalone server configuration and dispatch remain PostgreSQL.

Audience: Broker server integrators and clients using signed Broker access JWTs.
The endpoint calls the [actual SQL PROJECT authorizer](rust-broker-project-authorization.md).
The application explicitly chooses this JWT factory or the separate
[opaque local factory](rust-project-authorization-http.md); the server never
selects a backend by inspecting credential format.

## Configure and serve

Call broker_presence::broker_project_authorization_router with the existing
Arc<PostgresControlStore>, an Arc<BrokerAccessVerifier> supplied by the trusted
configuration/key owner, and BrokerProjectAuthorizationHttpConfig. Supply
required_scopes, grants_json_bytes, body_bytes and request_timeout explicitly.
Scopes must be nonblank and contain no ASCII space; an empty vector infers none.
Byte caps are NonZeroUsize. Timeout must be positive and fit Instant; producer
grant caps must be valid. Invalid construction returns the existing finite
ProjectAuthorizationHttpConfigurationError; config Debug is redacted.

The [verifier](rust-broker-access-jwt.md) captures issuer, API audience, resource,
trusted Ed25519 JWKS and raw token byte cap. Request headers/body cannot provide
trusted keys. Rotation replaces the configured verifier snapshot; this factory
does not discover keys or create a refresh/cache service. The application owns
listener and shutdown; no separate SQL pool or runtime is created.

The standalone router has explicit JSON 404/405 fallbacks. Choose exactly one
factory for this path. Combine application routes before installing a common
fallback, as described by the [opaque router composition contract](rust-project-authorization-http.md).
Full bootstrap, discovery metadata and the Auth PROJECT consumer are separate
integration deliveries.

## Request and successful response

~~~text
POST /v1/project/access/authorize
Authorization: Bearer <signed Broker access JWT>
Content-Type: application/json
~~~

~~~json
{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"task","action":"read"}
~~~

The body contains exactly these three fields. project_id is one canonical
nonzero ULID; module is exactly task, memory, knowledge, ast or hub. The first
four modules admit read or write; hub admits only read. Hub write returns
400 invalid_request, including with a broad grant. Duplicate/unknown/missing fields, wrong types, aliases, enum
objects, root arrays, invalid UTF8 and trailing JSON fail closed. Nonempty
query strings are rejected. The raw body limit also applies to chunked input;
content type is checked by the SDK. Exactly one Authorization header must decode
through the headers SDK. Opaque credentials and ID tokens do not authenticate.

~~~json
{"subject":{"issuer":"https://broker.example.test","subject":"broker-subject"},"authorization_revision":7,"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"task","action":"read"}
~~~

200 returns exactly these fields. subject contains the literal signed Broker
iss/sub from the verified proof, with no conversion to a local SQL user or
upstream binding lookup. The revision comes from this call's current SQL policy.
The operation fields come from the successfully authorized decision.
No credential, username, claims, scopes, selectors or policy rules are exposed.

An operator grant must match the actual signed principal, exact capability and
project in the same rule. Read/write remain independent across the original
eight pairs. The additional Hub read pair uses capability hub; it cannot
authorize the other modules. Scopes and roles do not create PROJECT permission;
Presence, S3 and Knowledge permissions do not substitute for Hub read. See the [SQL/pattern contract](rust-broker-project-authorization.md).

## Freshness, failures and recovery

JWT authentication is local until signed exp, with signature, trusted algorithm,
issuer, audiences, time and access/client/resource claims checked. Revocation,
account disabling, changed profile and client removal may take until JWT
expiration to be observed. There is no UserInfo, introspection, SQL token/user
lookup, blacklist or fallback per request. The existing OP access TTL remains
10 minutes by default, configurable from 1 minute to 1 hour; the verifier trusts
the valid signed expiration rather than applying an invented TTL.

PROJECT grants are separate and read fresh from SQL on every call. Removing a
grant affects the next decision even while the same JWT remains valid. A
response observes one operation and is not a cacheable permission lease.

Errors have the finite envelope {"error":{"code":"static_code"}}:

| Status / code | Meaning |
| --- | --- |
| 400 / invalid_request | Invalid strict body/project/nonempty query. |
| 413 / body_too_large | Fixed or chunked raw body cap exceeded. |
| 415 / unsupported_media_type | SDK rejects JSON content type. |
| 401 / unauthenticated | Invalid headers/token/signature/claims, expired token; includes WWW-Authenticate: Bearer. |
| 403 / insufficient_scope | Valid JWT lacks a required scope; includes WWW-Authenticate: Bearer error="insufficient_scope" per [RFC 6750 §3.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1). |
| 403 / forbidden | No same-rule principal/capability/project match. |
| 503 / authentication_unavailable | Invalid verifier request configuration. |
| 503 / invalid_policy | Whole policy invalid, including unrelated rules. |
| 503 / authorization_unavailable | SQL/grant failure or grant payload cap/state error. |
| 503 / closed | Shared store closed. |
| 503 / outcome_uncertain | Producer SQL COMMIT confirmation uncertain. |
| 504 / deadline | Original admitted deadline exceeded. |
| 404 / not_found | Unmatched path, including trailing slash. |
| 405 / method_not_allowed | Exact path with method other than POST; HEAD has no body. |

Use a valid access token after 401, correct the operation/grant after 403, and
correct input/content type after 400/413/415. For 503 inspect configured trust,
policy and storage availability through operator diagnostics; responses never
include driver details, credentials or patterns.

One monotonic deadline is admitted before headers/body. Only body extraction
uses an enclosing timeout. SQL receives the same Original end, which the store
may shorten; body completion never starts a fresh budget. The SQL producer owns
COMMIT classification, without outer SQL timeout/retry replacing uncertainty.
The verified proof is checked after SQL before both allow and forbidden.
Abandoned HTTP responses confer no authority; normal store guards recover
connections. The application shuts down listener and store normally.

## Public integration fixture

Use the [native public PROJECT JWT fixture](rust-broker-project-authorization-fixture.md)
for a real configured endpoint, signed credentials and trusted public JWKS.
Its private IPC captures issuer/audience/resource/client/project IDs separately;
it implements no discovery or OAuth provider and does not qualify the Auth consumer.

## Qualification and boundaries

From the Broker workspace:

~~~text
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-presence --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-presence --test broker_project_authorization_http broker_project_authorization_http_postgres_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --test project_authorization_http project_authorization_http_postgres_contract -- --ignored --test-threads=1
~~~

The JWT native contract uses real TCP Axum/Hyper, SDK-signed Ed25519 and ordinary
NOSUPERUSER PostgreSQL TLS. It checks exact response/all eight operations,
fresh ACL changes, denied auth-table SELECT, invalid JWTs, strict HTTP input,
real ACL lock expiration before allow and forbidden, Original body+SQL deadline,
client transport abandonment and pool recovery, shutdown and reopen.
Unit mapping covers OutcomeUncertain without claiming a native readonly COMMIT
disconnect. The opaque native contract verifies the shared transport regression.
Linux results qualify these affected paths only; Windows/macOS, public Auth
fixture/consumer, full startup/discovery and the whole migration remain separate.

Sources: crates/broker-presence/src/project_authorization.rs and
tests/broker_project_authorization_http.rs, using the actual
[JWT verifier](rust-broker-access-jwt.md) and
[SQL authorizer](rust-broker-project-authorization.md).

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
