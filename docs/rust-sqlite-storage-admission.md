---
title: Rust SQLite storage admission
doc_type: reference
references:
  - target: {type: task, id: tsk-c055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-b770, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7cdb, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c73a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-18f1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: knowledge, id: Rust_mixed_storage_credentials_service, scope: project, scope_id: 01M1YEAE1WYMWG9KJKV1XQC4T4}
    relation: uses
  - target: {type: task, id: tsk-4f6e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7ac1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-80f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust SQLite storage admission

For Broker consumers wiring SQLite authentication and current resource grants into
`POST /v1/s3/credentials`. SQLite authorizers feed the existing
[storage credentials service](rust-storage-credentials-service.md), issuers and
HTTP encoder. They admit native Broker JWTs and LOCAL opaque human access/service
bearers. Federated bearers and browser cookies have no ingress here.

Source inspection and formatting do not validate physical SQLite admission or TCP credential issuance; use the native integration tests below.

## Configure the real factories

Open the actual `SqliteControlStore` with its executor budget and limits.
Native admission additionally borrows the real `BrokerAccessVerifier` with its
configured key, issuer, audience and resource trust. LOCAL admission borrows the
explicit audience and uses the current SQLite opaque verifier. Supply nonzero
identity/grant JSON caps where required and a nonblank default route; the
constructor trims the route. Request data cannot choose any of these authorities.

Control exposes these methods:

~~~text
SqliteControlStore::broker_storage_authorizer<'a>(
    &'a self, verifier: &'a BrokerAccessVerifier,
    grants_json_bytes: NonZeroUsize, default_route: &str,
) -> Result<SqliteBrokerStorageAuthorizer<'a>, StorageAdmissionError>

SqliteControlStore::local_storage_authorizer<'a>(
    &'a self, audience: &'a str,
    identity_json_bytes: NonZeroUsize, grants_json_bytes: NonZeroUsize,
    default_route: &str,
) -> Result<SqliteLocalStorageAuthorizer<'a>, StorageAdmissionError>
~~~

Native `authenticate(raw, required_scopes, original)` is synchronous; LOCAL
authentication is asynchronous. Both return `AuthenticatedStorageCaller<'s>`
borrowed from the actual factory. Both provide asynchronous
`authorize_authenticated(caller, &StorageScope)` returning
`AuthorizedStorageGrant<'s>`, and `authorize(raw, scopes, scope, original)`
composes the phases. The Instant argument is the existing absolute request
Original deadline, further bounded by the SQL executor. Keep the store, factory
and borrowed verifier/audience alive through authorization and issuance.

The caller is bound to the exact factory instance. SQLite `FactoryBinding`
variants hold the actual native or LOCAL authorizer; admission requires the
matching variant and `std::ptr::eq`. Another factory with identical configuration
is still another instance. A caller cannot transfer to another store, verifier
or mode. Caller and grant have no public constructor of authority, Clone,
Default, Serialize or Deserialize path; their Debug output is redacted.
A scope, selector, configuration value or observer getter cannot manufacture them.

Presence exposes three constructors, all returning
`Result<Router, StorageCredentialsHttpConfigError>`:

| Constructor | Arguments |
| --- | --- |
| `sqlite_broker_storage_credentials_router` | `Arc<SqliteControlStore>`, `Arc<BrokerAccessVerifier>`, `Option<Arc<StorageCredentialsService>>`, `BrokerStorageCredentialsHttpConfig` |
| `sqlite_local_storage_credentials_router` | store, optional service as above, `LocalStorageCredentialsHttpConfig` |
| `sqlite_storage_credentials_router` | store, verifier, optional service, Broker config, LOCAL config |

The backend and borrowed factory enums select actual PostgreSQL or SQLite
implementations; handlers, input decoder, issuer and encoder remain shared.
Broker config contains `required_scopes`, `grants_json_bytes`,
`default_route`, `body_bytes`, `request_timeout` and `enabled`. LOCAL config
adds `audience` and `identity_json_bytes`. Timeouts must be positive and
representable; required-scope strings cannot be blank. Composition requires
exact equality of enabled, required scopes, grant cap, default route, body cap
and request timeout. Disabled configuration returns its router before requiring
an issuer. Enabled configuration validates its real authorizers and requires
the configured storage service.

The mature LOCAL verifier constructor accepts a whitespace-only audience. A
fixture configured with `" "` must reach authentication, where a mismatch with
the SQL audience is denied. Do not infer a new blank-audience constructor
validator from a failed authentication case.

## Request journey and proof lifetime

1. Capture the absolute HTTP deadline and parse the canonical Authorization
   bearer header. Composition selects `gb_at_`/`gb_sc_` as LOCAL once; other
   envelopes select native verification. Failed authentication does not probe
   another authority.
2. Authenticate the genuine credential and required scopes before consuming or
   decoding the body. Native verification is cryptographic; LOCAL verification
   reads current SQLite identity/session state. Check the retained caller before
   and after the bounded asynchronous body read and after scope decoding.
3. Decode the strict JSON object. Its fields select resource DATA; they supply
   no identity, permission, route or grant. The same factory consumes the caller.
4. Read the complete current ACL through `SqliteResourceGrants`. A grant needs
   the snapshot's known COMMIT ACK and revision. Preserve `OutcomeUncertain`
   before any post-read proof error. For other read outcomes, recheck the
   retained caller before propagating the read error. Compile and evaluate the
   shared `StoragePolicy`, checking the caller after compilation and evaluation.
5. Return the grant with its same identity, proof, Original, scope, route,
   revision and per-operation prefixes. Call
   `StorageCredentialsService::issue(&grant)` for that admitted route.
   Recheck proof/deadline after the issuer await, after encoding and before
   returning credentials.

The SQL executor owns COMMIT uncertainty. No outer timeout may abandon its
COMMIT result, replay admission, or turn `OutcomeUncertain` into success or an
asserted rollback. The existing PostgreSQL implementation is a behavioral
precedent; this SQLite boundary does not import PostgreSQL locking internals.

Every new issuance reads current ACL/revision and current opaque state.
A retained `grant.check()` checks the captured authentication and deadline; it
does not reread ACL or retroactively revoke an already issued storage credential.
ACL/route changes affect the next issuance. Issuer expiry remains the issuer's
contract: no new TTL clamp to JWT/opaque proof expiry is introduced. AWS retains
its 900–43200 second duration bounds. An issued storage credential may outlive
the authentication used to obtain it, under its own captured authority/expiry.

## Seven resource selections

| Selection | Request fields | Server-confined roots |
| --- | --- | --- |
| PROJECT Hub | `scope: project`, `module: hub`, canonical `project_id` | `v1/projects/{project}/registry`, `v1/projects/{project}/artifacts`, `v1/projects/{project}/hub/metadata`, `v1/projects/{project}/hub/events` |
| PROJECT Task | `scope: project`, `module: task`, `project_id` | `v1/projects/{project}/corpora/task` |
| PROJECT Memory | `scope: project`, `module: memory`, `project_id` | `v1/projects/{project}/corpora/memory` |
| PROJECT Knowledge | `scope: project`, `module: knowledge`, `project_id` | `v1/projects/{project}/corpora/knowledge` |
| PROJECT AST | `scope: project`, `module: ast`, `project_id` | `v1/projects/{project}/corpora/ast` |
| USER Memory | `scope: user`, `module: memory`, `installation_id` | `v1/installations/{installation}/users/{namespace}/corpora/memory` |
| Global Hub | `scope: hub`, `module: hub` | `v1/hub/global/registry`, `v1/hub/global/rules` |

PROJECT rejects `installation_id`. USER rejects `project_id`; installation IDs
are 1–128 ASCII bytes, start/end alphanumeric, and otherwise allow alphanumeric,
dot, underscore and hyphen. The USER namespace derives from the authenticated
issuer and subject using the existing domain-separated, length-prefixed SHA-256
scheme. No body subject can choose another owner. Global Hub rejects both
identifiers and additionally needs a matching nonPROJECT Hub-capable rule.
PROJECT Hub has four roots; Global Hub has two.

For example, an authenticated caller selects USER Memory with:

~~~json
{"scope":"user","module":"memory","installation_id":"workstation-1"}
~~~

Only the strict object shape is accepted. Duplicate/unknown fields, arrays,
missing required fields and explicit null/non-string identifiers fail decoding.
Unsupported scope/module combinations fail scope validation. The body cap and
Original still apply when the body arrives across awaits.

## Shared principal, operation, prefix and route policy

The common Hub matcher treats authenticated identity values literally. A
glob-looking username, subject, organization or team is not a principal
expression. Rule project selectors and capability/operation patterns retain
their existing grammar. Matching `s3` or the corresponding `s3:read`,
`s3:write`, `s3:publish` and `s3:delete` capabilities supplies the four operation
masks; `s3_operations` further restricts them. Hub discovery alone grants no
S3 operation.

Only rules contributing an allowed operation and a nonempty confined prefix
select routes. Empty rule prefix lists select the server roots. Templates may
use `{project}`, `{username}`, `{organization}` and `{subject}`; unsafe values
or malformed paths fail policy validation. A nonPROJECT scope causes templates
containing `{project}` to contribute nothing. Slash-boundary intersection narrows
an ancestor to the root, retains confined descendants and excludes siblings.
Request data cannot widen server roots.

Each contributing rule selects its trimmed `s3_route`, using the configured
default only when that rule's route is empty. Conflicting contributing routes
fail closed. Noncontributing rules do not choose a route. The mature service
dispatches only the admitted route; unknown routes or provider failures return
directly without another issuer attempt.

## Response, errors and recovery

The shared encoder has fourteen required fields:
`access_key_id`, `secret_access_key`, `session_token`, `expires_at`, `bucket`,
`region`, `endpoint`, `conditional_delete`, `copy_if_not_exists`, `prefixes`,
`authorization_revision`, `scope`, `project_id` and `module`.
USER Memory adds `installation_id` as field fifteen. Global Hub stays at
fourteen. Both capability fields are mandatory, including false/unsupported
values. Revision is a positive decimal string; `prefixes` contains the admitted
issuer base prefix. Absent endpoint and nonPROJECT project ID retain their
empty-string wire values. Expiry comes from the issuer. The existing response
buffer zeroizes secrets and responses carry `Cache-Control: no-store`.

| Condition | HTTP result / finite code |
| --- | --- |
| Capability disabled | 404 `capability_disabled` |
| Invalid/expired bearer | 401 via shared authentication mapper |
| Required scope absent | 403 `insufficient_scope` |
| No contributing ACL permission | 403 `forbidden` |
| Bad object / resource selection | 400 `invalid_json` / `invalid_scope` |
| Body over cap | 413 `body_too_large` |
| Deadline elapsed | 504 `deadline` |
| Grant cap/decode/corruption or unavailable SQL | shared Control mapping, normally 503 `authorization_unavailable`; deadlines retain 504 |
| Configuration / authentication configuration | 503 `configuration_unavailable` / `authentication_unavailable` |
| Policy invalid / conflicting routes | 503 `invalid_policy` / `conflicting_routes` |
| Route absent / policy too large | 503 `route_unavailable` / `policy_too_large` |
| Issuer refuses grant | 502 `storage_credentials_refused` |
| Provider / SDK | 502 `credential_provider_unavailable` / `storage_credentials_unavailable` |
| Invalid provider output / serialization | 502 `invalid_credentials` / 503 `response_unavailable` |

LOCAL authentication retains its existing current-state mapper and finite
status/code choices. Errors reveal no SQL, raw proof or provider secret.
Correct the credential, request or configuration according to the error.
A final proof/deadline failure releases no credential, but consumers must not
infer that an issuer session was rolled back or invoke an invented replay or
revocation protocol.

## Sources and verification boundary

Product Source:
[SQLite admission](../crates/broker-control/src/sqlite/flow/storage_admission.rs)
and [Presence backend](../crates/broker-presence/src/storage_credentials.rs).
Shared consumers are the
[proof and scope types](../crates/broker-control/src/storage_admission.rs),
[storage policy](../crates/broker-control/src/storage_policy.rs),
[principal policy](../crates/broker-control/src/resource_policy.rs) and
[storage service](../crates/broker-storage/src/service.rs).

The SQLite gate includes `sqlite_storage_admission` and `sqlite_storage_credentials_http`. These have separate Control and HTTP cases; global Server integration and Hub resolve/catalog require their own consumers.

The [Hub admission](rust-hub-storage-admission.md), [Hub HTTP](rust-hub-storage-credentials-http.md), [PROJECT HTTP](rust-project-corpus-storage-credentials-http.md), [USER Memory HTTP](rust-user-memory-storage-credentials-http.md) and [Global Hub HTTP](rust-global-hub-storage-credentials-http.md) guides describe shared policy, issuer and encoding contracts.

The two new targets are `sqlite_storage_admission` in broker-control and
`sqlite_storage_credentials_http` in broker-presence. Planned commands from the
Broker repository root are:

~~~text
cargo test --locked --offline -j4 -p broker-control --test sqlite_storage_admission -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_storage_credentials_http -- --ignored --test-threads=1
~~~

The five distinct new cases cover real native
JWT, opaque human/service possession verified by productive
`SqliteLocalBearerVerifier` over controlled SQL/HMAC/CSPRNG fixture state,
private SQLite/reopen, exact-factory rejection, all seven scopes, fresh
ACL/revision, literal principals, operations/prefixes/routes, caps/corruption,
Original and proof expiry, real TCP, and actual credential issuance/encoding
through the mature service with a Filesystem issuer. This opaque fixture proves
admission of genuine possession; it does not prove a public SQLite bearer
issuance producer. That producer was not found by the bounded investigation,
and the administrative user/service-credential family has another owner under
the global work. No local emitter or fallback is introduced here.

### Expiry and serialization checks

The new SQLite HTTP cases delay the BODY and show that already-issued
credentials survive later authentication/ACL changes. They do not expire the
proof during a pending issuer call. That causal coverage is reused explicitly
from the unchanged mature paths:

Issuer tests cover genuine grants whose JWT expires while MinIO is paused during `issue`, timeout, future drop and pending-provider HTTP timeout without issuer or route fallback. These behaviors have their own storage and HTTP test targets.

Synchronous serialization has no dedicated causal runtime test here. `storage_credentials.rs` checks grants before the issuer, after its await, after encoding and after headers; `broker-storage/src/service.rs` checks before and after every dispatch.

Library tests do not establish other-platform execution, global Server selection or F1/cookie ingress. Those consumers have separate validation boundaries.
