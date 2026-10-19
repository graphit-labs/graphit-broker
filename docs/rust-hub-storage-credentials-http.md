---
title: Rust Hub storage credentials HTTP
doc_type: reference
references:
  - target: {type: task, id: tsk-c055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-7cdb, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b770, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-80f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e612, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-81ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust Hub storage credentials HTTP

For Broker server integrators and Hub project publishers. The Rust route consumes
actual [SQL storage admission](rust-hub-storage-admission.md) and the qualified
[mixed storage service](rust-storage-credentials-service.md), with its configured
[AWS](rust-hub-storage-aws.md) or filesystem issuer. This page focuses on
project/module Hub. The same generic router now also accepts
[PROJECT corpus bodies](rust-project-corpus-storage-credentials-http.md), with their
own HTTP/STS/S3 qualification. [USER Memory](rust-user-memory-storage-credentials-http.md)
has its distinct fifteen-field response. [Global Hub](rust-global-hub-storage-credentials-http.md)
uses its strict two-field body and fourteen-field response. The [Native server](rust-broker-server.md) composes these routers from its prepared
configuration.

The explicit [SQLite storage admission and HTTP composition](rust-sqlite-storage-admission.md)
uses current native JWT or verified opaque possession and the same protected grant,
route policy, credential service and issuers. This composition does not
issue human bearer credentials or select SQLite globally in Server.

## Integrate the router

`broker_storage_credentials_router(store, verifier, issuer, config)` takes the
shared `Arc<PostgresControlStore>`, actual trusted `Arc<BrokerAccessVerifier>`,
`Option<Arc<StorageCredentialsService>>` and `BrokerStorageCredentialsHttpConfig`.
`local_storage_credentials_router(store, issuer, config)` uses current opaque
SQL identity with `LocalStorageCredentialsHttpConfig`. Modes are explicit;
credentials are never probed against another mode or provider after failure.
Listeners, graceful shutdown and the shared SQL store belong to the application.

Native config requires `required_scopes`, `grants_json_bytes`, `default_route`,
`body_bytes`, `request_timeout`, `enabled`. Opaque config additionally requires
`audience` and `identity_json_bytes`. Caps are positive `NonZeroUsize`, budgets
are positive representable `Duration`, scopes cannot contain blank entries.
Empty scope lists add no inferred purpose scope; current SQL capability admission
still applies. No config implements Default; Debug and config errors are finite
and redacted. The Native verifier owns trusted signing keys, issuer, audience,
optional resource, purpose/type and its own token byte cap.

Enabled configuration requires `Some(issuer)` and valid admission-factory inputs.
Enabled with `None` fails construction. Disabled accepts `None`, empty route and
inactive opaque audience without fabricating AWS topology or a store. Its route
returns 404 `capability_disabled` before Bearer, body, authentication, SQL or AWS
work. Generic transport caps/budgets remain explicit. Caller-supplied route,
provider or topology cannot enable the service.

Standalone routers use finite JSON 404/405 fallbacks and `Cache-Control: no-store`
on every response. Compose them with the application's route topology rather
than blindly merging multiple standalone routers with conflicting fallbacks.
The library does not advertise `graphit-s3-credentials-v3` in discovery; discovery
is a separate server composition responsibility.

## Request and response

POST `/v1/s3/credentials` with exactly one `Authorization: Bearer ...` header and
`Content-Type: application/json`. Query credentials are not used. The complete
request is:

```json
{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub"}
```

The root must be an object. Unknown, duplicate, missing, positional and trailing
values fail. Strings are exact and the project must be a canonical nonzero ULID.
The body cannot choose operation, prefix, policy, route, role, bucket, endpoint,
provider, duration, identity or authentication mode. Unknown or incompatible scope/module pairs are rejected;
[USER Memory](rust-user-memory-storage-credentials-http.md) uses a separate strict
installation body through this generic route. [Global Hub](rust-global-hub-storage-credentials-http.md)
uses scope/module hub without project or installation IDs.

Authenticate before decoding or waiting for the body. The handler keeps the
actual factory alive and consumes its private authenticated caller to perform
fresh whole-policy SQL admission. A scope identifier or DTO is DATA; it cannot
construct an authenticated caller or grant. Operations and four Hub PROJECT roots come from actual admission: preserved
`v1/projects/{project}/registry` and `v1/projects/{project}/artifacts`, plus
`v1/projects/{project}/hub/metadata` and `v1/projects/{project}/hub/events`.
The [metadata/events extension](rust-project-hub-metadata-events-storage.md)
retains this body and fourteen-field response; the decoder does not grant roots.

200 JSON has exactly fourteen fields:

| Field | Meaning |
| --- | --- |
| `access_key_id`, `secret_access_key`, `session_token` | Actual temporary credentials from the selected issuer; not parent route credentials. |
| `expires_at` | Actual RFC3339 UTC storage-session expiration. |
| `bucket`, `region`, `endpoint` | Configured provider topology; standard AWS endpoint is an empty string. |
| `prefixes` | Array containing the configured provider base prefix. |
| `conditional_delete` | Required boolean backend capability for atomic `If-Match` DELETE; it grants no permission. |
| `copy_if_not_exists` | Required enum: `multipart` for S3, `if_none_match` for Filesystem; selects create-only SDK copy independently of Delete. |
| `authorization_revision` | Positive SQL authorization revision as an unsigned decimal string. |
| `scope`, `project_id`, `module` | `project`, actual admitted project and `hub`. |

The response contains no canonical subject, permanent credential, generated
policy or internal proof. Use all three temporary fields with the returned
provider topology. Object keys still need the admitted project's roots and
backend limits; this base-prefix metadata does not grant a broader object path.

## Conditional DELETE capability

Every successful Rust STSv3 response includes `conditional_delete` as a boolean.
S3 routes propagate their configuration; the server resolves an omitted S3 option
to `false`. Filesystem always returns `true` because its native backend enforces
atomic `If-Match` DELETE. The value is not inferred from an endpoint, brand,
credentials or a runtime probe, and it does not change SQL grants or IAM permissions.
A consumer must reject whole-artifact or final-version DELETE before an effect
when false; partial publication updates may still use conditional PUT. A separate
HEAD followed by DELETE is not equivalent.

The response field is required for every scope, including false. Consumers must not restore an omitted wire field through a compatibility default. PROJECT and global Hub have fourteen fields; USER Memory adds `installation_id` for fifteen.

## Create-only copy strategy

Every successful Rust response also requires `copy_if_not_exists`, a closed enum.
The S3 issuer emits `multipart`; the native Filesystem issuer emits `if_none_match`.
Consumers select the mature SDK strategies directly: multipart copy for S3,
or CopyObject with `If-None-Match: *` for Filesystem. An existing destination must
remain unchanged and report AlreadyExists. Filesystem does not implement UploadPartCopy.

This strategy is independent of `conditional_delete`, permissions, endpoints and operator configuration. It must not be inferred from the DELETE boolean or restored through an omitted wire default.

## Authentication, deadlines and credential lifetime

Native JWT validation is local against trusted keys and claims until expiration.
Account changes do not imply instant invalidation of an already trusted JWT.
Fresh SQL storage grants are independently required on every new request.
Opaque access/service credentials use actual current SQL identity at
request authentication, preserving their separate digest domains.

One original absolute deadline is captured at handler entry. Authentication and
admission retain their producer's actual UTC/monotonic proof window. Only SDK
body extraction has the HTTP input timeout; SQL owns its transaction/error
classification without an outer timer. The AWS producer bounds configuration,
credential discovery and SDK requests with its existing deadline. Private caller
checks run before and after body decoding, including negative decisions; grant
checks run before/after issuance and serialization. Neither phase renews the
original budget or constructs replacement proof clocks.

A late/invalid proof suppresses response construction. Hyper owns the subsequent
socket transfer; this library does not promise a formal last-byte-before-expiry
property or rollback of an AWS session that may already have been issued.
Dropping futures or disconnecting a client is not an AWS session revocation or a
guarantee that credential_process terminates physically. A broken input stream
fails decoding; every recovery request authenticates and reads policy again.

STS expiration is independent of the Broker JWT. Issued credentials can outlive
the JWT and subsequent SQL grant withdrawal. Consumers must respect AWS expiry;
no JWT clamp or instant revocation of an existing STS session is promised.

Owned raw bearer copies use `Zeroizing` and Authorization header values are marked
sensitive before decoding. Issued secrets remain private to the producer and
response path. Serialization borrows getters into one owned zeroizing buffer;
`axum::body::Bytes::from_owner` retains its owner until the final byte handle
is dropped. Third-party HTTP/SDK buffers have their own lifecycles; this is not
a universal physical memory-erasure claim. No driver/body/credential cause is
retained in finite public errors.

## Failures and recovery

All failures use `{"error":{"code":"finite_literal"}}` and no-store.

| Status/code | Meaning |
| --- | --- |
| 404 `capability_disabled` | Service disabled; configure the server to enable it. |
| 401 `unauthenticated` + Bearer challenge | Missing, duplicate, invalid, expired or wrong-mode credential. |
| 403 `insufficient_scope` + scope challenge | A valid Native JWT lacks configured purpose scope. |
| 400 `invalid_json` / `invalid_scope` | Fix request shape, project, scope or module. |
| 413 `body_too_large` | Respect the configured input cap. |
| 403 `forbidden` | Current whole storage ACL grants no matching authority. |
| 503 `invalid_policy` / `conflicting_routes` | Repair the server's whole stored policy or route selection. |
| 503 `configuration_unavailable` / `route_unavailable` / `policy_too_large` | Repair configured topology or the admitted policy; no fallback is selected. |
| 503 `authentication_unavailable` / `authorization_unavailable` | Restore the relevant identity/policy backend or repair malformed stored state/caps. SQL role privilege failure is a backend failure, not ACL denial. |
| 503 `closed` / `outcome_uncertain` | Preserve actual producer origin; restore the service or resolve the ambiguous outcome. |
| 502 `storage_credentials_refused` / `credential_provider_unavailable` / `storage_credentials_unavailable` / `invalid_credentials` | Actual AWS/provider/output failure. Resolve server configuration or availability; no automatic Broker replay. |
| 504 `deadline` | Original/proof/AWS budget expired; a new request starts a new operation. |
| 404 `not_found` / 405 `method_not_allowed` | Use the exact POST path. HEAD has no response body. |

## Verification and limits

The focused real command is:

```
cargo test --locked -j1 -p broker-presence --test storage_credentials_http hub_storage_credentials_http_postgres_sts_contract -- --ignored --exact --test-threads=1
```

The test uses actual TCP Axum/Hyper, PostgreSQL TLS under NOSUPERUSER, real JWT signature/claims and opaque access/service state, the pinned MinIO/mc fixture, actual AWS SDK AssumeRole and signed object_store operations. It checks mode/security/body/NoStore, current ACL/identity/route errors, role SQL denial, expiry/deadline/recovery and conditional/multipart storage. SDK DATA units provide separate decoder/error checks.

Linux fixture signals do not establish Windows/macOS proof. The emulator does
not qualify AWS IAM trust/role chaining, real SSO/process/ECS/IMDS deployments,
production TLS or a full session-expiry wait. The full migration integration
matrix remains a separate work unit. The [Native Hub process fixture](rust-hub-storage-fixture.md)
composes the public Native Resolve and STSv3 services for consumer tests;
native artifact publication and readers remain qualified by their consumers.
