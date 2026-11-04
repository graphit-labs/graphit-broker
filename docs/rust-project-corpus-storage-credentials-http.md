---
title: Rust PROJECT corpus storage credentials HTTP
doc_type: reference
references:
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-5976, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-aff6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4c48, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust PROJECT corpus storage credentials HTTP

For Broker server integrators and native corpus callers. The Rust HTTP router
accepts PROJECT Task, Memory, Knowledge, AST and Hub, then consumes the actual
[SQL grant](rust-project-corpus-storage-admission.md) and
[mixed storage service](rust-storage-credentials-service.md). The configured
AWS and filesystem issuers preserve the grant-derived scope. Qualification for this HTTP extension is
functionally qualified on Linux in `tsk-aff6` by the current real HTTP/STS/S3
contract. It does not qualify a remote native dataset. Earlier failing rounds
remain recorded with no cause attributed, as explained below. The [Hub HTTP guide](rust-hub-storage-credentials-http.md) explains
shared configuration, authentication, budgets, buffers and error behavior.

## Request and response

Send an authenticated POST to `/v1/s3/credentials`. Select the Native JWT router
`broker_storage_credentials_router` or the opaque access/service router
`local_storage_credentials_router` explicitly. Both authenticate before reading
the body and use one original deadline; they do not try another token format.
Disabled capability returns 404 before authentication, body, SQL or provider
activity; enabled configuration requires an issuer.

~~~json
{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task"}
~~~

Exactly one `scope`, canonical nonzero project ULID and `module` are required.
Module is exactly `task`, `memory`, `knowledge`, `ast` or `hub`; case aliases and
`dream` are not remote corpus names. Installation, issuer, subject, username,
instance, root, route, provider, operation and duration are not request fields.
Unknown, duplicate, missing, null, array or trailing fields fail after actual
authentication. A project/module is DATA identifying the resource; the actual
SQL principal, operations and contributing prefix rules must authorize it.

The response contains the fourteen fields documented in the [API](api.md):
`access_key_id`, `secret_access_key`, `session_token`, `expires_at`, `bucket`,
`region`, `endpoint`, `conditional_delete`, `copy_if_not_exists`, `prefixes`, `authorization_revision`, `scope`, `project_id`
and `module`. Scope is `project`, project is the admitted ID and module is taken
from the actual private grant, rather than a body echo or provider configuration.
Revision is a positive decimal string. The response is JSON with `no-store`;
credential bytes owned by the server use its private zeroizing body owner.
No installation, identity, policy, permanent credential or Auth token is returned.

## Object isolation

Each corpus uses the root defined by the [qualified SQL library](rust-project-corpus-storage-admission.md):
`v1/projects/{id}/corpora/{task|memory|knowledge|ast}`. Hub retains only
`v1/projects/{id}/registry` and `v1/projects/{id}/artifacts`. The physical provider
prefix is applied exactly once by the issuer. The qualified Code DATA URI helper
`tsk-c027` produces matching keys/URIs; it does not admit a caller or grant access.
Dataset branch selection and codecs remain with the native caller/SDK.

A broad project prefix is intersected with the admitted module's roots. It never
turns a Hub STS session into access to corpora, nor one corpus into another module,
sibling project, USER memory or global Hub. A read session may list its own prefix
and fetch objects; a write session adds conditional writes/multipart while still
excluding delete; publish adds deletion; delete-only does not grant read/list.
Actual operations follow the mature issuer's existing operation mapping.

Policy size, complete key bounds, route endpoints, explicit static credentials or
DefaultChain and the current 900–43200-second STS configuration are unchanged.
Grant expiry/deadline checks protect issuance; an already-issued STS session has
its fixed policy and may outlive the bearer or a later SQL withdrawal. This route
does not promise logout or socket loss will revoke that session.

## Errors and recovery

Bearer failures return 401; missing Native scope retains 403 and its challenge.
An ACL denial is 403. Invalid JSON/scope is 400 and an oversized body is 413.
Invalid whole policy, conflicting routes, unavailable configuration or causal SQL
failures retain 503. Actual AWS provider/service/output errors retain 502; deadline
is 504. Correct the actual identity/grant/route or backend before re-observing.
A previous response, DATA scope or URI is not authority for a new issuance.
SQL owns COMMIT uncertainty; no external timer/replay conceals its outcome.

## Qualification and persistent gate

The ignored corpus contract uses actual TCP, PostgreSQL TLS under a NOSUPERUSER
role, real EdDSA JWT and opaque access/service authentication, mature SDK STS and
signed S3 operations against owned MinIO. It checks all four corpora, twelve-field
wire, strict body/authentication ordering, sibling and Hub boundaries, actual
read/write/publish/delete, conditional writes/CAS/multipart, current ACL/identity,
invalid policy/route, expired requests and SQL/provider failure/recovery.
These are server/object-store checks, not Lance datasets or native caller codecs.

~~~text
cargo test --locked -p broker-presence --test project_corpus_storage_credentials_http -- --ignored --exact project_corpus_storage_credentials_http_contract --test-threads=1
cargo test --locked -j1 -p broker-presence -p broker-storage --all-targets
cargo test --locked -j1 -p broker-presence -p broker-storage --doc
cargo clippy --locked -j1 -p broker-presence -p broker-storage -p xtask --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

On Linux, the historical exact corpus qualification in `tsk-aff6` passed with one test and no failures
(runtime 271.94 seconds; wall 274.60 seconds). Earlier passing rounds took 48.48
and 223.03 seconds of test runtime. The affected Hub HTTP regression passed,
alongside 42 ordinary tests, 25 documentation tests, strict clippy and formatting.
The ignored contracts are qualified by their separate real runs, rather than
ordinary-suite skips.

Receipts and logs are retained under
`.build/rust-project-corpus-storage-http-2026-10-12/`. Earlier rounds failed in
S3 denial/CAS checks; their cause has not been established, and passing rounds
do not erase them. A too-specific bad-secret expectation was separately corrected
to the existing provider 502 contract. Credential-redacted error-chain diagnostics
and strict success/denial oracles remain in the fixture. The migration
coordinator reconciled the current functional qualification against passing
rounds 7/8 and the additional diagnostic round 9 (28.87 seconds test runtime),
without adding a repeated stability campaign as a gate. This qualifies the
current functional contract; it does not establish the cause or correction of
historical Generic failures, accept them as permission denials, or promise
universal runtime stability. A currently violated assertion would still block
the delivery.

The isolated runner counterproof used the actual saved selector, executor and
CLI failure loop. It selected the new phase while omitting earlier phases only
in that fixture; an actual ignored Rust assertion failure stopped it with exit 1
before the audit. This proves the runner barrier, not Broker backend behavior or
the entire qualification suite. Git hooks use the native Git registry.

The first exact command is the `PROJECT_CORPUS_HTTP_STS` qualification phase,
after the existing exact Hub AWS phase and before the USER Memory phase and
dependency audit. Other
phases, hooks and lockfiles stay intact. Ordinary tests remain in pre-commit.
The separate [USER SQL guide](rust-user-memory-storage-admission.md) describes
literal owner admission. The [USER HTTP guide](rust-user-memory-storage-credentials-http.md)
describes its separate installation body and fifteen-field response.
[Global Hub](rust-global-hub-storage-credentials-http.md), Hub metadata/events, native callers/datasets and final
migration integration have separate delivery/qualification. Platform proof is
recorded with actual results; no Windows/macOS success is inferred from Linux.

The causal regression in `tsk-5976` selects the mature signed S3 client's
`ClientOptions::with_pool_max_idle_per_host(0)` only in this fixture, retaining
zero retries, existing request/connect bounds and every functional/security
oracle. The original current regression failed with a SendRequest connection
closing before its expected S3 denial response completed; that failure remains
recorded without an established root cause. The explicit current test transport
qualifies actual protocol behavior without idle pooling, not pooled consumer
stability or a production/client transport default. Hub's unaffected passing
fixture retains its original transport.

The current `tsk-5976` causal PROJECT regression passed its exact real command
with all original oracles (34.49 seconds runtime, 36.64 seconds wall).
The prior current original-transport failure remains in that delivery's receipts.
