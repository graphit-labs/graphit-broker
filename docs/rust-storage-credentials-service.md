---
title: Rust mixed storage credentials service
doc_type: reference
references:
  - target: {type: task, id: tsk-c055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8914, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-f7f9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust mixed storage credentials service

For Broker server integrators. `StorageCredentialsService` composes AWS and
filesystem issuers while preserving [SQL storage admission](rust-hub-storage-admission.md).
Its public configuration enum is closed:
`StorageIssuer::Aws(AwsStorageIssuer)` or
`StorageIssuer::Filesystem(FilesystemStorageIssuer)`. Supply a nonempty vector
to `StorageCredentialsService::new`; names must be unique across all issuers,
and filesystem buckets must be unique across all filesystem issuers. AWS remote
buckets retain their own topology. Configuration supplies every issuer field;
the library creates no provider, endpoint, pepper or duration default.

The [native PostgreSQL server](rust-broker-server.md) now owns a productive listener and consumes this service, composed JWT/local ingress and filesystem IO shutdown.

The explicit [SQLite storage admission and HTTP composition](rust-sqlite-storage-admission.md)
uses current native JWT or verified opaque possession and the same protected grant,
route policy, credential service and issuers. Its separate receipt records the
SQLite SQL/TCP qualification and reused issuer evidence. This composition does not
issue human bearer credentials or select SQLite globally in Server.

## Select a route from authority

`issue(&AuthorizedStorageGrant)` selects the configured issuer solely from
the current private grant's route. An unknown route returns `RouteUnavailable`.
A selected provider's error is returned directly; the service does not try another
route or driver. The grant is checked before dispatch and after its result.
The [AWS issuer](rust-hub-storage-aws.md) and
[filesystem issuer](rust-filesystem-storage-session.md) keep their existing
scope, operation, prefix, duration, redaction and request-lifetime contracts.

Both HTTP credentials constructors now receive
`Option<Arc<StorageCredentialsService>>`. A service with only
`StorageIssuer::Aws` is an explicit AWS configuration. Disabled capability,
authentication before body parsing, strict JSON, current SQL admission, Original,
status mappings and the fourteen/fifteen response fields are those of the
[Hub](rust-hub-storage-credentials-http.md),
[PROJECT](rust-project-corpus-storage-credentials-http.md),
[USER](rust-user-memory-storage-credentials-http.md) and
[global Hub](rust-global-hub-storage-credentials-http.md) HTTP contracts.
Changing a SQL route changes a fresh issuance. Previously issued sessions retain
their captured authority until their own expiry; changing the SQL route does not
revoke them or transfer objects to another driver.

## Compose filesystem HTTP

Open native volumes once, then call
`service.filesystem_gateways(stores, FilesystemGatewayConfig)` with exactly one
store for every configured filesystem bucket. Missing, duplicate or extra stores
fail configuration. All gateways share the precise private issuer instance used
for credential issuance. An AWS-only service accepts no stores and produces an
empty gateway vector. The explicit gateway timeout must still be valid.

Construct `FilesystemStorageHttp::new(gateways, request_timeout)` in Presence,
using `Arc` gateway values and a positive HTTP timeout. `router()` registers only
the configured bucket roots with and without a trailing slash, plus key wildcard
routes. Merge this router into the
server with its credentials router. It forwards method, URI, headers and body
through Axum and S3s without buffering the object or normalizing its key. Bucket
observers register trusted topology; a name is never authority to access data.
The [S3 gateway](rust-filesystem-s3-gateway.md) verifies MAC and actual SigV4
before any filesystem effect.

The adapter captures an HTTP deadline at handler entry and the gateway limits
that deadline by its own configured budget and the captured session lifetime.
`shutdown(original_deadline)` closes adapter admission and awaits every gateway's
tracked IO with that same deadline, including when another gateway reports an
error. New requests receive S3 `ServiceUnavailable`. The enclosing server owns
listeners and connection bodies: stop accepting connections, initiate adapter
shutdown, and join/drop owned connections before releasing volumes. An elapsed
IO shutdown is a real error. No outer timer may abandon a mutator's result or
claim rollback after an uncertain publication.

Root server composition, production listener/configuration integration and native
client cutover are separate consumers. This component introduces no authentication
TTL, quota, UserInfo requirement or new filesystem metadata format.

## Verification

Source: `crates/broker-storage/src/service.rs`, the consumed AWS route observer,
the gateway bucket observer, and Presence's `storage_credentials.rs` and
`filesystem_storage.rs`. The focused integration fixture is
`crates/broker-presence/tests/mixed_storage_credentials_http.rs`:

```text
cargo test --locked --offline -p broker-presence --test mixed_storage_credentials_http -- --ignored --exact mixed_storage_credentials_http_contract --test-threads=1
```

Resolve/fetch locked dependencies before an offline execution. The fixture uses
PostgreSQL TLS under a NOSUPERUSER role, real Native JWT and opaque access/service
admission, actual AWS SDK issuance against owned MinIO STS through an observed
loopback HTTP endpoint, and S3 SDK requests against native filesystem TCP. STS TLS
is not executed by this fixture; production TLS configuration is preserved.
The fixture's current execution evidence belongs to its Task; a command or source
inspection alone does not qualify its behavior. The final integrated Broker and
native clients require their own executions.

The long hook runs the exact `MIXED_STORAGE_HTTP_STS` phase after
`FILESYSTEM_S3_GATEWAY` and before audit. Its failure barrier is verified separately
with the current versioned runner and a real failing Rust test; earlier fake runner
phases provide no product proof. No Git push is needed to execute that counterproof.

The current focused mixed contract passed on Linux in `tsk-b72e`, together with
the five affected HTTP/STS/S3 regressions, scoped strict Clippy, documentation
tests, formatting and the saved phase failure barrier. Receipts, source hashes
and preserved earlier attempts are under
`.build/rust-mixed-storage-service-2026-10-13/qualification.json`. This qualifies
the composed server component, not RootMain or a native client migration.
