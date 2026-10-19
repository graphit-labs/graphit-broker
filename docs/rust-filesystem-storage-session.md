---
references:
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target:
      type: task
      id: tsk-700b
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-8914
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
---
# Native Rust filesystem storage sessions

Audience: Broker maintainers and server integrators. `broker-storage` emits and verifies native filesystem credentials from actual SQL storage admission. The filesystem object backend, S3 gateway and mixed HTTP composition have separate deliveries; this library does not establish that those components or the migration are complete.

The [mixed storage service](rust-storage-credentials-service.md) composes the same
issuer with Presence HTTP adapters. Its factory validates the exact configured
store set; its adapter shutdown joins gateway IO. The enclosing server owns
listeners and connection lifetimes.

## Issuance and configuration

Build `FilesystemStorageRouteConfig` with an explicit name, DNS bucket, region, base prefix, endpoint origin, session duration and security-token header budget. `FilesystemStorageRoute::new` validates these fields. The endpoint requires HTTPS except on loopback and cannot contain credentials, a path, query or fragment. Buckets cannot shadow Broker paths. Durations must be integral seconds between 900 and 43200. The library supplies no defaults; the server compositor owns active configuration defaults. `token_bytes` is the actual permitted security-token header size, not a capacity reservation.

`FilesystemStorageIssuer::new` consumes configured routes and a `Zeroizing<Vec<u8>>` pepper containing at least 32 bytes. Empty topology, duplicate route names and duplicate filesystem buckets fail configuration. Supply the configured pepper directly; no environment lookup or public pepper getter is involved. Keep the same key material available to processes that must verify the same sessions. Rotation invalidates existing sessions; there is no key history or fallback verifier.

Call `issue(&AuthorizedStorageGrant).await` with the private grant from the [SQL storage admission factory](rust-hub-storage-admission.md). Admission still authenticates the caller and uses current grants. Issuance checks the original request before and after work, selects exactly `grant.route()`, applies the base prefix once, and retains the complete four operation vectors, canonical subject, PROJECT/USER/Global Hub scope, module and SQL authorization revision. An unknown route fails without trying another issuer.

The result is `IssuedStorageCredentials`, shared with the [AWS issuer](rust-hub-storage-aws.md). Its borrowed getters expose client credential DATA; it has no `Clone`, `Default` or deserializer and its debug output is redacted. DATA cannot construct admission or a verified session. The fourteen/fifteen-field HTTP scope contracts are described in the [HTTP API](api.md#temporary-s3-credentials) and consumed by the [mixed service](rust-storage-credentials-service.md). Filesystem credentials expose `supports_conditional_delete() == true` because the native backend enforces atomic conditional DELETE. The required `copy_if_not_exists` strategy is `if_none_match`, selecting the mature SDK's conditional CopyObject path. Neither capability grants an operation or changes the session payload.

## Native token and verification

The native token is `rust-fs1.<base64url JSON>.<base64url MAC>` without padding. Its closed private payload binds the random access key, configured route/bucket/region, subject, scope/module, revision, issue/expiry times and all physical prefixes. HMAC-SHA256 authenticates the length-framed payload under `graphit-broker/rust-filesystem-session/v1` with a terminal NUL. A distinct `graphit-broker/rust-filesystem-secret/v1` domain derives the secret from length-framed access-key and authenticated MAC bytes. The maintained HMAC library performs constant-time verification. This is a native format with no older-format decoder or importer.

`verify_session(route, access_key, token)` checks the input budget and MAC before JSON decoding, then validates closed fields, canonical scope, time, route/bucket/region and access-key binding. It produces `VerifiedFilesystemSession` with private fields, no deserializer/clone/default, redacted debug output and a zeroizing secret. Its scope is resource DATA and its proof is specific to filesystem session verification; it is not a reusable SQL grant. The gateway must additionally verify the actual SigV4 request through S3s. MAC verification alone does not authenticate an S3 request.

`check(original_deadline)` enforces UTC expiry and the remaining lifetime captured as a monotonic deadline. A backwards wall-clock change cannot extend that captured lifetime. Storage expiry is independent of the JWT that authorized issuance. Sessions retain their admission snapshot until expiry; account/grant changes are checked on subsequent issuance, without a SQL session table or per-object admission RPC. No immediate storage-session revocation or last-byte delivery guarantee is promised.

## Operations and failures

| Admitted operation | Filesystem permissions |
|---|---|
| read | Read and list beneath its prefixes |
| write | Read, write, list and multipart beneath its prefixes |
| publish | Read, write, delete, list and multipart beneath its prefixes |
| delete | Delete beneath its prefixes |

Object keys must be 1–1024 ASCII bytes without backslash, quotes, empty path segments, `.` or `..`. Prefix matching accepts the exact root or descendants separated by `/`; adjacent names never match. Listing requires an explicit permitted prefix. A resource scope or client response cannot widen these masks.

Invalid configuration, unknown routes, oversized session credentials and admission failures remain typed `StorageIssueError` results. Verification returns static, redacted `FilesystemSessionError` values for malformed/misbound tokens, expiry, request deadline, unavailable routes or cryptography failure. Consumers must not log tokens, secrets or pepper when handling errors.

## Verification

Production sources are `crates/broker-storage/src/filesystem_session.rs` and `issued.rs`. Unit tests cover configuration, native MAC/access-key binding, rotation, expiry/deadline, operation union, prefix boundaries and authenticated malformed payloads. Compile-fail examples exercise private construction and unavailable restoration/clone/default paths.

Run `cargo test --locked -p broker-storage --all-targets` for ordinary tests. The real PostgreSQL TLS fixture is `cargo test --locked -p broker-storage --test filesystem_sessions -- --ignored --exact filesystem_sessions_postgres_contract --test-threads=1`. It uses a NOSUPERUSER store, Native JWT and actual opaque access/service callers, all five PROJECT modules, USER Memory and Global Hub, and four operation masks. The parent fixture also passes the issued token through stdin to an independent process using the same configured key; no credentials are placed in child arguments. The saved `FILESYSTEM_SESSION` phase runs this fixture before audit in the long hook; it is not a gateway or client interoperability qualification.
