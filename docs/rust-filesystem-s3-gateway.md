---
references:
  - target:
      type: task
      id: tsk-4552
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-f7f9
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-700b
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
  - target:
      type: task
      id: tsk-6b60
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
  - target:
      type: task
      id: tsk-d646
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
  - target:
      type: task
      id: tsk-d74c
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
---
# Native Rust filesystem S3 gateway

Audience: Broker server integrators and maintainers. `FilesystemGateway` exposes the native filesystem components through S3s 0.17 and actual SigV4. Its TCP fixture uses production PostgreSQL admission and MAC session issuance. Mixed HTTP composition, deployment, client cutover and whole-migration integration have independent qualification.

The [mixed storage service](rust-storage-credentials-service.md) composes the same
issuer with Presence HTTP adapters. Its factory validates the exact configured
store set; its adapter shutdown joins gateway IO. The enclosing server owns
listeners and connection lifetimes.

## Compose the server component

Open each [native volume](rust-filesystem-object-store.md) once and construct the [filesystem issuer](rust-filesystem-storage-session.md) from trusted configured routes and pepper. Pass the issuer, matching `Arc<FilesystemStore>` values and `FilesystemGatewayConfig` to `FilesystemGateway::new`. The gateway requires one store for every issuer route, unique buckets, a positive request timeout, a nonzero request-head byte budget and a token-header budget that fits that ingress budget. Region is validated through S3s. Configuration has no gateway defaults.

`handle(HttpRequest<s3s::Body>, original_deadline)` returns the S3s HTTP response or an HTTP stream error. A Hyper caller can map its incoming body through `s3s::Body::http_body_unsync`; preserve the original accepted-request deadline. The gateway selects only a configured bucket from a path-style URL, `<endpoint>/<bucket>/<key>`. It provides no fallback HTTP router or ambient storage writer. The enclosing server owns HTTP admission and connection lifetimes.

The gateway consumes its actual head budget across URI and headers. XML has a 1 MiB parsing budget; decoded object and part bytes use the configured volume limit. The parser's chunk limit is bounded by that same object limit. These do not change authentication TTL, storage-session duration, grants or per-user quotas. The [server compositor](configuration.md#the-filesystem-driver) supplies existing configuration defaults.

## Authenticate each request

Require one nonempty `x-amz-security-token` header and unique Authorization, Host, `x-amz-date` and payload-hash headers. Reject presigned/query credentials and ambiguous headers. S3s parses the actual access key; the request-scoped provider verifies the native MAC, route, access-key binding and expiry before returning only its derived secret. S3s then checks the actual signature. `S3Access` requires signed credentials and the matching bucket/operation/key before inserting a private request-bound proof. Every backend handler requires that same proof and rechecks the native request constraints.

Signature V2, presigned URLs and POST-form signatures are disabled. The configured region and service `s3` are explicit. Wrong region produces `AuthorizationHeaderMalformed`; an unsupported signing service produces S3s `NotImplemented` (501). Anonymous, malformed, expired or misbound credentials cannot reach filesystem effects. Header SigV4 with `UNSIGNED-PAYLOAD` remains supported. Native session snapshot/renewal/rotation rules remain those of the issuer; MAC verification alone never authorizes an unsigned request.

## Operations and payload integrity

| Operation | Native behavior |
|---|---|
| GET / HEAD | Actual file metadata, quoted SHA256 ETag, Content-Type and mtime; normal/suffix ranges and full-covering Range return 206. Conditional reads return 304/412 and invalid ranges return 416. HTTP dates compare at second precision, including dates before 1970. |
| PUT | Stream the decoded body, validate EOF, then use bounded staging and target CAS. |
| COPY | Require source read and target write independently, preserve raw bytes/Content-Type and source/target conditions within one bucket. |
| ListObjectsV2 | Native prefix/delimiter/cursor pagination. URL-encoded keys/common prefixes are serialized once; cursors supply no authority. |
| DELETE | Per-key Delete permission. Optional If-Match checks the current ETag under the PUT key guard; success204, precondition failure412. Missing objects are idempotent only on the unconditional path. |
| DeleteObjects | Unchanged per-key unconditional deletion, mixed results and quiet mode. XML integrity is verified before batch effects. |
| Multipart | Create, upload/list parts, complete and abort through the [native multipart contract](rust-filesystem-multipart.md), including actual ETags, ordering, aggregate limits, target CAS and renewal on the same key. |
| GetBucketLocation | Authenticated lookup of the configured bucket/region. |

### Conditional DeleteObject

`DeleteObject` now accepts `If-Match` through the existing conditions codec and calls the store's [conditional delete](rust-filesystem-object-store.md#conditional-deletion-by-current-etag). Native Delete permission is sufficient; no Read grant or public HEAD is added. Matching uses the native quoted SHA256 ETag literally, including its quotes; the existing matcher only splits commas and trims alternatives. `*` requires an existing object. Native absence or mismatch returns412 with the existing `PreconditionFailed` XML code and preserves data/metadata. No condition keeps the previous idempotent delete path.

Success returns the existing empty DeleteObject output/HTTP204. `version_id`, `if_match_size` and `if_match_last_modified_time` remain501/NotImplemented; no unsupported condition is silently ignored. The [AWS DeleteObject reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html) describes the conditional header; [RFC9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match) specifies current-representation matching. This page states the native behavior, not complete AWS feature equivalence. MAC, SigV4, request proof and owned IO checks are unchanged. The real IO result and any `CommitUncertain` cause survive post-effect failure; no outer timeout substitutes a rollback/no-effect result.

S3s `UploadStream` verifies ordinary signed body hashes; its decoder verifies signed chunks and trailer signatures. The backend additionally computes declared Content-MD5/checksum headers and trailer values with S3s `ChecksumHasher`, then compares them at EOF before object or part publication. Signed and unsigned checksum trailers are supported. A correct trailer signature with a false content checksum still fails `BadDigest`. Decoder errors retain the library's typed S3 code and actual cause. XML digest expectations use a private request-bound EOF result checked before backend effects. Payload files contain decoded raw bytes, with no chunk or XML framing.

Versioning, bucket management, cross-bucket COPY and UploadPartCopy return `NotImplemented`. Unsupported AWS owner/account expectations, GET response overrides, requester-payer, authored Cache-Control/Content-Disposition/Content-Language/Expires or non-framing Content-Encoding, and metadata/ACL/encryption/object-lock/tagging/storage-class extensions and extra multipart checksum expectations also return `NotImplemented`; the gateway supplies no invented AWS owner or new metadata format. XML aws-chunked and POST-form uploads are outside the active protocol contract. PUT/UploadPart signed chunks remain active.

## Cancellation and uncertain outcomes

The effective deadline is the minimum of Original, the explicit gateway timeout and the session's already-captured monotonic lifetime. UTC expiry is checked too. Input/output body frames check those constraints before and after polling and retain mature timer/cancellation futures so a stalled body wakes. A successful buffered response gets a final validity check before its headers leave `handle`. Dropping a response body cancels that request.

All blocking IO is owned by `TaskTracker`; admission and closing use one mutex to prevent work from entering after shutdown closes admission. A mutator retains and awaits its actual IO result instead of abandoning its join handle at an outer timeout. GET retains its file while tracked chunks are read. `shutdown(original_deadline)` cancels requests and waits for tracked IO; an elapsed shutdown deadline is a real `ShutdownTimeout`. The enclosing HTTP server must close admission and join/drop its connections before releasing the volume.

Checks do not interrupt kernel IO or promise that the last response byte arrives before expiry. Publication and authored metadata are separate atomic/synced steps under the [native object contract](rust-filesystem-object-store.md). A post-publication failure retains `CommitUncertain` and its actual cause, exposed as an S3 server error. Read the target before retrying an uncertain mutation; a disconnected or timed-out request is not proof of rollback.

## Verification

New assertions use the existing PostgreSQL admission, real MAC session and SigV4 TCP fixture: ETag mismatch/stale-after-PUT preservation, wildcard existing/missing, Delete-only with Read denied, invalid token/signature, and unsupported version/size/mtime conditions. The fixture extends existing coverage rather than adding a selector, hook, fake authority or new metadata format. Other platforms and actual Hub consumers require separate tests.

Source: `crates/broker-storage/src/filesystem_gateway.rs`, consumed private issuer/deadline accessors in `filesystem_session.rs` and the native object/listing/multipart components. Fixture: `crates/broker-storage/tests/filesystem_s3_gateway.rs`.

Run unchanged on supported hosts:

```text
cargo test --locked --offline -p broker-storage --test filesystem_s3_gateway -- --ignored --exact filesystem_s3_gateway_postgres_contract --test-threads=1
```

Resolve/fetch locked dependencies normally before an offline run. The real fixture uses PostgreSQL TLS/NOSUPERUSER, Native JWT admission, MAC issuance, Hyper TCP, the official AWS header signer and mature S3s chunk/trailer signing/XML support. It checks active operations, raw bytes, ranges/conditions/pre-epoch dates, prefix boundaries, COPY/batch/multipart, checksum/header/trailer tampering, credential binding/expiry/renewal/pepper, request budgets, ambiguous/query/unsigned credentials, Original frame expiry and a stalled TCP PUT whose shutdown joins IO and cleans its stage. A library or signer probe is not substituted for this fixture.

The long hook's exact `FILESYSTEM_S3_GATEWAY` phase follows native multipart and precedes audit. Linux execution establishes this fixture's native server protocol behavior; Windows/macOS, actual client cutover and integrated mixed HTTP serving require their own executions.
