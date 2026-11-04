---
title: Rust AWS issuer for Hub storage
doc_type: reference
references:
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-80f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b770, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6488, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Rust AWS issuer for Hub storage

For Broker server integrators. `broker-storage` issues real temporary AWS STS
credentials from an actual [Hub storage grant](rust-hub-storage-admission.md).
The current Rust issuer passed the focused real STS/S3 contract on Linux.
A scope DTO, project identifier, bearer alone or read selector cannot replace the
private grant. HTTP delivery and the server configuration compositor are separate
work units. The issuer does not register a route or change SQL grants.
The generic `AuthorizedStorageGrant` also supports [PROJECT corpus SQL admission](rust-project-corpus-storage-admission.md);
[corpus HTTP/STS/S3 qualification](rust-project-corpus-storage-credentials-http.md) is a separate delivery.
The [USER Memory SQL library](rust-user-memory-storage-admission.md) adds actual
USER grants; their credential DATA project identifier is empty.
[USER HTTP/STS/S3 qualification](rust-user-memory-storage-credentials-http.md) is
separate, and this Hub issuer qualification does not establish it.

The issued credential DATA and errors now live in `crates/broker-storage/src/issued.rs` and keep their existing public exports and borrowed getters. The [native filesystem session issuer](rust-filesystem-storage-session.md) uses the same DATA boundary. This does not alter AWS provider discovery, STS policy or HTTP routing.

## Required configuration and ownership

Construct `AwsStorageRoute::new(AwsStorageRouteConfig { ... })` with explicit
`name`, `region`, `bucket`, `base_prefix`, `s3_endpoint`, `sts_endpoint`, `role_arn`,
`session_name`, `session_duration`, `credential_source`, `endpoint_transport`,
and `conditional_delete`.
All fields are required, even optional endpoint values. There is no `Default`.
The separate server compositor must supply the active region/session/duration
defaults and validate required topology before calling this library. Its
implementation is not delivered by this crate.

Route names, bucket literals and prefix segments reject wildcard, traversal and
unsafe path syntax. Base-prefix surrounding whitespace/slashes are normalized;
segments are explicit safe ASCII values. A complete admitted literal prefix,
including the base prefix, must fit the S3 1024-byte key limit. Future object
operations must also respect the backend's complete-key limit; IAM does not
truncate arbitrary future keys.

Session duration is a whole number of seconds in 900–43200, independently of the
Broker JWT lifetime. Session base names normalize surrounding whitespace, then
validate 2–64 AWS-safe ASCII characters. The final name trims peripheral `-_`,
keeps up to 47 base bytes and appends `-` plus the first eight SHA256 bytes of the
actual canonical subject as sixteen lowercase hexadecimal characters. Its maximum
is 64 bytes. No username, caller field or token becomes AWS parent credentials.

`AwsEndpointTransport::HttpsOnly` requires HTTPS for configured endpoints.
`LoopbackHttp` additionally allows HTTP only for `localhost` or IP loopback.
The mature URL parser rejects missing hosts, URL credentials, invalid schemes,
query and fragment input. This policy never disables TLS verification. An
explicit STS endpoint wins; otherwise a supplied S3-compatible endpoint selects
STS; otherwise the SDK resolves its AWS service endpoint. Inherited
`AWS_ENDPOINT_URL_STS`/global/profile endpoint settings cannot silently select
this Role STS transport. Credential-provider discovery is separate SDK behavior;
this route policy does not qualify all SSO/web-identity/ECS/IMDS transport paths.

`AwsCredentialSource::StaticPair` accepts an indivisible
`PrivateStaticCredentials::new(Zeroizing<String>, Zeroizing<String>)` pair.
Failure never falls back to environment or another credential source. It builds
the service SDK configuration directly, without consulting personal AWS profiles.
`DefaultChain` explicitly selects mature SDK discovery, including environment,
session/shared profiles, web identity, ECS/IMDS, credential_process and SSO.
The shared SDK configuration is cached per route; its provider resolves current
credentials once per issuance. Provider discovery/fetch remains within the
operation's bounded future. No test changes the global process environment.

`AwsStorageIssuer::new(routes, request_timeout)` rejects duplicate route names,
empty route collections and zero/unrepresentable operation budgets. Route
configuration, credential sources, issuer and issued-result Debug are redacted.
Owned secret fields use `Zeroizing`; third-party SDK caches retain their own
lifecycle, without a promise of universal byte erasure.

`conditional_delete` explicitly declares whether the configured backend atomically
enforces `If-Match` on DELETE. It is copied to issued DATA through
`supports_conditional_delete()`; it does not grant Delete or modify the IAM policy.
The library neither detects an endpoint/brand nor probes that backend. The server
configuration defaults this S3 option to false. Set true only for a backend whose
atomic behavior has been established. The pinned MinIO fixture uses false; the
[native filesystem issuer](rust-filesystem-storage-session.md) reports true from
its implementation. Issued DATA additionally carries `copy_if_not_exists()`, a closed
`StorageCopyIfNotExists` enum. S3 always emits `Multipart` (wire `multipart`),
while Filesystem emits `IfNoneMatch` (wire `if_none_match`). This fixed SDK
strategy has no operator setting and is independent of the DELETE capability.

## Admit, issue and consume

Keep the actual configured admission factory alive through authentication,
current SQL authorization and issuance. Call:

```rust
# async fn issue(issuer: &broker_storage::AwsStorageIssuer,
# grant: &broker_control::AuthorizedStorageGrant<'_>) -> Result<(), broker_storage::StorageIssueError> {
grant.check()?;
let credentials = issuer.issue(grant).await?;
assert!(!credentials.session_token().is_empty());
# Ok(()) }
```

Every new request obtains a fresh grant. A retained observation does not cause
quiet instant revocation or replace fresh SQL policy checks. The issuer selects
only the configured name returned by that grant, and uses the grant's actual
operation-specific prefix observations, revision, project and canonical subject.
It never accepts route, bucket, policy, role, duration or prefix authority from
the HTTP caller.

The inline IAM policy adds the configured base prefix to each literal admitted
prefix. It grants GetBucketLocation and groups deterministic object resources by
operation actions. Read grants GetObject; Write additionally grants PutObject,
AbortMultipartUpload and ListMultipartUploadParts; Publish also grants
DeleteObject; Delete grants DeleteObject only. Read/Write/Publish listing is
limited by `StringLike s3:prefix` to exact roots and their descendants. Object
resources are exact root plus descendants. Empty access is forbidden; policy
encoding above 2048 UTF-8 bytes fails before STS. No broad bucket object wildcard,
custom SigV4 or fabricated admission is introduced.

The official `aws-sdk-sts=1.119.0` and `aws-config=1.12.0` use
`BehaviorVersion::v2026_01_12`. The SDK supplies standard retries, currently three
attempts total by default; DefaultChain honors supported SDK retry configuration.
The Broker adds no retry loop and never manually replays an uncertain issuance.
See [AWS retry configuration](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/retries.html).
All retries remain inside the original deadline. The explicit static branch uses
`RetryConfig::standard()` without inventing a new attempt count.

Issuance is bounded by the minimum of `grant.request_deadline()` and the explicit
issuer budget. Real grant checks run before/after policy, configuration, provider
and service boundaries, including final negative results. SDK service timeout
settings derive from the remaining budget. The outer timeout wraps AWS work,
never the qualified SQL reader. A late or invalid grant suppresses a successful
SDK response. Dropping the future does not revoke a possibly issued AWS session
or promise physical termination of credential_process.

A successful SDK response requires all three nonempty credential fields and a
representable future expiration. `IssuedStorageCredentials` exposes explicit
access-key, secret, session-token and RFC3339 UTC expiry getters plus actual
bucket, region, endpoint, base prefix, project and authorization revision.
It has no Clone, Default or Deserialize. It is AWS credential DATA, not a
constructor for Broker admission. Permanent route credentials and the generated
policy are never returned. The separate HTTP delivery must serialize the v3 wire scope/module/revision-string
fields and `Cache-Control: no-store`; this issuer does not provide that endpoint.

STS expiry may outlive a ten-minute JWT and subsequent grant withdrawal; there
is no JWT clamp or promise to revoke already issued sessions. Services and callers
must enforce the returned AWS expiry when using or caching these credentials.

## Failures and qualification

Finite `StorageIssueError` values preserve the actual `Admission` origin and
otherwise distinguish InvalidConfiguration, RouteUnavailable, PolicyTooLarge,
Forbidden, Deadline, Provider, Sdk and InvalidResponse. Actual SDK timeout maps to
Deadline. Errors retain no SDK cause/body/credential and have no Error source.
Service refusal and storage/transport failure are not treated as successful empty
credentials. Admission Original/expiry is checked again before an error escapes.

The focused integration command is:

```
cargo test --locked -j1 -p broker-storage --test aws_hub_storage -- --ignored --exact aws_hub_storage_sts_s3_contract --test-threads=1
```

The Rust-owned test fixture reuses the pinned mature MinIO/mc binaries qualified
by tsk-6488 and owns each process, bucket, private directory and synthetic IAM
caller. It combines PostgreSQL TLS NOSUPERUSER, real Native/opaque grants, actual
SDK-signed AssumeRole and object_store signed S3 calls. It reaps the owned service
before deleting private files. No personal AWS credentials or profiles are read.
The environment/profile provider tests run in isolated child processes.

The focused real contract passed after executing all four operations, denied
siblings/prefix boundaries, create/update conditions, multipart completion/abort,
Native and opaque access/service admission, deadline/expiry suppression and
future-drop recovery. Isolated children exercised environment and shared-profile
credentials, a missing chain and an invalid StaticPair alongside valid ambient
credentials. Already issued AWS access remained usable after SQL grant withdrawal,
confirming the documented lack of instant session revocation.

SDK DATA tests check complete/future expiration and the exact 2048-byte policy
boundary. Endpoint regression captures mature SDK endpoint resolution before any
network access; it does not fabricate a Broker grant or STS success. Four rustdoc
checks cover the real borrowed-grant API and absence of Clone/Default/Deserialize.
Affected Storage/Control/Presence ordinary suites passed with 135 tests; the
separate ignored STS/S3 contract also passed. Strict clippy and formatting checks
passed. Source review found no remaining static fault, protected files remained
unchanged, and normal resolution preserved all 312 previous package pins and
checksums. Receipts and failed attempts are retained under
`.build/rust-hub-storage-aws-2026-10-12/`. The local emulator does not qualify AWS
IAM trust/role chaining, real SSO/process/ECS/IMDS setup, production TLS or a full
15-minute expiration wait. Other storage modules, HTTP composition, the server
binary and the full migration are separate outcomes.


## Recurring checks

Run `make check` for workspace tests, including the ordinary Storage targets.
`make qualify` runs the ignored STS/S3 contract and requires the PostgreSQL
and MinIO fixtures. The pause/resume scenarios use Linux signals.
