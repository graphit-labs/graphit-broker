---
title: Rust USER Memory storage credentials HTTP
doc_type: reference
references:
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-5976, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-ce8e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-80f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust USER Memory storage credentials HTTP

For Broker server integrators and USER Memory callers. The generic Rust
credentials router accepts canonical installation DATA and consumes the actual
[USER SQL grant](rust-user-memory-storage-admission.md) before the mature
[mixed storage service](rust-storage-credentials-service.md). The current HTTP/SQL/STS/S3 server protocol is functionally qualified on Linux
in `tsk-5976` under the explicit fixture transport below.
The server endpoint does not qualify the native Memory dataset, Auth client,
Dream, discovery advertisement or final application composition.

## Integrate and request credentials

Select `broker_storage_credentials_router` for Native JWT or
`local_storage_credentials_router` for current opaque access/service credentials.
Keep the configured shared SQL store, actual verifier and configured storage service alive.
Use the explicit [configuration and lifecycle](rust-hub-storage-credentials-http.md).
Enabled ingress requires an issuer; disabled ingress accepts no issuer and
returns 404 before authentication, body, SQL or provider activity. Authentication
modes do not probe another token format after failure.

Send POST `/v1/s3/credentials`, exactly one `Authorization: Bearer ...` header,
and `Content-Type: application/json`:

~~~json
{"scope":"user","module":"memory","installation_id":"Install-A"}
~~~

The root is exactly one object. All three fields are required strings; scope
and module are exactly `user` and `memory`. Installation is 1–128 ASCII bytes,
alphanumeric at both ends, with only alphanumerics, `.`, `_` and `-` inside.
Case is preserved without trimming or normalization. It is not a project ULID
or an implicit instance ID. Unknown, duplicate, missing, null, positional or
trailing values fail after actual authentication. An explicitly present null
project/installation ID is rejected even when that field is incompatible.

USER cannot include `project_id`, issuer, sub, subject, username, instance ID,
hash, root, prefix, route, policy, operation, provider or duration. PROJECT
continues to accept its [five modules and exact fourteen-field response](rust-project-corpus-storage-credentials-http.md),
with a canonical project ULID and no installation field. [Global Hub](rust-global-hub-storage-credentials-http.md)
has its separate strict two-field body and fourteen-field response. There are no case aliases or `dream` modules.
The DATA body cannot authenticate, select another identity or restore a grant.

## Response and namespace

A successful USER response has exactly the fourteen common credential fields
plus `installation_id`:

| Field | Meaning |
| --- | --- |
| `access_key_id`, `secret_access_key`, `session_token` | Actual new temporary credentials from the configured issuer. |
| `expires_at` | Actual RFC3339 UTC storage-session expiry. |
| `bucket`, `region`, `endpoint` | Configured provider topology; standard AWS endpoint is an empty string. |
| `prefixes` | Array containing the configured provider base prefix. |
| `conditional_delete` | Required boolean backend capability for atomic `If-Match` DELETE; it grants no permission. |
| `copy_if_not_exists` | Required enum: `multipart` for S3, `if_none_match` for Filesystem; selects create-only SDK copy independently of Delete. |
| `authorization_revision` | Positive current SQL revision as a decimal string. |
| `scope`, `module`, `project_id` | `user`, `memory`, and the empty string. |
| `installation_id` | Exact canonical installation from the admitted private grant. |

Scope, module, installation and project DATA come from the actual grant, rather
than a body restored outside SQL admission. No issuer, subject, owner hash,
policy, permanent credentials, Auth token or internal proof is returned.
The body is JSON with `Cache-Control: no-store`. The serialization borrows
private issued-credential getters into a zeroizing owned buffer retained by
`Bytes::from_owner`; third-party buffers retain their own lifecycles.

The actual authenticated owner is `(installation_id, literal issuer, literal sub)`.
Native uses verified JWT claims; opaque uses the current SQL local identity.
Display name, organization and preferred username cannot reassign that owner.
The grant's exact namespace is:

~~~text
v1/installations/{installation_id}/users/{identity_key}/corpora/memory
~~~

The [SQL guide](rust-user-memory-storage-admission.md) defines the mature SHA-256
framing equal to Core `UserIdentity::namespace_key` and qualified Code DATA URI
producer `tsk-c027`. Callers compose the configured provider base prefix exactly
once with their namespace and object key. A computed hash or URI remains DATA.
Even a broad `v1` S3 policy is intersected with this owner's Memory root; it does
not authorize siblings, another issuer/subject/installation/case, PROJECT, global
Hub or other corpora. Read permits own list/get, write permits conditional and
multipart writes, publish includes read/write/delete, and delete-only grants no
read/list. Existing policy and complete-key bounds remain 2048/1024 bytes.

## Current policy, errors and recovery

Each request authenticates before body extraction using one original absolute
budget, then reads and compiles the full current SQL snapshot. USER requires
actual S3 capabilities/operation masks/prefixes and a contributing route from
nonPROJECT rules (`projects=[]` or `*`); exact PROJECT rules cannot authorize it.
A valid `{project}` template contributes no prefix, operation or route without
a project. Invalid whole policy still fails. Explicit default/conflicting route
behavior remains the existing contract.

Inventory absence neither grants USER authority nor denies an otherwise
admitted USER owner. The handler does not read/register inventory, require
Presence, call UserInfo/introspection/polling, or introduce a binding callback.
A native caller journey that actually consumes an existing binding checks that
binding against its literal authenticated owner and is qualified separately.

Use the [finite status/error and recovery table](rust-hub-storage-credentials-http.md#failures-and-recovery).
Invalid shape/installation/scope is 400, body cap 413, authentication 401,
insufficient Native purpose scope 403 with its challenge, current ACL denial 403,
whole-policy/routes/configuration/SQL backend failure 503, actual AWS/output
failure 502, and original/proof/provider deadline 504. Fix the concrete input,
identity, current policy or backend before a new request. SQL privilege failure
is an unavailable backend rather than permission denial. A malformed body fails
before admission SQL or provider effects; authentication failures do not wait
for the body.

Caller/grant checks surround body, SQL admission, issuance and serialization.
SQL retains transaction/COMMIT uncertainty without an outer timer or replay.
The mature configured STS lifetime remains 900–43200 seconds and is not clamped
to the JWT. Withdrawn SQL policy or disabled current opaque identity denies new
issuance, but an already-issued STS session can outlive a bearer or withdrawal.
No instant logout/revocation or last-byte-before-expiry guarantee is promised.

## Real qualification and persistent gate

The exact long `USER_MEMORY_HTTP_STS` phase follows `PROJECT_CORPUS_HTTP_STS`
and is followed by `GLOBAL_HUB_HTTP_STS` and `PROJECT_HUB_METADATA_EVENTS_STS`
before Audit in the existing qualification runner:

~~~text
cargo test --locked -j1 -p broker-presence --test user_memory_storage_credentials_http -- --ignored --exact user_memory_storage_credentials_http_contract --test-threads=1
cargo test --locked -j1 -p broker-presence --test storage_credentials_http -- --ignored --exact hub_storage_credentials_http_postgres_sts_contract --test-threads=1
cargo test --locked -j1 -p broker-presence --test project_corpus_storage_credentials_http -- --ignored --exact project_corpus_storage_credentials_http_contract --test-threads=1
cargo test --locked -j1 -p broker-presence -p broker-storage -p xtask --all-targets
cargo test --locked -j1 -p broker-presence -p broker-storage --doc
cargo clippy --locked -j1 -p broker-presence -p broker-storage -p xtask --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The actual test uses TCP Axum/Hyper, PostgreSQL TLS under NOSUPERUSER, EdDSA
Native claims and current opaque access/service identities, mature SDK AssumeRole
and signed S3 against the existing owned MinIO fixture. Five literal identity
vectors and two canonical installations cover four operation masks, owner/case/
issuer/subject/corpus isolation, actual conditions and multipart, strict body,
NoStore, current withdrawal/revision/identity, absent inventory with SELECT
removed, whole-policy/routes, SQL failures/recovery, expiry/deadline/provider
errors and explicit owned shutdown. Directly affected PROJECT/Hub real HTTP
regressions preserve their oracles. Ordinary skips do not qualify backends.

The USER fixture's signed S3 client explicitly uses the mature
[ClientOptions idle-pool setting](https://docs.rs/object_store/latest/object_store/client/struct.ClientOptions.html#method.with_pool_max_idle_per_host)
with zero retained idle connections and zero retries, retaining the same request
and connect bounds. This qualifies actual signed protocol/authorization behavior
under that explicit test transport. It does not select a production/client
transport default or qualify the stability of pooled consumer connections.
Historical SendRequest connection closures remain failures with no established
root cause; choosing this test transport does not prove their cause or repair.

Receipts in `.build/rust-user-memory-storage-http-2026-10-12/` record actual
passes/failures and elapsed times. The reused isolated runner counterproof
establishes only that a real failing USER HTTP Rust assertion blocks Audit;
it does not qualify Broker or the whole qualification suite. Windows/macOS,
production AWS IAM/TLS/provider deployments, native caller/datasets, Global Hub,
metadata/events and final migration integration remain separate qualifications.

Current Linux receipts record the exact USER gate passing 1 test (37.54 seconds
runtime, 39.76 seconds wall), the affected PROJECT corpus regression passing
(34.49/36.64 seconds) and the untouched Hub regression passing (55.78/57.74 seconds).
The affected ordinary suite passed 44 tests with 17 ignored backend tests
(25.71 seconds wall), rustdoc passed 25 examples including compile failures
(1.34 seconds), and strict Clippy with all features and formatting passed.
The isolated current USER runner assertion failed with exit 1 before Audit
(0.32 seconds), proving only the saved barrier.

Earlier failed receipts remain distinct: initial fixture seed preparation
interfered with a later own read, the terminal closed-store assertion used the
wrong existing error code, and later original pooled S3 operations encountered
premature connection closures. The first two fixture expectations were corrected
against unchanged functional oracles/existing producer errors. The latter failures
have no established root cause and are not claimed fixed by selecting the current
explicit fixture transport. PROJECT's missing ID and incompatible installation
retain their historical `invalid_json` mapping; existing PROJECT/Hub test oracles
were preserved. No production defaults, manifests, locks, Auth client, Core or
native dataset code were changed by this delivery.
