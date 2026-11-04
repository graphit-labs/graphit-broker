---
title: Rust global Hub storage credentials HTTP
doc_type: reference
references:
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-f7ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-c1be, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-80f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust global Hub storage credentials HTTP

For Broker server integrators and global Registry/Rules callers. The generic
Rust credentials router consumes [actual Global SQL admission](rust-global-hub-storage-admission.md)
before the [mixed storage service](rust-storage-credentials-service.md). The server HTTP/SQL/STS/S3 protocol is functionally qualified on Linux in
`tsk-f7ba` under the explicit fixture transport below. This qualification
is distinct from native Registry/Rules codecs, datasets, callers, discovery
advertisement and final application/migration integration.

## Integrate and request

Use `broker_storage_credentials_router` for trusted Native JWT and
`local_storage_credentials_router` for current opaque access/service credentials.
Keep the actual verifier, shared SQL store and issuer alive as described in
[router configuration and lifecycle](rust-hub-storage-credentials-http.md).
Enabled ingress requires an issuer. Disabled ingress returns 404 before
Auth/body/SQL/STS and requires no issuer. Neither mode probes another token
format after authentication failure.

Send POST `/v1/s3/credentials`, one `Authorization: Bearer ...` header and
`Content-Type: application/json`, with exactly:

~~~json
{"scope":"hub","module":"hub"}
~~~

Both required fields are literal strings. The root is one object; unknown,
duplicate, missing, null, positional, trailing or oversized input fails after
actual authentication. PROJECT or installation IDs are incompatible even when
explicitly null. Scope aliases (`global`, `HUB`), module aliases, issuer, sub,
subject, username, instance ID, hash, root, prefix, route, policy, provider,
operation and duration cannot be supplied. A valid body constructs only DATA.

[PROJECT](rust-project-corpus-storage-credentials-http.md) retains its three-field
body, canonical project ULID, five modules and fourteen-field response.
[USER Memory](rust-user-memory-storage-credentials-http.md) retains its three-field
installation body and fifteen-field response. No literal `global` ProjectId,
compatibility/import path or fallback is introduced.

## Current authority, response and roots

Authenticate first, then compile the complete current SQL snapshot. A successful
Global grant needs effective Hub capability and S3 operation/prefix authority in
nonPROJECT rules (`projects=[]` or `*`). They may be independent applicable
rules. Capabilities use the established SDK glob grammar matched against literal
`hub`; `hub*` can match it, while `hub:admin` and `hub.*` do not. PROJECT Hub,
PROJECT S3, discovery, selectors, lease, URI or body do not authorize Global.
A Hub-only rule contributes no S3 route. A valid `{project}` prefix without a
project contributes no prefix/operation/route; invalid whole policy still fails.

A success has exactly fourteen JSON fields:

| Fields | Meaning |
| --- | --- |
| `access_key_id`, `secret_access_key`, `session_token` | Actual newly issued temporary credentials from the configured issuer. |
| `expires_at` | Actual RFC3339 UTC provider expiry. |
| `bucket`, `region`, `endpoint` | Configured topology; standard AWS endpoint is an empty string. |
| `prefixes` | Configured provider base prefix in an array. |
| `conditional_delete` | Required boolean backend capability for atomic `If-Match` DELETE; it grants no permission. |
| `copy_if_not_exists` | Required enum: `multipart` for S3, `if_none_match` for Filesystem; selects create-only SDK copy independently of Delete. |
| `authorization_revision` | Positive current SQL revision as a decimal string. |
| `scope`, `module`, `project_id` | `hub`, `hub`, and the empty string, derived from the admitted grant. |

No installation ID, owner, issuer, subject, policy, permanent credentials,
Auth token or internal proof is returned. `Cache-Control: no-store` applies to
success and finite errors. Serialization borrows private credential getters
into an owned zeroizing buffer retained by `Bytes::from_owner`; third-party
buffers have their own lifecycle.

The only logical roots are:

~~~text
v1/hub/global/registry
v1/hub/global/rules
~~~

Compose the configured physical base prefix exactly once. Broad `v1` or
`v1/hub` S3 prefixes still intersect only these roots at segment boundaries.
Global artifacts/metadata/events, sibling paths, PROJECT, USER and corpora are
excluded. Read allows admitted listing/get, write adds conditional create/update
and multipart without delete, publish includes read/write/delete, and delete-only
gives no read/list. Existing 2048-byte policy and 1024-byte complete-key bounds,
route conflict/default rules and mature endpoint/credential-provider behavior remain.

## Failures and recovery

Use the [finite error/recovery table](rust-hub-storage-credentials-http.md#failures-and-recovery).
Invalid body/scope is 400, body cap 413, authentication 401, missing Native purpose
scope 403 with its challenge, current ACL denial 403, invalid policy/routes/config
or unavailable SQL 503, AWS/output failure 502, and original/proof/provider
deadline 504. Explicit closed-store failure retains 503 `closed`. Correct the
concrete input, current identity/policy, provider or backend before a new request.
Auth failure does not wait for a body; malformed input does not touch admission
SQL or STS. SQL privilege failure is not ACL denial.

Caller and grant checks surround body, SQL admission, STS issuance and response
serialization, using one Original absolute deadline bounded by existing operation
budgets. SQL keeps COMMIT uncertainty without an outer timer or replay. STS
lifetime remains 900–43200 seconds, without JWT clamping. Policy withdrawal or
disabled current opaque identity denies new issuance; already-issued sessions
can outlive withdrawal or a bearer. No instant revocation, rollback on disconnect
or last-byte-before-expiry guarantee is promised.

Inventory absence does not supply authority or deny otherwise admitted Global
storage. This handler does not register inventory, require Presence or add
UserInfo/introspection/polling/binding callbacks. Native caller journeys that
actually consume a binding remain separately qualified by their owner.

## Real qualification and saved gate

`GLOBAL_HUB_HTTP_STS` follows `USER_MEMORY_HTTP_STS`; the
[PROJECT Hub metadata/events phase](rust-project-hub-metadata-events-storage.md)
follows Global and precedes Audit in the
existing qualification runner. All other phases, hooks, classifiers and targets remain.
The same exact command is usable on supported platforms:

~~~text
cargo test --locked -j1 -p broker-presence --test global_hub_storage_credentials_http -- --ignored --exact global_hub_storage_credentials_http_contract --test-threads=1
cargo test --locked -j1 -p broker-presence --test project_corpus_storage_credentials_http -- --ignored --exact project_corpus_storage_credentials_http_contract --test-threads=1
cargo test --locked -j1 -p broker-presence --test user_memory_storage_credentials_http -- --ignored --exact user_memory_storage_credentials_http_contract --test-threads=1
cargo test --locked -j1 -p broker-presence -p broker-storage -p xtask --all-targets
cargo test --locked -j1 -p broker-presence -p broker-storage --doc
cargo clippy --locked -j1 -p broker-presence -p broker-storage -p xtask --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The ignored contract uses actual TCP, PostgreSQL TLS NOSUPERUSER, EdDSA JWT and
current opaque access/service authentication, SDK STS and signed MinIO S3.
The original qualification checked the earlier twelve-field response, both roots/four operations, conditional
create/CAS/stale update/multipart, real foreign-prefix denials, independent and
same-rule Hub/S3, nonPROJECT domains, wrong principal, missing Hub/S3, current
withdrawal/revision/identity, whole-policy/routes, SQL failure/recovery, strict
input, auth-before-body, disabled ingress, expiry and body/provider deadlines.

The fixture uses mature `ClientOptions.with_pool_max_idle_per_host(0)`, zero
retries and the existing finite request/connect bounds. This qualifies signed
protocol/authorization under that explicit test transport; it does not select a
production/client default or establish pooled consumer stability. Historical
connection closures in earlier related fixtures retain their unresolved cause.
Receipts in `.build/rust-global-hub-storage-http-2026-10-12/` distinguish actual
passes, failures and unrun checks. An isolated runner failure counterproof proves
the saved barrier before Audit; it is not Broker backend or full-pipeline proof.
Linux does not establish Windows/macOS, deployed AWS IAM/TLS/provider behavior,
native codecs/datasets/callers or final migration qualification.

Current Linux receipts record the exact Global gate passing one actual test
(16.29 seconds runtime, 18.49 seconds wall). The affected Hub/PROJECT/USER HTTP
regression command passed three actual tests (137.13 seconds wall). The affected
ordinary suite passed 45 tests with 18 ignored backend tests (25.30 seconds);
ignored tests do not supply backend evidence. Rustdoc passed 25 examples including
private-proof/lifetime compile failures (11.43 seconds), strict all-features
Clippy passed (7.56 seconds) and formatting passed (0.57 seconds). The current
isolated Global runner assertion failed with exit 1 before Audit (0.28 seconds).

Two earlier fixture failures are retained separately: a textual adaptation
changed the SQL NOSUPERUSER literal, and the negative admission matrix used
empty capabilities and an unsupported selector kind. The fixture now preserves
NOSUPERUSER with an actual non-superuser assertion and uses valid rules lacking
Hub/S3 plus the existing `user` selector. Expected ACL 403, invalid-policy 503,
real S3/CAS/conditional/multipart oracles and production policy remain intact.
No Control policy, AWS production defaults, manifests, locks or other-project
interfaces were changed by this HTTP leaf.
