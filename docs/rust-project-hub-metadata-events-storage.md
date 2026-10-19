---
title: Rust PROJECT Hub metadata and events storage
doc_type: reference
references:
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-e0b4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-826e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-f7ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust PROJECT Hub metadata and events storage

For Broker server integrators and PROJECT Hub publishers. The existing
[SQL admission](rust-hub-storage-admission.md), [credentials HTTP route](rust-hub-storage-credentials-http.md)
and [mature AWS issuer](rust-hub-storage-aws.md) now cover four Hub roots for the
admitted project. The HTTP/SQL/STS/S3 server storage contract is functionally
qualified on Linux in `tsk-e0b4` under the explicit fixture transport below.
This qualification is distinct from native metadata/events
codecs, datasets, event replay, callers, publisher journeys, discovery advertisement
and final application/migration integration.

## Request and actual authority

Keep the actual shared PostgreSQL store, Native verifier or opaque audience,
private authentication factory and issuer alive. Use
`StorageScope::project(project_id, StorageModule::Hub)` for SQL admission or send
POST `/v1/s3/credentials` with one `Authorization: Bearer ...` header and
`Content-Type: application/json`:

~~~json
{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub"}
~~~

The project is a canonical nonzero ULID. The strict three-field body and
[current fourteen-field response](rust-hub-storage-credentials-http.md) retain
scope project, module hub and the admitted project ID, without installation ID.
No module/subscope, metadata/event selector, branch, dataset version, root,
operation, prefix, route, provider or duration field is added. Unknown, duplicate,
missing, null, positional or trailing input and incompatible installation IDs
remain rejected after actual authentication; body caps and errors retain their
existing mapping.

Native trusts the configured JWT verifier; opaque access/service uses current
SQL identity. Neither authentication mode probes an alternate token format.
A current matching principal/project S3 rule, its capability/operation masks,
fixed-root intersections and contributing route authorize storage. PROJECT
retains its concrete S3 admission; the separate
[Global Hub](rust-global-hub-storage-admission.md) nonPROJECT Hub capability
requirement is not inserted into PROJECT. URI, discovery selector, lease or DATA
constructor cannot create a grant. No new SQL table, bucket, dataset, codec or
event transport is introduced.

## Exact roots and restricted prefixes

The admitted PROJECT Hub roots are exactly:

~~~text
v1/projects/{project_id}/registry
v1/projects/{project_id}/artifacts
v1/projects/{project_id}/hub/metadata
v1/projects/{project_id}/hub/events
~~~

Registry/artifacts preserve their existing paths. Metadata/events agree with
qualified Code `tsk-c027` ProjectHub DATA URI roots. Other project corpora,
[USER Memory](rust-user-memory-storage-admission.md) and Global Registry/Rules
retain their distinct roots. Branch selection remains with the actual dataset
SDK; a branch, URI or fixture payload does not authenticate or authorize.

An empty `s3_prefixes` or broad `v1/projects/{project}` prefix intersects the four
roots, never a project-wide object wildcard. Prefixes and operations remain
independent, deduplicated and sorted literally. These narrower examples are
logical SQL prefix templates, not extra request fields:

| Prefix | Admitted Hub resource |
| --- | --- |
| `v1/projects/{project}/hub` | Metadata and events only. |
| `v1/projects/{project}/hub/metadata` | Metadata only, excluding events, registry and artifacts. |
| `v1/projects/{project}/hub/events` | Events only. |
| `v1/projects/{project}/registry` | Preserved registry only. |
| `v1/projects/{project}/artifacts` | Preserved artifacts only. |
| `.../metadata2`, `.../events2`, corpus, USER, Global or another project | No contribution. |

Intersection requires exact segment boundaries. Only contributing operation/
prefix pairs select a route; conflicts remain errors and missing authority is
403. The complete stored policy compiles even for unmatched rules, so invalid
whole policy is 503. Templates retain actual authenticated attribute validation;
there is no new owner placeholder, alias, fallback or invented default.

Compose the physical provider base prefix exactly once. The mature STS policy
limits object actions and listing to admitted prefixes. Read allows get/list;
write adds conditional create/CAS and multipart without delete; publish includes
read/write/delete; delete-only grants no read/list. Existing 2048-byte policy
and 1024-byte complete-key bounds remain. Credentials are temporary, JSON is
`Cache-Control: no-store`, and grant-derived serialization retains the owned
zeroizing body. Permanent route credentials, policy and internal proofs are not
returned.

## Errors, clocks and recovery

Use the [SQL error guide](rust-hub-storage-admission.md#freshness-lifetime-and-failures) and
[HTTP recovery table](rust-hub-storage-credentials-http.md#failures-and-recovery).
Authentication is 401; Native purpose scope is 403 with its challenge; ACL denial
is 403; strict input is 400 and body cap 413; whole policy/routes/config/current
SQL backend/closed store failures are 503; actual AWS/output failure is 502; and
Original/proof/provider deadline is 504. Fix the concrete input, identity, policy
or backend before requesting a new grant. SQL privilege failure is unavailable
backend rather than ACL denial.

One Original absolute deadline is bounded by existing operation budgets. Actual
caller/grant checks surround body, fresh SQL admission, STS issuance and owned
response serialization. SQL retains transaction/COMMIT uncertainty without an
outer timer or replay. Configured STS lifetime remains 900–43200 seconds, without
JWT clamping. Fresh withdrawal or current opaque identity disable denies new
issuance; an already-issued session can outlive withdrawal or a bearer. No
instant revocation, disconnect rollback or last-byte-before-expiry guarantee is
promised. The handler does not introduce inventory/Presence or binding callbacks;
separate native caller journeys verify a binding when actually consumed.

## Real qualification and saved gate

`PROJECT_HUB_METADATA_EVENTS_STS` follows `GLOBAL_HUB_HTTP_STS` and precedes Audit
in the existing pre-push runner. Only its exact target/args, array/assert and
causal guide command were added; all other phases/hooks/classifiers are retained.

~~~text
cargo test --locked -j1 -p broker-presence --test project_hub_metadata_events_storage -- --ignored --exact project_hub_metadata_events_storage_contract --test-threads=1
cargo test --locked -j1 -p broker-control --test storage_admission --test project_corpus_storage_admission -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --test storage_credentials_http --test project_corpus_storage_credentials_http --test user_memory_storage_credentials_http --test global_hub_storage_credentials_http -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence -p xtask --all-targets
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control -p broker-storage -p broker-presence -p xtask --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The ignored focal contract uses actual TCP, PostgreSQL TLS NOSUPERUSER, EdDSA JWT
and current opaque access/service credentials, actual SDK STS and signed MinIO
S3. It checks all four roots/four operations, the unchanged three-field request and
twelve-field response,
real CAS/create/stale/multipart, sibling/corpus/USER/Global denials, metadata-only
operations excluding events/registry/artifacts, Hub ancestor restriction, concrete
PROJECT S3 authority, current withdrawal/revision/identity, invalid policy/routes,
SQL privilege failure/recovery, strict input, auth-before-body, disabled ingress,
expiry and body/provider deadlines. The existing Hub and PROJECT corpus SQL
fixtures assert the literal four-root result and preserved isolated corpora.

The signed S3 fixture uses mature `ClientOptions.with_pool_max_idle_per_host(0)`,
zero retries and the existing finite request/connect bounds. It qualifies signed
protocol/authorization under that explicit test transport; it does not select a
production/client default or establish pooled consumer stability. Earlier related
fixture connection closures retain their unresolved cause. Receipts in
`.build/rust-project-hub-metadata-events-storage-2026-10-12/` distinguish actual
passes/failures and unrun checks. An isolated failing Rust assertion at the saved
phase proves the barrier before Audit, not a Broker backend or the full pipeline.
Linux does not establish Windows/macOS, deployed AWS IAM/TLS/provider behavior,
native metadata/events codecs/datasets/replay/callers or final migration qualification.

Current Linux receipts record the exact metadata/events focal passing one actual
test (44.17 seconds runtime, 44.42 seconds wall). The affected Hub/PROJECT corpus
SQL command passed two actual tests (30.39 seconds wall); the affected
Hub/PROJECT/USER/Global HTTP command passed four actual tests (104.98 seconds).
The affected ordinary suite passed 151 tests with 90 ignored backend tests
(15.53 seconds); skipped tests do not supply backend evidence. Rustdoc passed
157 examples including private-proof/lifetime compile failures (3.80 seconds),
strict all-features Clippy passed (37.38 seconds) and formatting passed (0.76
seconds). The current isolated phase assertion failed with exit 1 before Audit
(0.30 seconds), proving only the saved barrier. No focal failure was recorded in
this leaf. Bounded source diffs confirm production is only the two exact roots,
with two causal SQL expected-root fixtures and the ceded phase hunks; handler,
policy, AWS production configuration, support, manifests, locks and other-project
interfaces were preserved.
