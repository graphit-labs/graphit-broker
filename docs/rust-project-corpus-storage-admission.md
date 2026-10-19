---
title: Rust PROJECT corpus storage admission
doc_type: reference
references:
  - target: {type: task, id: tsk-4c48, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c73a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Rust PROJECT corpus storage admission

For Broker maintainers and server integrators. The `broker-control` SQL boundary
admits Task, Memory, Knowledge and AST corpora for an authenticated project.
This unit implements the library boundary. The focused actual SQL contracts,
affected ordinary tests, private-proof/lifetime doctests and strict checks passed
on Linux for `tsk-4c48`. The [corpus HTTP/STS router](rust-project-corpus-storage-credentials-http.md)
has its own implementation and qualification. These SQL results do not qualify a remote
corpus dataset or native caller; Windows/macOS and final migration integration
remain unverified by this unit.

## Admit a corpus

Use an open PostgreSQL control store, the actual configured verifier or opaque
local audience, positive JSON bounds, an explicit default route and one absolute
monotonic deadline. The [Hub admission guide](rust-hub-storage-admission.md)
describes authentication, current SQL, factory binding and errors shared by all
PROJECT storage modules.

~~~rust
let factory = store.broker_storage_authorizer(
    &verifier, grants_json_bytes, &configured_default_route,
)?;
let caller = factory.authenticate(&bearer, &required_scopes, original)?;
let scope = StorageScope::project(&canonical_project_id, StorageModule::Task)?;
let grant = factory.authorize_authenticated(caller, &scope).await?;
grant.check()?;
~~~

This excerpt assumes the configured values and imports. The compiling example
and lifetime/private-proof checks are in
[the grant API](../crates/broker-control/src/storage_admission.rs).
`local_storage_authorizer(audience, identity_json_bytes, grants_json_bytes,
default_route)` authenticates opaque human access or service credentials
asynchronously. Neither factory tries another authentication format.

`StorageScope::project(project_id, module)` accepts a canonical nonzero ULID and
one `StorageModule`: `Hub`, `Task`, `Memory`, `Knowledge` or `Ast`.
`project_id()` returns `Some` for PROJECT, `installation_id()` is `None`, and
`module()` / `StorageModule::as_str()` are DATA observers. The separate
[USER Memory SQL guide](rust-user-memory-storage-admission.md) describes the
canonical installation and authenticated owner path; this PROJECT qualification
does not prove that USER extension.
A scope can be cloned; the actual caller and authorized grant cannot be cloned,
constructed publicly, defaulted or restored through a codec. The caller is tied
to the same actual factory and its verifier through issuance.

## Roots and operations

| Module | Private server root |
|---|---|
| Task | `v1/projects/{id}/corpora/task` |
| Memory | `v1/projects/{id}/corpora/memory` |
| Knowledge | `v1/projects/{id}/corpora/knowledge` |
| Ast | `v1/projects/{id}/corpora/ast` |
| Hub | `v1/projects/{id}/registry`, `/artifacts`, `/hub/metadata`, and `/hub/events` |

The corpus roots agree with the qualified Code DATA URI producer `tsk-c027`.
Hub preserves registry/artifacts from `tsk-826e`; the [metadata/events extension](rust-project-hub-metadata-events-storage.md)
appends the two exact ProjectHub DATA roots from `tsk-c027`. Branch selection remains with
the real dataset SDK; no Git version, local filesystem path or artifact version
is inserted into these roots. Scope/root/URI DATA never grants permission.

Each call reads and compiles the entire current SQL policy and its positive
revision. A rule must match the authenticated principal and project. Empty or
`*` projects select any project; an exact project selects only that project.
The existing S3 capability and operation patterns determine read, write, publish
and delete independently. Only contributing operation/prefix pairs select a
route; absent authority is forbidden, while conflicting contributing routes are
an error.

An empty `s3_prefixes` contributes only the admitted module's roots. A broad
`v1/projects/{project}` prefix intersects those roots, rather than becoming a
project-wide resource grant. A Hub grant therefore cannot reach any corpus, and
a Task grant cannot reach Memory, Knowledge, AST or Hub. A specific corpus prefix
cannot authorize a different module. Intersection is literal at segment
boundaries: an ancestor contributes the admitted root, a descendant contributes
its own prefix, and `task2` or a sibling project contributes nothing.

The existing templates `{project}`, `{username}`, `{organization}` and
`{subject}` retain their literal attribute validation. All rules compile even
when they do not match. Invalid grammar, malformed stored data, closed stores,
route failures and SQL failures remain causal errors; they are not silently
converted to missing permission.

## Failure, recovery and qualification

Authentication failures retain Native/local error distinctions; insufficient
Native scope remains distinct from an ACL denial. A scope fails validation before
admission. Withdrawal or a current local identity change is observed on the next
real authorization. The original deadline, actual authentication expiry and final
checks remain active on positive and negative paths. SQL owns COMMIT uncertainty;
the caller must not hide it under an external timer or replay.

Correct denied access through the real identity/grant configuration. Correct an
invalid policy or conflicting route as a whole before retrying. Recover a failed
backend before re-observing current policy. DATA getters and a previous observation
are not reusable authority. Issued STS TTL and credential endpoint behavior are
unchanged by this SQL unit.

The new ignored contract uses real PostgreSQL TLS under a NOSUPERUSER role,
actual EdDSA JWTs and opaque access/service credentials. It covers all four
corpora, isolated projects/modules, broad and restricted prefixes, independent
operations, route conflicts, whole-policy errors, current withdrawal/identity,
expiry, factory mismatch and SQL failure/recovery. The existing real Hub contract
remains a separate regression.

~~~text
cargo test --locked -j1 -p broker-control --test project_corpus_storage_admission -- --ignored --exact project_corpus_storage_admission_contract --test-threads=1
cargo test --locked -j1 -p broker-control --test storage_admission -- --ignored --exact hub_storage_admission_postgres_contract --test-threads=1
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence --all-targets
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control -p broker-storage -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The [AWS issuer](rust-hub-storage-aws.md) consumes only an actual private grant.
The [HTTP guide](rust-project-corpus-storage-credentials-http.md) describes the PROJECT
body and twelve-field response. Corpus HTTP/STS/S3, USER/global scopes, native
caller/dataset/codecs and final migration integration have distinct deliveries;
this SQL contract does not qualify them.

The [global Hub SQL library](rust-global-hub-storage-admission.md) is a separate
nonPROJECT admission contract for Registry/Rules, requiring effective Hub plus
S3 authority. Its DATA constructor and empty project observer do not grant
permission or enable a Global HTTP body; these existing PROJECT/USER contracts
retain their roots and authority.
