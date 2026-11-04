---
title: Rust USER Memory storage admission
doc_type: reference
references:
  - target: {type: task, id: tsk-ce8e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-319e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c73a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Rust USER Memory storage admission

For Broker maintainers and server integrators. The Rust SQL library selects
USER Memory for the actual authenticated owner and a canonical installation ID.
The SQL implementation is qualified on Linux in `tsk-ce8e` using actual
PostgreSQL TLS and authenticated Native/opaque identities. [USER HTTP/STS/S3](rust-user-memory-storage-credentials-http.md) and native caller
integration are separate deliveries. PROJECT keeps five modules and twelve
response fields; USER HTTP uses its separate installation body and thirteen fields.

## Admit the actual owner

Keep the actual factory alive through authentication, SQL admission and later
credential issuance. Use `broker_storage_authorizer` with the configured Native
JWT verifier or `local_storage_authorizer` with its current opaque access/service
verifier. They do not switch token formats. Their required scopes, positive input
bounds and explicit default route remain configured by the server.

~~~rust
let factory = store.broker_storage_authorizer(
    &verifier, grants_json_bytes, &configured_default_route,
)?;
let caller = factory.authenticate(&bearer, &required_scopes, original)?;
let scope = StorageScope::user_memory(&captured_installation_id)?;
let grant = factory.authorize_authenticated(caller, &scope).await?;
grant.check()?;
~~~

The excerpt assumes supplied configuration, imports and actual credentials.
The [private proof and grant API](../crates/broker-control/src/storage_admission.rs)
contains compiling lifetime examples. Opaque authentication is asynchronous;
the remaining two-phase flow is the same. A DATA scope cannot construct a caller
or grant, restore authority through a codec, or replace the factory's proof.

`StorageScope::user_memory(installation_id)` accepts exactly 1–128 ASCII bytes,
with alphanumeric first/last bytes and only alphanumerics, `.`, `_` and `-`
inside. Case is preserved; whitespace and normalization are not accepted.
An installation ID is not required to be a project ULID or an instance ID.
`project_id()` is `None`, `installation_id()` is `Some` of the literal ID and
`module()` is `StorageModule::Memory`. The [PROJECT constructor](rust-project-corpus-storage-admission.md)
retains its canonical nonzero ULID constraint, with `Some` project and `None`
installation observers. These values remain DATA.

## Literal namespace and isolation

Only the private authenticated proof supplies issuer and subject. Native uses
the literal verified issuer/sub; opaque uses its actual current local identity,
rather than stale display metadata or the token's unrelated pseudonymous field.
The owner tuple is `(installation_id, issuer, subject)`. Username, organization,
groups, a project ID, Git version or a caller-supplied hash cannot select another owner.

The exact root is:

~~~text
v1/installations/{installation_id}/users/{identity_key}/corpora/memory
~~~

The mature `sha2` SHA-256 implementation derives the same key as qualified Core
`UserIdentity::namespace_key`: bytes `graphit-user-namespace-v1` followed by NUL,
then issuer and subject in order, each preceded by its literal UTF-8 byte length
as unsigned 64-bit big-endian, followed by those bytes. The output is exactly
64 lowercase hexadecimal characters. URL/case folding, trimming and delimiter
concatenation are not used. Even pairs with the same `issuer|sub` observer retain
distinct namespaces. That observer, hash and URI are never authentication.
The qualified Code DATA URI producer `tsk-c027` consumes the same namespace contract.

The [policy intersection](../crates/broker-control/src/storage_policy.rs) selects
only the authenticated owner's Memory root or authorized descendants. Broad
`v1` or installation prefixes do not grant another issuer, subject, installation,
case variant, PROJECT corpus/Hub or global Hub. Provider prefixes and object key
encoding remain with the [AWS issuer](rust-hub-storage-aws.md) and native DATA caller.
No SQL database format, owner table or import/conversion path is added.

## Current SQL policy

Every request authenticates through its actual factory, reads the full current
SQL snapshot and compiles the whole policy with a positive revision. The
[principal matcher](rust-hub-storage-admission.md) remains literal. USER selects
only rules with an empty `projects` list or containing `*`; an exact PROJECT rule
cannot authorize USER. Actual S3 capabilities, four operation masks, prefixes
and a contributing route must still match. No default authority is introduced.

The existing prefix grammar validates every rule, including irrelevant domains.
A valid `{project}` template has no contribution without a PROJECT ID: it
selects no prefix, operation or route. It never receives a fabricated project,
empty replacement, global root or owner placeholder. Unknown/invalid grammar
still fails the whole policy. Other relevant identity expansions retain their
existing unsafe/missing-attribute errors. No installation/owner template names
are added. PROJECT rendering and Hub registry/artifact roots are preserved.
Only contributing S3 rules choose a route; the explicit default and conflicting
route behavior are unchanged. No current operation/prefix pairs means denial.

The SQL boundary does not read inventory, register an instance, acquire Presence
permissions or introduce a universal binding callback. Inventory absence neither
grants USER authority nor denies an otherwise authorized USER owner. A separate
native journey that actually consumes an existing binding checks that binding
against its real literal owner; that caller journey is qualified by its own owner.

## Errors, clocks and recovery

Invalid installation DATA produces `InvalidScope`. Authentication, missing
scopes, fresh ACL denial, invalid whole policy, conflicting routes, SQL storage/
closed/deadline and uncertain COMMIT outcomes preserve their concrete error kinds.
Correct the input, actual identity, policy or backend before a new observation;
a previous scope, URI or grant is not renewed authority. The HTTP status mapping
for USER belongs to the following HTTP delivery.

Authentication retains its actual UTC and monotonic expiry, the one original
absolute deadline and private factory binding. Checks surround admission and
later issuance; SQL owns transaction/COMMIT uncertainty without an outer timer
or replay. Changing display metadata does not reassign an owner. Disabling the
current opaque identity or withdrawing policy denies new admission. A grant
check does not promise instant remote logout or revocation of issued STS sessions.
The mature AWS 900–43200-second configuration is unchanged. Its credential DATA
has an empty project identifier for USER; this does not create a PROJECT grant
or substitute for the separately qualified USER HTTP delivery.

## Verification and persistent gate

The ignored USER contract uses actual PostgreSQL TLS under NOSUPERUSER,
actual EdDSA JWTs and current opaque access/service credentials. Literal constant
vectors check Core byte framing, Unicode, case, percent characters, ambiguous
concatenations and canonical-subject collisions through actual authentication.
Tests cover installation bounds/case, all operation masks, prefix ancestors/
descendants and foreign owners, nonPROJECT selection, no inventory read effect,
whole-policy/template validity, contributing routes, fresh withdrawal/revision,
current opaque identity, factory mismatch, expiry, SQL failure and recovery.
PROJECT and Hub SQL are separate directly affected regressions.

~~~text
cargo test --locked -j1 -p broker-control --test user_memory_storage_admission -- --ignored --exact user_memory_storage_admission_contract --test-threads=1
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence -p xtask --all-targets
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control -p broker-storage -p broker-presence -p xtask --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The existing long `POSTGRES` qualification phase includes this real USER SQL target.
The exact phase, assertion and [SQL gate documentation](rust-sql-schema.md) are
maintained together, preserving all AWS/PROJECT HTTP phases, hooks and locks.
Its isolated runner counterproof checks a real Rust assertion failure blocks
later phases; it does not qualify a Broker backend, HTTP/STS/S3 or datasets.
Ordinary tests remain under the existing pre-commit barrier.

Linux receipts in `.build/rust-user-memory-storage-admission-2026-10-12/`
record the focused USER contract passing (13.75 seconds test runtime; 15.19 seconds
wall), the exact saved SQL phase passing all 17 actual tests (230.68 seconds wall),
and the affected ordinary suite passing 147 tests with 86 ignored backend tests
(140.50 seconds wall). The ignored tests are qualified by the separate actual
SQL runs, rather than by their ordinary-suite skip. Rustdoc passed 157 examples,
including private-proof/lifetime compile failures (35.28 seconds wall), strict
Clippy with all features passed, and formatting passed. The isolated SQL runner
counterproof exited 1 on the real failing USER assertion before the sessions phase.

Earlier failed receipts are retained. Fixture compile mistakes were corrected;
the elapsed authentication deadline assertion now checks its existing concrete
`Control(Deadline)` error. An ordinary regression caught unnecessary changes to
existing Hub diagnostic strings; those strings were restored and the affected
ordinary suite passed again. These corrections preserve the functional oracles.
No USER HTTP/STS/S3 or caller/dataset qualification is claimed here.
A Linux result does not establish Windows/macOS success or migration completion. Other storage scopes, USER HTTP, callers/datasets and
final integration remain with their separate deliveries.

The [global Hub SQL library](rust-global-hub-storage-admission.md) is a separate
nonPROJECT admission contract for Registry/Rules, requiring effective Hub plus
S3 authority. Its DATA constructor and empty project observer do not grant
permission or enable a Global HTTP body; these existing PROJECT/USER contracts
retain their roots and authority.
