---
title: Rust global Hub storage admission
doc_type: reference
references:
  - target: {type: task, id: tsk-c1be, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-c027, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c73a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: memory, id: 01M4RTBP4TS3SY0WPFK6K0M0GY, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust global Hub storage admission

For Broker server maintainers and integrators. The Rust SQL library admits the
global Hub registry and rules through actual authentication and current
nonPROJECT Hub plus S3 authority. The SQL server library is qualified on Linux in `tsk-c1be` by the focused
actual contract and saved SQL phase, with affected checks passed.
This SQL library qualification does not establish HTTP/STS/S3 behavior. The
[separate Global HTTP extension](rust-global-hub-storage-credentials-http.md)
consumes this actual grant; native callers/codecs and migration integration remain separate.

## Request the resource and authenticate

Keep the actual `broker_storage_authorizer` or `local_storage_authorizer` factory
alive through authentication, admission and later issuance. Native verifies its
configured JWT trust; opaque access/service verifies current SQL identity and its
explicit audience. Modes do not probe another credential format after failure.
The [private proof/grant API](../crates/broker-control/src/storage_admission.rs)
contains compiling lifetime examples.

~~~rust
let scope = StorageScope::global_hub();
let caller = factory.authenticate(&raw_bearer, &required_scopes, original)?;
let grant = factory.authorize_authenticated(caller, &scope).await?;
grant.check()?;
~~~

The excerpt assumes actual configured imports, factory and credentials. Opaque
authentication is asynchronous. `StorageScope::global_hub()` and its observers
are DATA: `project_id()` and `installation_id()` are `None`, and `module()` is
`StorageModule::Hub`. No project/installation/owner/hash input is accepted.
The string `global` is not a canonical ProjectId or a project-selector alias.
A scope, discovery `HubProjectSelector`, transport lease, URI or saved codec
cannot construct an authenticated caller or private grant.

The exact private roots match qualified Code DATA producer `tsk-c027`:

~~~text
v1/hub/global/registry
v1/hub/global/rules
~~~

Roots are relative to the explicitly configured physical provider prefix. There
are no Global artifacts, metadata/events, PROJECT or USER roots. Library
credential DATA keeps the project identifier empty for this nonPROJECT scope;
that is not a fabricated PROJECT grant. The separate [PROJECT Hub roots](rust-hub-storage-admission.md),
[PROJECT corpora](rust-project-corpus-storage-admission.md) and
[USER Memory](rust-user-memory-storage-admission.md) remain intact.

## Effective nonPROJECT Hub and S3 authority

Each request reads a complete fresh SQL snapshot with a positive revision and
compiles every rule, including invalid irrelevant domains. The existing actual
literal principal matcher and SDK capability globs compiled into anchored byte
regexes are reused; no raw regex syntax is introduced. Only rules
applicable to that principal with `projects=[]` or containing `*` are eligible
without a PROJECT ID.

An effective capability matching the literal value `hub` is required among
those eligible rules. It can come from a different rule than the S3 rule that
contributes an operation and prefix. Exact PROJECT Hub grants cannot supply this
global capability, even alongside nonPROJECT S3. Literal `hub:admin` is not `hub`;
a mature SDK glob such as `hub*`, whose compiled regex actually matches `hub`,
retains its existing semantics. `hub.*` contains a literal dot in this grammar.
S3 without Hub or Hub without contributing S3 denies admission.

For each read/write/publish/delete operation, one contributing S3 rule must
itself match `s3` or `s3:<operation>` and its own `s3_operations` constraint.
Do not combine a capability from one rule with another rule's operation mask.
Logical prefixes intersect only the two fixed global roots at segment boundaries.
A broad `v1`/`v1/hub` prefix therefore cannot grant other global subtrees,
PROJECT, USER or sibling roots; an authorized descendant remains narrower.

Only an effective S3 operation plus intersecting prefix selects a route. A Hub
rule with no S3 operations does not choose or conflict with a route. Empty route
uses the explicit configured default; conflicting contributing routes fail.
A valid `{project}` template without ProjectId contributes no prefix, operation
or route, without inventing a replacement value. The whole grammar is still
validated, so an invalid placeholder/pattern in an irrelevant rule fails the
entire policy. No new template names, capability defaults or selectors are added.

For example, a current nonPROJECT authenticated rule with capability `hub` may
coexist with a separate applicable rule `s3:read`, prefix `v1/hub/global/registry`
and route `primary`. Only Registry read is admitted. A Hub-only rule's unrelated
route does not change that result. Both policies remain current SQL authority,
rather than permission supplied by the scope constructor.

## Clocks, failures and recovery

One original absolute deadline is supplied. Existing authentication applies the
earlier original/configured operation bound; admission retains that same bound
and actual UTC/monotonic credential expiry. It never renews the original budget.
Private same-factory binding and checks around positive/negative decisions
remain required. SQL owns transaction/COMMIT uncertainty without an outer timer
or replay. The existing access and AWS STS TTL configuration is unchanged.

Missing effective Hub/S3 or noncontributing operation/prefix is `Forbidden`.
Invalid whole policy, conflicting routes or configuration preserve their concrete
errors; invalid/expired Native or unauthenticated opaque credentials preserve
mode-specific errors. Actual SQL privilege failure is a storage/backend error,
not ACL denial; closed, deadline and uncertain outcomes preserve their producers.
Fix the actual identity, policy or backend before a new request. Disabling a
current opaque identity or withdrawing Hub authority denies new admission; a DATA
scope or earlier grant is not a renewal or an instant STS-revocation guarantee.

## Verify the library and saved SQL gate

The actual ignored contract uses PostgreSQL TLS under NOSUPERUSER, EdDSA JWT
verification and current opaque access/service credentials. It covers independent
and same-rule Hub/S3, empty/wildcard vs exact PROJECT domains, actually matching
capability regexes vs `hub:admin`, other principals, both roots and four masks,
ancestor/descendant/sibling/PROJECT/USER boundaries, contributing routes, invalid
whole policy, fresh revision/Hub withdrawal, current identity, wrong mode,
factory mismatch, expiry, bounded original deadline and SQL failure/recovery.

~~~text
cargo test --locked -j1 -p broker-control --test global_hub_storage_admission -- --ignored --exact global_hub_storage_admission_contract --test-threads=1
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence -p xtask --all-targets
cargo test --locked -j1 -p broker-control -p broker-storage -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control -p broker-storage -p broker-presence -p xtask --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The existing [POSTGRES phase](rust-sql-schema.md) includes the exact global target
and all existing SQL targets. Its current actual execution qualifies directly
affected PROJECT/USER/Hub SQL regressions separately from ordinary skipped tests.
The reused isolated runner counterproof tests a real failing Global Rust assertion
stops before the sessions phase; it proves the barrier, not a Broker backend.
All existing HTTP/STS/AWS phases, hooks, classifiers, manifests and locks are retained.

Receipts in `.build/rust-global-hub-storage-admission-2026-10-12/` distinguish
actual passes, failed fixture expectations and unrun/platform limits. Linux does
not establish Windows/macOS, global HTTP/STS/S3, caller/codecs or final migration
qualification. The current HTTP router retains PROJECT twelve fields and USER
thirteen fields; the separate [Global HTTP extension](rust-global-hub-storage-credentials-http.md)
adds a two-field body and twelve-field response without changing those contracts.

Linux qualification receipts record the focused real Global contract passing
one test (108.98 seconds runtime, 115.31 seconds wall), and the exact saved
seven-target SQL phase passing all 18 actual tests (344.03 seconds wall), including
Hub, PROJECT and USER regressions. The affected ordinary suite passed 150 tests
with 88 ignored backend tests (150.17 seconds wall); skips are not backend proof.
Rustdoc passed 157 examples including private-proof/lifetime compile failures
(2.53 seconds), strict Clippy with all features passed (21.52 seconds), and
formatting passed (0.62 seconds). The isolated failing Global Rust assertion
stopped the current saved SQL runner before sessions, exit 1 (0.78 seconds).

Earlier fixture failures are retained: the opaque enum used an incorrect
variant, temporary arrays did not live through SQL awaits, an expected deadline
ignored the existing configured operation bound, and the positive capability
pattern used raw-regex assumptions instead of the SDK glob grammar. Those
expectations were corrected against actual existing producer contracts; no
production syntax, budget, errors or security oracle was relaxed. Only current
SQL server admission is qualified, with global HTTP/STS/S3 and native codecs/
callers left to their respective deliveries.
