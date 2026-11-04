---
references:
  - target: {type: task, id: tsk-5e58, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e89c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0d97, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-b9ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-e381, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-60d0, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
---
# Shared Rust Now DATA contract

For Broker and Runtime transport integrators. `broker-now-wire` is the canonical
pure crate for the [strict Now DATA contract](rust-now-snapshot-data.md), version
0.1.0, Apache-2.0, Rust 1.98/edition 2024. It contains the previously qualified
codec extracted without changing validation, types or fields. Import
`broker_now_wire::NowSnapshotData`; the old Control module and exports are
removed rather than maintained as aliases.

## Use one validated type

The crate exports `NowSnapshotData`, `NowSnapshotDataError`, `NowSectionsData`,
`NowSectionData`, `NowSectionAvailability`, `NowSectionErrorCode` and typed
`NowTaskData`, `NowSessionData`, `NowMemoryData`, `NowKnowledgeData` rows.
Read model fields remain private. `decode(&[u8], NonZeroUsize)` checks the
complete byte budget before parsing; oversize is `ReadLimitExceeded` and every
syntax/schema/semantic rejection is `InvalidData`. Neither error retains input
or a parser cause. Debug omits DATA contents.

Validated Deserialize on `NowSnapshotData` permits direct embedding into a
Serde command envelope. The containing command must impose its own total byte
budget. Do not decode into a generic Value first: duplicate fields would be
lost before validation. There is no public read model constructor or Default;
rows and sections remain Serialize-only. All strict object/field/enum,
required-nullable, precision, canonical time/identifier, availability, complete
top20 and ordering rules remain in the DATA reference. DATA does not prove
Auth, current ACL, corpus scans, registered ownership or online presence.

The pure implementation uses std, pinned serde 1.0.229 with derive,
serde_json 1.0.151 and ulid 3.0.0 without default features. It has no Control,
SQL, Auth, Tokio, AWS, filesystem or network dependency. Broker channel/WS and
Runtime subscriber must consume this same validation implementation, while
owning their separate authentication, authorization and connection lifecycle.
Their product qualification remains separate from the pure codec tests.

## Consume DATA to remove selected sections

`NowSnapshotData::mask_sections(self, task_read: bool, memory_read: bool,
knowledge_read: bool) -> Self` consumes a validated snapshot. A false Task flag
removes both tasks and sessions; the other flags remove memories and knowledge
respectively. Each removed section becomes exactly `availability: "failed"`,
`items: []`, `total: null`, `has_more: null`, `error: "forbidden"`. Rows are dropped;
headers and permitted sections preserve literal values, ordering, counts and
existing failures, using their original allocations. The operation does not
clone, serialize or parse a second snapshot. Repeating a mask is idempotent;
passing true later cannot restore removed data.

```rust
use broker_now_wire::NowSnapshotData;

fn remove_task_data(snapshot: NowSnapshotData) -> NowSnapshotData {
    snapshot.mask_sections(false, true, true)
}
```

The flags are caller-selected DATA, not an Auth proof. The Broker channel
consumer must derive them from current module Read authorization and check its
actual proof and project before and after masking. The pure crate neither
loads ACL nor authenticates the caller. Task Read covers tasks and sessions;
Write, Presence or Hub permissions do not implicitly grant module Read. A
snapshot with all four sections denied is still valid DATA. No public row or
section constructor, generic mutator or alternative decoder is introduced.
Byte budgets remain the responsibility of the decoding transport.

## Source and build layout

The canonical producer is `crates/broker-now-wire` in the
[Graphit Broker repository](https://github.com/graphit-labs/graphit-broker).
Broker workspace crates use its internal path dependency. Code uses the published
Git revision selected in its Cargo manifest and lockfile. Code's producer-side
integration tests use the same revision as the wire crate, so Cargo resolves the
wire types from one source. Run `cargo fetch --locked` to prepare the dependencies
in a clean checkout.

## Checks and gate

From the Broker checkout:

~~~text
cargo test --locked -j1 -p broker-now-wire --all-targets
cargo test --locked -j1 -p broker-now-wire --doc
cargo tree --locked -p broker-now-wire
cargo test --locked -p broker-control -p broker-now-wire --all-targets
cargo test --locked -j1 -p xtask
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo run --locked --quiet -p xtask -- hook pre-commit
~~~

Pre-commit checks whitespace and formatting. `make check` runs strict workspace
Clippy and the ordinary workspace tests, including Control and the wire codec.
Use `make qualify` for native SQL and transport integration.

The original extraction compared Source and tests to the prior qualified
version after only the Rust crate import change. The later consuming DATA
operation is qualified separately from that extraction. The existing eight
contract tests include real Serde command embedding and byte caps; rustdocs
include positive decoding and four private API compile-fail checks. Affected
Control/Presence and xtask checks protect callers and the gate change.
Artifacts and actual results are retained in
`.build/rust-broker-now-wire-2026-10-11/`; pending consumers and remote CI cannot
be declared passed from this library's evidence. Linux qualification passed: 8 wire tests and 5 rustdocs,
98 Control ordinary tests/90 rustdocs, 17 Presence ordinary tests/4
rustdocs and 6 xtask tests. The existing pre-commit runner passed
(157.78 s wall), including strict workspace Clippy, the codec tests and
other existing fast Rust checks. An isolated staged Rust index kept this
qualification within the unit's scope. A controlled format fault caused the
same runner to exit 1 at formatting (0.76 s); the owned source was restored
byte-exactly and the shared Git index remained unchanged. Final fmt passed.
The lock adds only the new package; all previous package blocks and pins remain
identical. Sixteen protected hashes, two literal normalized moves and seven
affected document links qualify the scope. Windows/macOS, both actual transport
consumers and remote CI remain unrun in this leaf.


The consuming mask qualification is retained separately in
`.build/rust-now-wire-section-mask-2026-10-11/`. On Linux, all 11 wire tests,
the rustdocs (positive decoding/masking and five compile-fail cases), strict
wire Clippy with all targets/features, and workspace format checks passed.
The three added tests exercise all eight masks, mixed section states,
idempotence, monotonic removal, roundtrip validation and unchanged pointers for
permitted headers, row strings and vectors. Source normalization removes only
the added helper/API/rustdocs and recovers the prior codec byte-exactly; the
original eight strict tests remain unchanged. Twelve protected files,
including manifests/lockfile, remain byte-exactly equal to the baseline, and
six affected document links resolve. The existing gate already covers this
crate; no gate or manifest change was needed. This library result does not
qualify Broker channel Auth, Hub, WS, Runtime, remote CI or Windows/macOS.


The [Now channel authorization contract](rust-now-channel-authorization.md)
uses the actual verified principal, fresh whole SQL grants and registry, and
consumes the shared pure DATA mask. Channel observations remain separate from
Hub/WS/Runtime qualification.
