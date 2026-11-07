---
references:
  - target: {type: task, id: tsk-5e58, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-e89c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0d97, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b98d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Rust Now snapshot DATA decoder

For Broker transport integrators. `broker_now_wire::NowSnapshotData` decodes the
[Now local wire](rust-now-local-wire.md) emitted by the Runtime compositor.
This library validates DATA; it does not authenticate the publisher, prove a
corpus scan or admission, select an installed version, or establish presence.
HTTP/WS and the Runtime callers are separate deliveries.

## Decode and embed

```rust
use broker_now_wire::{NowSnapshotData, NowSnapshotDataError};
use std::num::NonZeroUsize;

fn receive(bytes: &[u8], byte_budget: NonZeroUsize)
    -> Result<NowSnapshotData, NowSnapshotDataError>
{
    NowSnapshotData::decode(bytes, byte_budget)
}
```

The caller supplies a positive byte budget; there is no default. The decoder
checks the complete input length before invoking Serde. Equality with the budget
is accepted. Oversize returns `ReadLimitExceeded`; every syntax/schema/semantic
failure returns `InvalidData`, without retaining input or a parser cause.
Replace invalid input at its producer; do not coerce, skip, truncate or invent
counts to admit it. A larger explicitly configured budget only addresses size.

`NowSnapshotData` also implements **validated Deserialize**. A containing WS
command must decode it directly through Serde and impose its own whole-command
byte budget. Do not first parse the snapshot into `serde_json::Value`: duplicate
fields would have been lost before validation. Generic Deserialize itself does
not impose the byte budget of `decode`. Either entry point validates the same
entire snapshot before constructing the public object. Trailing JSON is rejected
by `decode` and by `serde_json::from_slice` of a containing command.

All read model fields are private. The envelope exposes `project_id()`,
`generated_at()` and `sections()`; sections expose typed rows, availability,
nullable counts, `has_more` and error. Rows expose their allowlisted fields.
Among these read models only the envelope implements Deserialize; row/section objects have no public
constructor, Deserialize or Default. Serialize emits the exact local allowlist.
Debug omits snapshot contents, including titles, actors and IDs. These properties
limit accidental exposure and preserve whole-object invariants; DATA is never
an authorization proof.

The [consuming section mask](rust-broker-now-wire.md#consume-data-to-remove-selected-sections)
removes caller-selected modules from validated DATA without copying permitted
rows or changing these decoder invariants. Its flags are not authorization.

## Whole-input invariants

Every envelope, section and row field is required, including nullable fields.
Unknown and duplicate fields are rejected at every level. Objects must be JSON
objects, including rows; complete positional arrays are rejected. Availability
and finite error codes must be strings, never externally tagged objects. The exact row fields,
finite availability/error values and exclusions are in the local wire reference.
There is no USER memory, raw source/body/path, token, claim, publisher identity,
SDK generation, revision, progress or logical href in this shape.

| Availability | Items | Total | has_more | Error |
| --- | --- | --- | --- | --- |
| available | exactly min(total, 20) | safe unsigned integer | total > items.length | null |
| no_corpus | [] | 0 | false | null |
| failed | [] | null | null | one finite local error code |

An EOF-empty available corpus differs from no_corpus. Both have zero rows,
but the decoder cannot attest that absence or EOF was actually observed.
A failed section cannot retain data or counts. Every total and both session
counters are unsigned JSON integers no greater than 9007199254740991; a session's
completed_tasks cannot exceed total_tasks. Floats, clamping and fake zero fail.

Project, Task, Session and Memory IDs are canonical, nonzero ULIDs. A task's
session_id is mandatory, but that session need not occur in the selected top20.
Knowledge slugs are nonempty, contain no slash, backslash or control character,
and do not start with `..`; they retain literal text and case. Task and Session
titles are nonempty and already trimmed. Memory titles must be nonempty after
trimming but retain their literal text. Knowledge titles may be empty.
Task/Session owner and Memory updated_by are public Auth attribution encoded as
canonical uppercase 26-character ULIDs. All 128-bit values, including zero, are
valid attribution; this is not the nonzero entity-ID rule above or a creation
timestamp. Lowercase, aliases, overflow and the former 64-hex encoding fail
validation. These fields are never the authenticated channel owner.

All timestamps are canonical decimal **strings**, with no plus, redundant zeros,
negative zero, fraction or exponent. Task/Session/Memory timestamps are u64
milliseconds multiplied by 1000000, preserving the full range up to
18446744073709551615000000. Knowledge updated_at is signed i64 nanoseconds or
null, including negative/extreme values. generated_at is nonnegative and its
millisecond floor fits u64, so its maximum is 18446744073709551615999999.
Task/Session leases must be strictly later than that captured generated_at.
Validation never consults the current clock or adds a freshness TTL.

Rows have unique IDs/slugs within their section and sort by numeric updated time
descending, then literal ID/slug ascending. Knowledge unknown times sort last.
The decoder requires the producer's complete top20; a shorter nonempty prefix
or an empty slice with a positive total is invalid.

## Implementation and evidence

- [Envelope and codec](../crates/broker-now-wire/src/lib.rs): private Raw
  Serde models, one whole-input validation, finite errors and typed read models.
- [Contract tests](../crates/broker-now-wire/tests/now_snapshot.rs): strict fields
  at every level, nested command decoding, exact caps, allowlist roundtrip,
  availability/precision, native timestamp extremes, ordering and top20.
- The actual Runtime producer is graphit-code
  `crates/graphit-daemon/src/project_now.rs` (`read_project_now`, tsk-b98d).

Run `cargo test --locked -p broker-now-wire --test now_snapshot`, the affected
Control/Presence ordinary and doc suites, strict Clippy and formatting checks.
Codec fixtures are DATA inputs, not fake Auth/admissions or a qualification of
Runtime-to-Broker WS. Live presence, fresh PROJECT ACL and channel registration
must be proved by their own producers and integration tests.

The canonical codec is the standalone [broker-now-wire crate](rust-broker-now-wire.md).
Its extraction preserves the qualified DATA contract and gives Broker and
Runtime consumers one SQL-free implementation.

The [Rust realtime Hub](rust-realtime-hub.md) consumes actual channel proofs and strict snapshot DATA for ephemeral publication, project invalidations and authorized replay.

The [Rust realtime WebSocket server](rust-realtime-ws.md) composes these contracts with explicit runtime ownership, fresh authorization and full project views.
