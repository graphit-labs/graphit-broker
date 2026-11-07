---
references:
  - target: {type: task, id: tsk-795b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7240, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3ddd, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-08bd, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-a542, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust Now local wire contract

Audience: Runtime compositor owners and future Broker transport integrators.
This is the approved local DTO contract from ses-c98a, not an implemented
Now endpoint or a qualification of the compositor.

## Envelope and allowlist

~~~text
NowLocal {
  project_id: canonical project ID text,
  generated_at: DecimalEpochNs,
  sections: {
    tasks: Section<Task>,
    sessions: Section<Session>,
    memories: Section<Memory>,
    knowledge: Section<Knowledge>
  }
}

Section<T> {
  availability: "available" | "no_corpus" | "failed",
  items: T[],
  total: SafeCount | null,
  has_more: boolean | null,
  error: null | "forbidden" | "unavailable" | "invalid_data"
              | "limit_exceeded" | "counts_unavailable"
}
~~~

All fields are present. The envelope contains only these three fields.
Scope/version/instance identity belongs to the future remote Broker wrapper;
the local compositor retains its captured project/version internally. It does
not derive authority or the active version from maintained inventory.

| Item | Exact fields |
| --- | --- |
| Task | id, session_id, title, owner, lease_expires_at, updated_at |
| Session | id, title, owner, lease_expires_at, updated_at, completed_tasks, total_tasks |
| Memory PROJECT | id, title, updated_by, updated_at |
| Knowledge | slug, title, updated_at |

IDs and slugs retain their producer's canonical text representation.
Task session_id is required canonical SessionId text, matching the actual
TaskActivityHead producer; missing session linkage is an error, not null.
Task/Session owner and lease are present on included active records. Owner is
the actual persisted Auth attribution, a canonical uppercase 26-character ULID,
not a display name, publisher identity or selected agent. Memory updated_by
retains that public attribution; Knowledge has no invented author. Actor
attribution preserves all 128 bits, including zero, and does not encode creation
time. The former 64-hex encoding and noncanonical aliases are rejected by the
[shared decoder](rust-now-snapshot-data.md).

Exclude USER memories, source/body, physical paths/branches/corpus URIs,
audit/embeddings, raw causes, SDK generations, claim tokens, revision/epoch,
progress summaries/next steps and full stored objects. The minimal wire also
omits typed progress observations and logical href; adding either is a separate
contract decision.

## Availability and counts

An available section has error null, a real total and has_more. Published but
empty after complete EOF is available with []/0/false/null.

An actual producer NoCorpus is no_corpus with []/0/false/null. This is validated
absence through the producer's probes, not an assertion that a missing corpus
was scanned to EOF. NoCorpus and an EOF-empty published corpus are distinct.
A present Memory directory without its index is IncompleteCorpus and must
fail; storage/Auth/schema failures never become no_corpus.

A failed section has items [], total null, has_more null and exactly one finite
code. Unavailable session counts must not become zero or retain misleading
session items. The producer's valid 0/0 for a session with no linked tasks is
a real count, not an error fallback.

SafeCount is an unsigned JSON integer at most 9_007_199_254_740_991. Check every
section total and both session counters before emission. An actual wider count
fails its affected section with limit_exceeded and unavailable counts.
Do not round, clamp, truncate, skip records or add a scan quota to make it fit.
This bound protects the wire representation; it is not a RAM reservation.

## Activity, ordering and timestamps

Use the complete producer scan to EOF before filtering and totals.
Tasks/Sessions are active only when in_progress, with a real owner and a lease
strictly future relative to the same checked UTC observation instant. Equality
and an absent lease are inactive. Reading does not claim, expire, renew or
repair records. Session denominators count all linked tasks, including cancelled;
only completed tasks contribute to the numerator, before activity filtering
and top-20 selection.

Memory heads are PROJECT only, current head, not superseded and not tombstoned.
Knowledge uses its actual three-column head projection.

For each successful section: filter, calculate total, sort by updated time
descending then canonical ID/slug ascending, take 20, and compute
has_more = total > items.length. Knowledge unknown times sort last.
Do not compare serialized timestamp strings or apply SDK limit20 before totals.

DecimalEpochNs is a canonical signed decimal string in UTC epoch nanoseconds,
without exponent, leading plus or redundant leading zeros; zero is "0".
Every timestamp uses this encoding. Task/Memory native u64 milliseconds become
nanoseconds with checked wide integer arithmetic, preserving their entire
native range without narrowing through i64. Knowledge native signed i64
nanoseconds preserve negative values and null for unknown updated_at.
No timestamp becomes a JSON number, float, fabricated epoch or current time
substitute for missing Knowledge time.

generated_at uses a checked observation clock. Activity uses the corresponding
UTC milliseconds from the same observation. Failure to obtain a valid clock
aborts composition with a typed failure; it cannot manufacture epoch zero.

## Real producers and error mapping

The following sources are in logical project graphit-code.

| Producer | Native API / projection |
| --- | --- |
| Memory, tsk-3ddd complete | NativeMemoryStore::observe_heads(original, admission, MemoryHeadReadLimits); MemoryHeadRead NoCorpus or Published with id/title/updated_by/updated_at |
| Tasks/Sessions, tsk-08bd complete | NativeTaskStore::observe_heads(original, admission, TaskStoreReadLimits); TaskHeadObservation NoCorpus or Published with independent Task/Session Results and complete counts |
| Knowledge, tsk-a542 complete | read_native_knowledge_heads(original, admission, KnowledgeHeadReadLimits); KnowledgeHeadRead NoCorpus or Published with slug/title/optional updated_at |

| Finite wire code | Actual typed discriminants |
| --- | --- |
| forbidden | Auth(Denied/Expired), WrongAdmission, DifferentRequest; a refusal of authority/context, not necessarily only missing permission |
| limit_exceeded | Auth(Limit), Memory Limit, Knowledge LimitExceeded/Overflow, or the checked wire count bound |
| invalid_data | Memory Invalid/IncompleteCorpus; Task Invalid/MissingSession/IncompleteCorpus; Knowledge InvalidField/DuplicateSlug |
| counts_unavailable | Exactly TaskStoreError::CountsUnavailable |
| unavailable | Remaining acquisition/capture/IO/SDK/Arrow/store/branch wrappers or unexpected operation variants |

Auth Invalid/InvalidSetting/Request/Entropy/State use unavailable unless an
actual producer supplies a more specific typed discriminator. Task has no
Limit variant; do not invent one or classify by strings. Generic SDK/Arrow
errors are not automatically corrupt data. Never serialize Display, Debug,
source(), nested causes or raw driver details. Future error variants require
typed reconciliation rather than a string classifier.

Check the original cancellation/deadline before classifying producer errors and
again before final delivery. Request IO carries real Interrupted/TimedOut, while
AuthError::Request lacks that detail; rechecking the original is required.
Original cancellation/deadline aborts the entire composition, without a partial
snapshot. Expired authority while the original remains valid can fail a section
with forbidden; it does not prove that the original deadline expired.

Task/Session row-local isolation is preserved: an invalid Session can coexist
with valid Tasks; invalid Task heads make session counts unavailable. Global
identity/linkage/schema/SDK/Auth/context failures fail both sections.
Memory/Knowledge failures keep other sections only if their own admissions
remain valid. Recheck all successful admissions and the original before output.
Drop denied data and counts. There is no common atomic snapshot or continuing
authorization lease across the three corpora.

## Provenance and next implementation

Authoritative source locators in graphit-code:

- crates/graphit-records/src/memory_store.rs: MemoryStoreError.
- crates/graphit-records/src/memory_store/model.rs: MemoryActivityHead/MemoryHeadRead.
- crates/graphit-records/src/memory_store/read.rs: observe_heads/filter/EOF/limits.
- crates/graphit-records/src/memory_store/native.rs: admission and absence.
- crates/graphit-records/src/task_store.rs: TaskStoreError.
- crates/graphit-records/src/task_store/model.rs: Ownership/TaskActivityHead/SessionHead/TaskHeadObservation.
- crates/graphit-records/src/task_store/observation.rs: complete counts and error isolation.
- crates/graphit-data/src/knowledge_index.rs: head reader, error enum, probes and signed nanosecond codec.
- crates/graphit-auth/src/policy.rs and issuer/records.rs: typed authority and rechecked admissions.
- crates/graphit-core/src/file_io.rs: original cancellation/deadline.
- crates/graphit-core/src/version_context.rs: logical version versus internal branch.

tsk-7240 closes activity/counts/order/isolation and places composition in Runtime,
avoiding a Data→Records dependency cycle. tsk-a51f is qualified maintained
inventory, not a Now compositor, active-version selector or presence proof.

Main approved the local shape, encoding, availability, finite codes and count
precision bound. The Runtime owner must save/read back a bounded implementation
leaf under its existing delivery using these qualified producers before Source.
The new leaf should prove real admissions and late cancellation/Auth denial,
active/expired/equality leases, cancelled-inclusive session counts, more than20
and stable ties, independent errors, NoCorpus versus EOF-empty, USER exclusion,
Knowledge unknown/negative/extreme precision, exact allowlist, safe-count
boundaries without quota, and final rechecks. Never infer those passes from
producer suites or from this static contract.

Remote scope wrapper, fresh Broker project ACL, HTTP/WS, live presence,
subscription ordering/deltas/reconnect, CLI TTY/pipe/cancellation and final
integration remain separate work. Local composition does not wait for the
unrelated list or WebSocket contract.

The Broker [strict DATA decoder](rust-now-snapshot-data.md) validates this shape,
including required nullable fields, precision and the complete top20. Its public
Deserialize validates embedded snapshots directly; it establishes no Auth,
admission, registered channel or online presence.

The decoder is provided by [broker-now-wire](rust-broker-now-wire.md),
for server and Runtime consumers. Each consumer requires qualification in
its own delivery; this codec does not establish that qualification.
