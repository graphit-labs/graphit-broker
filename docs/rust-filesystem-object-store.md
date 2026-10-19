---
references:
  - target:
      type: task
      id: tsk-f7f9
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: uses
  - target:
      type: task
      id: tsk-4552
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-d646
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-6b60
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-700b
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
---
# Native Rust filesystem objects and conditional publication

Audience: Broker maintainers and server integrators. This component provides volume ownership, object reads/writes, byte ranges and deletion. It also provides listing, COPY and batch delete. [Multipart](rust-filesystem-multipart.md) is a separate server component; the [S3s gateway](rust-filesystem-s3-gateway.md) and mixed HTTP composition have separate qualification. Component tests do not establish a running S3 endpoint or a completed migration.

## Open the volume

`FilesystemStore::open` receives an explicit directory, bucket, nonzero object-byte limit and authored-metadata byte limit. The directory is trusted server configuration; requests cannot choose it. Startup opens that volume once through cap-std, acquires an exclusive `File::try_lock` and retains the owner handle. A second store/process cannot own the same locked volume. Ownership lasts until the store and all retained references are dropped.

New directories/files use owner permissions on Unix. Existing configured directories retain their permissions. Object paths are relative to held directory descriptors; every requested directory segment and final file is opened without following symlinks. Canonical keys use the [session rules](rust-filesystem-storage-session.md#operations-and-failures). The mapping has the filesystem's name/parent constraints: an object file cannot also be a directory containing another object.

Data files at `data/<key>` contain raw payloads. `meta/<key>` holds small native JSON with explicit nullable authored Content-Type and optional derived ETag/size/mtime cache. No envelope is added to data. Staging uses cap-tempfile directories relative to held `tmp`; it never builds an ambient path from a client key. Startup removes abandoned staging inside that owned directory.

## Read objects and RawDrop

Every operation requires a [MAC-verified session](rust-filesystem-storage-session.md), matching bucket/key permission and `FilesystemRequest` with the original deadline and cancellation token. The gateway must additionally verify the actual S3 signature.

`head` returns size, quoted SHA256 ETag, Content-Type and modification time. `open_range` captures a readable file and that information under the shard lock. Its typed range has inclusive start/exclusive end; end is clamped to size and empty/outside intervals fail. The [S3s gateway](rust-filesystem-s3-gateway.md) handles wire parsing, suffix/full-covering ranges and HTTP conditional dates, including pre-epoch timestamps. The caller owns streaming and the request lifecycle of the returned handle.

A valid derived cache with the same size/mtime avoids redundant hashing. Missing, malformed or stale derived values are recomputed from current payload bytes, preserving authored Content-Type. An unrepresentable derived timestamp also invalidates the cache; a valid pre-epoch modification time remains readable. Reads do not need to write a cache. Invalid authored metadata fails explicitly.

A raw file placed in the admitted data tree can be read directly. Without authored metadata, mime_guess infers its type by extension. Existing authored Content-Type survives a change of raw bytes. Broker ownership/locks do not serialize external RawDrop writers or promise integrity against an operator changing bytes and timestamps together.

## Write, compare and delete

`put` receives Content-Type, optional digest and conditional DATA in `FilesystemPutOptions`; these fields confer no authority. Authored JSON is checked against the metadata budget before reading the body; complete metadata is checked again before publication. The read-limit sentinel is validated before opening the volume. `put` streams through a bounded buffer, checking actual bytes, optional SHA256 digest, original request and cancellation. Oversize, invalid metadata/digest, expiry or cancellation before publication leave no published object. Staged payload and metadata are synced.

The fixed 256 mutex shards serialize a key. Publication checks its current ETag under the lock, then rechecks request/session validity before renaming complete raw data. `If-None-Match: *` admits one create winner; a known `If-Match` admits one replacement winner. Conditions accept comma-separated exact values and the existence wildcard; they do not grant permission.

After data rename, authored metadata is published and affected directories synced under the same shard. Success follows both records and final request checks. Post-publication IO or cancellation/deadline returns `CommitUncertain` retaining the actual cause. It does not claim rollback or durable indivisible publication across a crash. Read the current object before retrying an uncertain conditional write.

`delete` requires delete permission and removes data/metadata under the shard. Absence is idempotent. Failure after removal retains an uncertain outcome; deletion does not require read permission. This unconditional path does not start reading or validating object metadata; `delete_batch` keeps its existing unconditional/idempotent behavior.

### Conditional deletion by current ETag

`delete_if_match(session, key, if_match, request)` is implemented and qualified in the tsk-4552 Linux scope below. It requires the same verified session and Delete permission, not Read. The private common delete implementation acquires the same key guard used by PUT, opens the current data file and calls `describe`, checks the existing `FilesystemConditions`, then removes data/metadata and syncs while retaining that guard through its checks. It is not a public HEAD followed by a separate DELETE.

The native ETag is a quoted SHA256 string and comparison is literal. The existing matcher splits comma-separated alternatives and trims each alternative; it adds no new grammar, quote stripping or case normalization. `*` requires a current object. A missing object with either an ETag condition or `*`, and any mismatch, returns `FilesystemStoreError::Precondition` without removing data or metadata. Invalid authored metadata encountered by `describe` fails before removal; the unconditional path still does not parse it. Derived-cache recomputation remains the existing read/describe contract.

This check-before-effect contract follows [RFC9110 If-Match](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match). The [gateway](rust-filesystem-s3-gateway.md#conditional-deleteobject) maps a failed native precondition to412. Kernel IO remains owned and synchronous: failure after data removal, including metadata removal/sync or a final request check, retains `CommitUncertain` with its original cause. Inspect current state before retrying; no rollback or continuously atomic authorization/IO is promised.

The backend performs synchronous owned file IO and detaches no workers. A server adapter must isolate blocking work through its maintained executor and retain/join it on shutdown. Deadline checks surround IO; no claim is made that a kernel operation is interrupted or the final response byte delivered by a deadline.

## List, copy and batch delete

`list` requires a nonempty canonical prefix within the session's readable roots. Empty bucket listing and sibling roots fail. An admitted exact root also prunes adjacent physical siblings such as `artifacts2`. A prefix may be the exact root, end in a slash or select a partial descendant name. The delimiter is absent or `/`. Absent/zero `max_keys` means 1000; 1–1000 is accepted and other values fail.

Objects and common prefixes share lexicographic pagination slots. `start_after` is used without a continuation token. Native cursor DATA binds its raw marker to the same prefix/delimiter; invalid or out-of-scope cursors fail. It provides no authority. URL encoding affects returned keys/common prefixes only, preserving slashes and encoding spaces as `%20`; permissions and markers always use canonical raw keys. The S3s gateway preserves those encoded outputs without encoding them again.

The walker uses held directory capabilities and keeps at most `max_keys + 1` candidate keys, rather than a bucket snapshot. It may scan the whole matching subtree for each page and hash emitted objects when their derived cache is unavailable. Pages do not promise a consistent snapshot across concurrent writes. Symlinks and noncanonical keys in the selected subtree fail explicitly.

`copy` checks read access on the source and write access on the target separately. Its `FilesystemCopyOptions` contains only source/target conditions. It locks each distinct shard once in ascending order, including self-copy, captures source bytes/metadata and reuses the bounded staging/publication path. Content-Type and raw bytes are preserved; source conditions and target CAS can reject the copy. The operation is within one configured bucket. A post-publication error retains the actual uncertain cause.

`delete_batch` preserves input order and reports each key's result. Denied or invalid keys do not prevent other valid deletes; missing objects are successful idempotent deletions. Quiet mode omits successful entries only. Original/cancellation are checked before each next key and stop further processing; an uncertain IO result already obtained retains its actual cause. Denied/invalid entries alone do not imply an uncertain mutation. A deadline or cancellation crossing after a successful or uncertain operation cannot promise rollback. The gateway separately enforces its XML request budget.

## Validation and scope

The native assertions cover mismatched/stale ETags preserving data and metadata, wildcard existence, Delete-only sessions, cancellation/deadline before effects, corrupt authored metadata versus unconditional deletion, and DELETE-A/PUT-B contention with final B bytes, ETag and Content-Type. The barrier only releases the competing calls; it does not force a lock order. The Unix permission case checks data removed, metadata retained and a PermissionDenied cause inside `CommitUncertain`.

Source: `crates/broker-storage/src/filesystem_store.rs`. Real fixture: `cargo test --locked --offline -p broker-storage --test filesystem_objects -- --ignored --exact filesystem_objects_postgres_contract --test-threads=1`. It obtains PostgreSQL TLS NOSUPERUSER admission and a production session before using a temporary volume.

The fixture covers raw bytes, ownership/reopen, ranges, key/bucket denial, byte/digest limits, authored/derived metadata, real concurrent CAS writers, cancellation and deadline expiry during reading, author-budget rejection without reading, pre-epoch RawDrop/authored timestamps, Unix symlinks and metadata permission failure after data rename. The long hook saves `FILESYSTEM_OBJECTS` immediately after the session phase; listing follows it before audit. Linux execution does not establish Windows/macOS runtime qualification.

Listing/COPY/batch fixture: `cargo test --locked --offline -p broker-storage --test filesystem_listing -- --ignored --exact filesystem_listing_postgres_contract --test-threads=1`. It uses real SQL admission and a production MAC session, checks ordered/delimited pages, bound cursors and URL output, COPY conditions/self-copy/opposite concurrent copies and one create winner, mixed permission/quiet batches and a real symlink. The long hook selects `FILESYSTEM_LISTING` immediately after objects and before audit. Neither component fixture establishes actual S3 wire/signature behavior.

Current `.githooks` scripts and `graphit.lock.json` forward pre-commit/pre-push to the existing `cargo run --locked --quiet -p xtask -- hook <event>` commands. Recovered tsk-f7f9/check chk-5d5ee84ad3c1 records pre-push exit1 in1.19s at Rust FILESYSTEM_S3_GATEWAY, before Audit. That is historical fail-fast evidence, not a broad gate rerun for this unit; no new hook or push was performed.
