---
references:
  - target:
      type: task
      id: tsk-d74c
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-6b60
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
  - target:
      type: task
      id: tsk-700b
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: derived_from
---
# Native Rust multipart storage

Audience: Broker maintainers and server integrators. Multipart is part of the server filesystem component. The [S3s wire/signature gateway](rust-filesystem-s3-gateway.md), mixed HTTP composition and native client cutover have separate qualification; this component alone is not a running S3 endpoint.

## Create and transfer parts

Every call requires a production [MAC-verified session](rust-filesystem-storage-session.md), matching configured bucket, WRITE/PUBLISH permission on the canonical key and the original request deadline/cancellation token. Read permission alone cannot create, list, complete or abort an upload. The gateway must additionally verify the actual S3 signature.

`create_upload` validates authored Content-Type and the explicit metadata budget before creating an upload. It returns an opaque random 32-byte identifier encoded with unpadded base64url. The identifier is DATA, not a credential or authorization proof.

Native uploads live in `directory/multipart/<id>`, separate from disposable `tmp` stages. A bounded native JSON manifest binds bucket/key, nullable authored Content-Type, creation time and last confirmed part progress. `parts/<number>` contains raw part bytes. Every directory segment and file uses held capabilities without following symlinks. No access key or secret appears in a path, and no Go format is imported.

`upload_part` accepts numbers 1–10000 and streams through the configured object-byte limit. A replacement uses an atomic rename under the upload shard. The actual payload SHA256 produces the quoted ETag. The part and last-progress manifest are synced before success; an error after part publication returns `CommitUncertain` retaining the real cause.

`list_parts` returns ordered part information calculated from actual bytes. Marker is 0–10000; absent/zero maximum means 1000 and 1–1000 is valid. Its candidate set retains at most maximum plus one numbers. This does not promise a disk-speed or metadata-only listing.

## Complete, retry and abort

`complete_upload` requires a nonempty strictly increasing list. Part numbers may be noncontiguous and parts may be small. Each ETag must be canonical quoted SHA256 and match the bytes read from that part. Missing/invalid parts fail with `InvalidPart`; duplicate/reversed ordering fails with `InvalidPartOrder`. A different key or unknown upload identifier returns `NoSuchUpload` and cannot affect another upload.

Assembly holds the upload and target's distinct fixed shards once in ascending order. It retains one part descriptor at a time, hashes that descriptor while reading, and verifies each ETag at EOF. The shared [object staging/CAS path](rust-filesystem-object-store.md) enforces the aggregate byte limit, request validity, fsync and target conditions. It buffers no complete payload.

A failure before object publication removes only the stage and preserves all parts. Correct the part list, retry a lost CAS with a current condition, or abort. Successful publication immediately removes the upload's parts and syncs that removal. An error after object publication or during cleanup reports an uncertain outcome; it promises no rollback, journal or durable transaction between payload and metadata. Inspect the target before retrying an uncertain completion.

`abort_upload` validates the bound bucket/key and current permission before removing its own upload directory. Recursive removal does not follow child symlinks. An error after removal remains uncertain. A missing or misbound upload is not treated as permission to remove another directory.

## Restart, renewal and abandoned uploads

A fresh valid session may resume an upload on the same authorized key even when its access key differs. Ownership is not bound to an expiring access key. Fresh native manifests and parts survive restart.

Startup under the exclusive volume owner and a later create remove uploads abandoned for 24 hours since last confirmed part progress. Listing does not refresh that timestamp. The current path uses the same upload shard while pruning; it does not run a background cleanup worker. A native directory without a committed manifest is an incomplete native slot and is reclaimed, including residue from an interrupted cleanup. It does not represent an active resumable upload. An existing malformed manifest fails explicitly rather than being repaired or imported.

Synchronous IO remains owned by its caller. Deadline/cancellation checks surround IO and streaming; they do not promise kernel interruption. A gateway executor must retain and join blocking work on shutdown.

## Verification and scope

Source: `crates/broker-storage/src/filesystem_multipart.rs` and causal private hooks in `filesystem_store.rs`. Real fixture: `cargo test --locked --offline -p broker-storage --test filesystem_multipart -- --ignored --exact filesystem_multipart_postgres_contract --test-threads=1`.

The fixture obtains PostgreSQL TLS NOSUPERUSER admission and production MAC proofs for read and publish permissions. It checks 11-byte parts 1+3, replacement/pagination, mandatory actual ETags/order/binding, exact aggregate 32/33-byte boundaries and retained failed parts, actual IO failure after part publication and object cleanup, CAS loss/retry and concurrent completions, cancellation/deadline during transfer, renewed credentials/restart, startup/create cleanup and real symlinks. The saved long hook selects `FILESYSTEM_MULTIPART` after listing and before audit. Linux execution does not establish Windows/macOS qualification or actual S3 wire behavior.
