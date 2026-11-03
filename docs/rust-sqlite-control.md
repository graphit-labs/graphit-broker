---
references:
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-3025, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-c055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-4f6e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-7494, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9f63, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-0dff, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-3daa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-b75d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-44aa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-8802, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-b532, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-a51f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-173d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e69e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-cbcc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-d1a2, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# Rust SQLite control persistence

The explicit [SQLite storage admission and HTTP composition](rust-sqlite-storage-admission.md)
uses current native JWT or verified opaque possession and the same protected grant,
route policy, credential service and issuers. This composition does not
issue human bearer credentials or select SQLite globally in Server.

The explicit [SQLite Hub resolver and metadata catalog](rust-sqlite-hub-access.md) compose native JWT, current opaque identity and the existing bounded catalog reader. Executable backend selection is described in the [native Server guide](rust-broker-server.md#select-private-sqlite).

The explicit [administrative session ingress](rust-sqlite-admin-session.md) composes Broker access JWT for current LOCAL identity, common F1 upstream bearer, opaque LOCAL credentials and LOCAL/federated cookies on GET/HEAD session, with confirmed own-cookie logout. It uses current SQLite RBAC and genuine protected proofs. The [administrative browser adapter](rust-sqlite-admin-upstream-login.md), [full-channel administrative readers](rust-sqlite-admin-read.md), [grant mutations](rust-sqlite-admin-grants.md) and [role/assignment mutations](rust-sqlite-admin-rbac.md) compose these owners. See the [native Server guide](rust-broker-server.md#select-private-sqlite) for executable backend selection.

The explicit [federated browser grants and UserInfo](rust-sqlite-oidc-federated.md)
compose genuine H1, public browser/callback, native code/refresh and profile
lookup over the existing physical owner. They reuse the protected upstream proof,
current trust and bounded access snapshot. Their separate native evidence does
not select SQLite in Server. The separate administrative browser adapter supplies SQLite Admin upstream login.

The explicit [SQLite Native Presence integration](rust-sqlite-presence.md) supplies authenticated inventory PUT/own GET and Now WebSocket routers over genuine JWT, fresh whole ACL and the durable inventory producers. It preserves the existing private proofs and owned realtime lifecycle. Executable configuration and dispatch are described in the [native Server guide](rust-broker-server.md#select-private-sqlite).

The [opaque LOCAL verifier and PROJECT HTTP composition](rust-sqlite-local-bearer.md)
consume genuine raw access/service credentials, current user state and whole ACL
through the existing PROJECT route. The [LOCAL administrative cookie producer](rust-sqlite-admin-cookie-session.md)
adds genuine login issuance, current identity reads and confirmed own logout.
The qualified [LOCAL administrative HTTP adapter](rust-sqlite-admin-local-http.md)
composes the existing password/factor login, current cookie session and logout
through explicit SQLite factories; global server selection remains separate.

The explicit [SQLite Broker JWT PROJECT authorizer and HTTP router](rust-sqlite-broker-project-authorization-http.md) combine signed identity with a fresh whole ACL snapshot for each of the nine current operations. This library composition preserves the shared PROJECT wire; executable configuration and dispatch are described in the [native Server guide](rust-broker-server.md#select-private-sqlite).

This producer provides a concrete file-backed SQLite store with upstream OIDC flow persistence. The [native server](rust-broker-server.md#select-private-sqlite) selects SQLite explicitly. The [identity, role-definition and ACL snapshot APIs](rust-sqlite-identity-acl.md) provide metadata, while the [LOCAL producer](rust-sqlite-local-auth.md) supplies genuine password/MFA stages. The [administrative session metadata](rust-sqlite-sessions.md), [dynamic registration catalog](rust-sqlite-oidc-registration.md) and [durable inventory writer](rust-sqlite-instances.md) with its [bounded reader](rust-sqlite-instance-read.md) are additional library producers. The [administrative upstream browser adapter](rust-sqlite-admin-upstream-login.md), [seven full-channel readers](rust-sqlite-admin-read.md) and [authenticated grant writer](rust-sqlite-admin-grants.md) have explicit SQLite compositions. Individual library tests do not establish complete backend integration.

The explicit SQLite DCR HTTP constructor implements the shared public wire and lifecycle described in the DCR reference. Server configuration selects private SQLite through the explicit mapping in the [native Server guide](rust-broker-server.md#select-private-sqlite).

## Explicit configuration and private files

SqliteControlConfig::new accepts a PathBuf, positive startup/operation/shutdown durations and the existing FlowLimits. There is no default path, environment variable, connection URI, in-memory mode or path expansion inside the driver. The configuration caller owns expansion. Relative paths resolve against the process working directory.

New parent directories and database files are private before content is written: 0700/0600 on Unix and the existing Graphit FS private-access policy on Windows. An existing immediate parent must already be private; an existing database must be a private regular single-link file. Insecure permissions, symlinks and hard links are rejected without chmod repair or adoption. Existing WAL, SHM and rollback journals are checked before driver open. The store retains its private directory and uses SQLite's NOFOLLOW flag. Unix revalidation inspects entries relative to that directory and compares the database's opaque identity, without opening or closing database/sidecar descriptors while SQLite is active. This preserves the driver's POSIX locks when another cooperative connection closes. A private process-local mutex covers prepare, new-file birth and birth-handle drop before SQLite opens; live SQL operations hold no such mutex. Windows retains its native handle, DACL and sharing checks. These cooperative checks do not establish confinement against hostile namespace replacement by another process running as the same user.

On Windows the database directory has a protected ACL with one file-inheritable
allow entry for the current user. An existing directory must already meet that
policy. SQLite's own journal, WAL and SHM files inherit this entry at creation;
their handles are verified before reuse. The main database still requires an
explicit protected private ACL.

SQLite uses the exact already-pinned rusqlite 0.40.2 bundled engine. It opens one physical owned connection and serializes operations. There is no accounting pool, idle timer, connection lifetime, importer, schema upgrade or Go fallback. FK enforcement is on, WAL mode is checked and busy_timeout is explicitly 5000 milliseconds. If concurrent startup causes a busy WAL-mode transition after schema initialization, only the idempotent pragma is retried within the existing startup deadline; the transaction is not replayed.

## Startup and reopening

The schema is [rust-broker-v1, epoch 2](rust-sql-schema.md). A BEGIN IMMEDIATE transaction serializes bootstrap. Existing catalog objects must exactly match a second real SQLite catalog generated from broker-store's closed TABLES definitions, including implicit primary-key and UNIQUE indexes. Unknown/missing/altered tables, indexes, triggers, views, format markers, epochs and foreign-key violations are rejected. SQLite STRICT tables are not substituted for the existing DDL: its established nullability is preserved.

A fresh database receives the fixed roles/actions, ACL revision and format marker in the same transaction. Reopening restores fixed built-in permissions and preserves existing ACL revision. Existing data is never imported, silently upgraded or deleted to make startup succeed. For a disposable database, the operator explicitly recreates only that database through normal filesystem operations after stopping its owners. Preserve deployment configuration and credentials separately.

Runtime flow transactions check the captured schema_version after obtaining their SQLite write lock. A schema change stops that operation before it emits a stored flow. Metadata and successful schema inspection confer no user or project authority.

## Flow lifecycle

SqliteControlStore::save_flow and consume_flow reuse OidcFlow and CredentialDigester. SQL retains separate domain-separated HMAC digests for state and browser binding; it does not store those raw inputs. Nonce, PKCE verifier and the closed continuation codec follow the existing upstream-flow contract. A continuation is protocol metadata, never authorization.

Save validates byte limits, PKCE and a positive lifetime of at most ten minutes before admission and again before committing. Duplicate state returns FlowExists. Consumption requires both digests in one BEGIN IMMEDIATE transaction, validates bounded stored fields before deletion and has one winner across independent store connections. Wrong binding leaves the row intact. Corrupt data never emits a flow. An expired matching flow is consumed and returns Expired only after its deletion COMMIT is known.

## Cancellation, acknowledgement and shutdown

Native work runs off the async executor. Cancellation owns a per-operation interrupt handle and stop state. The owned connection remains unavailable while that work or an unacknowledged result exists. Handle clearing and interruption are synchronized before owner release, so an old cancellation cannot interrupt the next caller.

Before COMMIT, cancellation rolls back and reports Deadline (or Closed during shutdown). A confirmed COMMIT result remains successful even when a later clock observation passes the deadline. Once COMMIT has started without acknowledgement, the result is OutcomeUncertain: no flow is returned and the caller must not replay automatically. A transaction left pending after failure causes the connection to be closed rather than reused.

Constructing shutdown closes admission synchronously and interrupts active work. Its future waits for the owner and joins the native connection close. Success confirms that work and close finished. A shutdown deadline reports failure. The polled shutdown still retains the owner acquisition and native close join until cleanup finishes, including an already expired Original or a close queued beyond its deadline; it then returns the original deadline error. This cleanup wait does not renew the operation budget. SQLite's busy handler and native filesystem calls cannot be universally preempted; caller deadlines and retained ownership do not promise a hard operating-system cleanup latency. Database files are not removed on shutdown.

All public errors are finite and omit driver errors, SQL, paths and credential values. Debug output for configuration and the store is redacted.

## Qualification

Run the persistent contract with the same command on supported hosts:

    cargo test --locked -p broker-control --test sqlite_control

Private executor tests exercise real long-running SQL interruption, rollback, COMMIT without caller acknowledgement and shutdown waiting for the actual owner. The existing broker-store schema_contract remains the DDL oracle. Source portability or a successful typecheck does not prove native Windows/macOS behavior.

The consumer now uses Graphit FS's dedicated database birth and existing-file APIs. On Windows these share read/write access while excluding delete sharing; the existing-file opener is read-only and cannot create or truncate. Sidecar verification handles are short-lived and are dropped before native SQLite cleanup. Document/stage and lock sharing contracts remain separate. No native Windows/macOS runtime success is claimed.

## LOCAL OIDC grants

The [LOCAL OIDC grant integration](rust-sqlite-oidc-local-grants.md) composes
pending requests, genuine LOCAL completion, code exchange and refresh rotation
with an explicit Presence token router. It retains the actual Arc issuer and
digester through the existing executor and known COMMIT acknowledgement.
The public LOCAL browser is described below; Server backend dispatch remains separate work.

The [LOCAL opaque administrative session](rust-sqlite-admin-local-bearer-session.md)
uses genuine access/service possession and fresh current SQL RBAC through the
existing session router, with explicit cookie precedence and no fallback.

## Public LOCAL browser

The explicit [SQLite public OIDC browser](rust-sqlite-oidc-browser.md) composes
authorize and login with the existing LOCAL runtime, grant completion and token
router. Identity/factors/CAPTCHA and one-time manual recovery remain owned by
the genuine producers. Native Server backend selection and dispatch remain
separate integration work.

## LOCAL Device authorization

The [SQLite Device producer and HTTP consumer](rust-sqlite-device-authorization.md)
use the physical owner for issue, genuine LOCAL preparation, explicit one-use
consent, persistent polling cadence and atomic access-only JWT redemption. This API does not select the SQLite backend in Server or add upstream/ID/refresh grants to Device.

## OIDC grant inspection and disposal

The explicit [SQLite OIDC lifecycle APIs](rust-sqlite-oidc-lifecycle.md) add
Bearer-and-row introspection, current-client raw-token revocation and signed
ID-hint pair disposal through three productive Presence router constructors.
These
operations reuse the existing IMMEDIATE owner and Work COMMIT acknowledgement,
with one original request deadline and causal uncertain outcomes. They do not
complete native Server dispatch or backend migration.

## Administrative reads

The [seven SQLite administrative reads](rust-sqlite-admin-read.md) compose genuine
Broker JWT, opaque LOCAL, F1 upstream bearer and LOCAL/federated cookie possession
with their specific current SQL action and a complete bounded projection in the
same IMMEDIATE transaction. They retain the genuine proof/window and require a
known COMMIT before response. The implemented API alone does not establish complete backend integration. Writes and global Server dispatch remain
independent work.

## Embedding capability admission

The explicit PostgreSQL and SQLite `embedding_admissions` factories now provide
the current capability observation for the embedding service under tsk-170b.
They borrow the configured native and optional upstream verifier owners, LOCAL
audience and required scopes, with explicit identity and whole-grant JSON bounds.
Their `authorize(raw, original)` operation accepts raw bearer possession or
absence of a bearer, verifies the configured transport, and reads a fresh SQL
grant snapshot even for a potential cache hit. Invalid bearer possession never
becomes anonymous.

Principal selectors are literal after trimming: user, team and organization
match exactly; subject matches its raw or issuer-qualified value. Capabilities
use the existing compiled glob policy. Embeddings has no project identifier, so
a rule's project list does not restrict this capability. Existing PROJECT, Any
and Hub discovery rules retain their own semantics.

The returned `EmbeddingAdmission` keeps its genuine authentication private.
Its synchronous `check()` validates the retained proof and original deadline;
it performs no SQL, network request or UserInfo polling. Snapshot waiting is
bounded by authentication expiry as well as Original, and a temporal read failure
is rechecked through the retained proof; uncertain COMMIT and previously observed
non-temporal failures keep their category. `deadline()` also
bounds a consumer by the original authentication expiry. Each physical SQL
operation retains its own operation budget without replacing the request's
original deadline with a renewed inference lifetime.

The native [embeddings Server configuration](rust-broker-server.md#native-embeddings) composes the PostgreSQL executable. Explicit SQLite embedding cache/admission/HTTP owners retain their own qualification and do not imply global SQLite Server selection.

The explicit [SQLite LOCAL user and credential adapter](rust-sqlite-admin-users.md) preserves the seven administrative operations with physical IMMEDIATE transactions and the shared password engine. It does not select SQLite globally in Server.

The [SQLite LOCAL inventory and Now consumers](rust-sqlite-local-presence-now.md) compose the current opaque verifier with registration, bounded candidates/own reads, partial LIST and live authorization. They use existing owners and genuine policy proofs, without issuing credentials or converting LOCAL registration into Native ownership.
