---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5ca4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9a45, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# PostgreSQL control persistence in Rust

`broker-control` provides PostgreSQL upstream OIDC flow persistence, consuming the [SQL schema and seeds](rust-sql-schema.md) and [credential digester](rust-credentials.md). The [native server reference](rust-broker-server.md) describes its integrated PostgreSQL authentication, administration, OpenID Provider and storage slices. Native MySQL flow, session, identity and role services have separate library qualification; the [private SQLite flow producer](rust-sqlite-control.md) is qualified locally on Linux, with complete backend families and server dispatch still pending. The raw flow-storage API does not authenticate a caller or grant permissions. The [upstream browser producer](rust-upstream-browser-login.md) authenticates identity through a genuine flow and OIDC exchange.

## Connection and startup

Construct `PostgresConfig` with a TCP host, nonzero port, database, username, zeroizing password owner, CA PEM bytes, positive byte limits, `PoolConfig` and `FlowLimits`. Every pool timeout and capacity is explicit. There is no Broker default configuration or DSN parser. Text values must be nonempty, fit the caller's byte cap and contain no NUL. A socket path is rejected. SQL timeout values must fit positive signed 32-bit milliseconds. Other durations must be positive and representable by the monotonic clock.

TLS uses mandatory `VerifyFull`: hostname verification and no plaintext downgrade. The explicit fixed trust set is the union of the WebPKI root bundle (`webpki-roots =1.0.11` in the lockfile) selected by the pinned SQLx feature and the configured CA PEM. The supplied CA is additive, not exclusive. Native OS/environment root discovery is disabled. Callers must accept this trust set when constructing the configuration; this API offers no CA-exclusive or plaintext mode. Before SQLx construction, presence of any of `PGPORT`, `PGHOSTADDR`, `PGHOST`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`, `PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `PGSSLMODE`, `PGAPPNAME` or `PGOPTIONS` is rejected, including empty and non-UTF8 values. Configure the environment before process startup; callers must not mutate it concurrently with opening. `new_without_pgpass` bypasses password-file discovery. SQL statement/value logging is disabled. SDK copies of credentials are ordinary driver-owned strings; zeroizing the supplied password does not promise deletion of these copies.

`PostgresControlStore::open(config, digester, deadline)` owns its pool and digester. Startup uses one `BEGIN ISOLATION LEVEL READ COMMITTED` transaction and advisory lock protocol 1 (`GBRKINIT`). The role/database isolation default cannot change the bootstrap isolation. Domain queries qualify `public`; catalog queries qualify `pg_catalog`.

Only an empty dedicated `public` namespace or the exact 25 persistent, owned tables with format `rust-broker-v1`, epoch 2 are accepted. Real PostgreSQL catalog descriptors are compared to TEMP copies of the closed producer DDL: columns, types, defaults, nullability, collation, identity/generated expressions, constraints, FK targets/actions/deferral/validation and complete index semantics. Rewrite rules, extra indexes, tables, missing markers, legacy layouts, RLS, inheritance, foreign triggers and disabled internal triggers are rejected. No import, compatibility adapter, automatic ALTER or structural repair runs. The [instance registration schema](rust-broker-instances.md) adds two tables; epoch-1 databases are rejected.

Fresh DDL, seeds and the format marker commit together; the marker is last. Each successful open restores the exact nine admin and two user actions, preserves existing role timestamps, custom roles/actions/assignments, and current ACL revision/timestamp. A new ACL state starts at revision 1. Unsupported structure returns `SchemaRejected`; use a separately provisioned empty database after an explicit operational decision. Do not silently recreate a database containing data.

The service uses official `sqlx-core =0.9.0` and `sqlx-postgres =0.9.0` directly. The facade's optional SQLite dependency conflicts with the schema producer's SQLite native library during Cargo resolution. Core's public API is SemVer-exempt; both crates stay pinned in lockstep. Any SDK upgrade requires focused qualification. Runtime/TLS features match the official facade's Tokio/ring/webpki mapping. There is no private SDK patch or second SQLite implementation.

## Save and consume a flow

Build `OidcFlow` with a nonce, RFC7636 PKCE verifier, typed `FlowContinuation` and `SystemTime` expiry. Continuations are exactly `Admin { provider_id }` or `OAuth { provider_id, request_id }`; JSON rejects unknown and duplicate fields. Provider/request text and serialized JSON have caller-supplied finite byte caps. Nonce is nonempty UTF-8 at most 128 bytes; PKCE is 43–128 ASCII unreserved characters. Existing producers persist an internal nonce even when upstream nonce policy is false; the [genuine upstream producer](rust-upstream-browser-login.md) applies the configured nonce policy. Owned Rust nonce and verifier strings use zeroizing storage; SQL and driver copies are not covered by that wiping claim.

`save_flow(state, browser_binding, flow, deadline)` validates before SQL, hashes state in credential domain 2 and browser binding in domain 3, and inserts in an explicit transaction. Raw state/binding are absent from SQL storage. Oversized stored continuation TEXT is rejected in the SELECT before its contents are fetched. Nonce and PKCE are necessarily protocol secrets stored in the protected database. Expiry must be later than now and within the existing ten-minute TTL. A duplicate state returns `FlowExists` without replacing the original bytes.

`consume_flow(state, browser_binding, deadline)` locks by both digests, rereads and validates the stored row, then deletes exactly one matching row and commits. Missing state or wrong binding returns `Unavailable` and preserves the row. Malformed continuation, purpose, nonce, PKCE or timestamps returns `CorruptFlow` and preserves the row. Expiry is checked after obtaining the row lock and again before commit; expiry equal to now is expired. A row observed expired after the lock remains expired even if the wall clock later moves backwards. A matching expired row is deleted and committed before `Expired` is returned. Two concurrent consumers have at most one successful result.

Timestamps are nonnegative signed 64-bit UTC microseconds, floored using the producer's timestamp type. The caller still must validate provider, issuer, PKCE and nonce policy at the HTTP/OIDC boundary; a continuation is not authority.

## Deadlines, uncertain writes and shutdown

Every operation takes an absolute monotonic caller deadline and uses the minimum of it and its configured budget. Connection acquisition, query work and commit share that budget. An error/cancelled future discards its leased connection with SQLx `close_on_drop`; it cannot return a dirty connection or detach it from pool accounting. A successful confirmed transaction returns the connection to the pool.

For operations that can persist application effects, timeout before commit starts returns `Deadline`. Once COMMIT starts, timeout or a driver commit error returns `OutcomeUncertain`: the server may have committed those effects. No flow payload is returned for an uncertain consume. Never infer rollback from this error or automatically replay a save/consume. A confirmed COMMIT stays successful even if a later clock observation passes the caller deadline. These are cooperative budgets, not hard real-time guarantees for OS/DNS work.

The SELECT-only [local bearer state](rust-local-bearer-state.md),
[resource grant snapshot](rust-resource-grants.md) and
[durable inventory](rust-instance-read.md) readers have no persistent application
effect. They still return observations only after successful COMMIT. Their
COMMIT errors use the existing storage mapping and their original-deadline
timeouts return `Deadline`, including while awaiting an ACK. Error/cancellation
discards the connection and releases no observation; no automatic replay runs.
This exception is limited to these three PostgreSQL readers. Other operations
and backends retain their own contracts. The focused
`postgres_readonly_commit_failures_preserve_state` TLS test exercises retained
ACK and physical disconnect for all three readers, unchanged SQL state and
recovery; its executed qualification is recorded with those reader contracts.

`shutdown(deadline)` closes pool admission synchronously when the close future is constructed, waits within its bounded budget and returns `Deadline` if leased work remains. Already leased operations retain their original deadlines. New operations return `Closed`. The service is not Clone; callers may share an `Arc`. The pepper remains owned until the service is dropped, including while other callers retain an Arc; shutdown does not claim to wipe an in-use key.

Public errors and Debug representations are static and redacted; driver errors and SQL values are not exposed as error sources.

## Verification and gates

Commands are project-relative and use executables on PATH:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p broker-control --all-targets
cargo test --locked -p broker-control --doc
cargo test --locked -p broker-control --test postgres -- --ignored --test-threads=1
cargo test --locked -p xtask --test guardrails -- --test-threads=1
cargo audit --file Cargo.lock --json
```

The normal control tests exercise typed limits and subprocess ambient inputs. The ignored integration fixture uses a pinned PostgreSQL 17.11 image, fresh ephemeral CA/server certificates, private test files, loopback-only dynamically assigned ports and owned-container cleanup. It exercises the public Rust service against real TLS, schema faults, concurrent opens/consumers, corruption, expiry while waiting, SQL errors, cancellation, pool pressure, COMMIT uncertainty and shutdown. Docker must be installed and usable; an absent engine is a failure, not a skipped pass.

Pre-commit checks whitespace and formatting. Pre-push runs strict workspace Clippy, Rustdocs and `cargo test --locked --workspace --all-targets`, including the ordinary Control contracts. Native PostgreSQL control, identity, role and session tests, SQL-server fixtures and packaging/container checks remain separate pre-push phases. Individual changes run affected functional suites and formatting/Clippy; complete integration and other-platform runtime behavior require their own validation.

Runtime write tests verify confirmed deferred COMMIT success and real timeout/disconnect uncertainty. The guarantee that confirmed success is not reclassified after ACK follows the production return path and Tokio Timeout polling its inner future before its timer; the fixture does not claim to force a clock tick between ACK and the synchronous return.

The TLS runtime fixture proves acceptance of its additional private CA and rejection of another private CA, an incorrect hostname and plaintext. The bundled WebPKI trust shape is established by the pinned SDK source and feature graph; these private fixture results do not prove a connection through a known public CA.

[Administrative session persistence](rust-admin-sessions.md) extends this store with create, consistent read and revoke, qualified on Linux in `tsk-dcfc`.

## Schema producer qualified on Linux

The typed schema producer generates owned `String` DDL from one immutable table
inventory. The TEMP reference uses that same generated DDL; no independently
maintained PostgreSQL or MySQL catalog is substituted. The production control-store
algorithm, configuration, security and transaction interfaces remain unchanged by
this producer work. The current public flow and administrative-session suites passed
against the generated DDL in the actual configured prepush counterproof on Linux
under `tsk-5ca4`; the restored SQL-server target also passed PostgreSQL 17.11. See [the typed MySQL reference](rust-mysql-catalog.md).

[PostgreSQL identity and current SQL roles](rust-postgres-identity.md) uses a borrowed readonly reader on this pool; its four native identity cases passed on Linux, and the affected flow and session native suites also passed on Linux.

[PostgreSQL role definition replacement](rust-postgres-roles.md) persists complete permission bundles on the existing control pool. It preserves built-ins and current RBAC semantics; all three native cases passed on Linux under tsk-d609. Authentication and HTTP authorization remain separate server deliveries.

## Installation inventory writer

PostgreSQL also provides `replace_instance_inventory` for the epoch2 normalized
installation schema. The [inventory contract](rust-broker-instances.md#postgresql-inventory-replacement)
describes immutable owner binding, canonical data, atomic replacement, no-op
timestamps and finite errors. This is SQL persistence; server authentication and
project authorization remain separate producers. Its focused native validation
and current qualification belong to `tsk-5870`, independently of the historical
flow qualification above.


## Local bearer SQL state

The borrowed [local bearer state reader](rust-local-bearer-state.md) reads a typed
opaque local token and current user attributes in one READ COMMITTED statement
snapshot. Its digest and DTOs are metadata. Bearer verification, current resource
grants and registration HTTP/WS consumers require their own server producers.

## Local opaque bearer verification

The [raw bearer verifier](rust-local-bearer-verifier.md) composes the current SQL
reader with Rust domain-separated digests, audience/scopes/expiry/revocation
checks and best-effort usage recording. Its private successful result still
requires current resource authorization before a consequential operation.

## Resource grant SQL snapshots

The [normalized grant reader](rust-resource-grants.md) reads current ACL revision
and all parents/children in one read-only statement snapshot. It returns metadata;
validated policy evaluation after current authentication remains a server producer.

The [local presence authorizer](rust-presence-authorization.md) composes raw local
bearer verification and fresh same-rule project ACL. Its qualification and
transport limits are recorded separately.

Authenticated ALL-project registration and empty-inventory ownership are provided
by [local instance registration](rust-instance-registration.md). This operation
composes current raw local Auth, fresh Publish grants and the SQL inventory writer.

The strict Rust [instance registration HTTP route](rust-instance-registration-http.md)
uses the authenticated business registrar through the shared control store.

Read one durable inventory through the [Rust SQL data reader](rust-instance-read.md).

Use the [authenticated own-inventory reader](rust-instance-inventory-read.md)
for current local Auth, literal ownership and complete Read permission.

Use the [own-inventory HTTP reader](rust-instance-inventory-read-http.md)
for GET reconciliation and explicit PUT+GET router composition.

Read complete candidates in C ID order through the [SQL candidate reader](rust-instance-candidates.md).

Use the [local authenticated inventory lister](rust-instance-list.md) for partial
Read projection, cumulative filters and a cursor for only visible returned items.

The [local logical PROJECT authorizer](rust-project-authorization.md) checks explicit
module/action capabilities using current opaque local Auth and the shared policy
matcher. Logical PROJECT permission and storage authority remain separate.
The [local PROJECT HTTP route](rust-project-authorization-http.md) exposes one
strict project/module/action request and an observed current local decision.

## OIDC stored access grant data

The [OIDC grant DATA reader](rust-oidc-access-grants.md) returns stored grant metadata,
optional dynamic registration and current local user data. It confers no authority
and is independent of local JWT authentication until expiry.
