---
references:
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5ca4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target:
      type: task
      id: tsk-3e19
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-ea46
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: relates_to
---

# Rust SQL durability contract

This reference describes the independent `broker-store` Rust library. It supplies
fixed SQL table definitions, initial role/action data and checked UTC timestamps.
This library does not open databases or authorize requests. The [native Rust server](rust-broker-server.md) consumes the PostgreSQL store for identity, authorization, administration, the Broker OpenID Provider and storage. Its configuration selects `database.backend: postgres` or explicit private `sqlite`; the [database operations reference](database.md) describes the same explicit native backend contract.

The Rust workspace requires Rust 1.98. Production library code has no external
dependencies. The typed producer generates small owned DDL strings on demand without
performing I/O. `schema_statements` yields `String`; callers borrowing SQL use `&sql`.
See the [typed MySQL reference](rust-mysql-catalog.md). The broker-store crate uses bundled SQLite as a development dependency to execute
the schema fixtures. The separate [SQLite control producer](rust-sqlite-control.md) uses the same exact engine pin for persistent flow storage. Pinned PostgreSQL and MySQL server fixtures also execute
the DDL and initial constraints. See [Rust PostgreSQL control persistence](rust-postgres-control.md) and [Rust MySQL control persistence](rust-mysql-control.md) for their native runtime stores. MySQL server selection remains follow-on work.

## Format and durable fields

The exact new identity is `rust-broker-v1`, epoch `2`. The fixed `schema_meta`
table has a single allowed ID, `1`, and stores that identity and epoch. An SQL
adapter must read and validate both through `SchemaVersion::validate` before
using other tables. This check describes database data and grants no authority.
Unknown identities and zero, old or future epochs produce a static error
instructing the operator to recreate the database. No reader, importer or
converter accepts another format. Epoch-1 Rust databases are also rejected;
startup does not add missing tables or upgrade an existing database. For a disposable
development database, explicitly recreate it through the chosen engine’s normal
operations, then initialize the new Rust service. Select only the development
database; preserve configuration and credentials separately. Never reset a database
automatically in response to this error.

The 25-table inventory includes these durability domains:

| Domain | Tables |
| --- | --- |
| Format | `schema_meta` |
| Roles and assignments | `roles`, `role_permissions`, `role_assignments` |
| Administration sessions | `admin_sessions`, `admin_session_principals`, `admin_session_claim_roles` |
| Upstream OIDC flows | `oidc_flows` |
| Local identities and MFA | `local_users`, `local_mfa`, `local_mfa_recovery_codes`, `local_auth_challenges` |
| Broker OP and credentials | `local_tokens`, `oidc_auth_requests`, `oauth_device_codes`, `oauth_dynamic_clients` |
| Resource authorization | `resource_acl_state`, `resource_grants`, `grant_capabilities`, `grant_projects`, `grant_s3_operations`, `grant_s3_prefixes` |
| Instance registration | `broker_instances`, `broker_instance_project_versions` |
| Embedding cache | `embedding_cache` |

The inventory contains 138 columns and twelve cascading foreign keys.
Instance registration adds two tables without changing the earlier domain structures;
see [the instance schema contract](rust-broker-instances.md). The embedding composite primary key remains
`(compatibility_hash, input_hash)`. The new metadata slot and timestamp
representation are deliberate changes to the fresh Rust format.

The definitions contain password PHC verifiers, credential HMAC fields and
encrypted MFA/challenge fields rather than new plaintext passwords, peppers,
bearer/refresh/code/recovery values or TOTP secrets. OIDC nonce, PKCE verifier and
administration CSRF state remain necessary protected protocol state in SQL.
Consequently SQL is not described as containing no secrets. Deployment
configuration, operational provider secrets, issued STS credentials and rerank
response caches have no new table. Cryptographic transformations and runtime
validation are responsibilities of subsequent producers.

## Dialects and time

`Table` and `Dialect` are closed enums. Their methods select fixed table names
and generate creation statements from immutable typed declarations. No API accepts an arbitrary SQL statement,
external identifier or placeholder template. Columns and relationships have one
canonical typed definition used by all three DDL renderers and the MySQL physical
projection. There is no retained SQL body or parallel manually maintained catalog.

SQLite and PostgreSQL share the fixed DDL. MySQL selects InnoDB with
`ROW_FORMAT=DYNAMIC` and `utf8mb4_bin`, and uses `LONGTEXT` for embedding JSON and instance project versions; other text columns use
`TEXT`. The opt-in fixtures qualify schema creation and initial constraints on pinned
PostgreSQL and MySQL servers; they do not qualify application connection pools.

All timestamp columns use `BIGINT` UTC microseconds, avoiding ordering through
variable-precision timestamp strings. Missing revocation, consumption, last-use
and last-poll events use SQL `NULL`. `TimestampMicros` accepts only nonnegative
`i64` values. Conversion from `SystemTime` rejects times before the epoch and
integer overflow, and explicitly discards sub-microsecond precision. This type
is data; it does not decide expiry, refresh eligibility or permission.

MySQL deployment must use 16 KiB InnoDB pages (the standard setting) so its
3072-byte composite index limit accommodates the largest 2560-byte key under
utf8mb4. Every indexed or foreign-key column is bounded `VARCHAR`, `SMALLINT` or
`BIGINT`; no `TEXT`/`LONGTEXT` column is indexed. The embedding key is two
64-character hashes. The largest composite key combines 512 and 128 characters
in role assignments and S3 prefixes. The MySQL fixture verifies page size, all 25 tables' actual engine/row format/collation
and the embedding column type. The extension qualified on Linux compares declared columns,
keys, indexes, foreign keys and CHECK enforcement, with 31 real native structural
mutants and actual hook counterproofs. Application pool qualification must retain these
prerequisites.

## Initial rows

`InitialSeeds` receives one caller-supplied `TimestampMicros` for all initial
rows. It exposes the built-in roles and their exact permission inventory:

- `admin`: `session.read`, `configuration.read`, `grants.read`, `grants.write`,
  `roles.read`, `roles.write`, `users.read`, `users.write`, `projects.read`.
- `user`: `session.read`, `projects.read`.
- Initial ACL revision: `1`.

No wildcard permission is seeded. These definitions do not assign an
administrator to a subject or create an authenticated capability. Runtime SQL adapters must install and maintain the built-in permission sets transactionally,
preserve valid custom roles, and enforce revision fences for subsequent ACL
writes.

## Verification and remaining integration

Run from the Broker workspace, unchanged across platforms:

```text
cargo test --locked --workspace --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo audit --file Cargo.lock --json
```

The contract suite executes DDL twice on a real in-memory SQLite engine, verifies
the exact table and durable-column inventory, all twelve foreign-key cascades,
orphan rejection, uniqueness, integer/NULL timestamps, exact identity/epoch
rejection and deterministic role/action seeds. MySQL/PostgreSQL default tests
are explicitly ignored; run their opt-in suite below to prove real server behavior. The SQLite fixture creates no persistent database
file and proves no filesystem privacy property.

The opt-in real-server check requires Docker and the two image digests pinned in
`crates/broker-store/tests/sql_servers.rs`:

```text
cargo test --locked -p broker-store --test sql_servers -- --ignored --test-threads=1
```

The fixture uses separate temporary containers with no networking or published
ports. It executes DDL twice, checks all 25 tables, initial seeds, orphan
rejection/cascade, embedding uniqueness and integer timestamps. Container IDs
returned by each successful creation are the only cleanup targets. Successful
qualification requires cleanup to succeed. This proves schema/constraint behavior;
it does not prove SQL application pools, private SQLite files or OP/runtime flows.

## Active development guardrails

`graphit.lock.json` and versioned `.githooks` dispatch the same portable runner:

```text
cargo run --locked --quiet -p xtask -- hook pre-commit
cargo run --locked --quiet -p xtask -- hook pre-push
```

Git activation uses `core.hooksPath=.githooks`. Pre-commit checks staged whitespace and Rust formatting. Affected native Makefile, shell/container and Admin UI paths retain their selected checks. Pre-push runs strict workspace Clippy, Rustdocs and `cargo test --locked --workspace --all-targets`, which includes the ordinary Storage, Security, Control/Now and schema contracts without duplicate subset invocations. Native SQL, storage, rerank, packaging and container phases remain selected separately. The raw NUL-separated Git path inventory is classified without lossy UTF-8 decoding. Unknown events, missing commands and failing children are errors. Installing or running a hook never initiates a push; the complete pre-push pipeline is not required for each partial change.

The specific PROJECT corpus HTTP/STS/S3 contract is also a long pre-push phase,
`PROJECT_CORPUS_HTTP_STS`, after the exact Hub AWS phase and before the audit:

~~~text
cargo test --locked -p broker-presence --test project_corpus_storage_credentials_http -- --ignored --exact project_corpus_storage_credentials_http_contract --test-threads=1
~~~

Its [HTTP corpus contract](rust-project-corpus-storage-credentials-http.md) uses
actual Native/opaque authentication, SQL, STS and signed S3. It does not qualify
USER/global storage or a native caller/dataset; existing phases remain selected
in their previous order around this added functional check.

The existing PostgreSQL pre-push phase also runs the ignored real Hub,
PROJECT corpus and [USER Memory SQL admission](rust-user-memory-storage-admission.md)
contracts. The USER target qualifies SQL admission separately from HTTP/STS/S3.
Its exact saved invocation is:

~~~text
cargo test --locked -p broker-control --test postgres --test postgres_identity --test postgres_roles --test storage_admission --test project_corpus_storage_admission --test user_memory_storage_admission --test global_hub_storage_admission -- --ignored --test-threads=1
~~~

Focused SQL runner counterproofs copy the actual selected phase, executor and
CLI failure loop into a disposable Cargo fixture, omitting only earlier phases.
A real ignored assertion failure in a storage target exits with failure
before PostgreSQL sessions. The USER addition reuses this existing runner
counterproof for its actual target. This qualifies the isolated runner, not a backend or
the full pre-push pipeline.

Both storage targets use actual PostgreSQL TLS and authenticated Native/opaque
factories. The [corpus admission guide](rust-project-corpus-storage-admission.md)
records the new module isolation contract; [Hub admission](rust-hub-storage-admission.md)
retains registry/artifacts. This extends the existing long SQL phase; ordinary control tests run in the workspace pre-push phase and other phase selection/order is unchanged.

Runner guardrails use disposable Git/Cargo fixtures to check that formatting and real test failures stop later phases, preserving staged changes and creating no commit. These validate runner failure handling; native service behavior has its own test targets. Identical commands and source portability do not establish Windows/macOS execution. Build output under `/target/` is ignored.

The [native Rust server](rust-broker-server.md) now integrates PostgreSQL startup, local password/MFA/CAPTCHA, identity, sessions, grants, upstream OIDC, the Broker OpenID Provider and storage. The [Device authorization reference](rust-device-authorization.md) records the current access-only Device Flow. Native [MySQL control persistence](rust-mysql-control.md) and its related domain references describe qualified library slices; the server selects PostgreSQL or private SQLite, while MySQL remains a library boundary. SQLite private birth and file/WAL lifecycle are qualified under [tsk-6ebc](rust-sqlite-control.md); [identity/role/ACL metadata](rust-sqlite-identity-acl.md) and [LOCAL authentication](rust-sqlite-local-auth.md) are separate library slices. The [session metadata](rust-sqlite-sessions.md), [dynamic client catalog](rust-sqlite-oidc-registration.md) and [durable inventory writer](rust-sqlite-instances.md) with its [bounded reader](rust-sqlite-instance-read.md) references delimit their additional library APIs and qualification. MySQL server selection, final consumer integration and native platform validation remain separate work. A schema fixture or an individual library does not establish completion of those deliveries.

The PostgreSQL service uses exact SQLx core/Postgres 0.9.0 crates, without the optional SQLite facade conflict. Its [official changelog](https://github.com/transact-rs/sqlx/blob/main/CHANGELOG.md)
states MSRV 1.94. The SQLite engine is pinned
[rusqlite 0.40.2](https://docs.rs/crate/rusqlite/0.40.2), with bundled SQLite.

The three administrative session tables are consumed by the [Rust session service](rust-admin-sessions.md), whose PostgreSQL persistence is qualified on Linux in `tsk-dcfc`.

## Typed producer qualified on Linux

`Table::definition()` returns a borrowed immutable `TableDefinition`. Its column,
primary-key and foreign-key getters expose declarations only. `Table::mysql_shape()`
returns an owned readonly expected projection derived from those same declarations;
it is not captured database state or an authorization capability. Fifteen inline
primary keys retain their lack of explicit `NOT NULL`: ordinary SQLite rowid tables
permit null in these keys, while PostgreSQL and MySQL physically require non-null.
The eight composite keys keep their explicitly non-null columns.

The workspace all-target test phase includes the Store `schema_contract` target. The SQL-server pre-push phase uses `cargo test --locked -p broker-store --test sql_servers -- --ignored --test-threads=1`. A Linux execution does not establish Windows/macOS behavior or full MySQL runtime integration.

The same saved phase now also runs the actual
[global Hub SQL contract](rust-global-hub-storage-admission.md), requiring current
nonPROJECT Hub and S3 authority. This target qualifies SQL only; Global HTTP/STS/S3
and native callers remain separate deliveries.
