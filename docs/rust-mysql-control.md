---
references:
  - target: {type: task, id: tsk-1e59, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9a45, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-5ca4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: memory, id: 01M4H3ZZ1XXQVBVFQ50YYTF20S, scope: project, scope_id: 01M1YEAE1WYMWG9KJKV1XQC4T4}
    relation: supports
  - target: {type: memory, id: 01M4H3ZZ3Q4202GARWZ2YV52P2, scope: project, scope_id: 01M1YEAE1WYMWG9KJKV1XQC4T4}
    relation: supports
---

# Rust MySQL control persistence

The [administrative session source](rust-mysql-sessions.md) extends this store within its existing lifecycle. Administrative HTTP and current authorization policy remain separate.

Audience: Broker operators and storage integrators. This implementation supplies MySQL control persistence. Its native contracts cover COMMIT uncertainty, lifecycle, expiry, DDL acknowledgment, payload, inbound authority, literal grants, schema and TLS. An independent SDK test does not establish service acceptance.

The candidate `MySqlControlStore` owns MySQL startup and upstream OIDC-flow
transactions. It reuses the [typed SQL producer](rust-mysql-catalog.md),
[credential digester](rust-credentials.md) and existing `OidcFlow` contracts.
Administrative sessions, HTTP login, cookies, identity policy, current
authorization and full Broker migration remain separate deliveries.

## Operator prerequisites

Use a dedicated database on a trusted, direct MySQL 8.4.11 server. The native
fixture selects `mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242`.
Other versions, HA/proxy/failover topologies and hostile peers are unqualified.

Provision credentials, schema and grants during exclusive maintenance. The DBA
is the trusted external control plane. Maintenance is an operational
precondition, not a token or condition that Broker can verify. `GET_LOCK`
serializes cooperating Broker startups; it does not prevent a DBA from changing
grants/schema. Metadata locks do not freeze ACLs. After external changes outside
this contract, recapture/startup under maintenance before exposing the service.
No atomic ACL snapshot, ABA detection or instantaneous global revocation is
promised.

Configure a TCP host, nonzero port and database explicitly. Supply an owned,
zeroizing password and an optional bounded CA PEM. `VerifyIdentity` requires the
certificate hostname and trust chain to validate. Trust is WebPKI plus the
explicit CA, not CA-exclusive trust. There is no DSN, socket, ambient environment,
OS-root or insecure fallback. SDK-internal password copies are not guaranteed
to be wiped; all service Debug and error values are redacted.

Use an ordinary account with actual privileges for the closed statements and an
explicit global PROCESS grant for complete incoming-FK metadata. Provision this
prerequisite administratively; the service never grants it. The
candidate does not set `innodb_strict_mode`: provision it ON; OFF fails session
proof. It never requests `SESSION_VARIABLES_ADMIN` or a DBA-loader role merely
to set an already-ON restricted variable.

The session installs the closed SQL-mode set ONLY_FULL_GROUP_BY,
STRICT_ALL_TABLES, NO_ZERO_IN_DATE, NO_ZERO_DATE, ERROR_FOR_DIVISION_BY_ZERO and
NO_ENGINE_SUBSTITUTION. It sets UTC, READ COMMITTED, utf8mb4/utf8mb4_bin, foreign
and unique checks ON, sql_quote_show_create ON and visible GIPK metadata ON,
then asserts the native session observations. Transaction controls use mature
SDK text execution for closed START TRANSACTION/COMMIT statements, preserving
the physical handle and finite commit acknowledgment state. ANSI_QUOTES,
NO_BACKSLASH_ESCAPES and PIPES_AS_CONCAT are outside that set. Native read_only
or super_read_only fails as `Denied(WritePrimary)`. Identity/version/database,
roles, settings and lower_case_table_names are observed on the actual handle
before and after capture; changing observations fail proof.

| Required capability | Proof and use |
| --- | --- |
| SELECT on every required column | Actual `SELECT ... LIMIT 0` on all 25 required tables, holding MDL within the transaction |
| SELECT at literal database scope for fresh inventory | Positive native lower grant plus bounded persistent-table/view inventory |
| TRIGGER at literal database or all required table scopes | Positive native lower grants before trusting the required-table trigger inventory |
| CREATE for all future required tables | Positive native lower grants before genuine fresh DDL |
| REFERENCES on each whole parent table | Positive native lower database/table grant; a column-only grant does not qualify |
| EVENT | Actual `SHOW EVENTS FROM database`, required for fresh and existing states |
| PROCESS | Positive global native grant plus complete bounded `INNODB_FOREIGN` capture on the same connection, for Fresh, Existing and catalogue-consuming operations |
| SELECT/INSERT/DELETE for seeds and flows | Native `EXPLAIN FORMAT=TRADITIONAL` of the actual closed operation templates and actual DML errors |

`SHOW GRANTS FOR CURRENT_USER` includes the session's active roles on MySQL
8.4.11. Its `TO` account is the authenticated context, not the source of a grant.
The finite decoder accepts visible lower database/table grants from this native
context; it does not reconstruct role unions or revocation matching. Global
grants are not a substitute for positive lower visibility proof. Native
aggregation can elide lower grants covered globally; missing proof remains
`Unproven` even if another privilege path would permit the SQL. Unrecognized,
malformed, hidden, truncated or partial observations never prove absence.

For database grants, `partial_revokes=OFF` makes unescaped `%`/`_` wildcard
patterns. Only a pattern producing one exact literal qualifies; backslash
escaping is decoded for that case. With `partial_revokes=ON`, the quoted name
is literal, including its backslashes. Table-scope names are always literal.
Quoted principal components can contain `@`, dots, keywords and backticks;
the decoder never splits the observed `CURRENT_USER` text to infer components.
See [native SHOW GRANTS](https://dev.mysql.com/doc/refman/8.4/en/show-grants.html)
and [GRANT scopes](https://dev.mysql.com/doc/refman/8.4/en/grant.html).

## Startup and recovery

Call `MySqlControlStore::open(config, digester, deadline)`. It validates explicit
limits before SQL, admits one private connection, establishes and observes
session settings, and acquires `graphit-broker-rust-control-startup-v1` once.
Native connection ID and lock owner must agree on the same server/session.
The lock wait fits the original deadline and configured lock budget.

Fresh means no persistent tables/views in the dedicated database, established
with literal database SELECT visibility, and zero autonomous events established
with actual EVENT permission. Routines not invoked by the closed SQL are inert;
startup does not claim absolute global object emptiness or require EXECUTE.

Fresh startup proves CREATE/whole-parent REFERENCES and future-table TRIGGER
coverage before executing the producer's 25 CREATEs in dependency order. MySQL
DDL has implicit commits: a failure can leave partial tables. A partial schema,
25 tables without the required marker, or a foreign marker fails; there is no
importer, DDL resume, compatibility mode, automatic DROP or fallback.

Existing startup must establish exact required structure and marker
`format=rust-broker-v1, epoch=2` before seeds. Additional objects outside the 25
required tables are not treated as globally absent; autonomous events remain
disallowed in the required database.

Inside READ COMMITTED, startup opens all required columns and retains each base
table's MDL until COMMIT. Same-session `SHOW CREATE TABLE` rejects TEMP shadows
and views. Bounded native metadata must match the immutable producer's tables,
138 columns, indexes, FK targets/actions and enforced CHECKs. Missing/hidden
information never qualifies an empty catalog. The [instance registration schema](rust-broker-instances.md) adds two tables without changing startup authority. Epoch-1 databases are rejected.

The server contract rejects every foreign key whose child is outside the 23
required tables and whose parent is required, across schemas and all actions.
The candidate captures `INNODB_FOREIGN` using binary bound parent paths derived
from the actual database and immutable producer. Positive global PROCESS and a
successful complete native capture are both required. Missing/revoked PROCESS,
native error1227, malformed/unknown TYPE or incomplete data yields `Unproven`;
row/cell/aggregate/statement overflow remains `Unproven(Truncated)`. A fully
captured external child yields `SchemaRejected(ForeignKeys)`. The collector
finishes and validates all bounded rows before classifying external children;
child-filtered KCU emptiness cannot prove incoming absence.

Fresh checks this authority before any CREATE, even with zero required tables
and an external orphan referencing an absent parent. Existing startup and every
save/consume repeat it on their own connection, inside the transaction after
opening required parent objects. Child ownership compares complete raw native
paths exactly, without splitting names or accepting collation aliases. Native
TYPE validates all sixteen combinations of DELETE/UPDATE RESTRICT, CASCADE,
SET NULL and NO ACTION; unknown or conflicting flags never qualify. Omitted
ON UPDATE contributes NO ACTION bit32, so the fixture's complete TYPE words
are CASCADE33 and RESTRICT32. This capture does not promise ACL/DDL atomicity
or that parent read MDL freezes all external DDL. No automatic grants, compatibility or assumed DBA proof is used.

Builtin admin/user roles are inserted only when absent, preserving existing
creation timestamps. Their permissions are replaced with producer actions;
custom roles/actions remain. ACL row 1 is inserted only when absent, preserving
an existing revision/timestamp. The fresh marker is inserted in the seed
transaction only after structure/proof succeeds. Ready requires seed/marker
COMMIT and startup-lock RELEASE acknowledgments.

| Failure | Caller action |
| --- | --- |
| `StartupBusy` | Another native owner holds the cooperative startup lock; inspect maintenance/owner state before trying a new explicit startup |
| `SchemaRejected(reason)` | Inspect the dedicated database/schema version; do not import, resume or silently repair it |
| `Denied(capability)` | Native SQL explicitly denied the required operation; correct provisioning under maintenance |
| `Unproven(reason)` | Visibility, settings, roles, metadata or bounds could not prove the contract; do not infer absence/authority |
| `OutcomeUncertain` | COMMIT attempt began without a confirmed ACK; never replay automatically |
| `StartupCommittedCleanupFailed(reason)` | Seed/marker COMMIT is known, but RELEASE_LOCK failed or its original deadline expired; no Ready result |
| `Deadline`, `Connection`, `Storage` | Operation failed; inspect context without treating a closed local socket as immediate remote cleanup |

The finite `UnprovenReason` vocabulary is `Visibility`, `SessionSettings`,
`SessionChanged`, `RoleChanged`, `GrantSyntax`, `Truncated`, `SecondaryExecution`
and `StorageOptions`. Unknown options/attributes use `StorageOptions`; no
temporal ACL stability proof is claimed. `CleanupReason` is `LockRelease` or
`Deadline`. Input/lifecycle outcomes also include `Configuration`, `Closed`,
`Clock`, `FlowExists`, `InvalidFlow`, `Unavailable`, `Expired` and `CorruptFlow`.

After uncertain COMMIT or known startup cleanup failure, an operator observes
server/owner/schema state and performs full Existing recapture under maintenance.
A later marker read is not proof that the prior caller received Ready. Local
transport drop is not an ACK and does not assert that the server already stopped.

## OIDC-flow API

`save_flow(state, browser_binding, flow, deadline)` validates before admission,
uses separate digester domains 2 and 3, and inserts eight bound fields in a
transaction. Nonce is nonempty, NUL-free and at most 128 bytes. PKCE verifier is
43–128 ASCII unreserved bytes. Provider/request limits remain caller-supplied;
typed JSON rejects unknown fields and distinguishes admin/OAuth continuation.
Creation time is checked UTC microseconds; expiry must be later and at most 600
seconds away, with a fresh check immediately before COMMIT.

MySQL's declared continuation column is TEXT. The effective cap derives from
`MysqlColumnShape::character_octet_length()` and is
`min(caller.continuation_bytes, 65_535)`. It applies to serialized JSON bytes,
including UTF-8 and escaping, before SQL. A caller limit above 65,535 is allowed
for smaller payloads; PostgreSQL's contract is not changed.

`consume_flow(state, browser_binding, deadline)` recaptures proof on its new
connection, locks the matching row by both digests, decodes bounded stored
fields, checks continuation/TTL and rejects future creation time. Wrong binding
or missing/replayed state returns `Unavailable` without deletion. Corruption
returns `CorruptFlow` without mutation. A valid expired flow is deleted and
returns `Expired` only after a confirmed COMMIT; expiry is latched after locking
and again immediately before COMMIT. Concurrent consumes have one winner.

Every flow transaction opens all 25 required base tables and repeats complete
native capture/TRIGGER/EVENT/operation-capability proof. Ready from startup is
not permanent authority for another connection. Flow COMMIT acknowledgment
returns a known result immediately, with local transport/permit dropped before
return and no additional fallible cleanup await. Failed/cancelled operations
never return a connection for reuse and never replay a write.

## Explicit bounds and lifecycle

There are no production defaults. The caller supplies positive connection
text/CA limits, admission count, acquire/connect/operation/startup/shutdown/lock
durations, metadata rows/cell/aggregate/grant rows/bytes/tokens/roles/statement
bytes/probes and continuation/provider/request limits. Catalogue statement/probe limits apply to capture and catalogue consumers; the direct [role definition writer](rust-mysql-roles.md) does not count its private DML against catalogue probes. Overflow or invalid
fixed-inventory capacity fails configuration. Budgets always intersect the
original caller deadline, including queueing, handshake, capture, locks, COMMIT
and startup release; they do not reset deadlines between phases.

Metadata queries use native CASE/OCTET_LENGTH and `LIMIT cap+1`, then bounded
stream decoding with checked aggregate accounting. SHOW outputs and tokenized
grant lines have explicit logical/owned limits. These are not bounds on SQLx
network reassembly, native receive buffers, predecode allocations, process RSS
or a malicious peer. Test fixtures' synthetic numbers are not server policy.

Admission counts actual private handles, including startup. Every operation
connects anew; there is no pool/idle lease/reset or caller setup SQL.
`shutdown(deadline)` first closes admission atomically and wakes queued callers
as `Closed`, then drains active handles within its remaining budget. An expired
caller deadline still closes admission. Cancellation releases local RAII state;
remote cancellation/lock absence is an eventual server observation, not a Drop
guarantee. Handshake plus full recapture cost must be measured at qualification.

## Effective storage options

The candidate always checks actual InnoDB/DYNAMIC/utf8mb4/utf8mb4_bin and exact
shape separately from requested `CREATE_OPTIONS`. Its finite decoder accepts
the native 8.4.11 renderer's bounded unsigned hints/statistics, boolean options,
known row-format spellings, COMPRESSION `''/none/zlib/lz4` and ENCRYPTION `Y/N`.
Requested DEFAULT can render an empty row-format value. Reserved/unknown,
duplicate, malformed or truncated spellings fail proof. Partitions are rejected;
secondary engine/load yields `Unproven(SecondaryExecution)`.

Encryption is preserved; omitted ENCRYPTION is not a claim of `N` or a database
default assertion. TABLES_EXTENSIONS attributes must be NULL or empty JSON
objects; unknown nonempty attributes remain unproven. CREATE_OPTIONS does not
cover TABLESPACE, DATA/INDEX DIRECTORY, AUTOEXTEND_SIZE or engine attributes.
PROCESS is required for incoming authority, separately from physical options.
There is no ALTER-to-approve or second M2A metamodel.
Native compression/hints/encryption combinations require actual fixture
qualification before support is reported.

## Source and scoped qualification

Production source is confined to `crates/broker-control/src/mysql/` and narrow
exports/dependencies in broker-control. It uses SQLx 0.9.0, Tokio, existing
Rustls/WebPKI, futures-util streaming and sqlparser 0.63's MySqlDialect tokenizer;
it does not implement a protocol/SQL parser, role matcher or external importer.
SQL templates, identifiers and operation choices remain private/closed.

The private lexical wrapper delegates MySQL tokenization and preserves its
dialect identity, disabling executable-comment expansion so all actual comment
tokens are rejected. Comment-looking text within quoted identifiers remains
literal. This follows the library's native
[comment handling](https://github.com/apache/datafusion-sqlparser-rs/blob/v0.63.0/src/tokenizer.rs)
without rewriting input or accepting another SQL dialect.

`tests/mysql_control.rs` uses native SQLx and the pinned owned Docker instance
with rcgen TLS credentials, ordinary accounts and real DDL/row/MDL/grant cases.
Opaque TCP/TLS byte forwarding plus native Performance Schema observation
targets actual COMMIT/lost RELEASE_ACK. The fixture uses the documented
[binlog commit-group delay](https://dev.mysql.com/doc/refman/8.4/en/replication-options-binary-log.html)
and test-only keyring provisioning for native encryption, following
[component installation](https://dev.mysql.com/doc/refman/8.4/en/keyring-component-installation.html).
Neither mechanism is a production policy or simulated SQL authority.

The expiry fixture holds opaque outbound bytes after a real locked-row SELECT,
confirms the ordinary session's granted native record lock and a still-live
expiry, then crosses expiry before permitting mutation/COMMIT to finish. It
expects `Expired` only after the committed deletion and replay rejection.
Clock reversal is separately covered by the private production latch predicate,
without changing the host clock or injecting a production clock provider.
The activated implementation emits real production TRACE events with static
targets/messages only: `broker_control::mysql::flow_locked_live` follows typed
locked-row validation and a fresh still-live wall time; `flow_delete_staged`
follows native DELETE acknowledgment within the transaction; and
`flow_consume_committed` follows confirmed COMMIT. No values, SQL, grants, clocks,
identifiers or credentials are recorded. Consumers install their own tracing
Subscriber; the service never installs a global one.
The fixture observes these events through a mature Registry/Layer attached to
the consuming future. Its listener only records phase bits/notifies; the parent
fixture independently holds/releases opaque transport and observes native record
locks. It also requires TRACE metadata containing only the message field. This
avoids treating a driver's statement-close packet as progress past
the first wall-time check.
Ready-service fixtures also apply `init_connect` TEMP contamination only to
subsequent connections and require both save/consume to reject it before writes.
The lifecycle and schema scenarios exercise this behavior.

The probe also creates a child referencing an absent required parent with
`FOREIGN_KEY_CHECKS=0`, observes it while the Broker schema has zero tables, and
creates the compatible parent from the immutable producer. MySQL's
[DDL source](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/sql/sql_table.cc#L6461)
permits this missing-parent case; the
[system view](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/sql/dd/impl/system_views/innodb_foreign.cc#L30)
does not join the referenced parent. The actual private fixture observed this
reference with zero required tables under Root and fixture PROCESS, while
no-PROCESS access returned1227 and ordinary KCU remained empty. Compatible
parent creation preserved the reference.
An empty Broker schema therefore cannot by itself prove the absence of external
inbound constraints.

Queries compare raw native names using binary bound parent paths from `TABLES`, SQL cell caps with original lengths, bounded streaming, row/total limits and one observation deadline. Service category configuration retains its 138-column minimum; the overflow fixture uses cap138 with139 real FKs. Pending MDL, explicit rollback acknowledgement and subsequent writer DDL acknowledgement are separate fixture observations; holding parent read MDL does not freeze all external DDL.

The five-second observation deadline covers session identity, grants, rows and
the final identity check together. Fixture setup has separate budgets: Docker
control commands have 30 seconds, initial server readiness has 60 seconds,
verified connections have five seconds, and the TLS configuration handshake,
four configuration statements and verified connection share one 15-second
deadline. Setup SQL has ten seconds after connection. Native pending-lock polling
shares one one-second deadline; an error or timeout is recorded and cannot prove
absence of a pending lock. These limits do not claim a whole-fixture deadline.

The saved commands are unchanged across host platforms:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p broker-control --all-targets
cargo test --locked -p broker-control --doc
cargo test --locked -p xtask --lib
cargo test --locked -p broker-control --test mysql_control -- --ignored --test-threads=1
cargo test --locked -p xtask --test guardrails precommit_stops_after_real_formatter_failure -- --exact
cargo audit --file Cargo.lock --json
```

Pre-commit checks whitespace and formatting. Pre-push runs workspace Clippy and all-target tests, plus the native SQL suites. The guardrail regression runs the real formatter
in a minimal Git fixture and verifies that a formatting failure stops later
checks. No mutation pipeline or resource reservation is needed.

See [database operations](database.md), [declared MySQL projection](rust-mysql-catalog.md)
and [PostgreSQL control persistence](rust-postgres-control.md) for separate contracts.

The native fixture allocates its container before startup and keeps the actual
container ID under cleanup while `docker start` runs. Cleanup removes that owned
container and its anonymous volumes; it never prunes shared Docker resources.
Closed test administration commands (`USE`, backup lock/unlock and transaction
controls) use the SDK's text-query API where MySQL rejects prepared execution.
Docker failures identify only the static operation, without argv, credentials
or server output. The original control deadline remains unchanged.

Native statement observation keeps its original five-second end for connection
and query waits and rejects a late result before accepting the event. Diagnostic
counters distinguish event-text absence from executing thread information; they
retain no SQL text or parameters. The original event-text predicate was preserved
until the expiry snapshot below established the need for the singleton thread-text
criterion.
On a query deadline, the last observed numeric tuple is retained; an absent
snapshot stays absent rather than being reported as a zero or empty catalog.

The native fixture observes only five closed statement phases, including the exact marker CREATE specialization. Prepared statements
can have a null `events_statements_current.SQL_TEXT`; the expiry diagnostic actually
observed zero event-text matches and one executing thread-text match. Synchronization
therefore requires a matching `threads.PROCESSLIST_INFO`, an active command, exactly
one total session of the dedicated fixture account, and positive native session and
thread identifiers. Sleeping or competing sessions prevent acceptance. This is an
observation of execution, not a COMMIT or ACK proof. Text, parameters and identifiers
are never emitted. The original five-second observer deadline still clips connection
and query work, and is checked before accepting a snapshot.

Catalog capture distinguishes complete multiple partition rows (rejected as partitions) from missing required-table observations (unproven visibility), with capture limits unchanged. Six closed fixture routine, event, trigger and role DDL controls use SDK text queries because MySQL cannot prepare them. Only CREATE ROLE needs text execution in the role scenario; GRANT ROLE and both SET DEFAULT ROLE forms retain prepared execution. The row-lock expiry fixture first saves a valid flow, then stages its existing two-second expiry in the administrator's blocking transaction. Production TTL and operation budgets are unchanged. COMMIT observation failures record only a closed phase, numeric snapshot and finite operation outcome.

The runtime cost fixture keeps one administrator connection across isolated
startup, save, consume and closed-call windows. It compares server connection
attempts, TLS handshakes initiated and successfully finished, and the dedicated
account's cumulative connections. It requires native account instrumentation,
zero account/thread losses and no remaining ordinary connection before accepting
a bounded snapshot. Missing counters never become zero. The fixture performs no
restart, TLS reload, truncation, user change or other connection during a measured
window. These counters cover server-observed attempts and accounted sessions; they
do not prove network attempts that never reach the server, peer identity by
themselves, per-operation allocations or a hard memory bound.

The Fresh COMMIT scenarios use the fixture caller deadline,
clipped by the unchanged fifteen-second production startup budget. They observe the exact first `CREATE TABLE schema_meta (` in native `Execute`,
excluding `Prepare`, and retain its opaque response while an
administrator locks the newly created `schema_meta` table for writing. The remaining
DDL runs with the binlog delay disabled. A native pending metadata lock proves the
startup is blocked on that object; only then does the same administrator handle
arm the existing commit delay and release its lock. This fixture barrier changes
no rows and is not seed, catalog, ACL, Ready or COMMIT authority. The COMMIT observer
still requires the actual active singleton statement, with its five-second limit
clipped to the unchanged startup end, before the final opaque transport fault.
Scalar and statement observers use their own VerifyIdentity connection and prepared
queries under one specified end, reject late results and return finite optional
snapshots. Other scalar callers retain their original five-second wrapper. A missed
Fresh barrier reports only its closed phase, optional numeric snapshot and actual
finite startup outcome.

MySQL 8.4.11 InnoDB does not support ENGINE_ATTRIBUTE: both a nonempty JSON object and `{}` are rejected by ALTER TABLE with error 3981, before either can become catalog metadata. The native fixture requires both errors and then opens the unchanged schema and saves/consumes a real flow. It does not claim that the Broker captured and rejected a persisted attribute. The private extension validator used by catalog capture separately rejects nonempty objects, arrays, scalars, JSON null and malformed JSON as Unproven(StorageOptions); absence or an empty object remains admissible. Its pure unit test covers this conservative classification, while the native schema scenario covers actual compression, hints and encryption. Sources: [InnoDB capabilities](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/storage/innobase/handler/ha_innodb.cc#L5468), [ALTER attribute check](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/sql/sql_table.cc#L16703), and [prepared role commands](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/sql/sql_prepare.cc#L1283).

The TLS inactive-role fixture retains only `SELECT(name)` on `roles` to permit login to the configured database, and revokes it before activating the role. This column privilege supplies no full SELECT visibility proof. The expected inactive-role result remains Unproven(Visibility); production connection error classification is unchanged.

The schema fixture now establishes keyring immediately after its initial verified
server setup, before schema mutations. Its executable-read and two file-mode
controls have distinct static phases, retaining their original Docker deadline
and cleanup. The actual binary path, basename `mysqld`, native `@@plugin_dir`,
restart and Active-component readback remain mandatory. That diagnostic was
required to identify the failing control before any identity change; no install
path or extra Linux capability was assumed.

The keyring fixture reads the native executable as the image's `mysql` user, without adding capabilities. Success is required; returned executable and plugin paths remain native facts.

The TLS-off control now retains one verified administrative connection and uses
`ALTER INSTANCE RELOAD TLS NO ROLLBACK ON ERROR`. The ordinary statement's default
rollback would preserve the previous TLS context on error. The forced reload
must acknowledge success and emit native Warning 3888; the fixture reads only its
level and code, with a finite deadline and no warning-message persistence. A new
ordinary VerifyIdentity connection must then fail as Connection. The same held
administrator restores TLS version and reloads with confirmed ACKs; a new
ordinary open/shutdown must prove restoration. Every control retains the original
ten-second setup-query budget and finite error phase. No extra root is opened
while TLS is disabled. SHOW WARNINGS uses SDK RawSql text execution,
consuming one optional row and then the result terminator under the same ten-second
deadline before reusing root. No messages are extracted or persisted.
See [ALTER INSTANCE](https://dev.mysql.com/doc/refman/8.4/en/alter-instance.html) and
[runtime TLS configuration](https://dev.mysql.com/doc/refman/8.4/en/using-encrypted-connections.html).

The keyring diagnostic now reads `@@plugin_dir` and `@@datadir` under its existing
query budget and requires the actual component library to be readable as mysql.
That diagnostic rejected placement of the old fixture keyring file inside the
observed datadir before installing configuration or restarting. The official package lists the
component, but only the native library check qualifies this image's availability.
The [keyring component contract](https://dev.mysql.com/doc/refman/8.4/en/keyring-file-component.html)
prohibits keyring data inside datadir. That diagnostic required identification of this precondition before any
conditional directory change; the prior daemon cause remains unobserved.

The fixture creates a private directory as mysql, obtains its canonical path and the canonical datadir, requires absolute non-root locations and verifies that the keyring directory is outside datadir. Native mode700 and write access are required. The config uses this owned directory; key data remains in the ephemeral container and owned-container cleanup removes it. No installation path, extra capability, host key, package substitution or fallback is introduced. These provisioning preconditions and restart acknowledgement alone do not prove component Active or encryptionY/N. The configured keyring path is a file, as the official contract requires.

The fixture captures diagnostics after the original startup failure and before owned-container cleanup. Each Docker control retains its 30-second deadline. Only typed running/status/exit-code/OOM/error-presence fields, native MY-six-digit codes, finite severity and selected keyword-presence booleans are emitted; raw daemon messages, paths and configuration are not emitted. The log window is the last forty lines on both stdout and stderr, with a checked combined 65,536-byte limit before UTF-8 parsing and at most eighty native code records. No codes means only absence in that valid capture; invalid, oversized or unavailable capture fails explicitly. Keywords alone do not establish cause. Per-control deadlines are not a whole-fixture deadline.

The diagnostic records published-port equality after restart. It retains the actual configured keyring path as
private fixture state and probes the primary file and its `.backup` as mysql.
Only parent access, a finite object kind, mysql/root ownership booleans, octal
mode and read/write access are emitted, with strict bounded parsing. Metadata
and access tests all follow symlinks to describe the same target. UNOBSERVED
is an unsuccessful existence test, including inaccessible objects, and does not
prove absence. Neither file contents nor UIDs or paths are emitted.

For MY-013714, the diagnostic classifies only the closed initialization reasons
from MySQL8.4.11. Configuration-unavailable/invalid/missing-field reasons stay
combined because the native config reader does not distinguish them. MY-015106
reports backend file-read failure and its parameter is a path, not errno; missing
permission keywords do not rule out denied access.

The fixture now resolves the actual single IPv4 published port both initially
and after restart, using the same bounded parser, before connecting. It creates
a new empty keyring file as nonroot mysql with mode0600 before installing the
manifest, then verifies regular type, zero size, owner and read/write access.
Existing objects or symlinks fail the precondition; noclobber additionally protects
regular files. This scope is the new private directory without concurrent fixture
writers, and does not claim atomic exclusion of arbitrary filesystem races.
No existing key data is reset or imported and no JSON initialization is used.
The [pinned entrypoint](https://github.com/docker-library/mysql/blob/01f90d87012e46cd174073bba02d64e9fc693ed3/8.4/docker-entrypoint.sh#L368)
runs a root config check before dropping privileges; the native backend accepts
an empty file and does not recreate a readable existing file.

## Local identity and role read

The borrowed [local identity view](rust-mysql-identity.md) shares this owner
and fresh proof, with one bounded consistent SQL snapshot of a local row and
current system roles. Its
reference requires prior caller authentication; neither the snapshot nor seeds
grant resource access or establish an authorization lease.

[MySQL role definition replacement](rust-mysql-roles.md) uses the existing TLS connection and transaction machinery to persist complete permission bundles, preserve built-ins and update current RBAC. Its real SQL permissions are enforced by the statements; the HTTP caller still needs authentication and current authorization.
