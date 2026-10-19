---
references:
  - target: {type: task, id: tsk-1c24, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1e59, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Rust MySQL administrative sessions

Audience: Broker server maintainers and administrative HTTP consumers. This source implements creation, consistent reading and revocation of administrative session metadata using the [MySQL control store](rust-mysql-control.md).

A caller authenticates before creating a session and evaluates current identity,
issuer, user revision and authorization policy before using retrieved metadata.
Teams and claimed roles confer no permission. A successful read is a snapshot,
not an authorization lease until expiry. HTTP login, cookies, CSRF comparison,
current policy, full OIDC and background cleanup remain separate server work.

## Provisioning and lifecycle

Use the pinned MySQL 8.4.11 service and explicit TCP/TLS configuration required by
the [control-store operator prerequisites](rust-mysql-control.md#operator-prerequisites).
Provision credentials, schema and grants under trusted exclusive maintenance.
The service neither grants missing privileges nor repairs/imports another schema.
It requires the declared 23-table schema, its strict settings, complete incoming
FK visibility, EVENT and TRIGGER proof, and the same verified ordinary connection.

Administrative operations additionally prove their actual SQL capabilities:
creation explains INSERT on all three session tables; reading explains the
joined SELECT with parent locking and DELETE for expiry; revocation explains
DELETE on the parent. EXPLAIN performs no writes. Store startup alone does not
prove that these administrative operations are available. Required columns are
also checked by the existing same-handle catalog proof.

Each operation uses the original store's admission, digester, budgets and shutdown
state. It opens one fresh private connection, begins READ COMMITTED and rechecks
the full catalog while retaining metadata locks. Caller deadline and configured
operation timeout bound admission, proof, SQL, locks and COMMIT together. An
operation cannot renew its deadline or use a separate admission pool.
Transport drop does not promise instantaneous server cancellation. Shutdown
closes admission and bounds draining; an already admitted operation may finish.

Metadata locks do not freeze DBA ACL changes or establish an atomic global policy
snapshot. External maintenance remains an explicit operating precondition.

## Public API and explicit limits

`broker-control` exports these additions:

```text
MySqlControlStore::admin_sessions(limits: SessionLimits)
    -> Result<MySqlAdminSessions<'_>, MySqlControlError>

MySqlAdminSessions::create_session(raw_token: &str, input: &NewAdminSession,
    deadline: Instant) -> Result<(), MySqlControlError>
MySqlAdminSessions::session(raw_token: &str, deadline: Instant)
    -> Result<AdminSession, MySqlControlError>
MySqlAdminSessions::revoke_session(raw_token: &str, deadline: Instant)
    -> Result<SessionRevocation, MySqlControlError>
SessionRevocation::{Revoked, Absent}
```

The view borrows the store, keeps its limits private and exports no connection,
pool, digester or arbitrary SQL. It has no Clone, Default or Serde implementation;
its Debug is redacted. The existing [session types and validation contract](rust-admin-sessions.md)
remain the common input/result boundary. Their constructor returns `ControlError`;
the MySQL view returns the finite `MySqlControlError` domain.

Supply every `SessionLimits` field: scalar/CSRF/team/role byte capacities,
team/role counts, serialized JSON capacities and maximum lifetime. There are no
repository defaults. The view first validates the original limits, including
checked allocation products and positive microsecond lifetime. It then derives
the JSON capacities from the public MySQL column shape:

```text
effective.teams_json_bytes = min(caller.teams_json_bytes, teams_json TEXT maximum)
effective.roles_json_bytes = min(caller.roles_json_bytes, roles_json TEXT maximum)
TEXT maximum = 65,535 octets in the declared MySQL shape
```

This applies before serialization or SQL and includes UTF-8 and JSON escaping.
A larger caller cap can admit a smaller payload; it does not enlarge physical
storage. The original caller value is preserved. An invalid original configuration
cannot become valid merely by applying the physical minimum. Other policy limits
and absolute expiry retain their explicit values; the login-flow TTL is not used.

Creation independently revalidates under the view's limits, even when the input
constructor used a more permissive policy. Raw allocation belongs to the caller.
The common validator checks bytes, character widths, NUL, list counts and entries
before normalization or cloning. Teams and roles are trimmed, empty entries are
removed, duplicates are removed without folding case, and entries are sorted.
Claim selectors preserve their exact bounded nonempty spelling, including meaningful whitespace; an empty claim-role array is valid and differs from absent claims. Principal metadata is mandatory; claims are optional. No user or role lookup
turns these stored values into current authority.

For a consumer with an already authenticated input and explicit policy:

```rust
use broker_control::{
    AdminSession, MySqlControlError, MySqlControlStore, NewAdminSession, SessionLimits,
};
use std::time::Instant;

async fn persist_then_read(
    store: &MySqlControlStore,
    token: &str,
    input: &NewAdminSession,
    policy: SessionLimits,
    deadline: Instant,
) -> Result<AdminSession, MySqlControlError> {
    let sessions = store.admin_sessions(policy)?;
    sessions.create_session(token, input, deadline).await?;
    sessions.session(token, deadline).await
}
```

The result still requires current policy evaluation. Emit a cookie only after
confirmed creation; clearing a cookie does not prove SQL revocation.

## Atomic persistence and consistent reading

The token is hashed with credential kind 1, AdminSession. SQL receives only its
hex64 digest. CSRF remains recoverable SQL data owned by `Zeroizing<String>`;
this does not promise erasure of driver or server copies. Public errors, Debug
and operational trace events contain no token, CSRF, identity, SQL or driver error.

Creation inserts `admin_sessions`, required `admin_session_principals` and optional
`admin_session_claim_roles` in one transaction. Each INSERT must affect one row.
A duplicate parent returns `SessionExists` and preserves the existing metadata.
Any later INSERT failure or precommit cancellation rolls back this operation's
earlier writes. Creation time is captured after acquisition and proof. Absolute
expiry must follow creation and fit the explicit lifetime. A fresh precommit
clock check prevents publishing an already expired session.

Reading uses one parent/LEFT JOIN children projection and `FOR UPDATE OF s` in
READ COMMITTED. MySQL supports the table alias in that clause; its actual joined
and concurrent behavior must pass the native qualification below. The SQL caps
every scalar and JSON text with CASE/OCTET_LENGTH before fetch. Separate presence
markers distinguish missing children from cap-rejected NULL values. Borrowed SDK
text is checked and charged to the aggregate work budget before copying.
The result is an immutable fetched snapshot: it does not freeze later external
updates/deletions of existing children. A missing-claims INSERT must acquire the
parent FK lock; the native test checks its wait against the reader parent lock.
The server-owned create/revoke/expiry protocol remains the consistency boundary,
and this view provides no lease for current identity or authorization policy.

Missing parent is `SessionUnavailable`. Missing principal, malformed JSON,
noncanonical lists, empty/oversized/NUL claim selector, invalid scalar/count/revision/time/lifetime and future creation
time are `CorruptSession`; those rows are preserved. Missing claims is valid None.
Corruption takes precedence over expiry, and reading never silently repairs data.
Individual payload failures are corruption; exhausted aggregate proof/work
capacity remains `Unproven(Truncated)`.

A valid read does not consume metadata. Equality is expired. Once expiry has been
observed after locking, a later backwards clock movement cannot revive that
observation. A clock before the stored creation time is rejected. Valid expiry
deletes the parent with cascading children and returns `SessionExpired` only
after confirmed COMMIT. Explicit revocation can remove corrupt metadata:
zero deleted parents yields confirmed Absent, one yields confirmed Revoked.
A later revocation may follow a confirmed read, so consumers must not treat that
read as a lease or evidence of current permissions.

## Errors and uncertain outcomes

| Result | Meaning and action |
| --- | --- |
| `InvalidSession` | Input, token or freshness failed; no partial successful publication |
| `SessionExists` | Parent digest already exists; existing session is preserved |
| `SessionUnavailable` | No matching parent in this read |
| `CorruptSession` | Metadata fails the strict reader; preserve and investigate, or explicitly revoke |
| `SessionExpired` | Valid expired metadata was removed by confirmed COMMIT, or creation expired before publication |
| `Denied(capability)` / `Unproven(reason)` | Provisioning or native proof cannot establish the operation; correct under maintenance |
| `Deadline` / `Closed` | Original budget/admission prevents completion before COMMIT is sent |
| `OutcomeUncertain` | COMMIT was attempted without a confirmed ACK; never replay automatically |

Before COMMIT is sent, failure drops the private connection and staged transaction.
After sending it, timeout or network failure can leave a committed server state
without an acknowledged result, including a read or revocation. Observe state
under the documented maintenance contract before deciding any subsequent action.
No marker read or socket drop retroactively proves that the caller received an ACK.
After a confirmed COMMIT, there is no new fallible cleanup await that can
reclassify the known result.

## Qualification boundary and commands

The native fixture reuses the pinned verified TLS service, ordinary account and opaque relay. It contains nine `mysql_sessions_*` cases for roundtrip/caps (including multibyte UTF-8 at the physical octet boundary), corruption, second/third INSERT rollback, actual capability/proof, competing operations, external child update/delete and missing-claims insert while a fetched reader holds the parent, expiry after lock and before commit, cancellation/shutdown, and write/readonly COMMIT ACK loss. Root-only orphan injection is a test fixture: it restores FK checking before invoking the service and checks rollback through independent SQL.

The readonly ACK test advances bounded opaque chunks and observes the completed
COMMIT of the same singleton native session in Performance Schema. A message-only
trace marks progress but never proves execution or permits a production operation.
The original operation deadline bounds relay steps and native polling.
The cancellation/deadline fixture captures the caller end once before spawning.
Its deadline case uses seven seconds, before the configured operation budget of
eight seconds, and requires a larger `innodb_lock_wait_timeout` observed for the
actual blocked ordinary connection in `variables_by_thread`. It assumes no server
default and never renews the caller deadline. The named startup lock budget does
not configure InnoDB row-lock waits.

Iterate with the affected test targets:

```text
cargo test --locked -p broker-control --test mysql_control mysql_sessions_ -- --ignored --test-threads=1
```

The final affected native suite and saved MYSQL_CONTROL gate use the unchanged:

```text
cargo test --locked -p broker-control --test mysql_control -- --ignored --test-threads=1
```

The historical M2C snapshot included ten control cases and nine session cases.
The current suite also includes four local identity cases. Normal tests,
doctests, strict Clippy, formatting, auditing and affected xtask checks are also
required. The guardrail regression now uses a minimal Git fixture with the real
formatter and verifies fail-fast behavior. The older mutation guards have been
removed; their results below are historical evidence for the M2C snapshot.

Windows/macOS execution and per-operation memory/latency qualification remain
unproven. Whole-fixture timings and sampled cumulative process memory do not
prove per-operation latency, allocations, complete peaks or a hard bound.
The runtime evidence binds tested Rust source, maintained document hashes,
actual commands/logs, resource domains, cleanup and independent review; historical
failures and their corrections remain recorded. Full Broker and migration
integration remain with the main migration chat.

## Local identity consumer boundary

Stored local session metadata still requires current username/enabled/subject/
revision validation and SQL RBAC in an authenticated consumer. The
[local identity read](rust-mysql-identity.md) defines that bounded
MySQL snapshot. This does not turn a
session profile or reference into an authenticated principal or a policy lease.
