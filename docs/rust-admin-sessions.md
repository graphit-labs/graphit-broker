---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-cbcc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9a45, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Rust administrative session persistence

Audience: Broker server maintainers and future administrative HTTP consumers. `broker-control` extends the [PostgreSQL control store](rust-postgres-control.md) with creation, consistent reading and revocation of administrative session metadata. PostgreSQL persistence is qualified on Linux in `tsk-dcfc`; the evidence covers this service boundary. HTTP login, cookies, CSRF comparison, current user/issuer validation, RBAC, the full OAuth/OIDC provider, MySQL and background cleanup remain separate deliveries. The [SQLite session metadata library](rust-sqlite-sessions.md) under tsk-cbcc separately implements private file-backed creation, coherent reading and revocation using the shared DTOs and limits; it does not change the PostgreSQL wrapper or provide cookies, login, current-policy authorization or complete SQLite server dispatch.

The [first native Admin session HTTP route](rust-admin-session-http.md) composes genuine access JWT authentication with current LOCAL binding and SQL `session.read`, without creating session metadata. It does not deliver cookie login, CSRF or logout. The persistence types below remain data-only.

A caller must authenticate and authorize before creating a session. Profile, local revision, teams and claimed roles are data; they confer no permission and do not replace current policy. Emit a cookie only after confirmed creation. Clearing a browser cookie does not prove SQL revocation.

## Public API and ownership

`session.rs` defines and `lib.rs` exports:

```text
SessionProfile { subject: String, name: String, email: String }
SessionPrincipal { issuer: String, username: String, organization: String,
                   teams: Vec<String>, local_user_revision: i64 }
SessionClaimRoles { selector: String, roles: Vec<String> }

NewAdminSession::new(profile: SessionProfile, principal: SessionPrincipal,
    csrf_token: Zeroizing<String>, claimed_roles: Option<SessionClaimRoles>,
    expires_at: SystemTime, limits: &SessionLimits)
    -> Result<NewAdminSession, ControlError>

PostgresControlStore::admin_sessions(limits: SessionLimits)
    -> Result<AdminSessions<'_>, ControlError>

AdminSessions::create_session(raw_token: &str, session: &NewAdminSession,
    deadline: Instant) -> Result<(), ControlError>
AdminSessions::session(raw_token: &str, deadline: Instant)
    -> Result<AdminSession, ControlError>
AdminSessions::revoke_session(raw_token: &str, deadline: Instant)
    -> Result<SessionRevocation, ControlError>
SessionRevocation::{Revoked, Absent}
```

Raw structs have public owned fields and are unvalidated; their initial allocations belong to the caller. Raw structs, creation input, stored result and borrowed view redact identity/secret contents in custom Debug. The data types expose no Default or Serde serialization. `NewAdminSession`, `AdminSession` and the borrowed view have no Clone implementation. The view borrows the original store and exports no pool, digester or arbitrary SQL.

Input and result provide `profile() -> &SessionProfile`, `principal() -> &SessionPrincipal`, `claimed_roles() -> Option<&SessionClaimRoles>` and `csrf_token() -> &str`. `None` means no claim source; there is no parallel roles-source flag. Input retains absolute `expires_at() -> SystemTime`, has no creation field/getter, and never renews expiration. Result exposes `created_at() -> TimestampMicros` and `expires_at() -> TimestampMicros`, using the [UTC microsecond producer](rust-sql-schema.md). Creation time is captured by the store after acquire. Private result fields are immutable and no partial result is returned.

## Explicit limits and validation

`SessionLimits` has public NonZeroUsize fields `text_bytes`, `csrf_bytes`, `team_bytes`, `role_bytes`, `max_teams`, `max_roles`, `teams_json_bytes`, `roles_json_bytes`, and a Duration `max_lifetime`. `validate() -> Result<(), ControlError>` performs no I/O. Capacities and worst-case list/JSON allocation products must fit checked usize/isize arithmetic and SQL byte bounds must fit i64. Lifetime must be at least one microsecond and fit positive i64 microseconds. There are no default caps or lifetime. The flow's ten-minute TTL and existing HTTP policy are not repository defaults.

Issuer, subject and CSRF are nonempty; name, email, username and organization may be empty. All reject NUL. Local user revision is nonnegative metadata. No issuer, subject, username or email normalization occurs.

| Field | Maximum Unicode characters | UTF-8 byte cap |
| --- | ---: | --- |
| Issuer | 1024 | text_bytes |
| Subject, name, email, username, organization | 512 | text_bytes |
| CSRF | 128 | csrf_bytes |
| Claim selector | 4096 | text_bytes |
| Canonical role entry | 128 | role_bytes |
| Team entry | No independent VARCHAR width | team_bytes |

Raw list counts and each entry's bytes/NUL are checked before trim, cloning, deduplication or serialization. Lists use Unicode whitespace trimming, empty removal, case-preserving deduplication and UTF-8 lexicographic sorting. Empty canonical teams are valid. A claim selector is preserved literally after raw bounds and must be nonempty: whitespace may be part of the configured claim key. Canonical claimed roles may be empty; `Some([])` retains a configured claims source and differs from `None`. The [genuine federated cookie consumer](rust-admin-federated-cookie.md) then uses only implicit `user` and current SQL definitions, without falling back to assignments. Unknown role names remain metadata, with no permissions lookup. Serialization writes only within the explicit JSON byte cap.

The constructor checks positive expiration through TimestampMicros conversion without capturing creation time or establishing final freshness. `create_session` independently checks all normalized input against the view's limits before digesting or SQL. A more permissive constructor does not authorize a stricter view. Freshness and maximum lifetime use server time after acquire; expiration must follow creation and remain within `max_lifetime`. A fresh precommit check prevents publishing an already expired session. Neither expiry nor the original deadline is renewed.

## Atomic storage and consistent reading

The raw token is hashed using credential kind 1, AdminSession, with [producer input bounds](rust-credentials.md). SQL sees only its hex64 digest. Raw token values do not enter SQL, logs or public errors. CSRF remains recoverable in protected SQL, owned by Zeroizing<String>; this does not promise erasure of SDK or SQL copies.

Creation inserts `public.admin_sessions`, required `public.admin_session_principals` and optional `public.admin_session_claim_roles` in one explicit READ COMMITTED transaction. Values are bound and identifiers are constant. Each INSERT must affect exactly one row. Duplicate parent yields SessionExists and preserves existing rows. Errors/suppressed inserts in any stage roll back all three tables. Expiry observed before COMMIT yields SessionExpired without publication.

Reading uses one parent/LEFT JOIN children SELECT and `FOR UPDATE OF` parent in READ COMMITTED. Child primary keys provide at most one of each row. SQL CASE/octet_length caps every scalar and JSON text before fetch; separate child-presence markers distinguish missing children from over-limit values. Missing parent is SessionUnavailable; missing principal is CorruptSession; missing claims are valid None.

Stored fields, list counts, bytes/characters, arrays, nonnegative revision and UTC lifetime must satisfy the same limits. JSON must be an array of strings without null/object/number/trailing data/NUL. Lists must already be canonical; selectors retain their exact bounded nonempty spelling. Noncanonical or oversized data is never repaired. Corruption takes precedence over expiry and preserves the stored rows. Future creation time is corrupt.

Clock observations follow parent locking and precede terminal commit. Equality is expired. Once expiry is observed, a backwards clock movement cannot revive that observation. Valid matching expiry deletes the parent with cascading children and returns SessionExpired only after confirmed COMMIT; other sessions remain intact. A valid read does not consume the session. A later revocation may follow its confirmed read: this result is not a lease or authorization until TTL.

## Revocation and lifecycle

Revocation deletes by kind-1 digest in an explicit transaction. Zero rows gives confirmed Absent; one gives confirmed Revoked; more is Storage and rollback. Explicit revocation may delete corrupt metadata and is not read-and-authorize. Repeating a confirmed revocation gives Absent.

One original monotonic deadline, the minimum of caller and configured operation budget, covers acquire, statements and COMMIT. The private connection guard closes failed/cancelled transactions rather than lending their connection to another caller. Shutdown closes admission while leased work retains its original budget. There is no detached operation or automatic replay.

Before COMMIT starts, a timeout yields Deadline. After real COMMIT starts, timeout/disconnect yields OutcomeUncertain without payload or confirmed Absent/Revoked. The conservative read classification also applies because it may perform expiry cleanup; a read's uncertainty does not imply it wrote. Confirmed ACK is not reclassified by a later clock tick. Observe current state before any deliberate recovery; do not infer rollback from an uncertain result.

| Session error | Static message |
| --- | --- |
| SessionUnavailable | administrative session unavailable |
| SessionExpired | administrative session expired |
| InvalidSession | invalid administrative session |
| CorruptSession | corrupt administrative session |
| SessionExists | administrative session already exists |

Existing login-flow variants/messages remain intact; Storage, Clock, Closed, Deadline and OutcomeUncertain are shared. Driver error details/sources are not exposed.

## Verification and future integration

Fast contracts cover data/limits/redaction/canonicalization and timestamp conversion. Real owned PostgreSQL TLS fixtures exercise the public API, actual SQL faults, locks, races, cascades, COMMIT delay/disconnect, cancellation and shutdown. The private fixture lifecycle is reused from the qualified control-store suite. No mocked commit phase or alternate authority is introduced.

```text
cargo test --locked -p broker-control --all-targets
cargo test --locked -p broker-control --test postgres_sessions -- --ignored --test-threads=1
cargo test --locked --offline -p xtask --test guardrails precommit_stops_after_real_formatter_failure -- --exact --test-threads=1
```

Pre-commit checks whitespace and formatting. Pre-push runs workspace Clippy, DOC and workspace all-target tests, then the existing native SQL, packaging and container phases. New oracles must fail in actual configured hooks with clean fmt/Clippy, leave no HEAD, and pass exact restored commands. Running a hook never initiates a push. One-platform execution does not qualify other platforms.

The later HTTP consumer must validate current user state/revision, issuer configuration, selector policy and RBAC, compare CSRF, and distinguish SQL Absent/Revoked/Uncertain from cookie clearing. This leaf does not complete administrative login or the Broker migration.

The [native LOCAL Cookie producer and current consumer](rust-admin-cookie-session.md) and [federated cookie consumer](rust-admin-federated-cookie.md) reuse the private insert/read helpers in their own transaction; metadata DTOs themselves still confer no authentication.
