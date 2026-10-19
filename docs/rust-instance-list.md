---
references:
  - target: {type: task, id: tsk-d37e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-795b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-56ac, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-70b2, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6e9e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Local authenticated inventory listing in Rust

Audience: Broker server integrators. This PostgreSQL business API lists
maintained inventories with only the projects and versions the current local
principal may read. It composes the [current local verifier](rust-local-bearer-verifier.md),
[fresh whole policy](rust-presence-authorization.md),
[SQL candidates](rust-instance-candidates.md) and
[exact-ID SQL reader](rust-instance-read.md).
HTTP GET /v1/instances query parsing, wire serialization and router composition
are provided by the separate [HTTP LIST route](rust-instance-inventory-list-http.md).
This business library does not supply the HTTP default limit 50.

## API and configuration

~~~text
store.local_instance_inventory_lister(
  audience: &str,
  identity_json_bytes: NonZeroUsize,
  grants_json_bytes: NonZeroUsize,
  inventory_json_bytes: NonZeroUsize
) -> Result<PostgresLocalInstanceInventoryLister<'_>, InstanceListError>

InstanceListQuery::new(
  limit: NonZeroUsize,
  after: Option<String>,
  instance_id: Option<String>,
  project_id: Option<String>,
  version: Option<String>
) -> Result<InstanceListQuery, InstanceListError>

lister.list(raw: &str, required_scopes: &[String],
            query: &InstanceListQuery, original_deadline: Instant)
  -> Result<AuthorizedInstanceList, InstanceListError>
~~~

The lister borrows the existing store and explicit audience; no new pool or
runtime. Supply all three representable JSON byte caps and required scopes.
There are no policy, quota, timeout, audience or scope defaults.
The query limit must be 1–100; NonZeroUsize excludes zero. It has no Default.
after and instance_id use the exact [registration ID grammar](rust-broker-instances.md):
1–128 ASCII bytes, alphanumeric first/last and ._- permitted inside.
project_id is a canonical nonzero uppercase ULID. version uses the same
meaningful nonempty, control-free, exact-trim grammar as registration.
Nothing is trimmed, case folded or substituted.

## Authorization and projection

Each page verifies the exact raw local Access or Service bearer using current
SQL identity/token observations, then reads and validates one whole grant
snapshot. Invalid unrelated policy rules fail even at EOF or when an exact
instance filter is at/before after. An authenticated principal with a valid
policy and no matching Read permission receives an empty page.

For each nonempty stored inventory, include only projects for which the current
principal, presence:read capability and project match the **same** rule.
Presence:publish, Hub/admin roles and registration ownership do not grant Read;
capability/project matches from separate rules cannot be combined.
A readable nonempty inventory may belong to another principal.
This differs from [own-inventory GET](rust-instance-inventory-read.md), which
requires literal ownership and Read ALL projects before returning the full inventory.

Filters are cumulative:
- project_id restricts the returned projects.
- version restricts the returned versions of every authorized project.
- version without project_id may match any authorized project.
- A project with no matching versions and an inventory with no visible projects
  are omitted. Return only matching versions, without extra versions.

For example, an inventory with projects A(main, release) and B(private), where
only A is readable, returns A(main, release). Adding version=main returns only
A(main). Adding project_id=B returns no item. Valid nonexistent filters return
an empty page.

An actually stored empty parent is visible only when its literal owner issuer
and raw subject equal the current principal and a same-rule Any-project Read
permission exists. Empty parents are excluded when project_id or version is
supplied. A nonempty inventory filtered down to zero projects never becomes
an owned empty inventory.

## Page order, cursor and concurrency

Items follow exclusive instance_id byte order (PostgreSQL C collation).
A missing after ID is valid and need not refer to a stored row.
Without instance_id, candidates are read sequentially until SQL EOF or
limit+1 **visible** items. Hidden IDs advance only an internal scan cursor.
The returned page contains at most limit items. next_after is the last visible
ID actually returned only when another visible item was found; otherwise null.
It never reveals the hidden scanned ID, extra visible item, owner or a count.
A full page followed only by hidden candidates has next_after null.

With instance_id, use the existing one-ID reader; an instance at/before after
returns empty after current Auth and whole policy validation. Exact lookup
does not scan unrelated candidates. There is no dynamic SQL filter builder.

Each SQL candidate read has its own coherent complete-inventory snapshot.
The page is not one database snapshot. Concurrent inventory changes can affect
later candidates/pages; this API promises no global total, frozen listing or
reusable authority lease. Each new page rereads Auth and the whole policy.

## Time, errors and ownership

Use one original caller deadline, bounded once by the store operation budget.
Inventory and grant producers are awaited directly, preserving their own
transaction/COMMIT outcome classification. There is no outer business timeout
around those SQL producers. The existing verifier retains its own timeout.
After SQL and before returning, recheck the observed bearer expiry with fresh UTC
and the original bounded monotonic deadline, including empty output. Project
and version loops check that deadline. The final expiry check does not reread
SQL revocation or freeze concurrent ACL changes.

InstanceListError is finite:
- InvalidQuery for invalid query data.
- Authorization(PresenceAuthorizationError) for current Auth, grant reads,
  malformed whole policy or business deadline failures.
- Inventory(InstanceReadError) for candidate/exact-ID reads, malformed stored
  inventories, cap failures or SQL failures.

Nested Deadline, Closed and OutcomeUncertain remain distinguishable.
A corrupt or oversized hidden candidate fails the scan; it is not silently
skipped, repaired or retried. Exact-ID lookup still reads only its selected row.
No inventory, owner, local user or grant is changed. The existing verifier's
best-effort token usage observation remains allowed.

AuthorizedInstanceList exposes only items() and next_after().
AuthorizedInstanceListItem exposes only inventory(), created_at_micros() and
updated_at_micros(). Inventory is the projected value; timestamps remain the
stored signed microsecond values. Outputs have no owner/principal/raw credential,
public factory, Clone, Deserialize or Default. Debug for query, lister and
outputs is redacted. These results describe one completed read.

## Evidence and integration boundary

Sources: [query and private outputs](../crates/broker-control/src/instance_list.rs),
[borrowed lister](../crates/broker-control/src/service/instance_list.rs),
[native contract](../crates/broker-control/tests/instance_list.rs).
The native test uses the pinned PostgreSQL TLS fixture with an ordinary
NOSUPERUSER role, actual schema/writer, current Access and Service users/tokens
and SQL grants. It checks partial foreign reads, same-rule filtering, owned
empty rules, visible cursors, cumulative filters, fresh Auth/ACL, whole policy,
caps, corruption, SELECT denial, expiry during a causally observed inventory
SQL lock, original deadlines, actual abort/JoinCancelled and pool recovery,
Closed/reopen, owned cleanup and unchanged inventory rows. Polling clears the
PostgreSQL statistics snapshot before each lock observation.

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test instance_list postgres_local_instance_list_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
~~~

Qualification is recorded in tsk-d37e. HTTP LIST is qualified separately in
tsk-1a3a; remote Now/WebSocket,
signed JWT/external OIDC authentication, MySQL listing, bootstrap integration
and whole Broker migration are separate outcomes. Linux execution does not
qualify Windows/macOS or the final integration suite.
