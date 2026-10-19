---
title: SQLite administrative resource grant writes
doc_type: reference
description: Exact-action SQLite grant mutations with revision CAS, genuine authentication and a fresh DATA response after known commit acknowledgement.
references:
  - target: {type: task, id: tsk-3daa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9f63, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0dff, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-2a30, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-698c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# SQLite administrative resource grant writes

This reference is for operators and backend integrators creating, replacing or removing resource grants on the [private SQLite control store](rust-sqlite-control.md). The writer shares the [native grant contract](rust-admin-grants.md), genuine [administrative ingress producers](rust-sqlite-admin-session.md) and [complete SQLite read composition](rust-sqlite-admin-read.md).

Both public factories are exported. Global Server composition and other-platform execution require separate validation.

## Change a rule with an explicit revision

1. Obtain the policy document and revision through an explicitly authorized GET or HEAD /admin/api/v1/grants, or another trusted current revision source. A reader needs grants.read; a writer does not acquire that permission merely by having grants.write. A separate authorized reader may supply the revision as DATA.
2. Submit the intended mutation with If-Match containing that positive revision and a genuine configured credential. Cookie requests also supply their existing X-CSRF-Token.
3. On success, inspect the returned full policy document and matching ETag. Its revision may be later than this request's mutation because another writer can commit before the fresh response read.
4. On conflict, obtain an authorized current read, compare the actual state and prepare a new explicit change only if still needed. Do not automatically replay the old mutation.

| Method and path | Success | Operation |
|---|---|---|
| POST /admin/api/v1/grants | 201 | Create one rule |
| PUT /admin/api/v1/grants/{id} | 200 | Replace the rule and all four child sets; path ID overrides body.id |
| DELETE /admin/api/v1/grants/{id} | 200 | Delete the rule and its child rows |

If-Match accepts a positive decimal revision, quoted decimal or W/"decimal". Missing, repeated, malformed or zero values return 428 precondition_required. A well-formed stale revision returns 409 revision_conflict. A positive unsigned revision beyond the stored signed range cannot match. Incrementing the current signed revision is checked; it never wraps.

Create and replace accept closed JSON. Unknown/duplicate fields, wrong types and trailing documents are rejected by the existing parser, and the explicit body cap applies. DELETE requires the path and revision rather than a grant body. Example create body:

~~~json
{
  "id": "project-readers",
  "name": "Project readers",
  "access": "authenticated",
  "capabilities": ["hub"],
  "projects": ["*"]
}
~~~

The response is the complete bounded PolicyDocument, not just the affected rule:

~~~json
{"v":1,"revision":2,"updated_at":"2026-10-17T12:00:00Z","rules":[]}
~~~

The example is illustrative. Revision is a positive JSON number, updated_at is UTC RFC3339, and ETag is its quoted decimal revision. Normal handler responses retain no-store/no-cache and the existing finite request_id/X-Request-ID convention. A write does not renew a cookie or publish credentials.

## Use the genuine configured authority

Only the current grants.write action or wildcard authorizes a mutation. Neither session.read nor grants.read is an additional writer prerequisite. Resource capabilities and a previously returned session/profile/document are not administrative write authority.

The common AdminReadAuthentication input supports:

| Input | Current checks |
|---|---|
| Broker JWT LOCAL | Genuine proof from the configured BrokerAccessVerifier, current LOCAL human/service identity, enabled/binding/profile and SQL roles |
| Opaque LOCAL bearer | Actual LOCAL human/service possession and its current SQL authority |
| Upstream F1 bearer | Common real issuer/signature/audience/resource/scope/predicate verification and current SQL role definitions |
| LOCAL or federated cookie | Genuine protected session metadata/window, current LOCAL binding or federated trust/selector, and canonical constant-time CSRF verification |

Broker proof remains borrowed and retained by the caller/result; bounded locator/subject/expiry DATA crosses the worker. F1 verification produces an owned genuine proof retained through worker, ACK and result. Cookie authentication carries the configured upstream Arc where federated admission needs it. No new authentication enum or public proof constructor is introduced.

F1 selected claim roles, including Some([]), exclude SQL assignments and add implicit user. Without a selector, current literal issuer|mapped-subject assignments apply. A role without a current definition is inert and grants no permission. Federated cookies use current cookie-role selector and issuer policy, independently of the OAuth selector; LOCAL cookies retain their identity/revision/password-change rules. Existing ingress producers remain the source of these contracts.

A known nonempty administrative cookie has priority even if invalid: a valid bearer cannot rescue it. Missing/empty/literal-empty cookie permits the existing dispatcher: configured opaque prefixes, selected upstream F1, then Broker JWT. Failed selected authentication never probes another mode. Cookie mutation requires exactly one valid X-CSRF-Token; missing, duplicated or invalid CSRF denies the mutation. Bearer mutation does not require CSRF.

## Borrow the writer and retain the route owner

~~~text
SqliteControlStore::admin_grants(
    &self,
    limits: AdminReadLimits,
    routes: Arc<AdminGrantRoutes>,
) -> Result<SqliteAdminGrants<'_>, ControlError>

SqliteAdminGrants::write<'a>(
    &self,
    authentication: AdminReadAuthentication<'a, '_>,
    request: AdminGrantRequest<'_>,
    expected_revision: u64,
    csrf: Option<&str>,
    original: Instant,
) -> Result<AdminGrantResult<'a>, AdminGrantError>  // async
~~~

AdminGrantRequest has Create, Update and Delete variants. The factory validates existing read/authorization bounds and borrows the real store. AdminGrantRoutes contains public route names and the configured default, without storage credentials. Its genuine configured Arc is retained by the static job rather than copying route configuration on every request. Debug for inputs and protected results is redacted.

The applied transport factory is:

~~~text
sqlite_admin_grants_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    config: AdminGrantsHttpConfig,
) -> Result<Router, ControlError>
~~~

AdminGrantsHttpConfig supplies session limits/deadline, body_bytes, grants_json_bytes, response_json_bytes, optional LOCAL bearer/upstream/cookie configuration, and the actual routes Arc. It reuses existing handler/wire parsing and a private PostgreSQL-or-SQLite backend.

Compose the complete sqlite_admin_read_router from tsk-0dff with this write router using Router::merge. GET/HEAD /admin/api/v1/grants belongs to the reader; POST and PUT/DELETE belong to the writer. Disjoint methods share the path. No GET permission is silently added to a successful writer, and no new administrative endpoint, UI or global Server configuration is supplied.

## Authorize, compare and normalize in one transaction

The physical SQLite executor begins one IMMEDIATE transaction. It verifies the required existing admin role definition as catalog integrity; absence is CorruptRbac. This is not a requirement that the actor itself hold a role named admin.

Current actor/action admission and cookie CSRF precede the policy revision CAS; semantic mutation normalization follows CAS. This preserves authorization before revision/mutation errors, and a stale revision before invalid rule contents. The established transport still parses its credential/header/JSON shape before entering the Control mutation.

The transaction reads resource_acl_state.id=1, requires a positive current revision, checks the expected revision and checked signed increment, then mutates the rule and its four sets: capabilities, projects, S3 operations and S3 prefixes. Replacement preserves created_at and updates updated_at; policy revision/time advance atomically. Delete removes the associated child rows through the existing catalog relationships.

Shared pure PostgreSQL-extracted helpers trim text, lowercase access, sort/deduplicate nonempty sets and apply existing ID/text bounds. Capabilities must be nonempty. Global, anonymous and authenticated access have no principal; user, team, organization and subject require one. org is not an alias. Existing policy compilers validate patterns, project selectors, storage operations and prefixes. Route names must exist in the actual configured routes, and S3-capable rules need a configured route or valid default.

Validation covers the **entire resulting snapshot**, not only the changed rule. Invalid existing policy data can therefore reject a mutation. Configured identity/profile/grants/response bounds remain applicable; no global grant quota, truncation or parallel codec is added. Actor, CAS, all child sets and full-policy validation share the same IMMEDIATE transaction and known COMMIT. Physical owners serialize through SQLite; no PostgreSQL parent-lock or advisory-lock mechanism is ported and no new admin-state schema is created.

## Fresh DATA after ACK and recovery

Only after a known write COMMIT acknowledgement does the writer start a new resource-grants DATA read. It uses the existing data reader and grants_payload projection, bounded by the earlier of the same Original and retained factor expiry. It does not call AdminReads with GrantsRead or repeat grants.write authorization after its admitted mutation.

The genuine factor/window and Original remain retained and checked around this fresh read, serialization and HTTP response preparation. The returned document is current DATA, may include a concurrent later revision and is not a future authorization lease or a pre-COMMIT snapshot.

| Failure | Response / recovery |
|---|---|
| Invalid authentication | 401 admin_unauthorized |
| Missing current write action | 403 admin_forbidden |
| Invalid cookie CSRF | 403 csrf_failed |
| Missing/invalid revision | 428 precondition_required |
| Stale revision | 409 revision_conflict; inspect current authorized DATA before a new change |
| Invalid normalized rule or resulting policy | 400 invalid_grant |
| Duplicate create, absent update/delete or mutation failure | 400 grant_write_failed |
| Failed fresh DATA read or response serialization | 500 grants_read_failed; the write can already be committed |
| Deadline | Existing 504 administration_unavailable |
| Closed/unavailable owner or uncertain physical outcome | Existing 503 administration_unavailable |
| Other control corruption/limit failure | Existing finite administrative control error |

A 500 grants_read_failed after known write ACK must not be reported as rollback. A deadline or lost acknowledgement can also occur after effects persisted. The writer does not automatically retry, undo the change or claim the client received a successful response.

Recover with an explicitly authorized fresh GET, inspect the actual rule and revision, and decide whether any further mutation is needed. If the same actor lacks grants.read, use an authorized reader rather than bypassing that permission. If the diagnostic read fails, retain the uncertainty. Replaying create/update/delete blindly can conflict or apply a second change.

One finite Original crosses authentication, SQL, ACK, DATA reread and serialization; it is never renewed. Factor expiry also bounds waits and final checks. Causal OutcomeUncertain takes precedence over later clock/semantic classification. Body parsing may use the existing bounded transport timeout; SQL mutation is not wrapped in an outer timeout that abandons native work.

## Sources and verification

The targets are Control `sqlite_admin_grants` and Presence `sqlite_admin_grants_http`. They cover genuine ingresses/current action/cookie CSRF, CAS/four sets/normalization/rollback/concurrent owners, post-ACK DATA/Original causality, wire/revision handling and persisted writes after a failed DATA response.

Portable focal invocations are:

~~~text
cargo test --locked --offline -j4 -p broker-control --test sqlite_admin_grants -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_admin_grants_http -- --ignored --test-threads=1
~~~

Library tests do not establish Windows/macOS execution or complete administrative CRUD and Server composition.

Sources: [Control writer](../crates/broker-control/src/sqlite/flow/admin_grants.rs), [HTTP writer](../crates/broker-presence/src/admin_grants.rs), [shared validation](../crates/broker-control/src/admin_grants/validation.rs), [Control focal](../crates/broker-control/tests/sqlite_admin_grants.rs), and [HTTP focal](../crates/broker-presence/tests/sqlite_admin_grants_http.rs).
