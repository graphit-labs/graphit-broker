---
title: SQLite administrative role writes
doc_type: reference
description: Current-action SQLite role and assignment mutations with genuine authentication, last-admin protection and known-commit empty responses.
references:
  - target: {type: task, id: tsk-7494, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0dff, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-4697, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite administrative role writes

Operators and backend integrators can define or replace custom roles, delete them, and add or revoke assignments through the [private SQLite control store](rust-sqlite-control.md). This library reuses the [native administrative role contract](rust-admin-rbac.md), [genuine ingress producers](rust-sqlite-admin-session.md) and [current per-action authority](rust-sqlite-admin-read.md).

Global SQLite Server selection, other administrative mutation families and other-platform execution have separate validation boundaries.

## Perform one current-authority mutation

Use a configured genuine credential whose current SQL permissions include roles.write or wildcard. Neither session.read nor a prior session/read response authorizes this mutation, and session.read is not an additional prerequisite.

| Method and route | Body | Result after known COMMIT |
|---|---|---|
| PUT /admin/api/v1/roles/{name} | {"permissions":["roles.read"]} | 204, empty body |
| DELETE /admin/api/v1/roles/{name} | None | 204, empty body |
| POST /admin/api/v1/role-assignments | {"subject":"issuer\u007csubject","role":"auditor"} | 204, empty body |
| DELETE /admin/api/v1/role-assignments | Same assignment object | 204, empty body |

Create/replace a role with PUT, then assign it through POST as needed. To remove an assignment, DELETE the exact pair. To remove a custom definition and its dependent rows, DELETE its role path. The path determines the role name; the JSON body cannot override it.

The body is one closed JSON object bounded by the existing configured body limit. Duplicate/unknown fields, nulls, wrong types and trailing documents are rejected. Omitted permissions is an empty bundle and fails validation. Malformed paths/bodies retain the operation's existing finite error.

RBAC does not require or perform If-Match/CAS, advance resource ACL revision, return a policy document, or perform a fresh DATA reread after ACK. Successful mutation returns only the protected known-commit result and empty HTTP 204. Use a separately authorized administrative GET when a current role/assignment listing is needed.

## Definitions and assignment data

Role names are trimmed, case-sensitive ASCII identifiers, at most 128 bytes. Their first character is alphanumeric; subsequent characters may also be dot, underscore or hyphen. Permission strings must be one of the existing nine system actions or literal wildcard. Permissions are deduplicated and sorted; a custom bundle must be nonempty.

Exact built-ins admin and user cannot be changed or deleted by this adapter. Admin is a distinct valid custom name. PUT replaces the complete custom bundle atomically and preserves its original created_at. DELETE requires an existing custom role; its permissions and assignments are removed by the existing foreign-key cascade. Deleting an absent role fails.

Assignment subject and role are trimmed. The whole assignment subject must be nonempty, contain no control characters and have at most **512 Unicode characters**, counted by Rust chars. This is not a 512-byte UTF-8 limit and does not relax LOCAL identity validation. The subject may identify an external principal without a LOCAL account.

POST requires the role definition to exist. Repeating the same subject/role pair is idempotent and preserves its original creation timestamp. DELETE of an absent pair is a successful no-op. Revoking a present admin pair additionally applies the last-admin rule below.

The common assignment_values and role_values validators are reused. SQLite's replace_role operates on the caller's transaction and Work and is also used by the real low-level set_role producer. The administrative writer does not authorize in one transaction and call a separately committing set_role afterward. There is no new schema, table, quota or alternate permission codec.

## Authenticate without manufacturing authority

AdminReadAuthentication is the existing common input:

| Class | Genuine authentication and current observation |
|---|---|
| Broker LOCAL JWT | Proof from the configured BrokerAccessVerifier, current LOCAL enabled identity/binding/profile and current SQL roles |
| Opaque LOCAL | Actual human/service possession, current identity/revision and SQL authority |
| F1 upstream bearer | Real configured verifier, owned retained proof and current SQL role definitions |
| LOCAL or federated cookie | Protected stored session, real window, current LOCAL binding or federated trust/selector and current roles |

A known nonempty cookie has precedence even if a bearer is also present. Invalid cookie admission never falls back to a valid bearer. Missing/empty/literal-empty cookie permits the existing explicit bearer dispatcher: configured opaque prefix, selected upstream F1, then native Broker JWT. A failed selected mode never probes another mode.

Cookie mutation requires exactly one canonical X-CSRF-Token, checked against the observed cookie through the existing constant-time primitive. Missing, repeated, malformed or wrong CSRF denies the mutation. Bearer mutation does not require CSRF. CookieObserver and cookie_hash load genuine SQL metadata inside the caller's transaction; caller-provided profile/session DATA cannot issue a proof.

F1 retains its established issuer/audience/resource/scope/predicate checks. Some([]) claim-role selection excludes assignments; absent selection uses current assignments. Unknown role definitions are inert and add no permission. Federated cookies use current issuer/trust and cookie-role selector, independently of the bearer selector. Existing LOCAL cookie identity/revision/password-change and opaque/JWT distinctions remain intact.

Broker proof stays borrowed and retained through the caller/result; only bounded locator/subject/expiry DATA follows its worker. F1's genuine owned proof crosses the worker/ACK/result. The cookie branch retains its real configured upstream Arc. Inputs and results have redacted Debug and expose no public authority constructor.

## Borrow the actual producer and compose HTTP

~~~text
SqliteControlStore::admin_rbac(
    &self, limits: AdminBrokerSessionLimits,
) -> Result<SqliteAdminRbac<'_>, ControlError>

SqliteAdminRbac::write<'a>(
    &self,
    authentication: AdminReadAuthentication<'a, '_>,
    request: AdminRbacRequest<'_>,
    csrf: Option<&str>,
    original: Instant,
) -> Result<AdminRbacResult<'a>, AdminRbacError>  // async
~~~

AdminRbacRequest supplies SetRole, DeleteRole, Assign and Revoke. The factory validates limits and returns a view borrowed from the actual store.

The Presence factory uses these **seven actual arguments**:

~~~text
sqlite_admin_rbac_router(
    store: Arc<SqliteControlStore>,
    verifier: Arc<BrokerAccessVerifier>,
    session: AdminSessionHttpConfig,
    body_bytes: NonZeroUsize,
    local: Option<AdminLocalBearerHttpConfig>,
    upstream: Option<Arc<UpstreamBearerVerifier>>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError>
~~~

It reuses the existing configuration types and handlers with a concrete PostgreSQL-or-SQLite backend. Each configured authentication argument feeds its real producer. Integrators may merge this router with the complete SQLite administrative read router: reads retain their own actions and the mutation methods retain roles.write. This factory supplies no global Server configuration or additional UI/login route.

## Transaction and last explicit admin

One physical IMMEDIATE transaction validates the existing admin role parent, observes current actor/action and cookie/CSRF where applicable, then mutates the target. Missing parent is corrupt RBAC, not a reason to fabricate a built-in definition. Parent integrity does not require the actor itself to hold a role named admin.

SQLite serializes participating physical owners through its real writer transaction. No PostgreSQL row/advisory lock or FOR UPDATE protocol is emulated, and no admin_state table is introduced. Identity/candidate projections enforce types and byte bounds before copying. Mutation, role bundle and dependent assignment changes commit together.

Revoking a **present explicit admin assignment** requires another eligible explicit admin pair, excluding the target:

- An external subject without the literal local| prefix counts without a LOCAL lookup.
- A local|subject pair counts only through its current matching LOCAL row: enabled=1, canonical username/subject/kind, positive revision and exact literal binding.
- Missing or disabled LOCAL rows do not count. Malformed LOCAL candidate data actually observed fails closed.
- A custom wildcard role and an IdP admin claim do not count as an explicit admin assignment.
- A disabled target does not bypass protection. An absent target pair remains a no-op.

Assignment data's 512-Unicode-character bound is separate from the existing LOCAL subject validator's 512-byte bound. An accepted assignment string alone is not evidence that a LOCAL candidate is canonical or eligible. Competing independent owners perform this protection inside their serialized IMMEDIATE transactions rather than trusting a previous listing.

A valid self-demotion returns 204 after known ACK. The result checks retained factor/time, not the permissions the mutation may have just removed. If no remaining current role grants the next write, that next request is denied. The writer does not reauthorize after COMMIT to turn a known self-demotion into a false failure.

## Time, responses and recovery

One finite Original and the genuine UTC/monotonic factor or cookie window remain retained through native work, COMMIT ACK and final response checks. Waiting and late negatives preserve the earlier relevant expiry rather than renewing time. OutcomeUncertain has priority over later clocks/semantic errors. The existing public mapper may classify a cookie SessionExpired as invalid authentication; internal categories are not exposed directly.

| Condition | HTTP status / code |
|---|---|
| Invalid authentication/current binding | 401 admin_unauthorized |
| Missing current roles.write | 403 admin_forbidden |
| Invalid cookie CSRF | 403 csrf_failed |
| Invalid role definition/built-in replacement | 400 invalid_role |
| Built-in, invalid or absent role deletion | 400 role_delete_failed |
| Invalid assignment, missing POST role or last-admin protection | 400 assignment_failed |
| Authorization SQL/corrupt identity or RBAC control failure | 500 authorization_failed |
| Original deadline | 504 administration_unavailable |
| Closed or uncertain operation | 503 administration_unavailable |

Handler responses keep no-store/no-cache and the established request_id/X-Request-ID envelope; no cookie renewal or Set-Cookie is emitted. Error messages are finite and omit credentials, subject values, SQL and driver errors.

204 is published only after a known physical commit and final gates. Cancellation, deadline or failed work before confirmation cannot produce a late success. A lost ACK or late timeout can occur after effects persisted: do not claim rollback, replay automatically or reinterpret failure as an empty role/assignment list.

Recover by an explicitly authorized fresh read of roles/assignments, compare actual state with the intended change and decide on any further mutation. The reader needs its own roles.read authority; use another authorized reader if needed. A failed diagnostic read leaves uncertainty. Idempotent pair operations do not justify replaying a broader role change or bypassing fresh authority/last-admin checks.

## Sources and verification

The targets are `broker-control/sqlite_admin_rbac_write` and `broker-presence/sqlite_admin_rbac_write_http`.

The assigned-write fixture grants `roles.write`. A genuine signed bearer carrying an empty role claim, with the same subject and real assignment, sets/deletes a role with no selector before empty selected roles and unknown selected roles are denied. This provides a positive assignment baseline for selector negatives.

Portable target commands are:

~~~text
cargo test --locked --offline -j4 -p broker-control --test sqlite_admin_rbac_write -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_admin_rbac_write_http -- --ignored --test-threads=1
~~~

Library tests do not establish Windows/macOS execution or complete administrative CRUD and Server composition.

Sources: [SQLite writer](../crates/broker-control/src/sqlite/flow/admin_rbac.rs), [shared SQLite role replacement](../crates/broker-control/src/sqlite/flow/roles.rs), [HTTP writer](../crates/broker-presence/src/admin_rbac.rs), and [common request/result/assignment validation](../crates/broker-control/src/admin_rbac.rs).
