---
title: Native administrative role writes
status: qualified
references:
  - target: {type: task, id: tsk-7494, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-4697, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-d609, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native administrative role writes

The PostgreSQL implementation supplies four mutations under the existing enabled administration configuration. [Administrative reads](rust-admin-read.md), user management and resource grant writes have their own scopes.

| Method and route | Body | Required current action |
|---|---|---|
| `PUT /admin/api/v1/roles/{name}` | `{"permissions":["roles.read"]}` | `roles.write` or `*` |
| `DELETE /admin/api/v1/roles/{name}` | None | `roles.write` or `*` |
| `POST /admin/api/v1/role-assignments` | `{"subject":"issuer\u007csubject","role":"auditor"}` | `roles.write` or `*` |
| `DELETE /admin/api/v1/role-assignments` | Same assignment body | `roles.write` or `*` |

Bodies are single JSON objects with closed fields and the existing server body
limit. Duplicate fields, nulls, wrong types, unknown fields and trailing data are
rejected. Omitting `permissions` produces an empty bundle and fails validation.
The path selects the role; a body cannot rename or override it.

The explicit [SQLite writer and HTTP adapter](rust-sqlite-admin-rbac.md) preserve these four operations through current SQLite identity, action and last-admin checks in one IMMEDIATE transaction. Server backend selection is described in the [native Server guide](rust-broker-server.md#select-private-sqlite). The row-lock protocol below describes PostgreSQL; SQLite uses its physical writer transaction.

## Definitions and assignments

Role names are trimmed and case-sensitive ASCII identifiers, with at most 128
bytes: an alphanumeric first character followed by alphanumerics, dot, underscore
or hyphen. Permissions come from the existing nine system actions or literal
`*`; values are deduplicated and sorted. Empty custom bundles and unknown actions
are invalid. Exact built-ins `admin` and `user` cannot be changed or removed by
these HTTP operations. `Admin` is a distinct valid custom name.

PUT replaces the complete custom bundle atomically and preserves its creation
time. Deleting an existing custom role removes its permissions and assignments
through the existing foreign-key cascade, including roles with assignments.
Deleting an absent role is an error. The [low-level role primitive](rust-postgres-roles.md)
still preserves official built-in bundles; its connection-borrowed replacement
core is reused inside the administrative transaction rather than opening a
second transaction after authorization.

Assignment subject and role are trimmed. A subject must be nonempty, contain no
control characters and have at most **512 Unicode characters**, not 512 UTF-8
bytes. This is the assignment data contract, distinct from LOCAL identity
validation. POST requires an existing role; the principal need not be a LOCAL
account. Repeating a pair preserves its original creation time. DELETE of an
absent pair is a no-op. There is no HTTP revision or `If-Match` CAS for RBAC;
resource grant CAS is a different API.

## Authentication and transaction

The genuine configured ingress is reused: signed Broker LOCAL JWT and its current
binding, opaque LOCAL/service credential and current revision, upstream resource
access JWT through the shared verifier, or a genuine LOCAL/federated cookie.
Authentication inputs and read results do not grant write authority. The exact
`roles.write` action is read from current SQL in the same transaction as the
mutation; `session.read` is neither sufficient nor additionally required.

A known nonempty cookie takes precedence over Bearer, with no fallback on cookie
failure. Cookie writes require exactly one canonical `X-CSRF-Token`, compared
against the current cookie secret using the existing constant-time primitive.
Bearer writes require no CSRF token. JWT discovery/JWKS, expiry, subject and
issuer binding retain their existing verification contracts; no per-request
UserInfo, introspection, blacklist or new token lifetime is introduced.

Every participating administrative write locks the built-in admin parent first,
then the LOCAL actor and cookie where applicable, followed by its target. The
operation uses READ COMMITTED with existing row locks, Original deadline and
factor expiry, rather than claiming a global snapshot or permission lease.
Readers retain their existing behavior. External writers that do not follow the
parent-lock protocol are outside this concurrency guarantee.

Revoking a present explicit `admin` pair requires another eligible explicit
assignment. An external subject counts without a LOCAL lookup. A `local|` subject
counts only when its actual LOCAL row is enabled and has canonical username,
subject, kind and positive revision; malformed candidate data fails closed.
Missing or disabled LOCAL accounts do not count. A custom wildcard role or IdP
role claim does not count as an explicit admin assignment. An absent pair is a
no-op, and a disabled target is not itself a reason to skip protection.

Success is empty `204` only after known COMMIT and final time/factor checks.
Permissions are not read again after COMMIT: a valid self-demotion returns `204`
and its next unauthorized operation returns `403`. Cancellation, deadline or
failed SQL before confirmation closes the unconfirmed connection. An ambiguous
COMMIT returns an unavailable outcome and is never replayed automatically; no
response claims that it rolled back. Earlier semantic errors still undergo final
temporal checks, while COMMIT uncertainty retains priority.

## Responses and qualification

Responses retain `Cache-Control: no-store`, `Pragma: no-cache` and the existing
request ID behavior, with no cookie renewal. Messages are finite and contain no
driver errors, SQL, credentials or subject values.

| Condition | Status / code |
|---|---|
| Invalid authentication | `401 admin_unauthorized` |
| Current action denied | `403 admin_forbidden` |
| Missing, duplicate, invalid or wrong cookie CSRF | `403 csrf_failed` |
| Invalid role definition | `400 invalid_role` |
| Built-in, invalid or absent role deletion | `400 role_delete_failed` |
| Invalid assignment, missing POST role or protected last admin | `400 assignment_failed` |
| Authorization SQL or corrupt identity | `500 authorization_failed` |
| Original deadline | `504 administration_unavailable` |
| Closed or uncertain transaction | `503 administration_unavailable` |

The focused targets are `postgres_admin_rbac_write` in broker-control and
`admin_rbac_write` in broker-server. They use real TLS PostgreSQL with an ordinary
NOSUPERUSER owner, actual Graphit Broker binary, genuine LOCAL login/OIDC tokens,
CSPRNG opaque credentials, Rust HTTPS issuer and H1→H2 cookies. They cover current
permissions, all four operations/factors, CSRF and wire validation, Unicode,
cascade/idempotency, last-admin concurrency, rollback, cancellation/expiry,
actual COMMIT reply uncertainty and self-demotion. Affected project/federated readers and the role-replacement core have separate tests.

The existing read/write fixture is shared through `tests/support/admin_native.rs`.
Read assertions are preserved; credential producers use the same per-instance
loopback issuer as the configured public URL, retaining literal OIDC equality.
Qualification covers the affected consumers and role core, with no installed
vendor, universal PID campaign or broad benchmark required. Other
platforms, user/grant writes, browser integration and the overall migration remain
separate deliveries.
