---
title: Native administrative resource grant writes
status: integrated
references:
  - target: {type: task, id: tsk-9f63, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-2a30, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4697, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native administrative resource grant writes

The Rust PostgreSQL server mounts the resource grant mutations when
[administration](administration.md) is enabled. Implementation and focused
qualification are tracked in `tsk-2a30`; PostgreSQL and real HTTP consumers are
qualified by the focused evidence below.
These endpoints complement [administrative reads](rust-admin-read.md) and
[role management](rust-admin-rbac.md).

The explicit [SQLite grant writer](rust-sqlite-admin-grants.md) now supplies the same authenticated CAS and HTTP contract through `store.admin_grants(limits, Arc<AdminGrantRoutes>)` and `sqlite_admin_grants_router`. It observes the actor, cookie CSRF, current `grants.write`, CAS and resulting resource/storage policy in one IMMEDIATE transaction, then obtains a bounded DATA snapshot after known commit acknowledgement. Global SQLite Server integration remains separate. PostgreSQL and SQLite share the pure normalizer and resulting-policy validator.

## Access and requests

Each mutation requires the current SQL action `grants.write`. Neither a valid
JWT nor `session.read`, `grants.read` or a resource capability grants that action.
The same operation authenticates the retained native JWT, LOCAL opaque token,
upstream bearer or administrative cookie and authorizes the action before writing.
A nonempty administrative cookie takes precedence over Bearer; a rejected cookie
never falls back to the other credential. Cookie mutations also require exactly
one valid `X-CSRF-Token`. Bearer mutations do not require that header.

| Method and path | Success | Effect |
|---|---|---|
| `POST /admin/api/v1/grants` | `201` | Create one new rule. |
| `PUT /admin/api/v1/grants/{id}` | `200` | Replace that rule and all four sets; the path ID overrides a body ID. |
| `DELETE /admin/api/v1/grants/{id}` | `200` | Remove an existing rule and its child rows. |

All three requests require `If-Match` with the positive revision from the last
authorized `GET` or `HEAD /admin/api/v1/grants`. Decimal, quoted decimal and
`W/"decimal"` forms are accepted. Missing, repeated, malformed or zero revisions
return `428 precondition_required`; a stale revision returns `409 revision_conflict`.
A valid unsigned revision beyond the database's signed range cannot match and is
a conflict. Revision increment is checked rather than wrapping.

Example create body:

```json
{
  "id": "project-readers",
  "name": "Project readers",
  "access": "organization",
  "principal": "acme",
  "capabilities": ["task:read"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"]
}
```

JSON is closed: unknown or duplicate fields, wrong types and trailing documents
are rejected. IDs, names, principals and route names are trimmed; access is
lowercase; sets are trimmed, sorted and deduplicated. The capability set must be
nonempty. `global`, `anonymous` and `authenticated` have no principal; `user`,
`team`, `organization` and `subject` require one. `org` is not an alias.

Project selectors use current canonical project IDs or `*`. Existing glob and
storage policy compilers validate capabilities, principal patterns, operations
and prefix templates. Optional fields are `principal`, `projects`,
`s3_operations`, `s3_prefixes` and `s3_route`. Route references must exist in the
actual server configuration. A rule enabling S3 operations needs its configured
route or a valid configured default. Request limits and database field bounds
remain applicable; there is no global grant quota.

## Transactions, responses and recovery

Participating administrative writers take the shared admin parent lock before
the actor, cookie and target. The current action, CSRF, policy revision and rule
mutation share one transaction. The rule and its capabilities, projects,
operations and prefixes commit together. The resulting policy is validated
before COMMIT. Permission failures, stale revisions or rejected data cannot
expose a partially updated rule or policy revision.

After a known write COMMIT, the server performs a fresh DATA read using the same
Original deadline and retained authentication. The fresh read is bounded by the
earlier of that deadline and the retained factor expiry, including waits for a
connection or BEGIN reply. It does not repeat the action check after its valid
mutation. A successful response contains the current
`PolicyDocument` and matching quoted `ETag`:

```json
{"v":1,"revision":2,"updated_at":"2026-10-16T12:00:00Z","rules":[]}
```

`revision` is a positive JSON number and `updated_at` is UTC RFC 3339. A concurrent
writer can commit before this fresh read, so the response may contain a later
revision. The body is current data, not an authorization lease or a snapshot of
only this request's change. Responses use `Cache-Control: no-store`,
`Pragma: no-cache` and the existing request ID; writes do not renew cookies.

| Failure | Response |
|---|---|
| Invalid authentication | `401 admin_unauthorized` |
| Missing current action | `403 admin_forbidden` |
| Invalid cookie CSRF | `403 csrf_failed` |
| Invalid rule | `400 invalid_grant` |
| Duplicate create, absent update/delete or failed mutation | `400 grant_write_failed` |
| Failed current DATA projection | `500 grants_read_failed` |
| Deadline or unavailable/uncertain operation | Existing `504` or `503` administrative error |

A lost COMMIT acknowledgement, deadline or failed post-write read can occur after
the write took effect. The server does not retry automatically or claim rollback.
Recover with an explicitly authorized fresh GET, inspect the actual rule and
revision, and submit a new change only if still necessary. A failed diagnostic
read leaves the outcome unknown.

## Implementation and verification

`crates/broker-control/src/service/admin_grants.rs` composes the existing genuine
authentication observers, `lock_admin`, CAS and SQL writes.
`service/resource_grants.rs` supplies the existing DATA read, retaining connection
closure on uncertain commits; the temporary phase/time/pool diagnostics were
removed. `service/admin_read.rs::grants_payload` supplies one document projection
to both read and write consumers. `crates/broker-presence/src/admin_grants.rs` and
the server runtime provide the mounted HTTP paths.

Focused verification uses `postgres_admin_grant_write_contract` and `broker_admin_grant_write_http_contract`, plus the affected grant read consumer. These cover CAS, atomicity, real commit-ACK loss in the writer and reader, failed reread after confirmed write, a second writer committed before the fresh response, and factor expiry while awaiting the DATA read. User administration and other backends/platforms have separate tests.
