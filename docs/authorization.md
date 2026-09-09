# Resource authorization

Resource grants are the sole project-capability authorization source for consumer operations.
They live in normalized SQL tables and are independent from system RBAC roles. The broker
loads current grants for every consequential request, so a committed change applies to the next
Hub resolution, S3 pre-sign, embedding, or rerank request.

## Identity

The broker derives the principal from exactly one source:

- no `Authorization` header: anonymous principal;
- a SQL local user: the username-selected, globally peppered Argon2id identity and its persisted
  subject/username/organization/teams;
- an OIDC bearer: signature, issuer, audience, expiry, required scopes, and configured exact-key or
  RFC 9535 JSONPath claim selectors are validated before attributes are mapped.

Request bodies cannot provide identity claims. Canonical identity is `issuer|subject`; username,
organization, and teams are attributes from the verified token only. An invalid bearer returns
`401` and is never downgraded to anonymous.

RBAC is system-wide and orthogonal to grants. Every authenticated principal has the default `user`
role; SQL assignments or an authoritative OIDC role claim can add roles such as `admin`. Those
roles select broker/UI actions but do not make a resource grant match.

## Grant shape

```json
{
  "id": "platform-project",
  "name": "Platform project access",
  "access": "team",
  "principal": "platform",
  "capabilities": ["hub", "s3", "embeddings", "rerank"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
  "s3_operations": ["read", "write", "publish"],
  "s3_route": "primary",
  "s3_prefixes": ["v2/projects/{project}"]
}
```

- `id`: stable safe identifier used by CRUD URLs; required and unique.
- `name`: human-readable label.
- `access`: `global`, `anonymous`, `authenticated`, `user`, `team`,
  `organization`, or `subject`.
- `principal`: required only for `user`, `team`, `organization`, and `subject`.
- `capabilities`: one or more of the broker capabilities. `s3:<operation>` can narrow S3
  without granting the whole `s3` capability.
- `projects`: exact project ULIDs or `*`. An omitted list applies to every project. Broker
  grants intentionally do not accept name globs because the broker must authorize S3 before it
  may reveal project metadata.
- `s3_operations`: optional `read`, `write`, `publish`, or `delete` constraint.
- `s3_route`: optional configured private route; an empty value selects `default_route`.
- `s3_prefixes`: logical key templates. Supported placeholders are `{project}`,
  `{username}`, `{organization}`, and `{subject}`; all rendered segments must be safe.

Grants are additive. No match means deny. If matching S3 grants select different routes, the
request is rejected instead of guessing.

## How S3 grants select a route

The S3 pre-sign request contains `project`, an HTTP-style `operation` (`get`, `head`, `list`,
`put`, or `delete`), and a logical `key`. It deliberately has no client-controlled route field.
The bearer credential, or the absence of one, has already established the principal before route
selection begins.

The broker maps the requested verb to authorization operations in this order:

| Requested operation | Authorization operations tried in order |
|---|---|
| `get`, `head`, `list` | `read`, `write`, `publish` |
| `put` | `write`, `publish` |
| `delete` | `delete`, `publish` |

For each authorization operation, a grant matches only when all applicable selectors agree:

1. `access` and `principal` match the derived identity. The supported identity selectors are
   `global`, `anonymous`, `authenticated`, `user`, `team`, `organization`, and `subject`.
2. `capabilities` contains `s3` or the narrower `s3:<authorization-operation>`.
3. `projects` is empty, contains `*`, or contains the exact requested project.
4. `s3_operations` is empty, contains `*`, or contains the authorization operation.

The first authorization operation with a successful match wins. All grants matching that same
operation must resolve to one route: their explicit `s3_route`, or `default_route` when it is
empty. If they select different routes, the broker rejects the request as ambiguous. The rendered
prefixes of the matching grants are combined, and only then does the pre-sign service verify that
the logical `key` is within an allowed prefix.

Consequently, `s3_prefixes` constrains access after route selection; it is not a route selector.
The same principal, project, and authorization operation cannot be routed differently based only
on the key. Similarly, giving one principal `write` on `primary` and `publish` on `public` does not
make a `put` choose by key: `write` is tried first. Use distinct projects or identities when the
same HTTP operation must reach different routes.

### Internal and publication storage

For example, `primary` can hold internal project objects while `public` holds publication
artifacts. The route named `public` is still private broker configuration; anonymous access is a
separate grant decision.

An internal team can receive this grant:

```json
{
  "id": "project-internal",
  "name": "Internal project files",
  "access": "team",
  "principal": "engineering",
  "capabilities": ["hub", "s3"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
  "s3_operations": ["read", "write", "delete"],
  "s3_route": "primary",
  "s3_prefixes": ["v2/projects/{project}/internal"]
}
```

A separate local-user or OIDC identity used by a publication service can receive:

```json
{
  "id": "project-publisher",
  "name": "Project publication service",
  "access": "subject",
  "principal": "publisher-service",
  "capabilities": ["s3:publish"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
  "s3_operations": ["publish"],
  "s3_route": "public",
  "s3_prefixes": ["v2/projects/{project}/published"]
}
```

Because the publication identity does not also match the internal `write` grant, a `put` falls
through from `write` to `publish` and selects `public`. To allow unauthenticated reads of the
published objects while the bucket itself remains private, add a third grant:

```json
{
  "id": "project-public-read",
  "name": "Public project publications",
  "access": "anonymous",
  "capabilities": ["s3:read"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
  "s3_operations": ["read"],
  "s3_route": "public",
  "s3_prefixes": ["v2/projects/{project}/published"]
}
```

Anonymous callers receive only a short-lived pre-signed request; they never receive the route's
access key or secret.

### Staging and production routes

Routes can also represent `staging` and `production` storage. Within one broker, distinguish the
environments using exact project IDs, distinct principals, or preferably both:

```json
{
  "id": "staging-storage",
  "access": "subject",
  "principal": "ci-staging",
  "capabilities": ["s3"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
  "s3_operations": ["read", "write", "delete"],
  "s3_route": "staging",
  "s3_prefixes": ["v2/projects/{project}"]
}
```

```json
{
  "id": "production-storage",
  "access": "subject",
  "principal": "ci-production",
  "capabilities": ["s3"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAW"],
  "s3_operations": ["read", "write", "delete"],
  "s3_route": "production",
  "s3_prefixes": ["v2/projects/{project}"]
}
```

There is no generic client-supplied `environment` selector. OIDC audience and scope are validated
during authentication but are not independent grant selectors. Custom identity distinctions must
be represented by the supported subject, username, organization, or team attributes. If the same
principal sends the same operation for the same project, the broker has no additional environment
signal with which to choose between staging and production.

## Recommended project grant

For a team that must discover and use one project, grant both `hub` and `s3` for that exact
project. `hub` makes the project visible through `graphit-hub-access-v1`; `s3` permits the
subsequent metadata/content pre-signs.

```bash
curl -X POST https://broker.example/admin/api/v1/grants \
  -H 'Authorization: Bearer ADMIN_ID_TOKEN' \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "1"' \
  --data '{
    "id":"platform-project",
    "name":"Platform team project",
    "access":"team",
    "principal":"platform",
    "capabilities":["hub","s3"],
    "projects":["01ARZ3NDEKTSV4RRFFQ69G5FAV"],
    "s3_operations":["read"],
    "s3_route":"primary",
    "s3_prefixes":["v2/projects/{project}"]
  }'
```

Use the ETag from `GET /admin/api/v1/grants`; replace the illustrative tokens and IDs locally.

## Anonymous access

Anonymous clients omit `Authorization`. A grant must explicitly use `access: anonymous`.
Prefer exact projects, read-only S3 operations, and a dedicated storage route/prefix. A
`global` grant applies to anonymous and authenticated callers, so use it only for intentionally
public capability access.

## Authorization revisions

Every successful create, update, or delete increments one database revision in the same
transaction as the grant rows. Discovery and Hub/S3 responses expose this revision. Graphit
re-discovers and requires a consistent revision during an operation; a concurrent policy change
fails closed and the next request retries against the new state.

## Source-of-truth boundary

When Graphit selects a provider whose broker advertises `graphit-hub-access-v1`, this SQL grant
database is the only Hub ACL authority. Graphit never reads or falls back to S3 `projects.json`
grant documents. Providers without that capability continue to use their canonical
`projects.json` documents outside the broker. There is no synchronization or migration between
the two modes.
