# Resource authorization

Resource grants are the sole project-capability authorization source for consumer operations.
They live in normalized SQL tables and are independent from system RBAC roles. The broker
loads current grants for every consequential request, so a committed change applies to the next
Hub resolution, S3 credential issuance, embedding, or rerank request.

## Identity

The broker derives the principal from exactly one source:

- no `Authorization` header: anonymous principal;
- a local access or service token: its domain-separated HMAC, audience,
  expiry/revocation state, and owning SQL identity revision are validated before current
  subject/username/organization/teams are loaded;
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

## How S3 grants become an STS policy

`POST /v1/s3/credentials` requires an authenticated bearer and accepts exactly one framework-selected
scope: `project` with an immutable project ULID, `user`, or `hub`. Identity comes only from the
verified principal and authorization comes only from the current SQL grant snapshot. A client
cannot submit an operation, prefix, route, role, bucket, endpoint, duration, or policy; the project
ID only selects the resource whose grants must be evaluated.

For each matching rule, the broker includes an authorization operation when `capabilities` contains
`s3` or `s3:<operation>` and `s3_operations` is empty, contains `*`, or contains that operation.
Projects select whether a rule contributes to the requested scope. An omitted project list means
every project. The broker fixes the maximum logical roots to `v2/projects/<project>` for project
scope, `v2/users/<verified-username>/memory` for user scope, and `v2/registry` plus
`v2/global/rules` for Hub scope. Explicit prefix templates are rendered and intersected with those
roots, so even a template such as `v2` cannot enlarge the credential. User and Hub scopes require
an omitted, `*`, or `global` project selector; Hub scope additionally requires an effective `hub`
capability, which may come from a separate matching rule.

All matching S3 rules for the requested scope are additive and must select one route. An explicit `s3_route` selects it;
an empty value uses `default_route`. If the same principal matches rules for different routes, the
request fails closed because one credential response contains one bucket, region, and endpoint.
Different project scopes may select different routes and therefore different storage topologies.

The broker joins every logical prefix to the route's physical `base_prefix` and maps permissions to
AWS/MinIO actions:

| Grant operation | Session actions |
|---|---|
| `read` | prefix-constrained `ListBucket`, `GetObject` (including HEAD and Range GET) |
| `write` | read actions plus `PutObject` and multipart upload actions |
| `publish` | write actions plus `DeleteObject` |
| `delete` | `DeleteObject` only |

`GetBucketLocation` is limited to the selected bucket. Object resources and list-prefix conditions
carry the rendered paths. The broker passes the resulting JSON as an inline `AssumeRole` session
policy, so effective permissions are the intersection of the route role/user policy and current
Graphit grants. AWS STS limits that inline policy to 2048 bytes; the broker groups equal action sets
but rejects a larger result rather than dropping restrictions.

The response exposes the selected topology and one physical root prefix so Graphit can use S3,
LanceDB, and Ladybug directly. It never exposes the broker's permanent signing credentials. A new
call relays the latest authorization revision and mints a new session. Already issued credentials
retain their bounded session policy until their short expiry or storage-side revocation.

A route using the `filesystem` driver resolves grants identically and enforces the same table
itself, because the broker is the storage. The session it mints carries the rendered prefixes, and
every gateway request is checked against them: a read needs `read`, `write`, or `publish` on the
key; a write needs `write` or `publish`; a delete needs `publish` or `delete`; and a listing is
refused unless its requested prefix lies within a granted one, which is what the STS policy
expresses as a condition on `s3:prefix`. There is no inline-policy size limit on that driver, and a
session expires rather than being revocable, exactly as an STS session does.

### Internal and publication storage

A team that reads and updates internal project data can receive:

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

A publication service may instead receive `s3:publish` for its publication prefix. If it must use a
different bucket or account, give it a distinct principal so its complete matching grant set still
selects one route.

## Recommended project grant

For a team that must discover and use one project, grant both `hub` and `s3` for that exact
project. `hub` makes the project visible through `graphit-hub-access-v1`; `s3` permits the
subsequent direct S3 access through a restricted STS session.

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

Hub discovery and AI capabilities may still use explicit `anonymous` grants. Temporary S3
credentials are never issued to anonymous callers. Public object delivery must use an independently
public bucket or CDN policy instead of the broker credential endpoint.

## Authorization revisions

Every successful create, update, or delete increments one database revision in the same
transaction as the grant rows. Discovery and Hub/S3 responses expose this revision. Graphit keeps
the revision with each in-memory credential session and requests a new session before expiry.
A subsequent issuance always uses the latest committed grants; an already issued STS session remains
bounded by its original policy until expiry or storage-side revocation.

## Source-of-truth boundary

When Graphit selects a provider whose broker advertises `graphit-hub-access-v1`, this SQL grant
database is the only Hub ACL authority. Graphit never reads or falls back to S3 `projects.json`
grant documents. Providers without that capability continue to use their canonical
`projects.json` documents outside the broker. There is no synchronization or migration between
the two modes.
