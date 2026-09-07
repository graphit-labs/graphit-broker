# Administration

The administration control plane is served at `/admin/`. It manages every mutable broker
function: consumer authentication, administration OIDC, AI routes/caches, S3 routes, resource
grants, administrative roles, and role assignments.

## Bootstrap OIDC client

Register a confidential OIDC web application:

- exact redirect URI: `https://BROKER/admin/auth/callback`;
- authorization-code flow;
- scopes `openid profile email` (or equivalent);
- a client secret delivered to the broker as a secret;
- HTTPS except for deliberate loopback development.

Set `BROKER_SUPERADMIN_SUBJECT` to the exact immutable `sub` of the first administrator. On an
empty role-assignment table only this subject can sign in. The superadmin bypass is evaluated from
the deployment value on every request and cannot be changed by restoring/editing database state.

The browser login uses state, nonce, PKCE, a short-lived database flow record, and a secure
`HttpOnly`, `SameSite=Lax` session cookie. State-changing cookie requests also require the
per-session `X-CSRF-Token`.

## UI

The UI has three sections:

1. **Configuration** edits strict redacted YAML. Existing secrets appear as
   `[configured-secret]`; leave the marker to retain, replace it to rotate, or clear it to
   remove. Database driver/DSN and bootstrap superadmin remain deployment-owned.
2. **Resource grants** performs immediate create/update/delete operations. Every form submission
   includes the displayed ACL revision; a concurrent edit is rejected and must be reloaded.
3. **Roles & users** creates action-based roles and assigns them to exact OIDC `sub` values.

The built-in `admin` role always has every currently supported action and cannot be deleted.
Custom roles may contain `session.read`, `configuration.read`,
`configuration.write`, `grants.read`, `grants.write`, `roles.read`,
`roles.write`, or `*`.

Administrative roles do not grant consumer access. A person may administer grants while having no
Hub/S3/AI grant, or consume services while having no administration role.

## Grant API workflow

Read the current document and ETag:

```bash
curl -i https://broker.example/admin/api/v1/grants \
  -H 'Authorization: Bearer ADMIN_ID_TOKEN'
```

Create with that revision:

```bash
curl -i -X POST https://broker.example/admin/api/v1/grants \
  -H 'Authorization: Bearer ADMIN_ID_TOKEN' \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "1"' \
  --data '{"id":"team-project","name":"Team project","access":"team","principal":"platform","capabilities":["hub","s3"],"projects":["01ARZ3NDEKTSV4RRFFQ69G5FAV"],"s3_operations":["read"],"s3_route":"primary"}'
```

Use the returned ETag for the next update or delete:

```bash
curl -X PUT https://broker.example/admin/api/v1/grants/team-project \
  -H 'Authorization: Bearer ADMIN_ID_TOKEN' \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "2"' \
  --data '{"id":"ignored","name":"Team project read/write","access":"team","principal":"platform","capabilities":["hub","s3"],"projects":["01ARZ3NDEKTSV4RRFFQ69G5FAV"],"s3_operations":["read","write"],"s3_route":"primary"}'

curl -X DELETE https://broker.example/admin/api/v1/grants/team-project \
  -H 'Authorization: Bearer ADMIN_ID_TOKEN' \
  -H 'If-Match: "3"'
```

The path ID is authoritative for update. Every operation is one SQL transaction: revision compare,
normalized child-row changes, and revision increment commit together. A stale ETag returns
`409 Conflict`; there is no last-write-wins behavior.

## Configuration activation

`GET /admin/api/v1/config` returns redacted YAML and a configuration ETag. `PUT` requires
`If-Match`. The server validates and constructs the complete replacement runtime before
committing SQL, then atomically switches new requests to it. Database bootstrap fields are ignored
from submitted YAML and restored from deployment configuration.

Changing an upstream AI effective model requires a new immutable revision; local catalog models
append their computed effective identity automatically. Changing OIDC issuer/audience
affects subsequent consumer validation. S3 route changes must remain compatible with existing
resource grants.

## Role assignment

Assignments use the exact administration token `sub`, not email or display name. On successful
login the server checks `session.read`; every API call then checks its own action. Revocation
takes effect on the next request. If no assignment rows exist, the superadmin is still the only
administrator; once assignments exist, the deployment superadmin continues to retain emergency
access.

## Recovery

If all ordinary admin assignments are incorrect, fix `BROKER_SUPERADMIN_SUBJECT` in the
deployment and restart. If the database schema is incompatible, restore a backup for the exact
build or recreate an empty database and bootstrap again. No migration or legacy ACL import is
performed.
