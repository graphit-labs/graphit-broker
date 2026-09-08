# Administration

The administration control plane is served at `/admin/`. It manages every mutable broker
function: consumer authentication, administration OIDC, AI routes/caches, S3 routes, resource
grants, administrative roles, and role assignments.

## Bootstrap OIDC client

For OIDC login, register a confidential OIDC web application:

- exact redirect URI: `https://BROKER/admin/auth/callback`;
- authorization-code flow;
- scopes `openid profile email` (or equivalent);
- a client secret delivered to the broker as a secret;
- HTTPS except for deliberate loopback development.

Set `BROKER_SUPERADMIN_SUBJECT` to the exact immutable OIDC `sub` or configured API-key `subject`
of the first administrator. On an empty role-assignment table only this subject can sign in. The
superadmin bypass is evaluated from the deployment value on every request and cannot be changed by
restoring/editing database state. A local-only deployment may omit `administration.oidc` when at
least one `authentication.api_keys` identity is configured.

The browser OIDC login uses state, nonce, PKCE, and a short-lived database flow record. Local login
accepts an existing `authentication.api_keys` token once and validates it with the normal consumer
authenticator. Both flows issue a secure `HttpOnly`, `SameSite=Lax` session cookie; the API key is
not persisted by the UI. State-changing cookie requests also require the per-session
`X-CSRF-Token`.

## UI

The UI has four sections, shown according to the signed-in subject's permissions:

1. **Projects** lists the exact projects available through the subject's current Hub grants and
   provides copyable `graphit provider add` and `graphit login` commands tailored to the current
   OIDC or API-key session. A wildcard grant is shown as access to all projects because project
   metadata is resolved by Graphit Hub after CLI login.
2. **Configuration** edits strict redacted YAML. Existing secrets appear as
   `[configured-secret]`; leave the marker to retain, replace it to rotate, or clear it to
   remove. Database driver/DSN and bootstrap superadmin remain deployment-owned.
3. **Resource grants** performs immediate create/update/delete operations. Every form submission
   includes the displayed ACL revision; a concurrent edit is rejected and must be reloaded.
4. **Roles & users** creates action-based roles and assigns them to exact OIDC `sub` or API-key
   `subject` values.

The built-in `admin` role always has every currently supported action. The built-in `user` role
has only `session.read` and `projects.read`. Neither built-in role can be deleted. Assign `user` to
an exact OIDC `sub` or `authentication.api_keys[].subject` to let that identity enter the UI without
exposing any administrative screen.
Custom roles may contain `session.read`, `configuration.read`,
`configuration.write`, `grants.read`, `grants.write`, `roles.read`,
`roles.write`, `projects.read`, or `*`.

OIDC roles can instead come from `administration.oidc.role_claim`. If that selector is configured,
it must produce at least one string and the claimed roles are authoritative for the session: the
broker ignores all local `role_assignments` for that OIDC `sub`, including assignments that would
grant more access. A claimed `user` therefore overrides a local `admin`, and a claimed `admin`
overrides a local `user`. Claimed names resolve through the same database role definitions, so an
unknown name has no permissions. The deployment superadmin bypass remains in force. API-key login
continues to use local assignments because API keys do not carry claims.

UI roles do not grant consumer access. The projects list is filtered independently through current
resource grants using the verified OIDC or API-key subject, username, organization, and teams. An
identity with the `user` role but no matching Hub grant sees an empty project list.

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
takes effect on the next request for database-backed identities. When `role_claim` is configured,
local assignments for OIDC users remain visible/manageable but do not participate in their
authorization. Claim roles are captured in the browser session and refresh at the next login;
direct bearer requests evaluate the current token. If a deployment enables `role_claim`, older
sessions without captured claim roles are rejected and must sign in again. If no assignment rows
exist, the superadmin is still the only database-backed administrator; the deployment superadmin
always retains emergency access.

## Recovery

If all ordinary admin assignments are incorrect, fix `BROKER_SUPERADMIN_SUBJECT` in the
deployment and restart. If the database schema is incompatible, restore a backup for the exact
build or recreate an empty database and bootstrap again. No migration or legacy ACL import is
performed.
