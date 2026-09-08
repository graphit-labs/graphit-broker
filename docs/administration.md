# Administration

The administration control plane is served at `/admin/`. It shows deployment configuration as a
redacted read-only document and manages SQL-backed resource grants, administrative roles, and role
assignments. Consumer authentication, OIDC, AI, and S3 configuration change only by deployment and
restart.

## Bootstrap OIDC client

For OIDC login, register a confidential OIDC web application:

- exact redirect URI: `https://BROKER/admin/auth/callback`;
- authorization-code flow;
- scopes `openid profile email` (or equivalent);
- a client secret delivered to the broker as a secret;
- HTTPS except for deliberate loopback development.

There is no special superadmin subject. For a new database, configure a local Argon2id identity
with `roles: [admin]`; its role is authoritative and allows the first login before SQL assignments
exist. A local-only deployment may omit `administration.oidc`.

Inject a pepper of at least 32 bytes and generate the verifier with
`graphit-broker --hash-password --password-pepper-env BROKER_FIRST_ADMIN_PASSWORD_PEPPER`. For
unattended provisioning, use `--hash-password-stdin` with the same pepper-env flag and a
secret-manager command or mounted secret file; never pass the plaintext password in an argument or
environment variable. Then configure the first user:

```bash
# BROKER_FIRST_ADMIN_PASSWORD_PEPPER is injected by the deployment/secret manager.
graphit-broker --hash-password \
  --password-pepper-env BROKER_FIRST_ADMIN_PASSWORD_PEPPER

cat /run/secrets/broker-first-admin-password | graphit-broker --hash-password-stdin \
  --password-pepper-env BROKER_FIRST_ADMIN_PASSWORD_PEPPER
```

Both forms receive the password and the pepper, but through separate sensitive channels. Their
stdout is exactly the PHC assigned to `BROKER_FIRST_ADMIN_PASSWORD_HASH`; it contains neither input.

```yaml
authentication:
  api_keys:
    - username: first-admin
      password_hash: "${BROKER_FIRST_ADMIN_PASSWORD_HASH:?required}"
      pepper: "${BROKER_FIRST_ADMIN_PASSWORD_PEPPER:?at least 32 bytes}"
      subject: first-admin
      roles: [admin]
administration:
  enabled: true
  token_pepper: "${BROKER_ADMIN_TOKEN_PEPPER:?at least 32 random bytes}"
```

After logging in, assign the normal OIDC subjects/roles. The deployment may then remove or narrow
the first local administrator and restart. A literal `pepper` value is accepted, but keeping it in
the same file as `password_hash` removes the protection gained when only that file leaks. Pepper
loss or rotation requires regenerating `password_hash` with the new value. Changing username,
password hash, pepper, or configured roles invalidates existing local UI sessions after restart.

The browser OIDC login uses state, nonce, PKCE, and a short-lived database flow record. Local login
accepts the configured username and plaintext password once and validates it against the peppered
Argon2id verifier. Both flows issue a secure `HttpOnly`, `SameSite=Lax` session cookie; the password
is not persisted by the UI. State-changing cookie requests also require the per-session
`X-CSRF-Token`.

## UI

The UI has four sections, shown according to the signed-in subject's permissions:

1. **Projects** lists the exact projects available through the subject's current Hub grants and
   provides copyable `graphit provider add` and `graphit login` commands tailored to the current
   OIDC or API-key session. A wildcard grant is shown as access to all projects because project
   metadata is resolved by Graphit Hub after CLI login.
2. **Configuration** shows strict redacted YAML read-only. Change `config.yml`/secret injection and
   restart the deployment to apply configuration changes.
3. **Resource grants** performs immediate create/update/delete operations. Every form submission
   includes the displayed ACL revision; a concurrent edit is rejected and must be reloaded.
4. **Roles & users** creates action-based roles and assigns them to exact OIDC `sub` or API-key
   `subject` values.

The built-in `admin` role always has every currently supported action. The built-in `user` role
has only `session.read` and `projects.read`. Neither built-in role can be deleted. Assign `user` to
an exact OIDC `sub` or `authentication.api_keys[].subject` to let that identity enter the UI without
exposing any administrative screen.
Custom roles may contain `session.read`, `configuration.read`,
`grants.read`, `grants.write`, `roles.read`,
`roles.write`, `projects.read`, or `*`.

OIDC roles can instead come from `administration.oidc.role_claim`. If that selector is configured,
it must produce at least one string and the claimed roles are authoritative for the session: the
broker ignores all local `role_assignments` for that OIDC `sub`, including assignments that would
grant more access. A claimed `user` therefore overrides a local `admin`, and a claimed `admin`
overrides a local `user`. Claimed names resolve through the same database role definitions, so an
unknown name has no permissions. Local identities with configured `roles` use those roles
authoritatively; identities without them use database assignments.

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

`GET /admin/api/v1/config` returns a redacted, `Cache-Control: no-store` view of the effective
deployment configuration. There is no `PUT` route. Change `config.yml` and its environment/secret
inputs, then restart the broker. Changing an upstream AI effective model still requires a new
immutable revision, and S3 route changes must remain compatible with existing resource grants.

## Role assignment

Assignments use the exact administration token `sub`, not email or display name. On successful
login the server checks `session.read`; every API call then checks its own action. Revocation
takes effect on the next request for database-backed identities. When `role_claim` is configured,
local assignments for OIDC users remain visible/manageable but do not participate in their
authorization. Claim roles are captured in the browser session and refresh at the next login;
direct bearer requests evaluate the current token. If a deployment enables `role_claim`, older
sessions without captured claim roles are rejected and must sign in again. When no assignment rows
exist, access still works for a local identity with configured `roles` or an OIDC token whose
authoritative `role_claim` resolves to a defined role.

## Recovery

If all ordinary admin assignments are incorrect, temporarily add or restore a local identity with
`roles: [admin]` in deployment configuration and restart. If the database schema is incompatible,
restore a backup for the exact build or recreate an empty database and bootstrap again. No
migration or legacy ACL import is performed.
