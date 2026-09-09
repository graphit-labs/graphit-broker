# Administration

The control plane is served at `/admin/`. It uses the same authentication model as every broker
consumer: one configured OIDC issuer mapping or a SQL-backed local user. Administration is an RBAC
decision, not a separate identity provider. Deployment configuration remains read-only; local
users, roles, assignments, and resource grants are mutable SQL state.

## Unified OIDC login

Configure the browser client on one `authentication.oidc` entry. That same entry supplies issuer,
subject, username, organization, teams, and role mappings for bearer validation and browser login.
Register the exact redirect URI `https://BROKER/oauth/oidc/callback`, authorization-code flow,
PKCE-capable endpoints, the selected scopes, and a confidential client secret. HTTP callbacks are
accepted only on loopback.

There is no `administration.oidc`. The `administration` section contains only control-plane options:

```yaml
authentication:
  token_pepper: "${BROKER_AUTH_TOKEN_PEPPER:?at least 32 random bytes}"
  local_rate_limit:
    max_failures: 5
    window: 1m
    lockout: 5m
    max_concurrent: 2
    saturation_multiplier: 4
  local_mfa:
    required: true
    issuer: Graphit Broker
    challenge_ttl: 10m
  local_login:
    enabled: true
  local_tokens:
    audience: graphit-broker
    cli_client_id: graphit-cli
    cli_redirect_path: /oauth/callback
    access_ttl: 10m
    refresh_ttl: 720h
  oidc:
    - issuer: https://identity.example.com
      audiences: [graphit-broker]
      required_scopes: [graphit.use]
      client_id: graphit-broker
      client_secret: "${BROKER_OIDC_CLIENT_SECRET:?required}"
      redirect_url: https://broker.example.com/oauth/oidc/callback
      subject_claim: sub
      username_claim: preferred_username
      role_claim: "$.realm_access.roles[*]"
administration:
  enabled: true
  session_ttl: 8h
  cookie_secure: true
```

The browser flow uses state, nonce, PKCE, a browser-only 256-bit binding cookie, and a short-lived
SQL flow record containing only HMACs of state and binding. A callback from another browser fails
without consuming the original flow. OIDC and local login both issue `HttpOnly`, `SameSite=Lax`
session cookies. They are `Secure` by default; only an explicit
`administration.cookie_secure: false` disables that attribute for loopback HTTP development.
State-changing cookie requests require the per-session `X-CSRF-Token`. Direct bearer requests use
the normal broker authenticator and do not need CSRF.

## First local administrator

There is no superadmin bypass and no local user in `config.yml`. On an empty database, set
`authentication.token_pepper` and run:

```bash
graphit-broker --config config.yaml --bootstrap-admin
```

The terminal form reads and confirms the password without echo. Automation must pass the password
only through the explicit stdin form:

```bash
cat /run/secrets/broker-first-admin-password | \
  graphit-broker --config config.yaml --bootstrap-admin-stdin
```

Both commands accept only a password containing at least 15 Unicode characters. The supplied
password is temporary and must be replaced at the first login. They create the fixed local username and subject `admin`,
persist only its peppered Argon2id PHC, assign the `admin` role, and refuse to run when any local
user already exists. The pepper remains solely in deployment configuration. There is deliberately
no migration or compatibility path in this development version; recreate an incompatible database
before bootstrapping.

## UI

The UI shows sections according to effective role permissions:

1. **Projects** lists projects allowed by current resource grants and renders Graphit CLI commands.
2. **Configuration** shows the redacted deployment YAML read-only.
3. **Resource grants** manages the deny-by-default project capability policy with revision fencing.
4. **Local users** manages human identities and passwordless service identities, including
   forced password change, administrative MFA reset, and one-time display, listing, and revocation
   of service credentials.
5. **Roles** manages role definitions and assignments to canonical `issuer|subject` identities.

User responses never contain password PHCs or the deployment pepper. Subject is immutable; username
is the login selector and may be renamed without changing authorization identity. Password,
username, attribute, enabled-state, or deletion changes invalidate an existing local browser
session through the persisted user revision. Role changes are read from SQL on the next request.
The last explicitly assigned administrator cannot be demoted or deleted accidentally.

## System-wide RBAC

Every authenticated OIDC or local principal receives the built-in `user` role. It grants
`session.read` and `projects.read`. The built-in `admin` role contains every supported system action,
including configuration/grant/role/local-user management. Built-in roles cannot be deleted or
redefined to broader/narrower permissions; custom roles select from the same action catalogue.

SQL assignments use the canonical identity `issuer|subject`, never username or email. For local
users the issuer is `local`, for example `local|admin`. When an OIDC `role_claim` is configured, its
additional roles are authoritative instead of SQL assignments; the default `user` role still
applies. An unknown role grants no permission. Without `role_claim`, SQL assignment changes take
effect on the next request.

RBAC actions do not themselves grant project or S3/AI access. Resource grants independently match
the verified principal's subject, username, organization, or teams.

## Local-user API

- `GET /admin/api/v1/local-users`
- `POST /admin/api/v1/local-users`
- `PUT /admin/api/v1/local-users/{username}`
- `DELETE /admin/api/v1/local-users/{username}`
- `POST /admin/api/v1/local-users/{username}/mfa/reset`

Create requires `username`, immutable `subject`, and `kind`. `kind: human` requires `password`;
`kind: service` rejects passwords. Attributes, `roles`, and `enabled` are optional. Update is a
complete identity-attribute replacement with an optional password for human identities (empty
keeps the current verifier). Every password supplied at create/bootstrap or by an administrator is
temporary. Set `password_change_required: true` to force another change at the next login without
replacing the password. The flag cannot be cleared administratively: only a successful password
change by that user clears it. The API hashes password input immediately with
`authentication.token_pepper` and never returns it. New passwords require at least 15 Unicode
characters and have no character-class composition rules.

MFA is required for human local users by default. On first login, the UI displays a QR code and
manual `otpauth://` secret compatible with Google Authenticator and other TOTP applications. Login
continues only after the first six-digit code is confirmed. Ten one-time recovery codes are then
shown once. Reset MFA only when recovering a user who lost the factor: it deletes the old TOTP
secret and recovery codes, increments the identity revision, revokes active local tokens and login
flows, and forces a new enrollment at the next login. Service identities do not use MFA.

Service credentials are managed at:

- `GET/POST /admin/api/v1/local-users/{username}/credentials`;
- `DELETE /admin/api/v1/local-users/{username}/credentials/{credential}`.

The raw `gb_sc_...` credential appears only in the successful create response. SQL stores only its
domain-separated HMAC plus metadata, expiry, revocation, and last-use timestamps. Updating,
disabling, or deleting the service identity invalidates all credentials through its revision.

## Graphit Code authorization

Local passwords and upstream IdP tokens are never passed to Graphit Code as Bearer credentials.
A desktop client discovers the authorization URL, opens the Broker-owned
`GET/POST /oauth/authorize` page, and exchanges the one-time code at `POST /oauth/token`. That page
offers local and OIDC login only when each method is configured and available. The Broker completes
either method and issues its own opaque tokens; Graphit Code never needs the upstream issuer or
client secret. The broker
requires PKCE S256, the configured public client ID, an exact callback path, and an explicit
`127.0.0.1` or `::1` port. A headless CLI starts at `POST /oauth/device/authorize`, shows the returned
user code, and polls `/oauth/token` only after the user approves it locally at `/oauth/device`.

Access tokens default to ten minutes. Requesting `offline_access` also returns a rotating refresh
token. Reuse of an already rotated refresh token revokes the whole token family. Clients revoke a
token at `POST /oauth/revoke`. All these endpoints use form-encoded OAuth parameters, and discovery
is published at `/.well-known/oauth-authorization-server`.

## Grant API workflow

Read the current grant document and ETag, then include that ETag in every mutation:

```bash
curl -i https://broker.example/admin/api/v1/grants \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN'

curl -i -X POST https://broker.example/admin/api/v1/grants \
  -H 'Authorization: Bearer ADMIN_ACCESS_TOKEN' \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "1"' \
  --data '{"id":"team-project","name":"Team project","access":"team","principal":"platform","capabilities":["hub","s3"],"projects":["01ARZ3NDEKTSV4RRFFQ69G5FAV"]}'
```

The revision comparison, normalized row changes, and increment commit in one transaction. A stale
ETag returns `409 Conflict`.

## Recovery

Protect the last administrator and retain encrypted SQL backups. If every administrator is lost,
restore a compatible backup or recreate the development database and run the bootstrap command.
The bootstrap command intentionally refuses to overwrite a non-empty local-user table.
