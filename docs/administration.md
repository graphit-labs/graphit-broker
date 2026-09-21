# Administration

The control plane is served at `/admin/`. It uses the same authentication model as every broker
consumer: any configured OIDC issuer mapping or a SQL-backed local user. Administration is an RBAC
decision, not a separate identity provider. Deployment configuration remains read-only; local
users, roles, assignments, and resource grants are mutable SQL state.

## Unified OIDC login

Configure browser clients on one or more `authentication.oidc` entries. Each entry supplies issuer,
subject, username, organization, teams, and role mappings for bearer validation and browser login,
and its `display_name` labels the corresponding button on the login screen.
Register the exact redirect URI `https://BROKER/oauth/oidc/callback`, authorization-code flow,
PKCE-capable endpoints, the selected scopes, and a confidential client secret. HTTP callbacks are
accepted only on loopback.

There is no `administration.oidc`. The `administration` section contains only control-plane options:

```yaml
authentication:
  token_pepper: "${BROKER_AUTH_TOKEN_PEPPER:?at least 32 random bytes}"
  local:
    rate_limit:
      max_failures: 5
      window: 1m
      lockout: 5m
      max_concurrent: 2
      saturation_multiplier: 4
    captcha:
      enabled: false
      provider: turnstile # or recaptcha
      site_key: "${BROKER_LOCAL_CAPTCHA_SITE_KEY}"
      secret_key: "${BROKER_LOCAL_CAPTCHA_SECRET_KEY}"
      trigger_multiplier: 1.5
      verification_timeout: 3s
    mfa:
      required: true
      issuer: Graphit Broker
      challenge_ttl: 10m
    login:
      enabled: true
    tokens:
      audience: graphit-broker
      cli_client_id: graphit-cli
      cli_redirect_path: /oauth/callback
      access_ttl: 10m
      refresh_ttl: 720h
  oidc:
    - enabled: true
      display_name: Corporate SSO
      issuer: https://identity.example.com
      audiences: [graphit-broker]
      required_scopes: []
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

When adaptive CAPTCHA is enabled, the local credential panel renders the selected Cloudflare
Turnstile or Google reCAPTCHA v2 Checkbox widget only when the per-process authentication admission
reaches its configured threshold. A request that crosses the threshold receives
`captcha_required`, clears the submitted password, and must be retried with a new provider proof.
The threshold uses `max(1, ceil(max_concurrent * trigger_multiplier))`: omitting the multiplier uses
`1.5`, while explicitly setting `0` keeps the widget active from the first login attempt.
The password-change and MFA panels do not render CAPTCHA. Provider timeouts fail local login closed
while the threshold remains reached; organization OIDC login is independent and remains usable.

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

## Graphit Code OpenID Connect

Local passwords and upstream IdP tokens are never passed to [Graphit Code](https://github.com/graphit-labs/graphit-code) as Bearer credentials.
A desktop client first reads `/.well-known/graphit-broker`, then uses the Broker's standard
`/.well-known/openid-configuration`, authorization, token, JWKS, userinfo, and revocation endpoints.
The protocol implementation is provided by `github.com/zitadel/oidc/v3`; the Broker-owned page
offers local login and one named choice per available upstream OIDC provider. The Broker completes
either method and returns signed ID/access JWTs plus an opaque rotating refresh token. Graphit Code
never needs the upstream issuer or client secret. If exactly one upstream OIDC provider is enabled and
local login is disabled, the choice page is skipped and the browser is redirected automatically.
The broker
requires PKCE S256, the configured public client ID, an exact callback path, and an explicit
`127.0.0.1` or `::1` port. A headless CLI starts at `POST /oauth/device/authorize`, shows the returned
user code, and polls `/oauth/token` only after the user approves it locally at `/oauth/device`.

ID and access tokens use EdDSA and are verified through `/oauth/keys`; `sub` is stable and distinct from
`preferred_username`. Access tokens default to ten minutes and use the configured Broker audience.
Requesting `offline_access` also returns a rotating refresh
token. Reuse of an already rotated refresh token revokes the whole token family. Clients revoke a
token at `POST /oauth/revoke`. Revocation takes effect immediately at Broker endpoints, while an
offline JWKS validator accepts an access JWT already issued until `exp`. Browser/device login
security—temporary-password replacement, TOTP
enrollment/verification, MFA reset and adaptive CAPTCHA—remains enforced before authorization.

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


## Console navigation and visual identity

The Broker shares Graphit Code and the public site's cobalt/navy identity. Its internal workspaces start with the operator's decision: find the resource, inspect its authoritative state, then enter a dedicated change flow. Navigation exposes only sections allowed by the current session. Read permission permits inspection; write permission exposes mutation actions. Backend authorization remains authoritative.

### Find and connect a project

Open **Projects**, search an exact project identifier or capability, then select a project to inspect its access dossier. The list reports only identifiers and capabilities returned by the Broker. It does not imply project health, activity or ownership. A project or role removed from a refreshed directory also clears its old inspector; a new sign-in clears prior selections. An all-projects grant is shown explicitly, even when no exact identifiers are listed. Copy the Broker-provided connection commands from the inspector; Graphit Hub resolves project metadata after login.

### Compose resource access

Open **Resource grants** to search the policy by audience, identifier or capability. Select a grant name for read-only inspection. With write permission, choose **Compose grant** or **Edit**:

1. **Audience:** set the stable grant ID, display name and verified identity attribute. The ID is immutable when editing.
2. **Resources:** choose capabilities and exact project ULIDs. A blank project list means all projects.
3. **Storage:** review operation, route and prefix constraints when an S3 capability is present.
4. **Review:** inspect the complete scope, then explicitly create or update the grant.

The draft summary follows the selected audience and resources. No access simulation is implied. Rules are additive; unmatched requests are denied. Writes send the current policy ETag with `If-Match`. A revision conflict leaves the draft available for review; refresh the policy and reconcile before retrying. Deletion requires a separate confirmation describing its immediate effect.

### Inspect and maintain identities

**Local users** is a searchable directory with People, Services, Disabled and MFA-pending filters. **Open profile** shows stable identity, membership, authentication state and revision before exposing permitted actions. **Edit identity** opens a dedicated editor with Identity, Membership and Authentication sections. Subject and kind stay immutable; username may change. Human passwords require at least 15 characters. An empty password while editing retains the current password; services have no password or MFA fields.

A service profile opens its credential inventory. Creation shows the token once; copy it before dismissing or closing the inventory. The secret is cleared from the displayed inventory on dismissal, identity change or change of service. Delayed credential responses cannot reopen a closed inventory or display a token under another service. Credential scopes are metadata, not resource authorization. Revocation, identity deletion and MFA reset retain explicit confirmation and backend last-administrator protections.

### Define responsibility, then assign it

**Roles** separates **Role definitions** from **Identity assignments**. Select a definition to inspect its permission bundle. Built-in roles are read only. The custom-role editor groups the Broker's allowed-action catalog by domain, provides action search, and shows the selected count. An existing role name is immutable in this editor; use **Define role** to create another definition.

Assignments require an explicit role selection and canonical `issuer|subject`. **Assign this role** transfers the inspected role into the assignment form. Configured IdP role claims take precedence over database assignments. Resource grants remain independent from administration roles.

### Read effective configuration

**Configuration** provides a section index, text search, refresh and copy for the complete redacted YAML. It is read only. Search reports the count and first matching line; section buttons select the corresponding location. To change deployment configuration, edit `config.yml` or environment-provided secrets and restart the Broker.

### Authenticate one step at a time

The administration sign-in surface displays the current local-authentication step. Once password replacement, MFA or recovery is required, organization-method choices are hidden until the active challenge completes. OAuth and device authorization use a centered transaction surface with Identify → Verify → Connect context. Only the server-selected form is submitted; required password, MFA, recovery, CAPTCHA and device states are preserved. Recovery codes remain visible until the user explicitly continues. A fatal or expired request renders restart guidance without credential fields.

OAuth forms preserve the original request URL and challenge fields. The authentication template needs no inline application JavaScript and retains its strict CSP; configured CAPTCHA scripts are the only permitted providers. A single upstream OIDC provider with local login disabled still redirects automatically.

The console supports light/dark themes and mobile navigation with focus containment. Wide policy and credential tables scroll within their own surfaces; editors and inspectors stack on small screens. The standalone authentication template is light-only. System-font fallbacks require no external font request.

The canonical [Graphit design system](https://github.com/graphit-labs/graphit-code/blob/main/docs/specs/design_system.md) documents shared principles, tokens, page patterns, responsive behavior and evolution checks. The implementation owners are `internal/broker/adminui/index.html` and `internal/broker/oauthui/index.html`; API/security contracts remain covered by `admin_test.go` and `oauth_test.go`. Use the reference revision corresponding to the implementation under review.
