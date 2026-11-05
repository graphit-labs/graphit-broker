---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# Administration

The control plane is served at `/admin/`. It uses the same authentication model as every broker
consumer: any configured OIDC issuer mapping or a SQL-backed local user. Administration is an RBAC
decision, not a separate identity provider. Deployment configuration remains read-only; local
users, roles, assignments, and resource grants are mutable SQL state.

For the native PostgreSQL server, use the [native session reference](rust-admin-session-http.md)
and [LOCAL cookie reference](rust-admin-cookie-session.md). The [native administrative reads](rust-admin-read.md)
provide the caller's project catalog, roles, assignments, LOCAL users, principal hints,
grants with their ETag, and a redacted deployment view. Each read requires its own
current SQL action; `session.read` does not grant those actions. The session references cover current session reads,
the authenticated cookie producer and confirmed CSRF/logout. [Native HTTP password/MFA login](rust-admin-local-login.md)
adds genuine password/change/enrollment/TOTP/recovery→cookie steps. The
[native federated browser journey](rust-admin-upstream-login.md) serves the existing
workspace HTML and connects real upstream authentication to those reads. Native
[role and assignment mutations](rust-admin-rbac.md) are mounted for PostgreSQL, using their own current `roles.write` permission and cookie CSRF. [Resource-grant mutations](rust-admin-grants.md) are available in the native PostgreSQL and HTTP consumers. [LOCAL user/MFA/service-credential mutations](rust-admin-users.md) are mounted in their PostgreSQL and HTTP consumers. Use the native configuration
reference for every enabled section.

## The governance workspace

Start with the decision you need to make: **Local users** manages people and automation identities;
**Admin roles** governs administrative actions; **Project access** controls access to project capabilities;
**Projects** shows the current caller's authorized scope. Configuration is a read-only deployment view.

The older identities capture uses the former sidebar labels and is kept only as a historical
reference in [screenshot maintenance](screenshots.md). Use the current labels above when following
this guide.

## Agent instructions

**Operations → Agent instructions** manages Broker-wide Markdown overrides for
the Graphit agents. Create an override with the path relative to
`templates/agent-instructions/` in Graphit Code, for example
`skills/ast/entry.md` or `policy/mandates/task-coordinator.md`. The compiled
template can be included from `defaults/<path>` using the regular template
syntax.

Use **Save draft** to keep an inactive override, **Activate** to make it available
to clients, and **Publish changes** to update an active override. **Deactivate**
returns the entry to draft and removes it from clients on their next sync.
Graphit installations with this Broker active retrieve the active entries on
general sync or a specific native instruction sync. A project's rules, personal
rules and explicitly selected Hub artifacts retain priority over the Broker.

The administration view requires a cookie session with `configuration.read`
or administrator authority. Edits require the built-in `admin` role or wildcard
authority, a current CSRF token and the revision read from the server.
A stale revision returns HTTP 409. Refresh before retrying an edit. The sync
endpoint returns active templates to authenticated Graphit clients across
projects, so keep credentials and confidential project content out of them.

When administration cookies are enabled, the Broker stores the collection in
`agent-instructions.json` beside its deployment configuration by default.
Set `server.instruction_overrides_file` to use a file in a writable persistent
directory. Relative paths resolve from the configuration directory. Broker
replicas serving the same deployment should point at the same file on a volume
that supports atomic rename and file locking. Saving does not require a restart.

The administrative HTTP path is `/admin/api/v1/agent-instructions` (`GET`,
`PUT`). The PUT body uses the returned document shape
`{"revision":0,"templates":{"skills/ast/entry.md":{"enabled":false,"markdown":"..."}}}`.
Clients use `GET /v1/agent-instructions` with a Broker access bearer. The response
is `{"version":1,"templates":{"skills/ast/entry.md":"..."}}`. The collection is
limited to 512 KiB of JSON. Disabled entries are absent from that response.

Authentication and current edit permission are checked before the PUT body is
read. Loading and saving keep the editor and selection stable until the response
arrives; a response from a previous session cannot replace the current editor.
A failed load does not appear as an empty collection, and a revision conflict
preserves unsaved text so it can be copied before an explicit refresh. Invalid
persisted content is unavailable rather than silently published as an empty
bundle. [Testing boundaries](testing.md) distinguishes controller checks, real
HTTP authorization and interactive visual validation.

## Unified OIDC login

Configure explicit `browser_clients` on one or more native `auth.oidc` entries. Each entry supplies issuer,
subject, username, organization, teams, and role mappings for bearer validation and browser login,
and its `display_name` labels the corresponding button on the login screen.
For each browser client, `claims_source` selects the ID token (default), a verified JWT access token,
or userinfo as the source for those mappings; it does not change direct bearer validation.
Register the exact redirect URI `https://BROKER/oauth/oidc/callback`, authorization-code flow,
PKCE-capable endpoints, the selected scopes, and a confidential client secret. HTTP callbacks are
accepted only on loopback.

There is no `administration.oidc`. The `administration` section contains only control-plane options:

Use the complete [native server configuration](rust-broker-server.md#supply-configuration-and-key-files), [upstream browser policies](rust-admin-upstream-login.md), [LOCAL login policy](rust-admin-local-login.md) and [cookie transport bounds](rust-admin-cookie-session.md). These closed schemas require their explicit limits and enablement; an earlier authentication mapping is not accepted or imported.

The browser flow always uses state, PKCE, a browser-only 256-bit binding cookie, and a short-lived
SQL flow record containing only HMACs of state and binding. It sends and validates nonce by default;
an issuer with `require_nonce: false` omits only that optional protection. A callback from another
browser fails without consuming the original flow. OIDC and local login both issue `HttpOnly`,
`SameSite=Lax` session cookies. They are `Secure` by default; only an explicit
`administration.cookie_secure: false` disables that attribute for loopback HTTP development.
State-changing cookie requests require the per-session `X-CSRF-Token`. Direct bearer requests use
the normal broker authenticator and do not need CSRF.

After a bound administration callback, an upstream rejection, invalid identity, invalid saved
provider continuation, or missing administration permission returns the browser to the sign-in
screen with a fixed message.
The screen may show a request reference for log correlation, but never the provider error, token,
claim value, authorization code, or state. Callbacks whose state and browser binding cannot be
validated fail closed because there is no trusted administration or OAuth continuation to resume.

When adaptive CAPTCHA is enabled, the local credential panel renders the selected Cloudflare
Turnstile or Google reCAPTCHA v2 Checkbox widget only when the per-process authentication admission
reaches its configured threshold. A request that crosses the threshold receives
`captcha_required`, clears the submitted password, and must be retried with a new provider proof.
The threshold uses `max(1, ceil(max_concurrent * trigger_multiplier))`: omitting the multiplier uses
`1.5`, while explicitly setting `0` keeps the widget active from the first login attempt.
The password-change and MFA panels do not render CAPTCHA. Provider timeouts fail local login closed
while the threshold remains reached; organization OIDC login is independent and remains usable.

## First local administrator

The native Rust server creates its first local administrator through explicit stdin:

~~~text
cat /run/secrets/broker-first-admin-password | graphit-broker --config config.yaml --bootstrap-admin-stdin
~~~

Use the [native server configuration](rust-broker-server.md), including `auth.pepper`,
[LOCAL password and MFA policy](rust-admin-local-login.md), and enabled
[administrative cookie sessions](rust-admin-cookie-session.md). These features must already be
operational in the captured configuration; bootstrap does not enable them. Select PostgreSQL
or private SQLite explicitly. There is no local user in configuration or superadmin bypass.

Stdin must be a non-terminal stream ending at EOF. Supply one UTF-8 password containing at least
15 Unicode characters and at most 4096 bytes. Exactly one final LF, or CRLF, is removed; all other
bytes, including surrounding spaces, belong to the password. Invalid UTF-8, short or oversized
input fails before password workers or SQL are opened. Password input is never accepted as a
flag value or dedicated environment variable and never appears in output. Keep the stdin source
private. The interactive `--bootstrap-admin` flag is not part of the native executable.

The command creates the fixed username and subject `admin` as an enabled human with a temporary
peppered Argon2id PHC and explicit `local|admin` → `admin` role assignment in one transaction.
Any existing local user, including a service identity, prevents creation. Concurrent attempts can
create at most one administrator. It grants no project/resource access and issues no session or
token, initializes no storage volume and opens no listener. On success it prints only
`local administrator created` and physically closes password workers and SQL before exiting.

Start the server normally and open `/admin/`. The first login must replace the temporary password.
When `auth.local.mfa.required` is true, confirm TOTP enrollment and retain the ten recovery codes
before the administrative cookie is issued. With explicit `false`, the configured password-only
journey remains available. The account uses current SQL roles and the ordinary administrative
authorization checks. Resource grants remain a separate, initially empty policy.

If a write outcome is uncertain, inspect the database/retry result rather than assuming that no
account exists. A physical shutdown failure after commit is reported as a failure with creation
already acknowledged; it must not be treated as permission to overwrite the identity. There is no
migration or compatibility path: recreate an incompatible development database explicitly.

## UI

The UI shows sections according to effective role permissions:

1. **Projects** lists projects allowed by current resource grants and renders Graphit CLI commands.
2. **Configuration** shows the redacted deployment YAML read-only.
3. **Project access** manages the deny-by-default project capability policy with revision fencing.
4. **Local users** manages human identities and passwordless service identities, including
   forced password change, administrative MFA reset, and one-time display, listing, and revocation
   of service credentials.
5. **Admin roles** manages role definitions and assignments to canonical `issuer|subject` identities.

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
`auth.pepper` and never returns it. New passwords require at least 15 Unicode
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
The Rust Broker implements these endpoints in its control and server crates. Its login page
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

Open **Projects**, search a listed project identifier or capability, then select it to see what the current account can use. The list reports only identifiers and capabilities returned by the Broker; it does not imply project health, activity or ownership. If access covers **all projects** but no exact IDs are listed, the page says so and directs you to connect the CLI and find project details in Graphit Hub. A truly empty access list instead directs you to request project access. A project or role removed from a refreshed directory clears its old inspector; a new sign-in clears prior selections. Copy the Broker-provided connection commands when available.

### Give or remove project access

Open **Project access** to see who has access, which projects a rule covers and what it permits. Search by audience, project or capability; **Details** shows the exact rule. With write permission, choose **Give access**, **Change** or **Remove access**.

**Give access** starts with **People signed in**, **All projects** and **Read project data** selected. Confirming those choices grants `hub` discovery and S3 read access for every current and future project to authenticated identities when a default project storage route is configured. No rule ID or project ID is needed. On deployments without project storage, choose **Find projects** to grant discovery without S3; if the default read choice is submitted first, the form keeps the draft and explains the storage prerequisite. To narrow the grant, choose a team, person or another audience; choose **Specific projects** and paste exact project IDs. To change what people can do, choose one of these levels:

| Choice | Capabilities and storage operations |
|---|---|
| Find projects | `hub`; no storage access |
| Read project data | `hub`, `s3`; `read` |
| Work on projects | `hub`, `s3`; `read`, `write` |
| Manage project data | `hub`, `s3`; `read`, `write`, `publish`, `delete` |
| Use AI tools | `embeddings`, `rerank`; no storage access |
| Full project access | `hub`, `s3`, `embeddings`, `rerank`; `read`, `write`, `publish`, `delete` |

**Full project access** combines project data operations and AI tools for the selected audience; it requires configured project storage for its S3 operations. When **Specific projects** is selected, project IDs restrict Hub discovery and S3 data access. Embeddings and rerank requests have no project ID, so AI use applies across that audience. This grant does not confer administration roles. **Choose capabilities** and **Advanced details** retain specialized grants, including S3 route and prefix constraints. A new rule receives a generated stable ID; its optional display name is in Advanced details. Existing IDs remain unchanged. The summary beside the choices shows who, which projects and the selected access before saving; it is a description of the draft, not an access simulation. Public audiences include unauthenticated requests, but temporary S3 credentials still require authentication.

Rules are additive; unmatched requests are denied. Writes send the current policy ETag with `If-Match`. If the policy changes elsewhere, the form retains its choices and asks the operator to review the current rules before retrying. **Remove access** asks for confirmation and may cause matching requests to be denied immediately. Administration roles are independent of project access.

### Inspect and maintain identities

**Local users** is a searchable directory with People, Services, Disabled and MFA-pending filters. **Open profile** shows identity, membership and authentication state before permitted actions. **Add a person** asks for a name, username and temporary password; **Add a service** asks for a name and username. The Broker UI generates a permanent subject automatically. Open **Advanced details** only when an exact subject, membership, additional role or account state is needed. Human passwords require at least 15 characters and must be changed at first sign-in. Services use revocable credentials instead of passwords or MFA. **Edit account** retains the original subject and kind; username may change, and an empty password keeps the current one. **Reset changes** restores the persisted account while editing or clears a new-account draft.

A service profile opens its credential inventory with ID, scopes, expiry and revocation state. The inventory does not report a last-use metric. Creation shows the token once; copy it before dismissing or closing the inventory. The secret is cleared from the displayed inventory on dismissal, identity change or change of service. Delayed credential responses cannot reopen a closed inventory or display a token under another service. Credential scopes are metadata, not resource authorization. Revocation, identity deletion and MFA reset retain explicit confirmation and backend last-administrator protections.

### Define responsibility, then assign it

**Admin roles** opens on **Who has roles**, where operators can give or remove an administration role. With permission to view local users, choose a person or service by name; the Broker UI submits its stable `local|subject` identity. **External identity** accepts an exact `issuer|subject` when the account is supplied by an identity provider or the local directory is unavailable. Choose the role, then select **Give role**. Removal names the affected person or identity and asks for confirmation.

**Define roles** lists role definitions. Select one to inspect its permission bundle; built-in roles are read only. The custom-role editor groups allowed actions by domain and shows plain-language action names with their exact API codes underneath. Search matches either name or code; the count shows how many are selected. An existing role name is immutable in this editor; use **Define role** to create another definition. **Assign this role** transfers an inspected role into the assignment form and focuses the visible person picker or external-identity field. Configured IdP role claims take precedence over database assignments. Project access remains independent from administration roles.

### Read effective configuration

**Configuration** provides a section index, text search, refresh and copy for the complete redacted YAML. It is read only. Search reports the count and first matching line; section buttons select the corresponding location. An empty response explains that no configuration is available and disables copying. To change deployment configuration, edit `config.yaml` or environment-provided secrets and restart the Broker.

### Authenticate one step at a time

The administration sign-in surface offers an organization account and a Broker account when both are configured. Once password replacement, MFA or recovery is required, organization-method choices are hidden until the active challenge completes. OAuth and device authorization use a centered transaction surface with Identify → Verify → Connect context. Only the server-selected form is submitted; required password, MFA, recovery, CAPTCHA and device states are preserved. Recovery codes remain visible until the user explicitly continues. A fatal or expired request renders restart guidance without credential fields.

OAuth forms preserve the original request URL and challenge fields. The authentication template needs no inline application JavaScript and retains its strict CSP; configured CAPTCHA scripts are the only permitted providers. A single upstream OIDC provider with local login disabled still redirects automatically.

The console supports light/dark themes and mobile navigation with focus containment. Primary actions use the paired action/foreground tokens; destructive actions retain the danger color when hovered. Disabled buttons retain their disabled appearance on hover. Keyboard focus remains visible on the fixed navy navigation in either theme. At mobile widths, buttons and the menu trigger have a minimum 44px height, and editor actions wrap rather than being compressed into a single row. Wide policy and credential tables scroll within their own surfaces; editors and inspectors stack on small screens. The standalone authentication template is light-only. System-font fallbacks require no external font request.

The canonical [Graphit design system](https://github.com/graphit-labs/graphit-code/blob/main/docs/specs/design_system.md) documents shared principles, tokens, page patterns, responsive behavior and evolution checks. The native console consumes `crates/broker-presence/assets/admin/index.html`; OAuth/Device rendering uses the maintained Rust templates under `crates/broker-presence/src/templates/oauth/`. Native Control, Presence and Server contracts cover authentication, current SQL authorization and the HTTP journeys described above. Use the reference revision corresponding to the implementation under review.
