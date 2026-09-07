# Administration UI, OIDC and RBAC

The broker serves its control plane at `/admin/`. It is not protected by a broker API key: it uses
a separate OIDC web application, a server-side session, CSRF validation, and action-based roles.
Consumer bearer tokens still authorize only consumer endpoints unless their exact OIDC subject is
also assigned an administrative role.

## Register the administration OIDC client

Create a web/confidential application in the identity provider:

- flow: Authorization Code;
- client authentication: client secret when the provider supports confidential clients;
- redirect URI: exactly `https://broker.example.com/admin/auth/callback`;
- scopes: `openid profile email` (only `openid` is required by the broker);
- PKCE: S256 allowed or required;
- ID tokens: signed, with the broker client ID in `aud` and an immutable `sub`.

The broker validates discovery, signature, exact issuer, client audience, expiration and nonce. It
creates a short-lived one-time state record for each login and sends a PKCE challenge even for a
confidential client. A successful callback creates an opaque, hashed server-side session. The
browser receives only an `HttpOnly`, `SameSite=Lax` cookie; it is `Secure` when the callback URL is
HTTPS. State-changing cookie requests also require the per-session CSRF token.

```yaml
administration:
  enabled: true
  database_path: /var/lib/graphit-auth-broker/broker.db
  superadmin_subject: ${BROKER_SUPERADMIN_SUBJECT:?required}
  session_ttl: 8h
  oidc:
    issuer: ${BROKER_ADMIN_OIDC_ISSUER:?required}
    client_id: ${BROKER_ADMIN_OIDC_CLIENT_ID:?required}
    client_secret: ${BROKER_ADMIN_OIDC_CLIENT_SECRET:?required}
    redirect_url: ${BROKER_ADMIN_OIDC_REDIRECT_URL:?required}
    scopes: [openid, profile, email]
```

`client_secret` may be empty for an IdP that supports a public web client, but a confidential client
is recommended. Use HTTPS outside loopback development. Disabling administration removes all
`/admin` routes.

## Superadmin bootstrap

Set `BROKER_SUPERADMIN_SUBJECT` to the exact immutable `sub` claim of the initial owner. The
environment value overrides the YAML/SQLite value on every start, so database restore cannot change
who holds emergency ownership.

The superadmin always bypasses administrative role checks. When `role_assignments` is empty, every
other authenticated subject is denied. This is the initial safe state: sign in as the superadmin,
open **Roles & users**, and assign the built-in `admin` role to each administrator. Removing the last
assignment returns to bootstrap-only access; it never disables the superadmin.

Do not use email or username as the bootstrap identifier. Copy the exact `sub` from a verified token
or the IdP administrator console. If the IdP changes subject identifiers, update the environment and
restart the broker through the deployment's normal secret/change-control path.

## Roles and actions

Authentication and authorization are separate. A role is a name mapped to one or more actions; a
role assignment maps an exact OIDC subject to that role. The built-in `admin` role initially grants:

| Action | API surface |
|---|---|
| `session.read` | establish/read an authenticated administration session |
| `configuration.read` | read redacted complete configuration and session summary |
| `configuration.write` | replace complete configuration |
| `access.read` | read ACLs and consumer principals |
| `access.write` | replace ACLs |
| `roles.read` | list roles and assignments |
| `roles.write` | create/update roles and assign/revoke them |

The UI can create narrower roles such as an auditor (`configuration.read`, `access.read`,
`roles.read`) without changing OIDC. `*` is accepted by the storage model for a full administrative
role, while the UI presents the explicit known actions. Only subjects holding `roles.write` (or the
superadmin) can delegate access.

## What the UI manages

The **Configuration** tab edits one strict YAML document covering all mutable broker behavior:

- consumer OIDC issuers, audiences, scope and claim mappings;
- consumer API-key principals;
- administration OIDC client, scopes and session lifetime;
- all consumer ACL rules;
- embedding/rerank routes, upstream endpoints, models, credentials, limits and caches;
- direct S3 signing routes, buckets, regions, endpoints, prefixes and credentials;
- mutable HTTP server timeouts, public URL and body limit.

`administration.database_path`, `administration.enabled`, and the effective superadmin subject are
deployment bootstrap controls and cannot be moved through a database edit. A save is validated and
fully prepared before SQLite is updated. The active runtime then changes atomically: new consumer
requests immediately use the new OIDC/API keys, ACLs, AI routes and S3 routes.

Listener address and HTTP server read/write/idle deadlines belong to the already-created Go server;
their saved values take effect on the next broker restart. `public_url` and request-body limits are
read dynamically. The API returns success only after every dynamically replaceable component has
been prepared successfully.

The **Access rules** tab is a structured editor for the same `authorization.rules` data. The
**Roles & users** tab creates roles and manages assignments. Since ACL and full configuration saves
share one configuration revision, reloading after a conflict is mandatory.

## Revisions and secrets

`GET /admin/api/v1/config` and `GET /admin/api/v1/access` return an `ETag`. A write must send that
exact value in `If-Match`; a concurrent or stale write returns `409 revision_conflict`. The UI reloads
both views after a successful save.

Read responses never contain stored secrets. Each populated client secret, consumer token or token
digest, AI API key, and S3 secret key is rendered as `[configured-secret]`. On a complete
configuration PUT:

- leave `[configured-secret]` to retain the stored value;
- replace it with a new value to rotate the secret;
- use an empty value to remove it, provided the resulting configuration remains valid.

The S3 access-key identifier and route topology are visible to authorized administrators, but never
to consumer API responses. Treat the SQLite database as a secret because it stores the actual
configuration values.

## Automation API authentication

Browser automation should use the OIDC session and CSRF token. Non-browser administrators may send
a current OIDC **ID token** for the configured administration client as
`Authorization: Bearer TOKEN`; the exact token subject still passes through role authorization.
This mode avoids cookie CSRF because the credential is explicitly attached by the caller. Do not
send consumer access tokens unless they are also valid ID tokens for the administration client.

Example read:

```bash
curl -H "Authorization: Bearer $ADMIN_ID_TOKEN" \
  https://broker.example.com/admin/api/v1/config
```

For browser-session writes, fetch `/admin/api/v1/session`, retain the cookie, and send the returned
`csrf_token` as `X-CSRF-Token`. See [HTTP API](api.md) for every endpoint.

## Consumer ACL levels

Every ACL rule is an allow grant; there are no implicit grants or deny overrides. An empty policy
denies everything.

| `access` | `principal` | Matches |
|---|---|---|
| `global` | omitted | every request, authenticated or anonymous |
| `anonymous` | omitted | only requests with no `Authorization` header |
| `authenticated` | omitted | any successfully validated consumer OIDC/API-key principal |
| `user` | username | exact normalized verified username |
| `team` | team | one exact verified team membership |
| `organization` | organization | exact verified organization |
| `subject` | subject | exact `sub` or canonical `issuer\|sub` |

Capabilities are `embeddings`, `rerank`, `s3`, or operation-specific forms such as `s3:read`.
Storage grants may constrain project globs, logical operations (`read`, `write`, `publish`,
`delete`), one named S3 route and logical key-prefix templates. Multiple matching S3 routes fail
closed rather than choosing nondeterministically.
