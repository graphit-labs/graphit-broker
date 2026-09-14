# OIDC integration

OIDC is configured once under `authentication.oidc`. The broker uses the same trusted issuer,
claim selectors, and role semantics for consumer bearer tokens, direct administration bearer
requests, and browser authorization-code login. Administration does not define a second OIDC
provider.

## Configuration

```yaml
authentication:
  token_pepper: "${BROKER_AUTH_TOKEN_PEPPER:?at least 32 random bytes}"
  oidc:
    - enabled: true
      display_name: Corporate SSO
      issuer: https://identity.example.com
      audiences: [graphit-broker]
      required_scopes: [graphit.use]
      client_id: graphit-broker
      client_secret: "${BROKER_OIDC_CLIENT_SECRET:?required}"
      redirect_url: https://broker.example.com/oauth/oidc/callback
      scopes: [openid, profile, email]
      subject_claim: sub
      name_claim: name
      email_claim: email
      username_claim: preferred_username
      organization_claim: "$.organization.id"
      teams_claim: "$.groups[*].name"
      role_claim: "$.realm_access.roles[*]"
administration:
  enabled: true
  session_ttl: 8h
  cookie_secure: true
```

`enabled` defaults to `true` for each issuer. Set it to `false` to disable that issuer for bearer
validation and browser login, skip remote discovery, and reject its existing sessions and
Broker-issued grants after restart. The Broker's own OpenID Provider remains available when local
login is enabled. Required environment references are still expanded even in disabled entries.

`issuer`, `audiences`, required scopes, and signature/temporal checks protect bearer tokens.
`client_id`, `client_secret`, `redirect_url`, and `scopes` enable browser login independently on
each enabled issuer entry. `display_name` is required with those fields and is the label shown for
that issuer on the Broker and administration login screens. A deployment using only local browser
login may omit the browser-client fields and `display_name` from every issuer.

## Claims and identity

Claim selectors may be exact top-level keys or RFC 9535 JSONPath expressions beginning with `$`.
`subject_claim` defaults to `sub`, but remains explicit in examples because subject and username
have different jobs:

- subject is the stable authorization identity; canonical RBAC keys are `issuer|subject`;
- username is a login/display/resource-grant attribute and may change without changing identity.

`name_claim` and `email_claim` default to `name` and `email`. `username_claim` is required.
Organization and teams are optional. Invalid selectors or wrong selected types fail closed.

## Roles

RBAC is broker-wide. Every authenticated OIDC principal receives the built-in `user` role. Without
`role_claim`, additional roles come from SQL assignments keyed by canonical subject. When
`role_claim` is configured, its valid values are authoritative additional roles and SQL assignments
for that identity do not participate. An absent/empty role claim therefore leaves only the default
`user` role; malformed or unsafe role values are rejected. The `admin` role is an ordinary
privileged role, not a different authentication path.

## Browser flows and Broker issuer

The Broker is itself an OpenID Provider for [Graphit Code](https://github.com/graphit-labs/graphit-code). Graphit Code always uses standard
Authorization Code + PKCE against the Broker issuer, regardless of whether the Broker authenticates
the person with a local password or any configured upstream issuer. When multiple methods or
upstream issuers are enabled, the Broker renders each choice using its `display_name`; with exactly
one upstream OIDC provider and no local login it redirects immediately; with only local login it
renders only the local form.

```text
Graphit Code ── Authorization Code + PKCE ──> Broker OpenID Provider
                                               ├─ local password/change/TOTP
                                               └─ selected upstream OIDC client ──> organization IdP
Graphit Code <── Broker code/ID/access/refresh tokens ───────────────────┘
```

In both branches, the issuer visible to Graphit Code is the Broker and the returned subject is the
stable Broker `sub`. The upstream issuer and its authorization code, client secret, ID token,
access token, and refresh token are never returned to Graphit Code. The local branch implements an
OIDC login outcome without turning the password into an API credential.

Upstream OIDC may start from `GET /admin/auth/login?provider=ID` for administration or from a
provider choice inside the Broker authorization. Both create random state, nonce, PKCE verifier,
and browser-binding values. The selected provider ID is stored in the protected one-time flow, so
the callback exchanges the code only with the issuer that started the login. The
binding is held in an `HttpOnly`, `SameSite=Lax` cookie whose per-flow name permits concurrent
logins. Only HMAC-protected state and binding are stored in SQL, using
`authentication.token_pepper` and domains distinct from session and password domains. The callback
requires both values and consumes the flow once; a missing/wrong binding does not consume valid
state. It then exchanges the code using the
configured confidential client, verifies the ID token and nonce, maps the same subject/attribute
selectors, then either creates a short-lived administration cookie session or resumes the pending
Broker authorization. The OIDC provider library then returns a one-time code to Graphit Code's
loopback callback and signs an EdDSA ID token whose `sub` is derived from the canonical underlying
identity, independent of mutable username.
The access token is also an EdDSA JWT signed by the Broker and verifiable through its standard
discovery/JWKS. Its audience is the configured Broker token audience, and it carries the stable
Broker subject, client, scopes, preferred username, and non-empty optional organization/group/role
claims. Refresh tokens remain opaque and rotate on every use. Broker-side revocation is immediate
for Broker endpoints; offline JWKS validators accept an already issued access token until `exp`.
Both flow and session cookies are `Secure` by default. An explicit
`administration.cookie_secure: false` is available only for loopback HTTP development.

## Graphit relay and token exchange

For HTTP MCP, Graphit may relay the end-user token when MCP and broker share an audience, or use RFC
8693 exchange to obtain a broker-audience token. The broker independently verifies the final token
against the configured issuer, audiences, scopes, and claim mappings. Exchange failure never falls
back to relay or anonymous access.

## Failure behavior

The broker returns `401` for invalid signature, issuer, audience, expiry, required scope, subject,
username, or claim shape. A valid identity without the action required by RBAC returns `403`.
Anonymous behavior is considered only when no bearer credential was supplied.
