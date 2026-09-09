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
    - issuer: https://identity.example.com
      audiences: [graphit-broker]
      required_scopes: [graphit.use]
      client_id: graphit-broker
      client_secret: "${BROKER_OIDC_CLIENT_SECRET:?required}"
      redirect_url: https://broker.example.com/admin/auth/callback
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

`issuer`, `audiences`, required scopes, and signature/temporal checks protect bearer tokens.
`client_id`, `client_secret`, `redirect_url`, and `scopes` enable browser login on at most one
issuer entry. A deployment using only local browser login may omit those client fields.

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

## Browser flow

`GET /admin/auth/login` creates random state, nonce, PKCE verifier, and browser-binding values. The
binding is held in an `HttpOnly`, `SameSite=Lax` cookie whose per-flow name permits concurrent
logins. Only HMAC-protected state and binding are stored in SQL, using
`authentication.token_pepper` and domains distinct from session and password domains. The callback
requires both values and consumes the flow once; a missing/wrong binding does not consume valid
state. It then exchanges the code using the
configured confidential client, verifies the ID token and nonce, maps the same subject/attribute
selectors, authorizes `session.read`, and creates a short-lived cookie session.
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
