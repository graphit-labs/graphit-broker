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
      required_scopes: []
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
and browser-binding values. By default the Broker sends the nonce and requires the same claim in
the ID token. An issuer with `require_nonce: false` omits it from the authorization request and
skips only that check. The selected provider ID is stored in the protected one-time flow, so
the callback exchanges the code only with the issuer that started the login. The
binding is held in an `HttpOnly`, `SameSite=Lax` cookie whose per-flow name permits concurrent
logins. Only HMAC-protected state and binding are stored in SQL, using
`authentication.token_pepper` and domains distinct from session and password domains. The callback
requires both values and consumes the flow once; a missing/wrong binding does not consume valid
state. It then exchanges the code using the
configured confidential client, verifies the ID token and, when configured, its nonce, maps the
same subject/attribute selectors, then either creates a short-lived administration cookie session or resumes the pending
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

## External MCP clients

The Broker is the authorization server for a hosted agent that talks to a Graphit MCP endpoint, not
merely for Graphit Code's own login. Whatever authenticates the person upstream — a federated IdP or
a Broker local user — is invisible to that agent: it only ever speaks OIDC with the Broker, and the
token it receives is signed by the Broker's own key with the Broker's `iss`.

An agent that has never been provisioned reaches a usable token on its own when
`authentication.local.tokens.dynamic_registration` is enabled and `mcp_resources` names the Graphit
deployment. It discovers the Broker from the MCP endpoint's `401`, reads
`/.well-known/openid-configuration`, registers itself at `registration_endpoint` (RFC 7591), and
runs Authorization Code with PKCE while passing the MCP endpoint's canonical URI as the RFC 8707
`resource`. The Broker issues a **public** client only, so no secret is minted, stored, or returned;
see [configuration](configuration.md) for both keys and their exact validation rules.

Revocation reaches those clients differently from a pure offline validator. A Graphit daemon
revalidates every inbound MCP access token against `/oauth/userinfo`, so a revoked token stops
working on the next MCP request rather than at `exp`.

The two token types revoke different amounts on purpose. Revoking a **refresh token** ends the
whole authorization grant: that token, every access token minted from it, and any further
renewal, which is what RFC 7009 section 2.1 asks of a server that can revoke access tokens. This
is the call to make when someone's access has to stop. Revoking an **access token** ends only
that token and leaves its refresh token usable, which the same section leaves as a MAY; use it to
retire one leaked credential without forcing the client to authenticate again.

## Graphit relay and token exchange

For HTTP MCP, Graphit may relay the end-user token when MCP and broker share an audience, or use RFC
8693 exchange to obtain a broker-audience token. The broker independently verifies the final token
against the configured issuer, audiences, scopes, and claim mappings. Exchange failure never falls
back to relay or anonymous access.

## Failure behavior

The broker returns `401` for invalid signature, issuer, audience, expiry, required scope, subject,
username, or claim shape. A valid identity without the action required by RBAC returns `403`.
Anonymous behavior is considered only when no bearer credential was supplied.

### Diagnosing browser `invalid_identity`

When an upstream identity cannot be verified after a bound administration login callback, the
Broker returns the browser to `/admin/`. The sign-in screen shows a fixed, safe error and a request
reference instead of rendering a JSON response or exposing token-endpoint details, token contents,
claim values, or validation policy. Use that reference to find the matching structured
`OIDC identity exchange failed` entry in Broker logs. Its `error` field names the failed stage
without changing the browser message. Broker-managed OAuth authorization instead returns its
standard error to the registered client. A callback without valid state and browser binding still
fails closed because the Broker has no trusted continuation to resume.

Do not copy the callback URL, authorization code, state, ID token, access token, or client secret
into tickets or shared diagnostic output.

Check the logged stage in this order:

1. For `exchange OIDC code`, verify token-endpoint reachability and the configured `client_id`,
   `client_secret`, and exact `redirect_url`. Also check that the one-time code is fresh and unused
   and that the same login flow supplied its PKCE verifier. Start a new login after correcting the
   configuration; do not replay a callback URL.
2. For `OIDC response omitted id_token`, confirm that the authorization request includes `openid`
   and that the provider returns an ID token from its token endpoint for this client and flow.
3. For `verify OIDC ID token` or a nonce mismatch, verify provider discovery/JWKS reachability,
   issuer, client audience, signature and token time validity. With `require_nonce` omitted or
   `true`, a new login must return the nonce created for that same flow. Set `require_nonce: false`
   only when an Authorization Code provider cannot return it; this omits nonce from the request and
   does not weaken state, browser binding, PKCE, or the remaining ID-token checks.
4. For a claim error, inspect the provider's documented ID-token claim schema and the configured
   selectors. `subject_claim` (default `sub`) and `username_claim` must each select exactly one
   non-empty string. `name_claim`, `email_claim`, `organization_claim`, `teams_claim`, and
   `role_claim` are optional, but any selected value must have the documented string or string-array
   shape; configured role values must also be safe role identifiers. Prefer provider-side claim
   inspection or redacted schema information instead of logging token contents.

After a change, start a fresh browser login and confirm that the sign-in screen no longer reports a
failure and no new correlated log entry is written. A valid identity without administration access
returns to the same sign-in screen with an authorization-specific message; that is authorization,
not `invalid_identity`.
