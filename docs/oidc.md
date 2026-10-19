---
references:
  - target: {type: task, id: tsk-2080, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: corrects
  - target: {type: task, id: tsk-50e3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---

# OIDC integration

The [native Device flow](rust-device-authorization.md) keeps code TTL, polling and access TTL separate, requires LOCAL-bound consent, and emits an access JWT through the common signer. Its HTTP/browser composition uses explicit one-use consent after LOCAL authentication and is announced only with OIDC and LOCAL operational; focused HTTP/browser contracts are qualified locally on Linux. Device grants effective scope empty and rejects every nonempty scope request before SQL. Existing Code-grant scopes and refresh rotation remain unchanged. APIs requiring nonempty scopes reject Device tokens; current PROJECT/RBAC policy is separate.

The [native PostgreSQL server](rust-broker-server.md) has a separate clean YAML
[`oidc` code-exchange section](rust-oidc-token-exchange.md). It consumes genuine
LOCAL/P2b or [genuine federated codes](rust-oidc-federated-grants.md), signs access/ID tokens with the configured shared key and supports
[native refresh rotation](rust-oidc-refresh.md) and [explicit token revocation](rust-oidc-revocation.md). Public clients can also use
[native dynamic registration](rust-oidc-registration.md) when the same OIDC
section explicitly enables it. The server also publishes [native discovery](rust-oidc-discovery.md)
for its configured public issuer and productive endpoints. Registration commits client metadata;
a browser sign-in still requires the genuine authorization/login journey. The native library also has a
[genuine upstream browser producer](rust-upstream-browser-login.md) sharing the
[federated bearer provider](rust-admin-upstream-session.md), plus a [federated cookie consumer](rust-admin-federated-cookie.md).
The [native administrative browser adapter](rust-admin-upstream-login.md) connects
their real begin/callback and cookie chain to the existing HTML. The
[shared native callback](rust-oidc-browser-callback.md) also consumes protected OAuth
continuations and renders query, fragment and form_post responses without an
administrative session owner. The [public authorize/login transport](rust-oidc-browser-authorization.md) composes
LOCAL stages, recovery and upstream selection. Discovery describes those delivered endpoints;
remaining OP operations retain separate native deliveries. The release integration below
retains its own existing schema and supported routes. In the native producer,
UserInfo supplements only missing profile attributes and never subject or roles;
its strict ID-token audience trust is documented in that producer reference.

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
      claims_source: id_token
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
For browser login, `claims_source` chooses `id_token` (default), `access_token`, or `userinfo`
for all mapped claims, including roles. The ID token is still required and verified in every case.
The access-token option requires a JWT verifiable with the issuer's keys; the userinfo option
requires a discovered endpoint and uses the issued access token to call it. Both require a `sub`
matching the verified ID token. Missing claims follow the usual required/optional rules; the
Broker does not fall back to another source. This setting does not change direct bearer
validation.

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
same subject/attribute selectors from the configured claims source, then either creates a short-lived administration cookie session or resumes the pending
Broker authorization. The OIDC provider library then returns a one-time code to Graphit Code's
loopback callback and signs an EdDSA ID token whose `sub` is derived from the canonical underlying
identity, independent of mutable username.
The access token is also an EdDSA JWT signed by the Broker and verifiable through its standard
discovery/JWKS. It carries `token_use: access`, the configured Broker token audience, and the stable
Broker subject, client, scopes, preferred username, and non-empty optional organization/group/role
claims. A token requested for a configured MCP resource also includes that exact resource in
`aud`; a Broker API token without the resource is not valid for MCP. This is the Broker's own
access-token format, not the optional RFC 9068 JWT access-token profile. Refresh tokens remain
opaque and rotate on every use. [SQL family revocation](rust-oidc-refresh.md#atomic-rotation-and-reuse)
prevents further refresh and grant operations. Already issued access JWTs remain locally verifiable
until `exp`; resource authorization reads current SQL policy for each consequential operation.
Revoking a refresh family does not introduce an access-token blacklist or change its lifetime.
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
runs Authorization Code with S256 PKCE while passing the MCP endpoint's canonical URI as the RFC 8707
`resource` in both the authorization request and every token request, including refresh. The Broker
rejects an omitted or changed resource. The Broker issues a **public** client only, so no secret is minted, stored, or returned;
see [configuration](configuration.md) for both keys and their exact validation rules.

Graphit validates the access JWT locally until `exp`; MCP authentication does not require a
UserInfo or introspection request. Current resource grants remain a separate authorization check
for each consequential operation. The native Broker exposes [explicit revocation](rust-oidc-revocation.md), [UserInfo profile retrieval](rust-oidc-userinfo.md) and [Bearer-authorized introspection](rust-oidc-introspection.md), announced by [discovery](rust-oidc-discovery.md#follow-the-productive-endpoints). Introspection inspects only the caller's client/subject grants. [Native end-session](rust-oidc-end-session.md) disposes every SQL OIDC grant of the signed subject/client pair using a required ID hint, including expired hints or removed DCR clients, and returns204 without redirects. These operations do not become
a mandatory network gate for JWT consumers.

## Graphit Code web UI clients

When Graphit Code enables browser login, it registers a separate public client with an exact
`/api/auth/callback` redirect. This uses the Broker's own OpenID Provider, regardless of how the
Broker authenticates the person upstream. The client requests `<broker issuer>/v1` as its single
RFC 8707 `resource` on authorization, code exchange and refresh. In the native server, the operator
must explicitly include this exact resource in `oidc.accepted_resources`, alongside any desired MCP
resources; neither discovery nor authorization adds it implicitly. The Broker binds the accepted
resource to the grant and includes it and the Broker API audience in the access JWT. The web client
cannot change the resource during exchange or refresh; an MCP client still needs its endpoint's configured MCP resource. Dynamic
registration must be enabled for Graphit Code to create the web client. The Code server verifies
the signed ID and access JWTs and keeps the browser session in an encrypted HttpOnly cookie.

The [native explicit revocation API](rust-oidc-revocation.md) has different SQL effects for the two token types: a
**refresh token** revokes its whole family, including stored access rows and future renewal; an
**access token** revokes only that stored row and leaves its refresh usable. These SQL effects
do not invalidate an already issued JWT
for local verification before `exp`; current resource policy is checked independently.

## Graphit request bearer forwarding

For HTTP MCP, Graphit forwards the caller's Broker-issued access JWT unchanged. The JWT carries both
the exact MCP resource audience and the Broker API audience. The MCP listener validates the former;
Broker APIs validate the latter and apply the current authorization policy for the requested
operation. An invalid token is rejected without anonymous fallback.

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
4. For a claim error, inspect the provider's documented claim schema for the configured
   `claims_source` and the configured
   selectors. `subject_claim` (default `sub`) and `username_claim` must each select exactly one
   non-empty string. `name_claim`, `email_claim`, `organization_claim`, `teams_claim`, and
   `role_claim` are optional, but any selected value must have the documented string or string-array
   shape; configured role values must also be safe role identifiers. Prefer provider-side claim
   inspection or redacted schema information instead of logging token contents.

After a change, start a fresh browser login and confirm that the sign-in screen no longer reports a
failure and no new correlated log entry is written. A valid identity without administration access
returns to the same sign-in screen with an authorization-specific message; that is authorization,
not `invalid_identity`.

In the native federated OAuth grant backend, role claims are a protected snapshot
plus implicit `user`; absence of a selector does not use administrative SQL-role
fallback. Subject/username preserve H1 bytes and the signed Broker subject uses
domain-15 framed issuer/subject HMAC. See [native federated grants](rust-oidc-federated-grants.md)
for trust changes, time, LOCAL isolation and the separate browser-integration boundary.
