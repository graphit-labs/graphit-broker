# OIDC integration

When OIDC is configured, the broker uses two OIDC clients/trust paths:

- consumer bearer validation for Graphit MCP, Hub, S3, embedding, and rerank requests;
- a separate confidential web client for administration login.

They may use the same issuer, but their client IDs, redirect behavior, audiences, and policies are
independent.

Administration OIDC is optional when the UI is intentionally local-only and at least one
`authentication.api_keys` identity is configured. That mode does not change consumer OIDC
validation.

## Consumer issuer

Create an API/resource in the identity provider for the broker, for example audience
`graphit-broker`. Configure the issuer:

```yaml
authentication:
  oidc:
    - issuer: https://identity.example.com
      audiences: [graphit-broker]
      required_scopes: [graphit.use]
      username_claim: preferred_username
      organization_claim: "$.organization.id"
      teams_claim: "$.groups[*].name"
```

The broker discovers signing keys and verifies token signature, exact issuer, accepted audience,
expiry, and every required scope. It then maps configured claim selectors. A selector can be an
exact top-level key or an RFC 9535 JSONPath beginning with `$`; multi-value selectors can traverse
arrays and select multiple string nodes. The `sub` claim is always
required and canonical identity remains `iss|sub`; mapped fields cannot replace it.

Access tokens must be JWTs verifiable through issuer discovery/JWKS. Opaque tokens are not
introspected by this implementation. If an IdP issues opaque access tokens, configure it to issue a
JWT for this API or place a standards-compliant token-exchange/security gateway in front.

## End-user token from Graphit

For a Graphit OIDC provider using direct relay:

1. the user logs in through Graphit Authorization Code + PKCE;
2. the IdP issues an access token for the shared MCP/broker audience;
3. Streamable HTTP MCP validates that access token before running any tool;
4. Graphit binds the verified username/teams and raw bearer to that request;
5. every broker call forwards that request bearer;
6. the broker independently verifies it and derives the principal again.

No identity claim is copied from an untrusted request body. Two concurrent MCP users retain
separate request contexts; neither uses the other user's active profile token.

If MCP and broker require different audiences, configure Graphit's provider with RFC 8693 token
exchange. Graphit sends the incoming MCP token as `subject_token` to the configured/discovered
token endpoint, requests the broker audience/resource, and calls the broker with the returned
short-lived bearer. Exchange tokens are cached by provider revision, source-token digest, and
target resource only until shortly before expiry. Exchange failure fails closed; Graphit does not
fall back to relaying a token with the wrong audience.

The broker itself needs no special exchange endpoint: it receives and validates the final
broker-audience bearer.

## Required IdP values

Collect:

- exact issuer URL;
- broker API audience;
- optional required scope;
- stable username claim;
- optional organization and group/team claim selectors;
- for Graphit login, native/public client ID, scopes, and redirect policy;
- for token exchange, client authentication method and whether RFC 8693 is enabled for that client;
- for administration, confidential web client ID/secret and exact callback.

Test with two users belonging to different teams, an expired token, a token for another audience,
an invalid signature, and a request with no token. Only the intended grants should resolve.

## Administration OIDC

```yaml
administration:
  enabled: true
  superadmin_subject: "${BROKER_SUPERADMIN_SUBJECT:?required}"
  session_ttl: 8h
  oidc:
    issuer: https://identity.example.com
    client_id: graphit-broker-admin
    client_secret: "${BROKER_ADMIN_OIDC_CLIENT_SECRET:?required}"
    redirect_url: https://broker.example.com/admin/auth/callback
    scopes: [openid, profile, email]
    name_claim: name
    email_claim: email
    username_claim: preferred_username
    organization_claim: "$.organization.id"
    teams_claim: "$.groups[*].name"
    role_claim: "$.realm_access.roles[*]"
```

Register the callback exactly. The browser flow uses code, state, nonce, and PKCE. The broker
persists only hashed state/session tokens and server-side metadata. Set
`BROKER_SUPERADMIN_SUBJECT` from the immutable admin `sub`, never an email address.

All administration identity mappings accept exact claim keys or RFC 9535 JSONPath. `name`, email,
username, and organization must resolve to zero or one string (username is optional for the admin
client); teams and roles may resolve a string, a string array, or multiple strings. A configured
`role_claim` is required to return at least one role. Its values are authoritative and completely
replace local database assignments for that OIDC subject; they are not merged. Role permissions
still come from broker role definitions. Missing, empty, non-string, or syntactically invalid role
selection fails closed. API-key sessions keep using database assignments.

Examples for common token layouts:

```yaml
# Exact top-level/namespaced keys
username_claim: preferred_username
teams_claim: https://claims.example.com/teams

# Nested objects and arrays
organization_claim: "$.tenants[?@.primary == true].id"
teams_claim: "$.groups[*].name"
role_claim: "$.realm_access.roles[*]"
```

Exact keys are tested before traversal, including keys containing dots. A non-JSONPath dotted value
such as `organization.id` remains supported for compatibility when no exact key exists. Prefer
JSONPath for new nested/array mappings. Invalid JSONPath is rejected by `--check-config` and normal
startup.

## Common provider notes

- **Keycloak:** use separate clients/resources for Graphit native login and broker administration;
  add protocol mappers for username, organization, and groups; enable standard token exchange when
  using separate MCP and broker audiences.
- **Auth0/Okta/Entra-compatible issuers:** create an API audience for the broker, add required
  custom claims through supported actions/mappers, and ensure group claims fit token-size limits.
- **Dex/self-hosted providers:** confirm discovery exposes JWKS and token endpoints and that issued
  access tokens contain the configured audience.

Exact console labels change by IdP. The invariant is standards-level: discoverable issuer, signed
JWT access token, correct audience/scope, stable `sub`, and explicit claim mappings.

## Troubleshooting

- `401`: bearer missing/malformed, issuer/audience/signature/expiry/scope invalid.
- `403`: token valid, but no current resource grant matches.
- Graphit exchange error: RFC 8693 disabled, client authentication wrong, target audience/resource
  not permitted, or invalid subject token.
- Admin callback rejected: redirect URI mismatch, code/state/nonce/PKCE failure, invalid/missing
  role claim, or effective roles lack `session.read`.
