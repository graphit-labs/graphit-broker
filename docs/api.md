# HTTP API

All JSON request decoders reject unknown fields and oversized bodies. Consumer endpoints accept
`Authorization: Bearer ACCESS_TOKEN`; omitting the header selects the anonymous principal.
Malformed or invalid credentials return `401`, a valid principal without a matching grant
returns `403`, and disabled capabilities return `404`.

## Health and discovery

- `GET /healthz` — process liveness.
- `GET /readyz` — runtime/database readiness.
- `GET /.well-known/graphit-broker` — public capability negotiation.
- `GET /.well-known/openid-configuration` — standard OpenID Provider discovery when local or upstream OIDC browser login is enabled.

Example discovery:

```json
{
  "version": "1",
  "issuer": "https://broker.example",
  "authentication": {
    "schemes": ["anonymous", "bearer"],
    "audiences": ["graphit-broker"],
    "access_token_audience": "graphit-broker",
    "type": "openid_connect",
    "issuer": "https://broker.example",
    "client_id": "graphit-cli",
    "scopes": ["openid", "profile", "email", "graphit.use", "offline_access"],
    "redirect_uri_path": "/oauth/callback"
  },
  "services": {
    "hub_access": {
      "protocol": "graphit-hub-access-v1",
      "path": "/v1/hub/access/resolve",
      "authorization_revision": "7"
    },
    "s3_credentials": {
      "protocol": "graphit-s3-credentials-v2",
      "path": "/v1/s3/credentials",
      "authorization_revision": "7"
    },
    "embeddings": {
      "protocol": "openai-embeddings-v1",
      "path": "/v1/embeddings",
      "revision": "embedding-space-1",
      "dimensions": 1536,
      "max_batch": 256
    },
    "rerank": {
      "protocol": "graphit-rerank-v1",
      "path": "/v1/rerank",
      "revision": "rerank-route-1",
      "max_documents": 1000
    }
  }
}
```

Only enabled AI/S3 services appear. `hub_access` always appears because SQL grants are the
broker's authorization contract.

## Hub access resolution

`POST /v1/hub/access/resolve` takes one empty JSON object. Identity is derived only from the
verified bearer or absence of a bearer.

```json
{
  "v": 1,
  "authorization_revision": "7",
  "subject": "https://identity.example|00u123",
  "selectors": [
    {"id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
    {"all": true}
  ]
}
```

Selectors are deduplicated. Current broker-managed grants emit exact project IDs or `all`.
`Cache-Control: no-store` is returned. Graphit compares the response revision with discovery;
a concurrent change fails the operation closed.

## Embeddings

`POST /v1/embeddings` follows the OpenAI embeddings input/result shape:

```json
{"input":["first text","second text"],"input_type":"document"}
```

The request accepts `input` and optional `input_type`; `model` and `route` are rejected as unknown
fields. The broker invokes its configured model, validates dimensions and
indexes, and returns `X-Graphit-Embedding-Revision`,
`X-Graphit-Embedding-Dimensions`, and `X-Graphit-Cache: HIT|MISS`.

The response contains `object`, `data`, optional `usage`, and `graphit` metadata with `revision`
and `dimensions`. It does not expose a `model` field or a service alias.

`input_type` is an optional Graphit extension with values `query` and `document`; omitted means
`document`. It lets the broker translate asymmetric retrieval semantics to Cohere, Voyage, Google,
or the local model while leaving the response contract stable.

## Rerank

`POST /v1/rerank`:

```json
{"query":"atomic authorization","documents":["doc a","doc b"],"top_n":2}
```

The request accepts `query`, `documents`, and optional `top_n`; `model` and `route` are rejected
as unknown fields. The broker selects the upstream model from its own configuration.

The response contains indexed relevance scores under the versioned Graphit common contract.
Native rerank providers supply those scores directly. Embedding-only providers are adapted by
cosine-scoring the configured provider's query and document vectors, then applying `top_n` with
original-index tie breaking. Headers include `X-Graphit-Rerank-Revision` and `X-Graphit-Cache`.

## Temporary S3 credentials

`POST /v1/s3/credentials` requires an authenticated bearer and one framework-selected storage
scope. Project data uses an immutable project ULID; user memory and shared Hub metadata have
separate scopes:

```json
{"scope":"project","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}
```

The other valid bodies are `{"scope":"user"}` and `{"scope":"hub"}`. Unknown fields,
missing project IDs, project IDs on non-project scopes, and unsafe project IDs are rejected.

The broker evaluates the current grants that apply to the verified caller and requested scope,
selects one route for that scope, intersects any configured prefix templates with the fixed scope
roots, builds an inline session policy, and calls STS. The request cannot choose a route, operation,
prefix, policy, role, bucket, endpoint, or duration. A project ID identifies the resource being
authorized; it never supplies authorization or an object prefix.

```json
{
  "access_key_id": "ASIA...",
  "secret_access_key": "...",
  "session_token": "...",
  "expires_at": "2026-09-09T18:00:00Z",
  "bucket": "graphit-artifacts",
  "region": "us-east-1",
  "endpoint": "https://s3.example.com",
  "prefixes": ["graphit"],
  "authorization_revision": "7",
  "scope": "project",
  "project_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV"
}
```

Every successful call mints a new session. The response is marked `Cache-Control: no-store`.
The access key, secret, and session token are temporary and must be treated as secrets. Permanent
route credentials and the generated policy are never returned. `scope` and `project_id` let the
client reject a response that does not match its request.

## Administration API

Administration accepts a secure session cookie created by OIDC or by validating an existing
username-selected SQL local-user password at `POST /admin/auth/local` with JSON fields
`username` and `password`. A `200` response can require `password-change`, `mfa-enrollment`, or
`mfa`; continue at `POST /admin/auth/local/continue` with the opaque `challenge_token` plus either
`new_password` or `code`. MFA enrollment returns an `otpauth_uri`, QR data URL, and manual secret;
successful enrollment returns recovery codes once. State changes require the session CSRF
token. The password is used only to create a session and is never accepted as a Bearer credential.
A valid OIDC, local access, or service Bearer is accepted directly through the token authenticator.
Protected routes are:

The password is a sensitive request-body value: send it only over HTTPS from the UI or another
client that does not place it in process arguments, shell history, URLs, or logs. The response does
not echo it. Local passwords contain at least 15 Unicode characters. Invalid credentials return
`401`; after the configured per-username failure threshold, local authentication returns `429`
with `Retry-After` until the lockout expires. Authentication saturation is reached when running and
waiting local calls equal `max_concurrent * saturation_multiplier`; further calls return `429`
without starting Argon2id or recording a password failure.

When adaptive CAPTCHA is configured and the current request reaches
`max(1, ceil(max_concurrent * trigger_multiplier))`, the initial password request must also contain a
provider proof. `POST /admin/auth/local` returns `403` with error code `captcha_required` and a
public `captcha` object containing `provider`, `site_key`, and—only for Turnstile—the flow `action`.
Retry with the same username/password plus JSON field `captcha_token`. Browser forms use the native
`cf-turnstile-response` or `g-recaptcha-response` field. A missing, rejected, expired, replayed,
wrong-hostname/wrong-action proof, provider error, or timeout fails before Argon2id. Error responses
never return the submitted password, CAPTCHA token, provider secret, or provider diagnostics.

| Route | Action | Purpose |
|---|---|---|
| `GET /admin/api/v1/session` | `session.read` | identity, effective roles, `role_source`, actions, CSRF |
| `GET /admin/api/v1/projects` | `projects.read` | current identity's exact Hub projects and CLI commands |
| `GET /admin/api/v1/config` | `configuration.read` | redacted deployment YAML (read-only) |
| `GET /admin/api/v1/grants` | `grants.read` | list grants and ACL ETag |
| `POST /admin/api/v1/grants` | `grants.write` | create a grant |
| `PUT /admin/api/v1/grants/{id}` | `grants.write` | replace one grant |
| `DELETE /admin/api/v1/grants/{id}` | `grants.write` | delete one grant |
| `GET /admin/api/v1/principals` | `grants.read` | configured principal hints |
| `GET /admin/api/v1/roles` | `roles.read` | roles and supported actions |
| `PUT/DELETE /admin/api/v1/roles/{role}` | `roles.write` | manage role definition |
| `GET/POST/DELETE /admin/api/v1/role-assignments` | role action | manage exact-sub assignments |
| `GET/POST /admin/api/v1/local-users` | `users.read` / `users.write` | list or create SQL local users |
| `PUT/DELETE /admin/api/v1/local-users/{username}` | `users.write` | update or remove a local user |
| `POST /admin/api/v1/local-users/{username}/mfa/reset` | `users.write` | revoke and require reenrollment of a human user's MFA |
| `GET/POST /admin/api/v1/local-users/{username}/credentials` | `users.read` / `users.write` | list or issue credentials for a service identity |
| `DELETE /admin/api/v1/local-users/{username}/credentials/{id}` | `users.write` | revoke a service credential |

`GET /admin/api/v1/login-options` is public and reports whether OIDC and local-password login are
available. When the next local attempt would require CAPTCHA, it also reports the same public
`captcha` object so the UI can render the selected widget; it contains no credentials or identity
data.

`trigger_multiplier` defaults to `1.5` when omitted. An explicit `0` makes every initial
local-password request require CAPTCHA; positive fractional values can place the threshold below
`max_concurrent`.

The configuration response replaces `authentication.token_pepper` and every OIDC client secret
with `[configured-secret]`. Local-user responses omit password hashes entirely; no response exposes
the pepper. Role assignments use canonical `issuer|subject` values, and every authenticated
principal has the effective default `user` role.

## Graphit Code OpenID Connect API

- `GET /.well-known/openid-configuration` — standard provider metadata;
- `GET /oauth/keys` — Ed25519 JSON Web Key Set used to verify ID and access tokens;
- `GET/POST /oauth/authorize` — standard authorization endpoint; transfers control to the Broker-owned local/upstream method page;
- `GET /oauth/authorize/callback` — resumes the library-owned authorization after the selected method succeeds;
- `GET /oauth/oidc/callback` — completes an upstream OIDC login and resumes the Graphit Code authorization;
- `POST /oauth/device/authorize` — create a device/user code pair for headless CLI login;
- `GET/POST /oauth/device` — user-facing device approval;
- `POST /oauth/token` — standard Authorization Code or rotating refresh-token exchange; it also accepts the separate access-token-only device grant;
- `POST /oauth/revoke` — revoke a Broker-issued OIDC access or refresh token without revealing whether it existed;
- `GET/POST /oauth/userinfo` — standard claims for a broker-issued access token.
- `POST /oauth/introspect` — standard token introspection for the configured public client.
- `GET/POST /oauth/end-session` — standard OpenID RP-initiated logout endpoint.

The Broker is an OpenID Provider implemented with `github.com/zitadel/oidc/v3`. The public native
client uses Authorization Code, PKCE S256, `state`, `nonce`, and no client secret. Its callback has
the configured exact path on a dynamic loopback port. Graphit Code learns issuer, client ID, scopes,
and callback path from Broker discovery, then uses only standard OIDC discovery and endpoints; it
never receives upstream IdP configuration. ID and access tokens are signed with EdDSA. The ID token
exposes a stable, pairwise-style `sub` derived from the underlying canonical identity. The access
token is a JWT verifiable through discovery/JWKS; it uses `authentication.access_token_audience`,
contains `graphit.use`, client and identity claims, and expires after ten minutes by default.
Requesting `offline_access` produces an opaque refresh token with rotation and family reuse
detection. Token responses are `Cache-Control: no-store`; SQL stores no raw JWT or refresh token,
only the access-token `jti`, domain-separated credential HMACs, and lifecycle metadata. Revocation
is immediate at Broker endpoints; offline JWKS validators accept an issued access JWT until `exp`.

The device grant is deliberately separate from the Graphit Code browser login contract. It issues
only a short-lived local API access token and rejects `offline_access`; it does not produce an ID
token or a refresh token. Passwordless `gb_sc_...` service credentials are managed and revoked by
the local-user administration API, not by the public OIDC client.

Grant writes require `If-Match` with the current ETag. A stale revision returns `409`; a missing
precondition returns `428`. There is no configuration write endpoint; update deployment
configuration and restart the broker.

## Error envelope

```json
{"error":{"code":"forbidden","message":"access denied","request_id":"..."}}
```

Upstream response bodies and secrets are never copied into public errors. `X-Request-ID` is
accepted when bounded and generated otherwise.
