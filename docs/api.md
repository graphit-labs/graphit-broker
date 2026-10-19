---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
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

# HTTP API

The [native Device flow](rust-device-authorization.md) mounts code issuance, LOCAL browser consent and access-only JWT polling. Discovery announces Device only with OIDC and LOCAL operational. Focused HTTP/browser contracts are qualified locally on Linux.

The native token endpoint also supports [refresh rotation](rust-oidc-refresh.md),
with original grant expiry and family revocation on valid reuse.
[Native explicit revocation](rust-oidc-revocation.md) adds `POST /oauth/revoke` for bound raw
access/refresh disposal, without changing local JWT validity until expiry.
Its explicitly enabled [dynamic registration](rust-oidc-registration.md) adds
`POST /oauth/register` for public client metadata with known SQL COMMIT.

The [native Rust storage server](rust-broker-server.md) currently mounts health/readiness, public configured keys, composed storage credentials and filesystem buckets. Enabling its native OIDC section adds [authorization-code exchange](rust-oidc-token-exchange.md) at `POST /oauth/token`; [federated code/refresh grants](rust-oidc-federated-grants.md) use the common upstream verifier independently of administration. The [shared upstream callback](rust-oidc-browser-callback.md) completes protected OAuth flows independently of Administration and returns query/fragment/form_post responses. The [public browser transport](rust-oidc-browser-authorization.md) adds GET/POST `/oauth/authorize` and `/oauth/login`, bound LOCAL stages and upstream selection. HEAD returns405 before effects; OIDCoff leaves404. [Native discovery](rust-oidc-discovery.md) serves both well-known documents with GET/HEAD when OIDC is enabled, using the configured literal issuer and existing `/v1/oidc/keys`. Remaining OP endpoints remain unmounted. Its optional [native administration section](rust-admin-session-http.md) adds GET/HEAD `/admin/api/v1/session` for a signed LOCAL access JWT and current SQL `session.read` permission. The explicit [native Cookie transport](rust-admin-cookie-session.md) adds genuine LOCAL and [federated cookie](rust-admin-federated-cookie.md) session read and confirmed CSRF/logout. Enabled [native LOCAL password/MFA login](rust-admin-local-login.md) additionally mounts GET/HEAD `/admin/api/v1/login-options`, POST `/admin/auth/local` and POST `/admin/auth/local/continue`, requiring cookie transport. The [native upstream browser adapter](rust-admin-upstream-login.md) serves the existing HTML and composes real OIDC begin/callback with H2 cookies. [Native role and assignment writes](rust-admin-rbac.md) are mounted for PostgreSQL, with current `roles.write`, cookie CSRF and known-COMMIT responses. [Native resource-grant writes](rust-admin-grants.md) use the same current authorization and cookie CSRF requirements. [Native LOCAL user/MFA/service-credential writes](rust-admin-users.md) are mounted for PostgreSQL and the HTTP lifecycle. The full release API catalog below is not an advertisement of unimplemented routes in that binary.

The same enabled administration block mounts the seven [native administrative reads](rust-admin-read.md): GET/HEAD `projects`, `roles`, `role-assignments`, `local-users`, `principals`, `grants` and `config` beneath `/admin/api/v1/`. They require their own current SQL action, independently of `session.read`, and share genuine configured JWT, opaque, upstream bearer and cookie verification. Reads emit no cookie and require no CSRF token. Grant ETag/body use the same revision; configuration is an effective, typed, redacted deployment view.

The optional native `administration.local_bearer` block adds [opaque LOCAL/service session read](rust-admin-local-bearer-session.md) to that same endpoint.
It requires its own explicit audience, identity JSON cap and scope list when enabled;
current SQL `session.read` remains necessary. Known nonempty cookies have priority
and never fall through to Bearer. The [native Cookie producer and confirmed logout](rust-admin-cookie-session.md) are consumed by [native HTTP password/MFA login](rust-admin-local-login.md); RBAC writes share this genuine ingress and their own current `roles.write`; [LOCAL user lifecycle writes](rust-admin-users.md) require current `users.write`.

The [native password admission producer](rust-local-password-admission.md) bounds initial LOCAL password work and password-change KDFs through one engine. Its per-username lockout has independent expiry; only a genuine current SQL password proof with known COMMIT clears failures. Fixed trusted HTTPS CAPTCHA, cancellation retention and joined KDF shutdown are producer capabilities; [native LOCAL startup/options/login/continuation](rust-admin-local-login.md) uses that shared engine and admission owner. No new HTTP route or configuration default is delivered by that library.

The common native `auth.oidc` provider set adds [federated bearer session read](rust-admin-upstream-session.md).
It verifies one configured issuer with mature discovery/JWKS/JWS support, explicit
resource-token policy and limits, then reads current SQL system permissions.
Claim roles replace SQL assignments only when their selector is configured;
username never maps an external identity to a LOCAL account. The [federated cookie consumer](rust-admin-federated-cookie.md) uses genuine browser proofs in
the library and [native browser adapter](rust-admin-upstream-login.md). The separate [native federated OAuth grant backend](rust-oidc-federated-grants.md) consumes genuine OAuth proof for token exchange/refresh; the [shared callback](rust-oidc-browser-callback.md) provides OAuth completion and response modes. The [public authorize/login transport](rust-oidc-browser-authorization.md) consumes that callback; [native discovery](rust-oidc-discovery.md) advertises their configured endpoints.

Its explicit [native PROJECT section](rust-project-access-http.md) mounts POST `/v1/project/access/authorize` with Broker JWT authentication and current SQL grants. It requires scopes, grant/body caps and timeout when enabled; absent/false leaves the route unmounted. Read and Write remain independent for Task, Memory, Knowledge and AST; Hub admits only Read using the current hub capability and matching project. Hub Write is invalid. JWT/scopes/roles alone grant no PROJECT permission.

Its explicit [native Presence section](rust-presence-server.md) mounts inventory and HTTP1 WebSocket realtime with one mandatory authentication selector: `broker_jwt` uses configured JWT trust, while `local_opaque` uses current SQL access/service credentials and also serves the existing partial inventory LIST. Both modes require explicit caps, scopes and budgets; absent/false leaves these routes unmounted. Publish and own-read require every registered project, or an explicit Any grant for an empty inventory. Realtime applies current Presence and PROJECT section Read grants; it rechecks mutable authorization on operations. The owned runtime closes and joins before SQL during shutdown.

In the release API catalog below, JSON decoders reject unknown fields and oversized bodies.
Consumer endpoints accept
`Authorization: Bearer ACCESS_TOKEN`; omitting the header selects the anonymous principal.
Malformed or invalid credentials return `401`, a valid principal without a matching grant
returns `403`, and disabled capabilities return `404`.

## Health and discovery

- `GET /healthz` — process liveness.
- `GET /readyz` — runtime/database readiness.
- `GET /.well-known/graphit-broker` — public capability negotiation.
- `GET /.well-known/openid-configuration` — standard OpenID Provider discovery when local or upstream OIDC browser login is enabled.

The native Rust documents use `authentication.type: "oidc"`, the four CLI/DCR scopes,
only the configured API audience and literal `oidc.accepted_resources` as `mcp_resources`.
`auth.issuer` must equal `server.public_url` literally when OIDC is enabled.
OpenID discovery returns404 when OIDC is disabled; Native JWKS remains mounted independently.
Graphit discovery remains available when an embedding, rerank or S3 credential service is enabled.
Registration is advertised only when enabled. See the [native schema and example](rust-oidc-discovery.md).
Enabled storage publishes `services.s3_credentials` with protocol `graphit-s3-credentials-v3`
and path `/v1/s3/credentials`, with or without OIDC. Disabled storage omits that descriptor.
Discovery selects the service; the authenticated STSv3 response supplies its current authorization
revision, topology and temporary credentials. Discovery does not invent an authorization revision.
The release example below retains the release schema and capabilities:

Example release discovery:

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
    "scopes": ["openid", "profile", "email", "offline_access"],
    "redirect_uri_path": "/oauth/callback"
  },
  "services": {
    "hub_access": {
      "protocol": "graphit-hub-access-v1",
      "path": "/v1/hub/access/resolve",
      "authorization_revision": "7"
    },
    "s3_credentials": {
      "protocol": "graphit-s3-credentials-v3",
      "path": "/v1/s3/credentials"
    },
    "embeddings": {
      "protocol": "graphit-embeddings-v1",
      "path": "/v1/embeddings",
      "model": "deployed-embedding-model",
      "model_revision": "deployment-r1",
      "recipe": "retrieval-v1",
      "revision": "embedding-space-1",
      "dimensions": 1536,
      "max_batch": 256
    },
    "rerank": {
      "protocol": "graphit-rerank-v1",
      "path": "/v1/rerank",
      "model": "deployed-reranker",
      "model_revision": "deployment-r1",
      "recipe": "native-rerank-v1",
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

The [native Rust composition](rust-broker-server.md#native-embeddings) authorizes the current SQL `embeddings` capability before decoding or cache/provider work. Every cache hit requires fresh authorization. Enabled Graphit discovery publishes the effective service revision, dimensions and limits; disabled requests return `404 capability_disabled`. Partial provider failure returns a finite whole-request error while independently valid complete-response items may remain durably cached.

`POST /v1/embeddings` uses `graphit-embeddings-v1`, with indexed embedding results and its own query/document input envelope:

```json
{"input":["first text","second text"],"input_type":"document"}
```

The request accepts `input` and optional `input_type`; `model` and `route` are rejected as unknown
fields. The broker invokes its configured model, validates dimensions and
indexes, and returns `X-Graphit-Embedding-Revision`,
`X-Graphit-Embedding-Dimensions`, and `X-Graphit-Cache: HIT|MISS`.

The response contains `object`, `data`, optional `usage`, and `graphit` metadata with `model`, `model_revision`, `recipe`, the distinct service `revision`
and `dimensions`. The configured model identity is exposed only inside `graphit`; requests cannot select a different model or service alias.

`input_type` is an optional Graphit extension with values `query` and `document`; omitted means
`document`. It lets the broker translate asymmetric retrieval semantics to Cohere, Voyage, Google,
or the local model while leaving the response contract stable.

## Rerank

The Rust HTTP adapter uses the separate current SQL [`rerank` admission](authorization.md#native-rerank-sql-admission). CPU GGUF inference requires an explicit manifest and GGUF bundle. Generic inference support does not establish model relevance or GPU/other-platform support.

`POST /v1/rerank`:

```json
{"query":"atomic authorization","documents":["doc a","doc b"],"top_n":2}
```

The request accepts `query`, `documents`, and optional `top_n`; `model` and `route` are rejected
as unknown fields. The broker selects the upstream model from its own configuration.
Query and each document must contain non-whitespace text, within configured byte and
document-count limits. Omitted, null or zero `top_n` selects all documents; otherwise
it must be an integer from one through the document count. Duplicate fields, wrong
types and trailing JSON are rejected.

Every request, including a cache hit, authenticates and reads current grants before
body/provider/cache processing. The adapter reauthorizes from genuine SQL once
more after computation, preserving the first authentication/request cutoff before
cache or response publication. Cache scope binds canonical principal/organization,
provider/model identity, revision and all request data. Only complete successful
responses are cached. HIT/MISS describes that response cache, never authority.

Errors include `401 unauthorized`, `403 forbidden`, `503 authorization_unavailable`,
`400 invalid_json`/`invalid_request`, `413 request_too_large`,
`404 capability_disabled` and `502 upstream_failed`; responses do not include
provider bodies or credentials.

The response contains indexed relevance scores under the versioned Graphit common contract. Its `graphit` object contains `model`, `model_revision`, `recipe` and the distinct service `revision`, exactly matching discovery. Rerank does not advertise an embedding dimension. Remote model revision and recipe are explicit operator declarations; GGUF derives them from its verified manifest and effective identity. They participate in the cache identity. Selecting an embedding protocol explicitly enables cosine scoring; a native scorer failure does not silently select embeddings.
Native rerank providers supply those scores directly. Embedding-only providers are adapted by
cosine-scoring the configured provider's query and document vectors, then applying `top_n` with
original-index tie breaking. Headers include `X-Graphit-Rerank-Revision` and `X-Graphit-Cache`.

## Temporary S3 credentials

Native Rust [session issuance](rust-filesystem-storage-session.md), [objects/CAS and listing/COPY/batch](rust-filesystem-object-store.md), [multipart](rust-filesystem-multipart.md) and the [S3s gateway](rust-filesystem-s3-gateway.md) are server components. The gateway has a real TCP/SQL/MAC/SigV4 fixture. The [mixed credentials service and Presence adapter](rust-storage-credentials-service.md) select the configured AWS or filesystem issuer from the current SQL grant; Root server/listener integration and native client cutover have separate qualification.

The Rust Native PROJECT router accepts `task`, `memory`, `knowledge`, `ast` and
`hub` with the strict project body and fourteen-field response below. [PROJECT Hub](rust-project-hub-metadata-events-storage.md)
preserves registry/artifacts and adds exact `v1/projects/{id}/hub/metadata` and
`v1/projects/{id}/hub/events` roots without a new module or body field. Its corpus
extension has [separate HTTP/STS/S3 qualification](rust-project-corpus-storage-credentials-http.md);
a DATA URI does not supply permission. The native Rust [USER Memory extension](rust-user-memory-storage-credentials-http.md)
requires exactly `{"scope":"user","module":"memory","installation_id":"Install-A"}`;
its fifteen-field response adds the admitted installation, uses scope user and
module memory, and keeps project_id empty. Unknown/duplicate/null/incompatible
fields fail after actual authentication. The [Global Hub extension](rust-global-hub-storage-credentials-http.md)
accepts exactly two fields, scope/module hub, returning fourteen fields with an empty
project_id and no installation_id, after current nonPROJECT Hub plus S3 admission.

`POST /v1/s3/credentials` requires an authenticated bearer, one framework-selected storage
scope, and the Graphit module that will use the objects. Project data uses an immutable project
ULID; user memory and shared Hub metadata have separate scopes:

```json
{"scope":"project","project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"task"}
```

Project scope accepts `task`, `memory`, `knowledge`, `ast`, or `hub`. Native Rust USER
requires the complete pair and installation body
`{"scope":"user","module":"memory","installation_id":"Install-A"}`.
The shared Hub body is exactly `{"scope":"hub","module":"hub"}`; its fixed roots
are `v1/hub/global/registry` and `v1/hub/global/rules`. Neither project nor
installation IDs are accepted, including explicit null values. Unknown, duplicate,
missing or null fields, incompatible scope/module pairs, missing project IDs,
project IDs on USER, installation IDs on PROJECT, and unsafe IDs are rejected.

The broker evaluates the current grants that apply to the verified caller and requested scope,
selects one route for that scope, intersects any configured prefix templates with the fixed scope
roots and issues through the selected configured driver. AWS uses an inline STS session policy; filesystem uses a native signed storage session. The request cannot choose a route, operation,
prefix, policy, role, bucket, endpoint, or duration. A project ID identifies the resource being
authorized; the module narrows that resource to its fixed object roots. Neither field supplies
authorization or an arbitrary object prefix.

```json
{
  "access_key_id": "ASIA...",
  "secret_access_key": "...",
  "session_token": "...",
  "expires_at": "2026-09-09T18:00:00Z",
  "bucket": "graphit-artifacts",
  "region": "us-east-1",
  "endpoint": "https://s3.example.com",
  "conditional_delete": false,
  "copy_if_not_exists": "multipart",
  "prefixes": ["graphit"],
  "authorization_revision": "7",
  "scope": "project",
  "project_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "module": "task"
}
```

The current Rust STSv3 contract requires the boolean `conditional_delete` in every
successful response. It describes atomic `If-Match` DELETE support, independently
of grants; S3 configuration defaults to false and the native Filesystem issuer
returns true. Whole-artifact and final-version removal must fail before an effect
when false. Partial conditional PUT remains available; HEAD followed by DELETE
cannot replace an atomic condition. See the [capability contract](rust-hub-storage-credentials-http.md#conditional-delete-capability).

The required `copy_if_not_exists` enum selects create-only object promotion:
`multipart` for S3 or `if_none_match` for Filesystem. The consumer uses the SDK
multipart-copy strategy or conditional CopyObject respectively. This value is
independent of DELETE support, grants and operator settings; omitted/unknown
wire strategies are invalid. See the [copy contract](rust-hub-storage-credentials-http.md#create-only-copy-strategy).

Every successful call mints a new session. The response is marked `Cache-Control: no-store`.
The access key, secret, and session token are temporary and must be treated as secrets. Permanent
route credentials and the generated policy are never returned. `scope`, `project_id`, and `module`
let the client reject a response that does not match its request.

A route configured with the `filesystem` driver answers this same contract, with `endpoint`
pointing at the broker itself. The broker then mints the credentials and serves the objects from a
local volume at `<endpoint>/<bucket>/<key>` in path style with Signature Version 4: `GET`, `HEAD`,
`PUT`, `COPY`, and `DELETE` on an object, `ListObjectsV2`, batch delete, and multipart upload,
with ranged reads and the `If-Match`/`If-None-Match` conditional writes. Versioning, bucket
management, cross-bucket copy, and `UploadPartCopy` return `NotImplemented`. A request is authorized against the prefixes its own session carries, so
a project session reaching outside its prefixes gets `AccessDenied` exactly as the STS policy
would refuse it. The session carries that authorization itself, signed and never stored, so it
expires rather than being revoked — the same bound an STS session has. See [configuration](configuration.md#the-filesystem-driver).

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

`GET /admin/api/v1/login-options` is public and returns `local` plus the ordered
`oidc_providers` array of public provider IDs and display names, for example
`{"local":true,"oidc_providers":[{"id":"oidc_...","name":"Corporate SSO"}]}`. When the next
local attempt would require CAPTCHA, it also reports the same public
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
- `GET /oauth/oidc/callback` — completes an upstream OIDC login and resumes the [Graphit Code](https://github.com/graphit-labs/graphit-code) authorization;
- `POST /oauth/device/authorize` — create a device/user code pair for headless CLI login;
- `GET/POST /oauth/device` — user-facing device approval;
- `POST /oauth/token` — standard Authorization Code or rotating refresh-token exchange; it also accepts the separate access-token-only device grant;
- `POST /oauth/revoke` — revoke a Broker-issued OIDC access or refresh token without revealing whether it existed;
- `GET/POST /oauth/userinfo` — standard claims for a broker-issued access token.
- `POST /oauth/introspect` — [native token introspection](rust-oidc-introspection.md), authorized by a Broker access Bearer and restricted to its client/subject.
- `GET/POST /oauth/end-session` — [native RP-initiated disposal](rust-oidc-end-session.md) with mandatory signed ID hint and no redirects.

The Broker is an OpenID Provider implemented with `github.com/zitadel/oidc/v3`. The public native
client uses Authorization Code, PKCE S256, `state`, `nonce`, and no client secret. Its callback has
the configured exact path on a dynamic loopback port. Graphit Code learns issuer, client ID, scopes,
and callback path from Broker discovery, then uses only standard OIDC discovery and endpoints; it
never receives upstream IdP configuration. ID and access tokens are signed with EdDSA. The ID token
exposes a stable, pairwise-style `sub` derived from the underlying canonical identity. The access
token is a JWT verifiable through discovery/JWKS; it uses `authentication.access_token_audience`,
carries the granted standard OIDC scopes plus client and identity claims, and expires after ten
minutes by default.
Requesting `offline_access` produces an opaque refresh token with rotation and family reuse
detection. Token responses are `Cache-Control: no-store`; SQL stores no raw JWT or refresh token,
only the access-token `jti`, domain-separated credential HMACs, and lifecycle metadata. In the
[native Rust server](rust-oidc-refresh.md#atomic-rotation-and-reuse), SQL revocation prevents further
refresh and grant operations; already issued access JWTs remain locally verifiable until `exp`.
[Native explicit revocation](rust-oidc-revocation.md) is mounted and advertised by
[native discovery](rust-oidc-discovery.md). [Native UserInfo](rust-oidc-userinfo.md) and [authorized introspection](rust-oidc-introspection.md) are also mounted and advertised. Introspection accepts Bearer authority, never a public client ID with an empty Basic password. [Native end-session](rust-oidc-end-session.md) accepts GET/POST with a required signed ID hint, revokes its SQL subject/client pair and returns204 without redirects. Expired ID hints and removed DCR clients remain eligible for their own disposal.

The device grant is deliberately separate from the Graphit Code browser login contract. It issues
only a short-lived API access token. The [native SQL producer](rust-device-authorization.md)
signs that access token as a Broker JWT with empty effective scope, granting no scope-based
capabilities. Omit `scope` or send an empty value; any nonempty request, including `openid`,
`profile`, `offline_access` or custom names, is rejected before SQL. Identity claims are signed
user data, not client-supplied grants. The native HTTP/browser flow uses explicit one-use consent after LOCAL authentication; recovery codes are shown before the consent buttons. Passwordless `gb_sc_...` service credentials are managed and revoked by
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

## Static icon

`GET /favicon.svg` serves the existing administrative SVG with `image/svg+xml; charset=utf-8`, `X-Content-Type-Options: nosniff` and immutable public caching for 31536000 seconds. `HEAD` returns the same metadata without the body. The native executable serves this independently of administrative authentication.

The Rust server advertises `services.s3_credentials` only when storage and its STS issuer are
configured and enabled. A valid discovery omitting that descriptor selects local record storage
in Graphit. The descriptor identifies the STSv3 endpoint; the current authorization revision is
returned by the authorized credentials exchange rather than fabricated in public metadata.
PROJECT/version and USER/installation isolation remain enforced by the storage credential policy.
