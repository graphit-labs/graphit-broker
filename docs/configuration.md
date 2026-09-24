# Configuration reference

The broker reads strict YAML: unknown fields are errors. Environment expressions are expanded
before decoding:

- `${NAME}` — empty when unset;
- `${NAME:-fallback}` — use `fallback` when unset or empty;
- `${NAME:?message}` — fail startup with the supplied message.

Run `graphit-broker --config config.yaml --check-config` to validate without serving.

Without `--config` or `GRAPHIT_BROKER_CONFIG`, the executable reads
`.graphit/broker/config.yaml` beneath the current user's home directory. On Windows this resolves
through the Windows user profile; on Linux and macOS it resolves through the Unix home directory.
Set `GRAPHIT_GLOBAL_DIR` to relocate the entire `.graphit` root.

The expanded YAML document is the sole configuration authority. It is never serialized into SQL.
Change it through deployment/secret-management tooling and restart the broker to activate the new
configuration. `/admin/api/v1/config` is a redacted read-only view. Local users, Argon2id
verifiers, resource grants, roles, role assignments, login flows, and sessions remain durable SQL
state; the pepper and resource grants are never persisted from YAML.

## Database

| Field | Default | Meaning |
|---|---:|---|
| `driver` | `sqlite` | `sqlite`, `postgres`, or `mysql` |
| `dsn` | required | Driver-specific connection string |
| `connect_timeout` | `15s` | Timeout for the initial database connection; must be positive |
| `max_open_conns` | SQLite 1; remote 20 | Maximum pool connections |
| `max_idle_conns` | SQLite 1; remote 10 | Idle pool connections |
| `conn_max_lifetime` | `3m` | Maximum connection lifetime |

`dsn` has no hidden code default. The distributed configuration chooses both its environment name
and portable fallback:

```yaml
database:
  driver: sqlite
  dsn: "${BROKER_DATABASE_DSN:-~/.graphit/broker/broker.db}"
```

The executable has no special knowledge of `BROKER_DATABASE_DSN`; another YAML can choose another
name, a literal DSN, or a required reference such as
`${DATABASE_URL:?set the database connection}`. For SQLite and ONNX directory fields, a configured
leading `~/` is expanded through the operating-system user home on Linux, macOS, and Windows.
See [database backends](database.md).

`connect_timeout` uses a positive duration such as `5s` or `1m` and applies to the initial
database connection at startup. The SQL connection pool handles later reconnections as needed;
the broker has no configurable reconnection interval or retry count.

## Server

| Field | Default |
|---|---:|
| `address` | `:8080` |
| `public_url` | empty |
| `read_timeout` | `15s` |
| `write_timeout` | `60s` |
| `idle_timeout` | `120s` |
| `shutdown_timeout` | `15s` |
| `max_request_bytes` | 4 MiB |

`server.cors.allowed_origins` declares which browser origins may call the OAuth/OIDC endpoints:

```yaml
server:
  cors:
    allowed_origins: ["https://claude.ai"]
```

Empty is the default and emits no CORS headers at all, which is what the broker did before this
setting existed. Only a browser-based MCP client needs it; an agent whose runtime connects
server-side is unaffected. Credentials are deliberately not configurable, because OAuth here
authenticates with the `Authorization` header rather than cookies — which also makes the invalid
wildcard-with-credentials combination impossible to express. `WWW-Authenticate` is exposed so a
browser client can read the challenge on a failed request.

`public_url` is required when local or upstream browser authentication is enabled. It is the
OpenID Provider issuer and must be an origin without a path, query, or fragment. HTTPS is required
except for HTTP on `localhost` or a loopback IP such as `127.0.0.1` or `::1`. Private-network and
wildcard bind addresses do not qualify as loopback public URLs. Put the broker behind a TLS
reverse proxy in production. For local HTTP development, set `administration.cookie_secure: false`.

## Authentication

`authentication.token_pepper` is the single deployment secret used with domain separation for
local password preprocessing, administration sessions, upstream OIDC state, Broker OIDC subjects,
Ed25519 signing seeds, authorization grants, access/refresh records, MFA secrets,
and service credentials. It must contain at least 32 bytes whenever administration,
local login, or browser OIDC login is enabled and is never stored in SQL.

Local settings are grouped under `authentication.local`: `login`, `rate_limit`, `captcha`, `mfa`,
and `tokens`. The former flat `local_*` keys are rejected. The shared `token_pepper` remains directly
under `authentication`.

Local browser login is deployment-owned. It defaults to the value of `administration.enabled`, but
can be enabled independently for [Graphit Code](https://github.com/graphit-labs/graphit-code) login or disabled while keeping OIDC login:

```yaml
authentication:
  local:
    login:
      enabled: true
```

Local-password failures use a fixed-window limiter. Every field is optional and defaults as shown:

```yaml
authentication:
  local:
    rate_limit:
      max_failures: 5
      window: 1m
      lockout: 5m
      max_concurrent: 2
      saturation_multiplier: 4
```

Adaptive CAPTCHA is deployment-owned, disabled by default, and supports exactly one provider at a
time. `turnstile` renders Cloudflare Turnstile's managed widget; `recaptcha` renders Google
reCAPTCHA v2 Checkbox:

```yaml
server:
  public_url: https://broker.example.com
authentication:
  local:
    captcha:
      enabled: false
      provider: turnstile # or recaptcha
      site_key: "${BROKER_LOCAL_CAPTCHA_SITE_KEY}"
      secret_key: "${BROKER_LOCAL_CAPTCHA_SECRET_KEY}"
      trigger_multiplier: 1.5
      verification_timeout: 3s
```

When enabled, `server.public_url`, `provider`, `site_key`, and `secret_key` are required. The
provider is fixed to `turnstile` or `recaptcha`; Siteverify endpoints are not configurable. The
trigger must be between `0` and `local.rate_limit.saturation_multiplier`, inclusive; the timeout
must be between `500ms` and `10s`. The administration configuration response exposes the site key
and operational settings but replaces the secret key with `[configured-secret]`.

The threshold is `max(1, ceil(local.rate_limit.max_concurrent * trigger_multiplier))` per broker
process. Omitting `trigger_multiplier` uses the default `1.5`; setting it explicitly to `0` requires
CAPTCHA from the first attempt. Positive fractions allow the challenge to start before the Argon2id
worker limit—for example, `max_concurrent: 4` with `trigger_multiplier: 0.5` starts on the second
admitted attempt. With defaults `2 * 1.5`, the third admitted attempt requires CAPTCHA. The
admission slot is reserved before Siteverify, so external verification calls share the existing bounded capacity;
an absent proof causes no outbound call. A provider error or timeout fails the local login closed
only while CAPTCHA is required. OIDC login remains available. CAPTCHA applies only to the initial
password step of administration, Authorization Code, and Device Authorization—not password change
or MFA. Neither provider receives an IP address because the broker has no trusted-proxy policy.

Turnstile tokens are checked for success, exact hostname, and flow-specific action. reCAPTCHA v2
tokens are checked for success and exact hostname; the checkbox protocol does not return an action.
The providers enforce expiry and single use. Configure the same public hostname in the provider
console and use separate site keys for development and production.

Provider commercial limits can change. As checked on 2026-09-09, the
[Turnstile Free plan](https://developers.cloudflare.com/turnstile/plans/) allows unlimited
challenges and verification requests with up to 20 widgets and 10 hostnames per widget. Google
[reCAPTCHA Essentials](https://docs.cloud.google.com/recaptcha/docs/billing-information) permits
10,000 assessments per organization each month; without billing, requests fail after that quota,
while billed tiers charge beyond it.

Human local-user MFA is also deployment-owned and defaults to required:

```yaml
authentication:
  local:
    mfa:
      required: true
      issuer: Graphit Broker
      challenge_ttl: 10m
```

`issuer` is the label shown in TOTP applications. Challenges expire after `challenge_ttl`, which
must be between 2 and 30 minutes. Set `required: false` only when another deployment control
explicitly accepts single-factor local login; password-change enforcement remains active.

Five failures for one username within the window block that username for five minutes. There is no
failure counter or lockout across usernames. At most two expensive Argon2id checks run concurrently
per broker process. The saturation limit is `max_concurrent * saturation_multiplier` and includes
both running and waiting calls: the defaults admit eight calls, execute two, queue up to six, and
reject the ninth before the KDF. A queued call respects request cancellation and rechecks the
username lockout before starting Argon2id. Successful checks and saturation rejection do not
consume the per-username quota. Blocked or saturated HTTP requests return `429` with `Retry-After`.
All limits and durations must be positive, and their product must fit in an integer.

Broker OpenID Connect and automation credentials use these defaults:

```yaml
authentication:
  local:
    tokens:
      audience: graphit-broker
      cli_client_id: graphit-cli
      cli_redirect_path: /oauth/callback
      access_ttl: 10m
      refresh_ttl: 720h
      authorization_code_ttl: 1m
      device_code_ttl: 10m
      device_poll_interval: 5s
      service_credential_max_ttl: 8760h
      dynamic_registration: false
      mcp_resources: []
```

`mcp_resources` lists the canonical URIs of the Graphit MCP endpoints this deployment serves. It is
the single source for two jobs. It validates an RFC 8707 `resource` indicator on an authorization
request: an indicator outside the list, a relative URI, one carrying a fragment, or more than one in
the same request is rejected with `invalid_target` and no authorization code is issued. It is also
published in `/.well-known/graphit-broker`, which is how each Graphit daemon learns which resource it
is and therefore what to advertise as its OAuth protected resource metadata. Empty means no indicator
is accepted at all, so a deployment that never declares a resource cannot have tokens minted for an
audience it never authorized. Configuration loading trims and deduplicates the list, and rejects an
entry that is not an absolute URI or contains a fragment.

When a request carries an accepted indicator, the issued token's `aud` holds both the Broker audience
and that resource, and a refresh preserves the pair. Keeping the Broker audience is what lets the
same token continue to work against the Broker's own `/v1/*` API, which the Graphit daemon relays to
on the caller's behalf. The authorization-code and refresh-token requests may omit `resource`, in
which case the original grant is preserved. If either request repeats it, the value must exactly
match the single resource authorized earlier and must still be configured; another value or more
than one value returns `invalid_target` without consuming the code or refresh token. The Broker
deliberately allows one resource per grant even though RFC 8707 permits several, avoiding a bearer
token that either resource could replay against the other.

`dynamic_registration` opens RFC 7591 client registration at `POST /oauth/register` and advertises
it as `registration_endpoint` in `/.well-known/openid-configuration`. It is `false` unless the
deployment sets it, because enabling it lets anyone who can reach the Broker create a client. That is
the deliberate trade for letting a hosted MCP agent connect without an operator provisioning it by
hand: the agent discovers the Broker from the Graphit MCP endpoint, registers itself, and runs
Authorization Code with PKCE.

Registration only ever produces a **public** client, and the stored record has no secret column for
one to live in. A request is rejected with `invalid_client_metadata` when it asks for a confidential
`token_endpoint_auth_method`, a grant outside `authorization_code` and `refresh_token`, a response
type other than `code`, a scope the Broker does not support, or a redirect URI that is neither HTTPS
on a non-loopback host nor HTTP on loopback. Redirects carrying a fragment or embedded credentials
are refused as well. An HTTPS callback registers a web client; a loopback callback registers a native
one, which is what lets a desktop client vary its port. Registered clients get exactly the
capabilities of the configured CLI client and never more.

Desktop authorization is a standard public/native OIDC client and accepts only a loopback redirect
with a nonzero dynamic port and the configured exact path. PKCE method `S256`, `state`, `nonce`,
and `openid` are mandatory; `openid` because OIDC Core requires it, and no product-specific scope
beyond it, since a token's reach is decided by its audience. ID and access tokens use EdDSA and the public JWKS. Access
tokens are short-lived JWTs whose `aud` always contains `authentication.local.tokens.audience` and,
when requested, the validated MCP resource. Their signed claims include `sub`, `client_id`, `scope`,
`preferred_username`, and any non-empty optional identity attributes;
refresh tokens are issued only when `offline_access` is requested, rotate on every use, retain one
absolute lifetime, and revoke their family when reuse is detected. Service credential expiration
is mandatory and may not exceed `service_credential_max_ttl`.

The Broker consults SQL token state for its own API, userinfo, introspection, and revocation
endpoints, so revocation is immediate there. A service that validates an access JWT offline through
discovery/JWKS has no revocation lookup and will accept an already issued token until `exp`.

`authentication.oidc` is the shared list of trusted issuers for consumer bearer validation and
browser login. Each entry accepts `enabled` (default `true`). Setting it to `false` disables issuer
discovery, bearer validation, browser login, and continued use of its sessions and Broker-issued
grants. Its audiences are omitted from discovery. Inactive entries do not require valid integration
settings, but unknown YAML fields and required environment references are still checked. Every
enabled entry may configure browser-client fields and appears as a separate login choice. The Broker
can still serve its own OpenID endpoints through local login. Changes require a restart.

The following requirements apply to enabled entries:

| Field | Required | Meaning |
|---|---|---|
| `enabled` | no | Whether this upstream issuer is active; defaults to `true` |
| `display_name` | browser login | Login-button label, with at most 80 printable characters |
| `issuer` | yes | Exact HTTPS issuer used for discovery and signature validation |
| `audiences` | yes | At least one accepted broker audience |
| `required_scopes` | no | Every listed scope must be present in a token from this external issuer. Operator-defined and unrelated to the broker's own OpenID Provider, which requires no scope beyond `openid` |
| `client_id` | browser login | Confidential client ID used by the authorization-code flow |
| `client_secret` | no | Confidential client secret, normally injected from a secret manager |
| `redirect_url` | browser login | Exact `/oauth/oidc/callback` URL; HTTP is allowed only on loopback |
| `scopes` | no | Browser scopes; defaults to `openid profile email` |
| `require_nonce` | no | Require the authorization request nonce in the ID token; defaults to `true`. Set `false` only for Authorization Code providers that cannot return it; state, browser binding, PKCE, and all other ID-token validation remain enabled |
| `subject_claim` | yes | Stable identity selector; defaults to `sub` |
| `name_claim` | no | Display-name selector; defaults to `name` |
| `email_claim` | no | Email selector; defaults to `email` |
| `username_claim` | yes | Verified single-string claim selector |
| `organization_claim` | no | Verified single-string claim selector |
| `teams_claim` | no | Verified multi-string claim selector |
| `role_claim` | no | Authoritative additional system roles for this issuer |

Every claim selector accepts either an exact top-level claim key or an
[RFC 9535 JSONPath](https://www.rfc-editor.org/rfc/rfc9535.html) expression beginning with `$`.
Exact keys are checked first, so namespaced keys such as `https://claims.example.com/teams` and
literal keys containing dots work unchanged. As a selector shorthand, a non-JSONPath value whose
exact key is absent also supports dotted object traversal such as `organization.id`.
JSONPath should be used for arrays, wildcards, filters, slices, or unambiguous nested traversal:

```yaml
username_claim: "$.accounts[?@.primary == true].username"
organization_claim: "$.organization.id"
teams_claim: "$.groups[*].name"
```

Single-string mappings must select exactly one non-empty string. Multi-string mappings accept one
string, one string array, or multiple selected strings and flatten/deduplicate the result. Invalid
JSONPath fails configuration validation. The canonical identity is the verified issuer plus the
value selected by `subject_claim`, formatted `issuer|subject`. Username remains a separate mutable
login/display attribute and is never used as the stable RBAC key.

Local identities are not configuration. They are stored in the selected SQL backend and managed through
`/admin/api/v1/local-users` or the Local users screen. Each record has a unique username, immutable
stable subject, `human` or `service` kind, optional identity attributes, enabled state, revision,
and explicit role assignments. Human identities have an Argon2id PHC; service identities cannot
have passwords and instead use separately revocable credentials. A local password must contain at least 15 Unicode characters; there are no
character-class composition rules. The external pepper is `authentication.token_pepper`; it is never stored beside
the verifier. Changing a user's password, username, attributes, or enabled state increments its
revision and invalidates existing local browser sessions, access/refresh tokens, pending grants,
and service credentials. Role changes are resolved from SQL on the next request.

A password is accepted only by the administrative login, broker-owned authorization page, or device
verification page. It is never accepted in `Authorization`. Desktop CLI login uses OpenID Connect
Authorization Code with PKCE through the Broker-owned method chooser; headless login uses local
Device Authorization. Local and upstream browser methods both produce the same Broker OIDC session whose
raw values are never stored in SQL. Automation uses a credential attached to a `service` identity.
All local credentials are audience- and scope-bound and expire. The Broker's own request path also
checks revocation and the current identity revision. Broker-issued access JWTs validated by another
service through JWKS are intentionally self-contained and remain valid there until `exp`; use a
short `access_ttl` to bound that window. Omitting the header creates an anonymous principal, which
can work only when an explicit `anonymous` resource grant matches.

## Administration

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
      require_nonce: true
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
  cli:
    provider_name: organization-broker
    profile_name: organization-broker
```

There is no administration-specific OIDC provider. The same issuer and claim mappings validate
consumer bearers and populate browser identities; `client_id`, `client_secret`, `redirect_url`, and
`scopes` enable the browser authorization-code flow independently on each issuer. Each configured
browser client appears under its `display_name` in the login UI. A local-only UI may omit OIDC.
Session TTL must be between 5 minutes and 168 hours.

Browser login requires the ID-token `nonce` by default. An issuer configured with
`require_nonce: false` omits nonce from the authorization request and skips only that claim check.
Use the opt-out only for an Authorization Code provider that cannot return nonce; state, browser
binding, PKCE, signature, issuer, audience, expiry, and configured claim validation are unchanged.

`authentication.oidc[].role_claim` is optional. When absent, effective roles come from SQL
`role_assignments`. When configured, its additional role values are authoritative for that OIDC
identity and replace explicit SQL assignments for the same
canonical subject. Every authenticated identity additionally receives the built-in `user` role;
unknown claimed roles grant nothing. Local users always resolve their additional roles from SQL.
There is no superadmin bypass.

`administration.cli` supplies only the names used to render complete `graphit provider add --type
broker` and `graphit login` snippets. The public client ID and callback path come from
`authentication.local.tokens`; Graphit Code discovers both from the Broker and picks a free
loopback port.

Administration cookies are `HttpOnly` and `SameSite=Lax`. `administration.cookie_secure` defaults
to `true`; set it to `false` only for an explicitly configured loopback HTTP development server.

An enabled local user enters the UI with its SQL username and plaintext password. The password is
validated once and exchanged for a short-lived, `HttpOnly`, CSRF-protected session; only the
Argon2id verifier is persisted.

For a new database, run `graphit-broker --config config.yaml --bootstrap-admin`; automation may pipe
the password to `--bootstrap-admin-stdin`. The command accepts no username or secret argument,
creates the fixed local identity `admin` with roles `user` and `admin`, and refuses to modify a
database containing any local user. Continue user and role management through the UI/API. There is
no special superadmin subject or authorization bypass.

## ONNX upstreams

Local models use the same `upstream` configuration as HTTP providers:

```yaml
services:
  embeddings:
    enabled: true
    upstream:
      protocol: onnx
      model: coderankembed
      directory: "${BROKER_MODELS_DIRECTORY:-~/.graphit/broker/models}"
      device: cpu
      device_id: 0
  rerank:
    enabled: true
    upstream:
      protocol: onnx
      model: bge-reranker-base
      directory: "${BROKER_MODELS_DIRECTORY:-~/.graphit/broker/models}"
      device: cpu
```

`protocol: onnx` selects in-process inference. Each `model` names
`<directory>/<model>/manifest.json`. `directory` is required and is owned by YAML; the example
chooses an environment reference with a portable fallback. Services can use separate directories
and variable names. Model defaults are `coderankembed` for embeddings and
`bge-reranker-base` for rerank, with `device: cpu` and `device_id: 0`.

ONNX upstreams reject HTTP-only nonzero/nonempty options: `url`, `api_key`, `api_key_header`,
`api_key_scheme`, `send_dimensions`, and `timeout`. HTTP upstreams reject nonempty `directory`
or `device`, and nonzero `device_id`. Disabled services do not initialize or download models.

The former top-level `models` and service-level `backend`/`local` fields are no longer accepted.
Move model selection and device settings into each service's `upstream` and remove those fields.
There is no generation model selector or local generation service. Apply configuration changes by
restarting the broker. Manifest formats, acquisition policies, tensor semantics, and effective
identities are documented in the [local model catalog](models.md).

## Embeddings

Each AI service has one configured upstream. `upstream.model` selects its model; there is no
service-level `route` or client-side model selector. Discovery publishes the service path,
protocol, revision, and limits. Embedding compatibility uses the revision and dimensions.

```yaml
services:
  embeddings:
    enabled: true
    revision: embedding-space-2026-09-07.1
    dimensions: 1536
    max_batch: 256
    max_input_bytes: 1048576
    upstream:
      protocol: openai-embeddings-v1
      url: https://api.openai.com/v1/embeddings
      model: text-embedding-3-small
      api_key: "${OPENAI_API_KEY:?required}"
      api_key_header: Authorization
      api_key_scheme: Bearer
      send_dimensions: false
      timeout: 45s
    cache:
      ttl: 10m
      max_entries: 10000
```

The `cache` settings above bound only the in-memory complete-response cache. Individual
embeddings, including ONNX-local results, are also saved durably in the selected SQL database.
The SQL lookup uses an indexed SHA-256 input hash plus a compatibility fingerprint covering
provider, model, endpoint/local model identity, revision, dimensions, and input type. A batch
calls the model only for distinct missing inputs; valid results are saved even if another item
in the batch fails. SQL entries do not expire automatically.

`upstream.protocol: onnx` uses `upstream.model` for in-process inference; the default preset
is CodeRankEmbed-137M-INT8. Model files, tokenizer behavior,
prefixes, pooling, normalization, and dimensions belong to the selected manifest, not this service
block. `dimensions` may be omitted/zero for a local model and is inferred from its resolved
manifest and ONNX signature; a positive value is an assertion and startup rejects a mismatch.
`revision` is optional for local inference and becomes a readable prefix for the automatically
computed effective model identity.

For an HTTP provider, set `upstream.protocol` to one of the following. The public broker API
stays OpenAI-shaped while its adapter translates request and response fields:

| Provider | Protocol | Typical endpoint |
|---|---|---|
| OpenAI / compatible | `openai-embeddings-v1` or `openai-compatible` | complete `/v1/embeddings` URL |
| Cohere | `cohere` or `cohere-embed-v2` | complete `/v2/embed` URL |
| Voyage | `voyage` or `voyage-embeddings-v1` | complete `/v1/embeddings` URL |
| Google Gemini | `google`, `google-embed-content-v1beta`, `gemini`, or `gemini-embed-content-v1beta` | API base such as `/v1beta`, or complete `:batchEmbedContents` URL |

The broker always selects the configured model; a client-supplied model is ignored. For upstream
models the operator must change `revision` whenever the effective vector space changes. Local model
revisions include the catalog identity automatically. The response revision and dimensions are
part of Graphit's index-compatibility fingerprint. `input_type: query|document` selects the proper
asymmetric embedding mode; omission means `document`.

## Rerank

```yaml
services:
  rerank:
    enabled: true
    revision: rerank-route-2026-09-07.1
    max_documents: 1000
    max_document_bytes: 1048576
    upstream:
      protocol: cohere-v2
      url: https://api.cohere.com/v2/rerank
      model: rerank-v4.0-fast
      api_key: "${COHERE_API_KEY:?required}"
      api_key_header: Authorization
      api_key_scheme: Bearer
      timeout: 45s
    cache:
      ttl: 5m
      max_entries: 10000
```

`upstream.protocol: onnx` uses `upstream.model`; its default is the `bge-reranker-base` preset. Custom
cross-encoder inputs, output selection, prefixing, and score transformations are declared in the
bundle manifest. Native upstream protocols are `cohere`/`cohere-v2`, `voyage`/`voyage-v1`,
`jina`/`jina-v1`, and `graphit-rerank-v1`; configure each with its complete rerank endpoint.

OpenAI and Google Gemini do not expose the same native rerank contract. For them the broker honors
`graphit-rerank-v1` by embedding the query and every document, calculating cosine similarity, and
selecting the global `top_n` with original-index tie breaking. Configure an embedding endpoint and
model with one of these protocols:

| Provider | Simulated rerank protocol | URL |
|---|---|---|
| OpenAI / compatible | `openai`, `openai-compatible`, or `openai-embeddings-v1` | complete `/v1/embeddings` URL |
| Cohere Embed | `cohere-embed-v2` | complete `/v2/embed` URL |
| Voyage Embeddings | `voyage-embeddings-v1` | complete `/v1/embeddings` URL |
| Google Gemini | `google`, `google-embed-content-v1beta`, `gemini`, or `gemini-embed-content-v1beta` | API base such as `/v1beta`, or complete `:batchEmbedContents` URL |

Gemini Embedding 2 requests use Google's retrieval text prefixes; earlier Google embedding models
use `RETRIEVAL_QUERY` and `RETRIEVAL_DOCUMENT`. The configured rerank `revision` must change whenever
the embedding model, dimensions, or scoring behavior changes because these determine ranking.

For either local service, `upstream.device` accepts `auto`, `cpu`, `cuda`, or `coreml`. `cpu` is the
default. Set `device: auto` explicitly to try CoreML and then CPU on macOS, or the configured CUDA
`device_id` when an NVIDIA GPU is visible and then CPU. An accelerated-provider failure is logged
before fallback. Explicit `cuda` or `coreml` is strict and fails broker startup when the requested
provider cannot initialize; CoreML is valid only on macOS and uses `device_id: 0`. The model
manifest remains hardware-neutral.

During inference, `auto` also treats accelerator out-of-memory errors as temporary: it immediately
repeats that inference on CPU, then probes the accelerator with a real inference after 1 minute.
Repeated failed probes use delays of 2, 4, 8, and at most 10 minutes. The accelerator is selected
again only after the complete probe inference succeeds. All explicit modes (`cpu`, `cuda`, and
`coreml`) remain strict at runtime and never switch providers automatically.

## Storage credentials

Each storage route selects a `driver`. `s3` (the default) reaches an external S3 service and mints
credentials for it through STS. `filesystem` keeps the objects on a volume this broker serves
itself. Both answer the same `POST /v1/s3/credentials` contract, so a client never learns which one
a project uses.

### The `s3` driver

```yaml
services:
  s3:
    enabled: true
    default_route: primary
    routes:
      primary:
        driver: s3
        region: us-east-1
        endpoint: ""
        bucket: graphit-artifacts
        base_prefix: graphit
        sts_role_arn: "arn:aws:iam::123456789012:role/graphit-s3-access-role"
        sts_endpoint: ""
        sts_session_name: graphit-broker
        sts_duration: 1h
      public:
        region: us-east-1
        endpoint: "https://minio.example.com"
        bucket: graphit-public
        base_prefix: catalog
        access_key_id: "${PUBLIC_S3_ACCESS_KEY_ID:?required}"
        secret_access_key: "${PUBLIC_S3_SECRET_ACCESS_KEY:?required}"
        sts_role_arn: "arn:aws:iam::123456789012:role/graphit-public"
        sts_endpoint: "https://minio.example.com"
        sts_session_name: graphit-broker
        sts_duration: 1h
```

`base_prefix` is the storage root inside the bucket. For example, `bucket: artifacts` with
`base_prefix: graphit` puts broker-managed paths under `s3://artifacts/graphit/`. The Broker joins
this base with the paths authorized by resource grants when building the STS session policy.

Every enabled route requires region, bucket, a non-empty base prefix, and `sts_role_arn`.
`access_key_id` and `secret_access_key` are optional, but they must be set together when used. If
both are omitted, the broker uses the AWS SDK default credential chain. This includes AWS
environment variables such as
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, runtime role providers, shared configuration, and
the SDK's other supported sources. If both fields are set, that static pair overrides the default
chain for the route.

The resolved credential is the Broker's identity for calling `sts:AssumeRole`; it is not returned
to clients. `sts_role_arn` names the target role whose S3 permissions form the upper bound. The
Broker passes an inline policy for the requested project, so the issued session receives the
intersection of the target role's permissions and that project policy.

The source identity and target role must establish both sides of `AssumeRole`: the source identity
must be authorized to call `sts:AssumeRole` for the configured target ARN, and the target role's
trust policy must accept that source principal. Attach the bucket/object permissions to the target
role rather than relying on permissions of the source identity. How the runtime obtains its source
identity is deployment-specific and remains outside the Broker configuration contract.

If the source credential is already a temporary role session, assuming the target is role chaining
and AWS limits the new session to one hour; configure `sts_duration` accordingly.

`endpoint` may select an S3-compatible service. `sts_endpoint` selects its STS endpoint; when
omitted for an S3-compatible route it defaults to `endpoint`, while an empty AWS route uses AWS
STS. `sts_session_name` defaults to `graphit-broker`; `sts_duration` defaults to one hour and
must be between 15 minutes and 12 hours. MinIO self-assume accepts a placeholder AWS role ARN and
intersects the built-in user's policy with the inline session policy.

An S3 route is a named storage and STS profile. Any permanent access key and secret configured on
the route remain private to the broker; credentials resolved by the default chain are likewise
used only to sign the broker's STS request. The selected route's topology and newly minted
temporary credentials are returned to an authenticated Graphit client. Route names have no
built-in semantics. In particular, a route named `public` does not make its bucket, objects,
credentials, or broker endpoint public. `PUBLIC_S3_ACCESS_KEY_ID` and
`PUBLIC_S3_SECRET_ACCESS_KEY` above are merely environment-variable names referenced by the
explicit S3-compatible example; both values remain private to the broker. Public read access must
use an independently public bucket/CDN policy; the STS endpoint requires authentication. The
route can be removed when the deployment needs only one storage destination.

Clients submit only a `project`, `user`, or `hub` storage scope, plus the project ULID for project
scope. Matching resource grants select `s3_route`; an omitted value uses `default_route`. All
matching S3 grants for one requested scope must select the same route. Different projects may use
different routes and topologies. The broker intersects rendered prefixes with the scope's fixed
roots and maps operations into the STS session policy. See [resource
authorization](authorization.md#how-s3-grants-become-an-sts-policy) for the exact mapping.

Grant route names are validated when a grant is created or updated. Removing a route that an
existing grant uses makes that grant unusable until corrected; plan route changes together with
grant changes.

### The `filesystem` driver

```yaml
server:
  public_url: https://broker.example.com
authentication:
  token_pepper: "${BROKER_AUTH_TOKEN_PEPPER:?required}"
services:
  s3:
    enabled: true
    default_route: local
    routes:
      local:
        driver: filesystem
        region: us-east-1
        bucket: graphit-local
        base_prefix: graphit
        directory: /var/lib/graphit/hub
        endpoint: ""
        session_duration: 1h
        max_object_bytes: 5368709120
```

The broker stores the objects under `directory` and serves them from its own address at
`https://<endpoint>/<bucket>/<key>` in path style with Signature Version 4. Graphit clients need
no new code: the AWS SDK reaches it with the returned credentials, and the query engine reads
`s3://` URIs through its `httpfs` extension against the same endpoint, including ranged reads of
a large artifact. Objects live under `directory/data`, their ETags and content types under
`directory/meta`, and uploads are staged in `directory/tmp` before an atomic rename, so a
listing only ever reports complete objects.

`directory` is required and is created at startup with owner-only permissions; mount a volume
there and back it up like a bucket. `bucket` becomes the first path segment of every object URL,
so it must be a valid S3 bucket name and must not shadow a broker path such as `admin`, `v1`,
`oauth`, or `.well-known`; two filesystem routes cannot share one bucket. `endpoint` defaults to
`server.public_url` and is what clients are told to call, so a deployment behind another host name
sets it explicitly. `session_duration` defaults to one hour with the same 15 minute to 12 hour
bounds as `sts_duration`. `max_object_bytes` caps a single upload and defaults to 5 GiB.
`access_key_id`, `secret_access_key`, and the `sts_*` settings have no meaning for this driver and
are rejected on it, as `directory`, `session_duration`, and `max_object_bytes` are rejected on an
`s3` route.

Credentials for this driver are minted by the broker itself. They are self-contained: the session
token carries the authorization snapshot and is authenticated with a key derived from
`authentication.token_pepper`, which is therefore required, and the secret key is derived from
that token. Nothing about a session is stored, so a restart or a second broker process holding the
same pepper keeps verifying it, and a session simply expires like an STS one. Rotating the pepper
invalidates every live storage session, along with browser sessions and local tokens.

The gateway serves the operations Graphit's storage clients issue: `GET`, `HEAD`, `PUT`, `COPY`,
and `DELETE` on an object, `ListObjectsV2`, batch delete, and multipart upload
(`CreateMultipartUpload`, `UploadPart`, `ListParts`, `CompleteMultipartUpload`,
`AbortMultipartUpload`). Ranged reads, `If-Match`, and `If-None-Match` work, which is what makes
the Hub's compare-and-swap writes safe, and multipart is what lets LanceDB write a dataset here:
it starts one for every data file past 5 MiB. A part is verified against the ETag this gateway
issued for it, so a completion quoting a wrong or missing part fails rather than assembling a
corrupt object.

Completing an upload releases its parts at once: they are removed as soon as the assembled object
is committed, so the volume holds both copies only for the length of that assembly. A completion
that is refused — a conditional write that lost its race, say — keeps the parts instead, because
the client retries the completion rather than re-sending gigabytes.

An upload nobody completes or aborts holds its parts on the volume, so it is discarded once a day
passes with nothing written to it. That collection runs when the broker starts and whenever an
upload begins, not on a timer: an upload's directory is touched by every part it receives, so one
still being written is never old enough to collect, and a broker restarted mid-upload leaves it
resumable while sweeping what is genuinely abandoned. Half-written staging files, which no client
can resume, are removed outright at startup. Real S3 keeps an incomplete multipart upload until a
bucket lifecycle rule removes it; this driver needs no such rule.

Versioning, bucket management, cross-bucket copy, and `UploadPartCopy` are not served, and no
Graphit client asks for them. Driving every LanceDB operation this project performs — append,
upsert, merge, delete, snapshot, index build, search, compaction, time travel, restore, version
pruning, drop, and shallow clone — against this gateway issues only `GetObject` (whole and
ranged), `HeadObject`, `PutObject`, `ListObjectsV2` (with and without a delimiter), batch delete,
and the four multipart calls. The query engine reads `s3://` through its `httpfs` extension and
issues only `HEAD` and ranged `GET`.

The gateway is the broker's own code rather than an embedded object store, which is why it serves
only that. A read is a signature verification and a file read, so a full-object download runs at
disk and page-cache speed, and ranged reads are served concurrently with per-request overhead in
the tens of microseconds. A write costs an `fsync` before the atomic rename, which is what makes a
committed object durable, so writing many small objects is bound by that rather than by the
gateway, and a multipart upload pays it once per part plus one pass to assemble them. A listing
reads one metadata sidecar per reported key and walks only the directories the prefix can contain,
so it scales with the page rather than the bucket. `httpfs` sends a `HEAD` before each read unless
its remote cache is enabled, so a deployment reached over a network wants that cache on.
`go test ./internal/broker -bench BenchmarkStorage` measures all of it on the deployment's own
hardware. A deployment whose Hub traffic outgrows one machine wants a real object store behind the
`s3` driver, not a larger volume.

Conditional writes are serialized inside one process and land through an atomic rename, so
exactly one broker process may own a directory: do not point two brokers or two replicas at the
same volume, and prefer the `s3` driver with a real object store when a deployment needs more than
one broker.

See the complete [config.example.yaml](../config.example.yaml).
