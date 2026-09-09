# Configuration reference

The broker reads strict YAML: unknown fields are errors. Environment expressions are expanded
before decoding:

- `${NAME}` — empty when unset;
- `${NAME:-default}` — use a default;
- `${NAME:?message}` — fail startup with the supplied message.

Run `graphit-broker --config config.yaml --check-config` to validate without serving.

The expanded YAML document is the sole configuration authority. It is never serialized into SQL.
Change it through deployment/secret-management tooling and restart the broker to activate the new
configuration. `/admin/api/v1/config` is a redacted read-only view. Local users, Argon2id
verifiers, resource grants, roles, role assignments, login flows, and sessions remain durable SQL
state; the pepper and resource grants are never persisted from YAML.

## Database

| Field | Default | Meaning |
|---|---:|---|
| `driver` | `sqlite` | `sqlite`, `postgres`, or `mysql` |
| `dsn` | SQLite file below | Driver-specific connection string |
| `max_open_conns` | SQLite 1; remote 20 | Maximum pool connections |
| `max_idle_conns` | SQLite 1; remote 10 | Idle pool connections |
| `conn_max_lifetime` | `3m` | Maximum connection lifetime |

Default SQLite DSN: `/var/lib/graphit-broker/broker.db`. Environment overrides are
`BROKER_DATABASE_DRIVER` and `BROKER_DATABASE_DSN`. See [database backends](database.md).

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

`public_url` must be HTTPS when set. Put the broker behind a TLS reverse proxy in production.

## Authentication

`authentication.token_pepper` is the single deployment secret used with domain separation for
local password preprocessing, administration sessions, OIDC state, local OAuth grants, access and
refresh tokens, and service credentials. It must contain at least 32 bytes whenever administration,
local login, or browser OIDC login is enabled and is never stored in SQL.

Local browser login is deployment-owned. It defaults to the value of `administration.enabled`, but
can be enabled independently for Graphit Code login or disabled while keeping OIDC login:

```yaml
authentication:
  local_login:
    enabled: true
```

Local-password failures use a fixed-window limiter. Every field is optional and defaults as shown:

```yaml
authentication:
  local_rate_limit:
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
  local_captcha:
    enabled: false
    provider: turnstile # or recaptcha
    site_key: "${BROKER_LOCAL_CAPTCHA_SITE_KEY}"
    secret_key: "${BROKER_LOCAL_CAPTCHA_SECRET_KEY}"
    trigger_multiplier: 1.5
    verification_timeout: 3s
```

When enabled, `server.public_url`, `provider`, `site_key`, and `secret_key` are required. The
provider is fixed to `turnstile` or `recaptcha`; Siteverify endpoints are not configurable. The
trigger must be between `0` and `local_rate_limit.saturation_multiplier`, inclusive; the timeout
must be between `500ms` and `10s`. The administration configuration response exposes the site key
and operational settings but replaces the secret key with `[configured-secret]`.

The threshold is `max(1, ceil(local_rate_limit.max_concurrent * trigger_multiplier))` per broker
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
  local_mfa:
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

Graphit Code OAuth and automation credentials use these defaults:

```yaml
authentication:
  local_tokens:
    audience: graphit-broker
    cli_client_id: graphit-cli
    cli_redirect_path: /oauth/callback
    access_ttl: 10m
    refresh_ttl: 720h
    authorization_code_ttl: 1m
    device_code_ttl: 10m
    device_poll_interval: 5s
    service_credential_max_ttl: 8760h
```

Desktop authorization accepts only an HTTP `127.0.0.1` or `::1` redirect with an explicit dynamic
port and the configured exact path. PKCE method `S256` is mandatory. Access tokens are short-lived;
refresh tokens are issued only when `offline_access` is requested, rotate on every use, retain one
absolute lifetime, and revoke their family when reuse is detected. Service credential expiration
is mandatory and may not exceed `service_credential_max_ttl`.

`authentication.oidc` is the shared list of trusted issuers for consumer bearer validation and
browser login. At most one entry may configure the browser-client fields:

| Field | Required | Meaning |
|---|---|---|
| `issuer` | yes | Exact HTTPS issuer used for discovery and signature validation |
| `audiences` | yes | At least one accepted broker audience |
| `required_scopes` | no | Every listed scope must be present |
| `client_id` | browser login | Confidential client ID used by the authorization-code flow |
| `client_secret` | no | Confidential client secret, normally injected from a secret manager |
| `redirect_url` | browser login | Exact `/oauth/oidc/callback` URL; HTTP is allowed only on loopback |
| `scopes` | no | Browser scopes; defaults to `openid profile email` |
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
literal keys containing dots work unchanged. For backward compatibility, a non-JSONPath value
whose exact key is absent also supports dotted object traversal such as `organization.id`.
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
verification page. It is never accepted in `Authorization`. Desktop CLI login uses Authorization
Code with PKCE through the Broker-owned method chooser; headless login uses local Device
Authorization. Local and upstream OIDC browser logins both produce opaque broker tokens whose
raw values are never stored in SQL. Automation uses a credential attached to a `service` identity.
All local tokens are audience- and scope-bound, expire, can be revoked, and stop authenticating
when the owning identity revision changes. Omitting the header creates an anonymous principal,
which can work only when an explicit `anonymous` resource grant matches.

## Administration

```yaml
authentication:
  token_pepper: "${BROKER_AUTH_TOKEN_PEPPER:?at least 32 random bytes}"
  oidc:
    - issuer: https://identity.example.com
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
  cli:
    provider_name: organization-broker
    profile_name: organization-broker
```

There is no administration-specific OIDC provider. The same issuer and claim mappings validate
consumer bearers and populate browser identities; `client_id`, `client_secret`, `redirect_url`, and
`scopes` merely enable the browser authorization-code flow on one issuer. A local-only UI may omit
OIDC. Session TTL must be between 5 minutes and 168 hours.

`authentication.oidc[].role_claim` is optional. When absent, effective roles come from SQL
`role_assignments`. When configured, its additional role values are authoritative for that OIDC
identity and replace explicit SQL assignments for the same
canonical subject. Every authenticated identity additionally receives the built-in `user` role;
unknown claimed roles grant nothing. Local users always resolve their additional roles from SQL.
There is no superadmin bypass.

`administration.cli` supplies only the names used to render complete `graphit provider add --type
broker` and `graphit login` snippets. The public client ID and callback path come from
`authentication.local_tokens`; Graphit Code discovers both from the Broker and picks a free
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

## Model catalog

```yaml
models:
  directory: /var/cache/graphit-broker/models
  embedding: coderankembed
  rerank: bge-reranker-base
  generate: ""
```

`models` is the global selector for local ONNX bundles. `directory` is the persistent catalog root;
each task value names `<directory>/<model-id>/manifest.json`. The embedding and rerank values above
are the defaults and select the built-in presets. Custom models, acquisition policies, supported
manifest fields, tensor semantics, identities, and complete examples are documented in the
[local model catalog](models.md).

## Embeddings

```yaml
services:
  embeddings:
    enabled: true
    backend: upstream
    route: graphit-default
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
    local:
      device: auto
      device_id: 0
    cache:
      ttl: 10m
      max_entries: 10000
```

`backend` is `upstream` by default or `local` for in-process ONNX inference. A local backend uses
`models.embedding`; the preset is CodeRankEmbed-137M-INT8. Model files, tokenizer behavior,
prefixes, pooling, normalization, and dimensions belong to the selected manifest, not this service
block. `dimensions` may be omitted/zero for a local model and is inferred from its resolved
manifest and ONNX signature; a positive value is an assertion and startup rejects a mismatch.
`revision` is optional for local inference and becomes a readable prefix for the automatically
computed effective model identity.

For an upstream backend, set `upstream.protocol` to one of the following. The public broker API
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
    backend: upstream
    route: graphit-default
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
    local:
      device: auto
      device_id: 0
    cache:
      ttl: 5m
      max_entries: 10000
```

`backend: local` uses `models.rerank`; its default is the `bge-reranker-base` preset. Custom
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

For either local service, `local.device` accepts `auto`, `cpu`, `cuda`, or `coreml`. `auto` is the
default: on macOS it tries CoreML and then CPU; on Linux and Windows it tries the configured CUDA
`device_id` when an NVIDIA GPU is visible and then CPU. An accelerated-provider failure is logged
before fallback. Explicit `cuda` or `coreml` is strict and fails broker startup when the requested
provider cannot initialize; CoreML is valid only on macOS and uses `device_id: 0`. The model
manifest remains hardware-neutral.

During inference, `auto` also treats accelerator out-of-memory errors as temporary: it immediately
repeats that inference on CPU, then probes the accelerator with a real inference after 1 minute.
Repeated failed probes use delays of 2, 4, 8, and at most 10 minutes. The accelerator is selected
again only after the complete probe inference succeeds. All explicit modes (`cpu`, `cuda`, and
`coreml`) remain strict at runtime and never switch providers automatically.

## S3 pre-signing

```yaml
services:
  s3:
    enabled: true
    default_route: primary
    presign_expiry: 5m
    max_presign_expiry: 15m
    routes:
      primary:
        region: us-east-1
        endpoint: ""
        bucket: graphit-artifacts
        base_prefix: graphit
        access_key_id: "${PRIMARY_S3_ACCESS_KEY_ID:?required}"
        secret_access_key: "${PRIMARY_S3_SECRET_ACCESS_KEY:?required}"
      public:
        region: us-east-1
        endpoint: "https://minio.example.com"
        bucket: graphit-public
        base_prefix: catalog
        access_key_id: "${PUBLIC_S3_ACCESS_KEY_ID:?required}"
        secret_access_key: "${PUBLIC_S3_SECRET_ACCESS_KEY:?required}"
```

Every enabled route requires region, bucket, access key, and secret. `endpoint` may select an
S3-compatible service and `base_prefix` namespaces all physical keys. Neither value is returned
to Graphit. The authorization revision is generated from the grant database; it is not a service
configuration field.

An S3 route is a named, broker-private storage profile: endpoint, region, bucket, base prefix, and
the credential used to sign requests. Route names have no built-in semantics. In particular, a
route named `public` does not make its bucket, objects, credentials, or broker endpoint public.
`PUBLIC_S3_ACCESS_KEY_ID` and `PUBLIC_S3_SECRET_ACCESS_KEY` above are merely environment-variable
names referenced by the example route; both values remain private to the broker. Public read
access still requires an explicit `anonymous` grant (or an independently public bucket policy).
The route can be removed when the deployment needs only one storage destination.

Clients never submit an S3 route. A matching resource grant selects `s3_route`; an omitted value
uses `default_route`. The broker then verifies that the requested logical key is inside one of the
grant's rendered `s3_prefixes` before signing the request. See [resource
authorization](authorization.md#how-s3-grants-select-a-route) for the exact matching rules and
multi-route examples.

Grant route names are validated when a grant is created or updated. Removing a route that an
existing grant uses makes that grant unusable until corrected; plan route changes together with
grant changes.

See the complete [config.example.yaml](../config.example.yaml).
