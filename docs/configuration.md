# Configuration reference

The broker reads strict YAML: unknown fields are errors. Environment expressions are expanded
before decoding:

- `${NAME}` — empty when unset;
- `${NAME:-default}` — use a default;
- `${NAME:?message}` — fail startup with the supplied message.

Run `graphit-broker --config config.yaml --check-config` to validate without serving.

The YAML document seeds only an empty database. After initialization, mutable configuration is
read from SQL and edited through `/admin/` or `/admin/api/v1/config`. Database selection,
administration enabled state, and the effective superadmin subject remain deployment-owned.
Resource grants are never configured in YAML.

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

## Consumer authentication

`authentication.oidc` is a list of trusted issuers:

| Field | Required | Meaning |
|---|---|---|
| `issuer` | yes | Exact HTTPS issuer used for discovery and signature validation |
| `audiences` | yes | At least one accepted broker audience |
| `required_scopes` | no | Every listed scope must be present |
| `username_claim` | yes | Verified single-string claim selector |
| `organization_claim` | no | Verified single-string claim selector |
| `teams_claim` | no | Verified multi-string claim selector |

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
JSONPath fails configuration validation. The canonical identity remains the verified standard
`iss` plus `sub`; protocol claims including `iss`, `sub`, `aud`, expiry, nonce, and scopes are not
remappable selectors.

`authentication.api_keys` supports service/local identities. Each item has `name`, exactly one
of `token` or 64-character `token_sha256`, `subject`, `username`, optional
`organization`, and optional `teams`. Prefer the digest form. These keys are bearer
credentials and receive only grants matching their configured identity.

Consumer endpoints do not require OIDC when API keys are sufficient for the deployment. A broker
may configure only API-key identities, only OIDC issuers, or both. An API-key client sends the
original token as `Authorization: Bearer <token>`; `token_sha256` is the digest stored in
configuration. The broker has no built-in username/password identity store. Omitting the
`Authorization` header creates an anonymous principal rather than an authenticated identity, and
that principal can do work only when an explicit `anonymous` resource grant matches.

## Administration

```yaml
administration:
  enabled: true
  superadmin_subject: "${BROKER_SUPERADMIN_SUBJECT:?required}"
  session_ttl: 8h
  cli:
    provider_name: organization-broker
    profile_name: organization-broker
    oidc_client_id: graphit-cli
    oidc_redirect_uri: ""
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

When present, administration OIDC uses a separate confidential client. The callback may use HTTP
only on a loopback host. OIDC may be omitted for a local-only UI backed by at least one
`authentication.api_keys` identity. Session TTL must be between 5 minutes and 168 hours. The environment value
`BROKER_SUPERADMIN_SUBJECT` overrides YAML on every start. `name_claim` and `email_claim` default to
`name` and `email`. The username, organization, and team mappings let the projects UI evaluate the
same `user`, `organization`, and `team` resource grants as consumer requests; when omitted, those
three mappings inherit from a consumer OIDC issuer with the same issuer URL. All six mappings use
the exact-key/JSONPath rules above.

`administration.oidc.role_claim` is optional. When absent, UI permissions come from local SQL
`role_assignments`. When configured, it must resolve to at least one role string and is
authoritative for that OIDC identity: claimed roles replace, rather than merge with, every local
role assignment for the same `sub`. Role names still refer to role definitions and permissions in
SQL; an unknown claimed role grants nothing. The deployment `superadmin_subject` remains the
emergency bypass. API-key UI identities have no token claims and continue to use local database
assignments.

`administration.cli` supplies the non-secret public/native client details used to render complete
`graphit provider add` and `graphit login` snippets. An empty `oidc_redirect_uri` lets Graphit pick
a free loopback port; when set, it must be an HTTP loopback URL with an explicit port.

An identity from `authentication.api_keys` can also enter the UI with its original local token when
its configured `subject` has an assigned UI role. The token is validated once by the existing
consumer authenticator and exchanged for a short-lived, `HttpOnly`, CSRF-protected UI session; the
API key is not persisted by the UI. For local-only bootstrap, set `BROKER_SUPERADMIN_SUBJECT` to one
configured API-key `subject`. There is no separate local username/password store.

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
| Google | `google` or `google-embed-content-v1beta` | API base such as `/v1beta`, or complete `:batchEmbedContents` URL |

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
bundle manifest. Upstream protocols are `cohere`/`cohere-v2`, `voyage`/`voyage-v1`,
`jina`/`jina-v1`, and `graphit-rerank-v1`; configure each with its complete rerank endpoint. Unlike
embeddings, OpenAI has no rerank API contract, so arbitrary rerank endpoints must not be labeled
OpenAI-compatible.

For either local service, `local.device` accepts `auto`, `cpu`, `cuda`, or `coreml`. `auto` is the
default: on macOS it tries CoreML and then CPU; on Linux and Windows it tries the configured CUDA
`device_id` when an NVIDIA GPU is visible and then CPU. An accelerated-provider failure is logged
before fallback. Explicit `cuda` or `coreml` is strict and fails broker startup when the requested
provider cannot initialize; CoreML is valid only on macOS and uses `device_id: 0`. The model
manifest remains hardware-neutral.

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
