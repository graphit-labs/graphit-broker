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
| `username_claim` | yes | Verified string claim path |
| `organization_claim` | no | Verified string claim path |
| `teams_claim` | no | Verified string/string-array claim path |

Nested claim paths use dots, for example `organization.id`. The canonical identity remains the
verified `iss` plus `sub`.

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
  oidc:
    issuer: https://identity.example.com
    client_id: graphit-broker-admin
    client_secret: "${BROKER_ADMIN_OIDC_CLIENT_SECRET:?required}"
    redirect_url: https://broker.example.com/admin/auth/callback
    scopes: [openid, profile, email]
```

Administration uses a separate confidential OIDC client. The callback may use HTTP only on a
loopback host. Session TTL must be between 5 minutes and 168 hours. The environment value
`BROKER_SUPERADMIN_SUBJECT` overrides YAML on every start.

Consumer API keys are not an alternative administration login mechanism. When administration is
enabled, the administration UI and API require the configured administration OIDC provider; there
is no local username/password administration login. A self-hosted issuer such as Keycloak or Dex
can provide OIDC for an otherwise local deployment.

## Embeddings

```yaml
services:
  embeddings:
    enabled: true
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
    cache:
      ttl: 10m
      max_entries: 10000
```

The broker always selects the upstream model; a client-supplied model is ignored. Change
`revision` whenever the effective vector space changes. The response revision and dimensions
are part of Graphit's index-compatibility fingerprint.

## Rerank

```yaml
services:
  rerank:
    enabled: true
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
    cache:
      ttl: 5m
      max_entries: 10000
```

Supported rerank adapters are the protocols implemented by the broker, including the Graphit
common response contract and configured vendor adapters. Unlike embeddings, OpenAI has no rerank
API contract; do not label arbitrary rerank endpoints OpenAI-compatible.

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
