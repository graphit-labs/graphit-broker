# Configuration reference

The broker reads one strict YAML document. Unknown fields are rejected. Set its path with
`--config` or `GRAPHIT_BROKER_CONFIG`; the default is
`/etc/graphit-auth-broker/config.yaml`. `${NAME}` expands an environment variable and
`${NAME:?message}` makes it mandatory. Run `graphit-auth-broker --config FILE --check-config`
before rollout.

## Server

| Field | Default | Meaning |
|---|---:|---|
| `server.address` | `:8080` | Go listen address. The supplied container healthcheck expects port 8080. |
| `server.public_url` | empty | External HTTPS URL published by discovery. |
| `read_timeout` | `15s` | Whole-request read deadline. |
| `write_timeout` | `60s` | Response write deadline; keep above AI upstream timeout. |
| `idle_timeout` | `120s` | Keep-alive idle deadline. |
| `shutdown_timeout` | `15s` | Graceful shutdown window. |
| `max_request_bytes` | `4194304` | Maximum JSON request body. |

`public_url` and every OIDC issuer must use HTTPS. HTTP is accepted only for AI upstreams and S3
endpoints, allowing private/local services.

## Authentication

OIDC issuers and API keys are optional when the deployment serves only explicitly anonymous
grants. A missing `Authorization` header creates the built-in anonymous principal. A header that
is present but malformed or invalid always returns 401 and is never downgraded to anonymous.

```yaml
authentication:
  oidc:
    - issuer: https://id.example.com/realms/acme
      audiences: [graphit-broker]
      required_scopes: [openid, graphit.use]
      username_claim: preferred_username
      organization_claim: organization.id
      teams_claim: groups
  api_keys:
    - name: automation
      token_sha256: ${AUTOMATION_KEY_SHA256:?required}
      subject: automation
      username: ci
      organization: acme
      teams: [platform]
```

OIDC fields:

- `issuer`: exact `iss` value and discovery base URL. Trailing-slash differences matter.
- `audiences`: at least one must occur in the token's `aud` claim.
- `required_scopes`: every value must occur in `scope` (space-delimited) or `scp` (string/array).
- `username_claim`: required claim path used by ACL `users`.
- `organization_claim`, `teams_claim`: optional dotted paths. Teams may be a string or array.

Claim paths traverse nested JSON objects (`organization.id`). They are configuration, not code;
the same binary therefore supports several IdPs and tenant claim layouts simultaneously.

API keys are for local/service profiles. Configure exactly one of `token` or `token_sha256`.
`token_sha256` is recommended:

```bash
printf '%s' 'a-long-random-value' | sha256sum
```

## Administration

```yaml
administration:
  enabled: true
  state_file: /var/lib/graphit-auth-broker/access-policy.json
  api_keys:
    - name: platform-admin
      token_sha256: ${BROKER_ADMIN_TOKEN_SHA256:?required}
```

Administration credentials are separate from consumer credentials. Configure exactly one of
`token` or `token_sha256` per key; a digest is recommended. `state_file` must be on a writable,
persistent filesystem. Disable this section to remove every `/admin` route.

## Authorization

The default is deny. New rules use one framework access level: `global`, `anonymous`,
`authenticated`, `user`, `team`, `organization`, or `subject`. The `principal` value is required
for the last four and forbidden for the first three. `*`, `?` and character classes are supported
for project and capability patterns; principal matching is exact.

```yaml
authorization:
  rules:
    - name: authenticated AI
      access: authenticated
      capabilities: [embeddings, rerank]
    - name: project storage
      access: organization
      principal: acme
      capabilities: [s3]
      projects: [customer-*]
      s3_operations: [read, write, publish]
      s3_route: customer-data
      s3_prefixes:
        - v2/projects/{project}
```

The older selector arrays remain accepted only as an alternative representation and cannot be
mixed with `access`/`principal`. Capabilities are
`embeddings`, `rerank`, `s3`, or operation-specific values such as `s3:read`. S3 rules may also
restrict `projects`, `s3_operations`, `s3_route`, and `s3_prefixes`. Prefixes are logical Graphit
keys, not physical bucket paths. Prefix placeholders are `{project}`,
`{username}`, `{organization}`, and `{subject}`. Every substituted value must be one safe path
segment. An empty rule set grants nothing.

Graphit uses an immutable project ULID for project objects and the literal project value
`global` for Hub control-plane lookups. Add an explicit read-only `global` rule for the logical
registry and grant-document prefixes the principal may discover. This does not reveal or grant a
bucket: the selected route maps each already-authorized logical key to private storage topology.

## Embeddings

```yaml
services:
  embeddings:
    enabled: true
    route: graphit-default
    revision: embedding-route-2026-09-07.1
    dimensions: 1536
    max_batch: 256
    max_input_bytes: 1048576
    upstream:
      protocol: openai-embeddings-v1
      url: https://api.openai.com/v1/embeddings
      model: text-embedding-3-small
      api_key: ${OPENAI_API_KEY:?required}
      api_key_header: Authorization
      api_key_scheme: Bearer
      send_dimensions: false
      timeout: 45s
    cache:
      ttl: 10m
      max_entries: 10000
```

The upstream model is required but never advertised. `route` is the stable public name.
`revision` identifies the effective vector space; change it whenever model, weights, normalization,
dimensions or other output-affecting behavior changes. `dimensions` is enforced against every
returned vector. `send_dimensions` adds the configured width to compatible upstream requests.

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
      api_key: ${COHERE_API_KEY:?required}
      timeout: 45s
    cache:
      ttl: 5m
      max_entries: 10000
```

Supported upstream adapters are `cohere-v2`, `jina-v1`, `voyage-v1`, and
`graphit-rerank-v1`. The external client always sees Graphit rerank v1 and cannot choose the model.

## S3 signing

```yaml
services:
  s3:
    enabled: true
    default_route: primary
    presign_expiry: 5m
    max_presign_expiry: 15m
    authorization_revision: acl-2026-09-07.1
    routes:
      primary:
        region: us-east-1
        endpoint: ""
        bucket: graphit-artifacts
        base_prefix: graphit
        access_key_id: ${PRIMARY_S3_ACCESS_KEY_ID:?required}
        secret_access_key: ${PRIMARY_S3_SECRET_ACCESS_KEY:?required}
      eu:
        region: eu-west-1
        endpoint: https://objects.eu.example.com
        bucket: graphit-eu
        base_prefix: tenants/eu
        access_key_id: ${EU_S3_ACCESS_KEY_ID:?required}
        secret_access_key: ${EU_S3_SECRET_ACCESS_KEY:?required}
```

`routes` is the broker-private dynamic topology table. Each ACL rule may set `s3_route`; otherwise
`default_route` is used. If matching rules select different routes, the request fails closed as
ambiguous. Every route contains its own `bucket`, `region`, optional compatible `endpoint`,
`base_prefix`, `access_key_id`, and `secret_access_key`. These values are never copied into a
Graphit provider or returned by discovery. Put credentials in environment-expanded secrets, never
in version control. Changing a route needs no client provider update or new login. There is no
credential exchange or temporary credential contract: the broker signs the requested operation
directly with the selected route credential. If `authorization_revision` is omitted,
a short hash of ACL configuration is generated.

When S3 is enabled, presigning is the only public storage contract. Graphit requests one URL for
one GET, HEAD, PUT, DELETE or ListObjectsV2 operation. `presign_expiry` is the default lifetime and `max_presign_expiry` is the hard client
override ceiling (maximum one hour). The broker performs current ACL evaluation on every request
and returns only the signed HTTP request—not the credentials. Anonymous and authenticated grants
use the same signing path after ACL authorization. Keep `base_prefix` only inside a route. Explicit `s3_prefixes` are
evaluated against the caller's logical key; the selected route's base prefix is prepended only
after authorization and only inside the broker.
