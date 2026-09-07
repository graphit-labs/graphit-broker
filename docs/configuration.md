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

At least one OIDC issuer or API key is required. Every protected endpoint uses
`Authorization: Bearer <credential>`.

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

## Authorization

The default is deny. A rule grants access only if all non-empty identity selector categories match.
Within one category, any value may match. `*`, `?` and character classes use Go path-style globbing.

```yaml
authorization:
  rules:
    - name: acme platform AI
      organizations: [acme]
      teams: [platform, ml-*]
      capabilities: [embeddings, rerank]
    - name: project storage
      organizations: [acme]
      capabilities: [s3]
      projects: [customer-*]
      s3_operations: [read, write, publish]
      s3_prefixes:
        - organizations/{organization}/users/{username}/projects/{project}
```

Identity selectors are `subjects`, `users`, `organizations`, and `teams`. Capabilities are
`embeddings`, `rerank`, `s3`, or operation-specific values such as `s3:read`. S3 rules may also
restrict `projects`, `s3_operations`, and `s3_prefixes`. Prefix placeholders are `{project}`,
`{username}`, `{organization}`, and `{subject}`. Every substituted value must be one safe path
segment. An empty rule set grants nothing.

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

## S3/STS

```yaml
services:
  s3:
    enabled: true
    mode: assume_role
    region: us-east-1
    endpoint: ""
    bucket: graphit-artifacts
    base_prefix: graphit
    role_arn: arn:aws:iam::123456789012:role/graphit-broker-session
    sts_endpoint: ""
    duration: 1h
    authorization_revision: acl-2026-09-07.1
```

`mode` is `assume_role` (broker uses its AWS credential chain) or `web_identity` (broker forwards
the validated bearer token to AWS `AssumeRoleWithWebIdentity`). Duration must be 15 minutes through
12 hours and is still capped by AWS/role policy. `endpoint` is returned to Graphit for S3-compatible
stores; `sts_endpoint` changes only the exchange endpoint. If `authorization_revision` is omitted,
a short hash of ACL configuration is generated.
