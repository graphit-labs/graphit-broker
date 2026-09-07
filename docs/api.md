# HTTP API

All JSON request decoders reject unknown fields and oversized bodies. Consumer endpoints accept
`Authorization: Bearer ACCESS_TOKEN`; omitting the header selects the anonymous principal.
Malformed or invalid credentials return `401`, a valid principal without a matching grant
returns `403`, and disabled capabilities return `404`.

## Health and discovery

- `GET /healthz` — process liveness.
- `GET /readyz` — runtime/database readiness.
- `GET /.well-known/graphit-broker` — public capability negotiation.

Example discovery:

```json
{
  "version": "1",
  "issuer": "https://broker.example",
  "authentication": {
    "schemes": ["anonymous", "bearer"],
    "audiences": ["graphit-broker"]
  },
  "services": {
    "hub_access": {
      "protocol": "graphit-hub-access-v1",
      "path": "/v1/hub/access/resolve",
      "authorization_revision": "7"
    },
    "s3_presign": {
      "protocol": "graphit-s3-presign-v1",
      "path": "/v1/s3/presign",
      "authorization_revision": "7",
      "default_expires_in": 300,
      "max_expires_in": 900
    },
    "embeddings": {
      "protocol": "openai-embeddings-v1",
      "path": "/v1/embeddings",
      "route": "graphit-default",
      "revision": "embedding-space-1",
      "dimensions": 1536,
      "max_batch": 256
    },
    "rerank": {
      "protocol": "graphit-rerank-v1",
      "path": "/v1/rerank",
      "route": "graphit-default",
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

The broker ignores client model selection, invokes its configured model, validates dimensions and
indexes, and returns `X-Graphit-Embedding-Revision`,
`X-Graphit-Embedding-Dimensions`, and `X-Graphit-Cache: HIT|MISS`.

`input_type` is an optional Graphit extension with values `query` and `document`; omitted means
`document`. It lets the broker translate asymmetric retrieval semantics to Cohere, Voyage, Google,
or the local model while leaving the response contract stable.

## Rerank

`POST /v1/rerank`:

```json
{"query":"atomic authorization","documents":["doc a","doc b"],"top_n":2}
```

The response contains indexed relevance scores under the versioned Graphit common contract.
Headers include `X-Graphit-Rerank-Revision` and `X-Graphit-Cache`.

## S3 pre-signed request

`POST /v1/s3/presign` accepts:

```json
{
  "project": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "operation": "get",
  "key": "v2/projects/01ARZ3NDEKTSV4RRFFQ69G5FAV/project.json",
  "expires_in": 300,
  "if_match": "",
  "if_none_match": "",
  "limit": 0,
  "cursor": ""
}
```

Operations are `get`, `head`, `put`, `delete`, and `list`. The project must agree with
the logical key. The broker evaluates current grants, selects the private route, constrains the
key to an allowed rendered prefix, and signs exactly one request.

```json
{
  "method": "GET",
  "url": "https://opaque-signed-target.example/...",
  "headers": {},
  "expires_at": "2026-09-07T17:00:00Z",
  "key": "v2/projects/01ARZ3NDEKTSV4RRFFQ69G5FAV/project.json",
  "operation": "get",
  "authorization_revision": "7"
}
```

The response never contains bucket, region, base prefix, access key, or secret key and is marked
`Cache-Control: no-store`.

## Administration API

Administration accepts either the secure OIDC session cookie plus CSRF token for state changes, or
a valid administration OIDC bearer. Every route is protected by an action:

| Route | Action | Purpose |
|---|---|---|
| `GET /admin/api/v1/session` | `session.read` | identity, roles, actions, CSRF |
| `GET /admin/api/v1/config` | `configuration.read` | redacted YAML and ETag |
| `PUT /admin/api/v1/config` | `configuration.write` | validate, persist, hot activate |
| `GET /admin/api/v1/grants` | `grants.read` | list grants and ACL ETag |
| `POST /admin/api/v1/grants` | `grants.write` | create a grant |
| `PUT /admin/api/v1/grants/{id}` | `grants.write` | replace one grant |
| `DELETE /admin/api/v1/grants/{id}` | `grants.write` | delete one grant |
| `GET /admin/api/v1/principals` | `grants.read` | configured principal hints |
| `GET /admin/api/v1/roles` | `roles.read` | roles and supported actions |
| `PUT/DELETE /admin/api/v1/roles/{role}` | `roles.write` | manage role definition |
| `GET/POST/DELETE /admin/api/v1/role-assignments` | role action | manage exact-sub assignments |

Grant and configuration writes require `If-Match` with the current ETag. A stale revision returns
`409`; a missing precondition returns `428`. Grant CRUD increments only the ACL revision.
Configuration changes increment only the configuration revision.

## Error envelope

```json
{"error":{"code":"forbidden","message":"access denied","request_id":"..."}}
```

Upstream response bodies and secrets are never copied into public errors. `X-Request-ID` is
accepted when bounded and generated otherwise.
