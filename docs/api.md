# HTTP API

All bodies are JSON. Consumer endpoints accept either `Authorization: Bearer TOKEN` or no header
when an explicit anonymous rule grants the request. Unknown JSON fields,
multiple JSON objects and oversized bodies are rejected. Every response includes `X-Request-ID`.

Errors have a stable envelope:

```json
{"error":{"code":"forbidden","message":"access denied","request_id":"..."}}
```

## Health and discovery

`GET /healthz` proves the process is serving HTTP. `GET /readyz` proves initialization completed.
Neither requires authentication. `GET /.well-known/graphit-broker` advertises protocol version,
accepted audiences and enabled capabilities:

```json
{
  "version": "1",
  "issuer": "https://broker.example.com",
  "authentication": {"schemes":["anonymous","bearer"],"audiences":["graphit-broker"]},
  "services": {
    "embeddings": {"protocol":"openai-embeddings-v1","path":"/v1/embeddings","route":"graphit-default","revision":"embed-r1","dimensions":1536,"max_batch":256},
    "rerank": {"protocol":"graphit-rerank-v1","path":"/v1/rerank","route":"graphit-default","revision":"rerank-r1","max_documents":1000},
    "s3_presign": {"protocol":"graphit-s3-presign-v1","path":"/v1/s3/presign","authorization_revision":"acl-r1","default_expires_in":300,"max_expires_in":900}
  }
}
```

Clients must reject an unsupported discovery version or protocol.

## Embeddings

`POST /v1/embeddings` accepts the common OpenAI shape. `model` is accepted for compatibility but
ignored; the broker chooses its route/model.

```bash
curl https://broker.example.com/v1/embeddings \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"model":"ignored","input":["first document","second document"]}'
```

```json
{
  "object":"list",
  "data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],
  "model":"graphit-default",
  "graphit":{"revision":"embed-r1","dimensions":2}
}
```

The response includes `X-Graphit-Embedding-Revision`,
`X-Graphit-Embedding-Dimensions`, and `X-Graphit-Cache: HIT|MISS`. Graphit fingerprints the public
route, revision and width. Changing any output-affecting upstream behavior requires a new revision
and a vector reindex.

## Rerank

`POST /v1/rerank` uses Graphit rerank v1. `model` is ignored.

```bash
curl https://broker.example.com/v1/rerank \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"query":"OIDC authorization","documents":["storage","OIDC and ACL"],"top_n":2}'
```

```json
{
  "results":[
    {"index":1,"relevance_score":0.97},
    {"index":0,"relevance_score":0.05}
  ],
  "graphit":{"revision":"rerank-r1"}
}
```

The broker returns `X-Graphit-Rerank-Revision` and `X-Graphit-Cache`. The Graphit framework requests
all candidate scores so the search contract preserves the same result set.

## S3 pre-signed requests

`POST /v1/s3/presign` authorizes and signs exactly one S3 request. Graphit calls it before every
object-store request, so revocation takes effect on the next broker call and no AWS access key,
secret or session token is returned or stored by the framework.

```bash
curl https://broker.example.com/v1/s3/presign \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"project":"01PROJECT","operation":"list","key":"v2/projects/01PROJECT/artifacts/ast/example"}'
```

For an explicitly public project omit the Authorization header. Operations are `get`, `head`,
`put`, `delete`, and `list`. Optional fields are `expires_in`, `if_match`, `if_none_match`, `limit`
and `cursor`. Conditional fields are signed and must be replayed exactly.

```json
{
  "method":"GET",
  "url":"https://graphit-artifacts.s3.us-east-1.amazonaws.com/...?...",
  "headers":{},
  "expires_at":"2026-09-07T18:05:00Z",
  "key":"v2/projects/01PROJECT/artifacts/ast/example",
  "operation":"list",
  "authorization_revision":"acl-r1.4"
}
```

The example above represents a list response; its signed URL therefore carries ListObjectsV2
query fields even though they are abbreviated. `key` remains the caller's logical key. The selected
server-side storage route, bucket, region, endpoint, base prefix, access key, and secret key are never
response fields. The signed URL is opaque client input; it necessarily identifies its one destination and can
expose an AWS access-key identifier in SigV4
query metadata; it never contains the AWS secret. Do not log or persist it. Graphit validates
method, operation, key, revision, expiry and destination, executes it immediately, and discards it.

## Administration API

All administration APIs require an OIDC-authenticated subject authorized for the endpoint action.
The browser uses an opaque server-side session cookie; state-changing calls additionally send
`X-CSRF-Token` from `GET /admin/api/v1/session`. API clients may instead use an OIDC ID token whose
audience is the configured administration client ID. A consumer bearer key is not an administrator
credential merely because both use the Authorization header.

| Method and path | Required action | Purpose |
|---|---|---|
| `GET /admin/api/v1/session` | `session.read` | current subject, name/email, roles/permissions, superadmin status and CSRF token |
| `GET /admin/api/v1/config` | `configuration.read` | complete strict YAML with secrets redacted, revision and timestamp |
| `PUT /admin/api/v1/config` | `configuration.write` | validate, persist and atomically activate the complete YAML |
| `GET /admin/api/v1/access` | `access.read` | structured consumer ACL document |
| `PUT /admin/api/v1/access` | `access.write` | replace ACLs and atomically activate them |
| `GET /admin/api/v1/principals` | `access.read` | built-in and API-key principals without credentials |
| `GET /admin/api/v1/roles` | `roles.read` | role definitions and supported actions |
| `PUT /admin/api/v1/roles/{role}` | `roles.write` | create or replace a role's permissions |
| `DELETE /admin/api/v1/roles/{role}` | `roles.write` | delete a custom role and its assignments; built-in `admin` is protected |
| `GET /admin/api/v1/role-assignments` | `roles.read` | assignments and bootstrap-only status |
| `POST /admin/api/v1/role-assignments` | `roles.write` | assign a role to an exact OIDC subject |
| `DELETE /admin/api/v1/role-assignments` | `roles.write` | revoke one subject/role assignment |

Complete configuration reads return this envelope and an `ETag` header:

```json
{"revision":4,"updated_at":"2026-09-07T18:00:00Z","yaml":"server:\n  ..."}
```

Every populated secret in `yaml` is `[configured-secret]`. A PUT sends
`{"yaml":"..."}` with the current `If-Match`; unchanged placeholders retain stored secrets.
Access PUT similarly requires `If-Match` and sends the complete document:

```json
{"v":1,"rules":[{"name":"public catalog","access":"anonymous","capabilities":["s3"],"projects":["catalog"],"s3_operations":["read"],"s3_prefixes":["v2/projects/catalog"]}]}
```

Role writes use `{"permissions":["configuration.read","access.read"]}`. Assignment POST and
DELETE both use `{"subject":"immutable-oidc-sub","role":"admin"}`. Missing preconditions return
`428`, stale configuration revisions return `409`, invalid credentials return `401`, and a valid
identity without the required action returns `403`.

OIDC browser endpoints are `GET /admin/auth/login`, `GET /admin/auth/callback`, and
`POST /admin/auth/logout`. Login creates one-time state/nonce/PKCE data; callback consumes it and
creates the session; logout requires the session CSRF token and invalidates the server-side session.
See [Administration](administration.md) for bootstrap, role and secret semantics.
