# HTTP API

All bodies are JSON. Protected endpoints require `Authorization: Bearer TOKEN`. Unknown JSON fields,
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
  "authentication": {"schemes":["bearer"],"audiences":["graphit-broker"]},
  "services": {
    "embeddings": {"protocol":"openai-embeddings-v1","path":"/v1/embeddings","route":"graphit-default","revision":"embed-r1","dimensions":1536,"max_batch":256},
    "rerank": {"protocol":"graphit-rerank-v1","path":"/v1/rerank","route":"graphit-default","revision":"rerank-r1","max_documents":1000},
    "s3_credentials": {"protocol":"graphit-s3-credentials-v1","path":"/v1/s3/credentials","authorization_revision":"acl-r1"}
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

## S3 credentials

`POST /v1/s3/credentials` exchanges identity plus operation intent for a short-lived AWS session:

```bash
curl https://broker.example.com/v1/s3/credentials \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"project":"platform-api","operation":"write"}'
```

Operations are `read`, `write`, `publish`, and `delete`. The operation is sent on exchange—not on
every S3 object request. The broker checks ACL once per exchange and embeds the resulting bucket,
prefix and action restrictions into the AWS STS session policy. AWS/S3 therefore enforces the same
upper bound for every later object operation, even if a client bypasses Graphit.

```json
{
  "access_key_id":"ASIA...",
  "secret_access_key":"...",
  "session_token":"...",
  "expires_at":"2026-09-07T18:00:00Z",
  "bucket":"graphit-artifacts",
  "region":"us-east-1",
  "prefixes":["graphit/organizations/acme/projects/platform-api"],
  "authorization_revision":"acl-r1"
}
```

The response has `Cache-Control: no-store`. Graphit obtains credentials during login and renews
them near expiration. A renewal repeats authentication, current ACL evaluation and STS exchange,
so revoked membership stops producing new sessions; already issued sessions remain valid until
their short expiry.
