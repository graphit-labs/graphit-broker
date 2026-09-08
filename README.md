# Graphit Broker

Graphit Broker is the server-side identity, authorization, AI, and storage gateway for
Graphit. It validates end-user OIDC access tokens or explicitly configured service API keys,
evaluates deny-by-default resource grants from SQL, and exposes:

- `POST /v1/hub/access/resolve` — the authoritative Hub project grants for the verified caller;
- `POST /v1/s3/presign` — one narrowly scoped pre-signed request for each S3 operation;
- `POST /v1/embeddings` — an OpenAI-shaped contract backed by local inference or a broker-owned
  OpenAI-compatible, Cohere, Voyage, or Google adapter;
- `POST /v1/rerank` — the versioned Graphit contract backed by local inference, native
  Cohere/Voyage/Jina adapters, or embedding-simulated OpenAI and Google Gemini adapters;
- `/admin/` — an OIDC/local-password administration UI for read-only configuration, resource grants, roles,
  and user-role assignments.

Only the broker knows AI API keys, upstream models, S3 credentials, bucket, region, endpoint,
base prefixes, and route selection. Graphit receives no cloud credential and requests a fresh URL
for every object operation. Anonymous requests are accepted only when an explicit `anonymous`
grant matches.

For HTTP MCP, Graphit validates the end user's OIDC bearer and preserves it for every broker call.
The default direct-relay mode uses one shared MCP/broker audience. If the IdP supports RFC 8693,
Graphit may instead exchange the MCP token for a short-lived broker-audience token. The broker
validates the final token independently in both modes; exchange failure never downgrades to relay
or anonymous access.

## Persistence and authorization

`config.yaml`, after environment expansion, is the sole configuration authority. Changes are
applied by deployment/restart and the administration API exposes only a redacted read-only view.
SQL stores normalized resource grants, grant revision, administrative roles and assignments, OIDC
login flows, and sessions—but never the configuration document or its resolved secrets. SQLite is
the default single-node deployment; PostgreSQL and MySQL use the same domain model.

Resource grants are created through the UI or administration API. A new database has no grants and
therefore denies every consumer operation.

There is deliberately no migration, compatibility loader, dual read/write, or fallback path in
this development version. Recreate the database when the schema version changes.

Local identities use a unique `username`, a pepper of at least 32 bytes, and the matching Argon2id
PHC. Generate that PHC with `graphit-broker --hash-password --password-pepper-env ENV_NAME`, or use
`--hash-password-stdin` for automation; the password remains in TTY/stdin and only the pepper is
read from the named environment variable. See [configuration](docs/configuration.md) and
[administration bootstrap](docs/administration.md).

Administrative RBAC and resource authorization are separate:

- roles control who may operate the administration API; optional verified OIDC claim roles
  override local subject assignments;
- resource grants control which verified consumer may use `hub`, `s3`, `embeddings`, and
  `rerank`, for which exact projects and S3 operations/routes/prefixes.

## Quick start with Docker

Requirements: Docker 24+, either an OIDC web client or an `authentication.api_keys` identity for
administration, a first local identity with `roles: [admin]` (or an OIDC `role_claim` that yields
`admin`), a per-identity password pepper matching its generated Argon2id verifier, and the credentials for
any enabled upstream services. Local AI does not need provider credentials.

```bash
cp .env.example .env
# Fill the local, uncommitted environment file.
docker compose -f docker-compose.yml up --build -d
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/.well-known/graphit-broker
```

Compose persists `/etc/graphit-broker`, `/var/lib/graphit-broker`, and the model cache in the
  named volumes `broker-config`, `broker-state`, and `broker-models`. On the first run Docker seeds
`broker-config` with the image's `config.yaml`. To start from a customized file, create the service,
copy the file into its configuration volume, and then start it:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml first.
docker compose create broker
docker compose cp config.yaml broker:/etc/graphit-broker/config.yaml
docker compose up -d
```

When an enabled service has `backend: local`, startup downloads and initializes only that service's
model. On a host with the NVIDIA Container Toolkit, expose GPUs through the same Compose file. The
same image is used in both modes; `device: auto` prefers CUDA when exposed and falls back to CPU:

```bash
GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia docker compose up --build -d
```

Local ONNX models use manifest bundles under the persistent `broker-models` volume. Top-level
`models.embedding` and `models.rerank` select presets or custom IDs; each manifest controls verified
`on_demand`, explicit `setup`, or installed-only `never` acquisition and the complete inference
semantics. See the [local model catalog](docs/models.md) for all fields and examples.

Native releases for Linux amd64, macOS arm64, and Windows amd64 are single self-contained
executables. Linux and Windows embed the ONNX core plus shared/CUDA providers; macOS embeds the
CoreML-capable ONNX dylib. They extract atomically under
`${GRAPHIT_GLOBAL_DIR:-~/.graphit}/broker/runtime/onnxruntime` on first execution; subsequent starts use a
small completion marker and file metadata only. `device: auto` prefers CoreML on macOS, CUDA on
Linux/Windows when visible, and otherwise CPU.

Open `https://YOUR-BROKER/admin/`, sign in, and create the first resource grants. Until then,
consumer endpoints correctly return `403`.

Validate a configuration without starting the service:

```bash
docker build -t graphit-broker:local .
docker run --rm --env-file .env \
  -v "$PWD/config.yaml:/etc/graphit-broker/config.yaml:ro" \
  graphit-broker:local --check-config
```

For a harmless health-only smoke test:

```bash
docker build -t graphit-broker:local .
docker run --rm -d --name graphit-broker-smoke -p 18080:8080 \
  --tmpfs /tmp:size=16m,mode=1777 \
  -v "$PWD/examples/health-only.yaml:/etc/graphit-broker/config.yaml:ro" \
  graphit-broker:local
curl --fail http://127.0.0.1:18080/healthz
docker rm -f graphit-broker-smoke
```

## Documentation

- [Configuration reference](docs/configuration.md)
- [Local ONNX model catalog and examples](docs/models.md)
- [Native binary installation and CPU/GPU operation](docs/binary.md)
- [Database backends](docs/database.md)
- [OIDC integration](docs/oidc.md)
- [Resource authorization](docs/authorization.md)
- [Administration UI and API](docs/administration.md)
- [Consumer HTTP API](docs/api.md)
- [Deployment](docs/deployment.md)
- [Security model](docs/security.md)
- [Operations and troubleshooting](docs/operations.md)

## Development

```bash
make fmt
make test
make vet
make build
```

The unit suite is hermetic. OIDC, AI upstreams, and storage are represented by in-process synthetic
servers; tests do not contact real identity, model, database, or object-storage services.
