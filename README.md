# Graphit Broker

Graphit Broker is the server-side identity, authorization, AI, and storage gateway for
Graphit. It validates end-user OIDC tokens, short-lived local access tokens, or revocable service
credentials,
evaluates deny-by-default resource grants from SQL, and exposes:

- `POST /v1/hub/access/resolve` — the authoritative Hub project grants for the verified caller;
- `POST /v1/s3/credentials` — renewable temporary S3 credentials restricted to one authorized project, user-memory, or Hub-metadata scope;
- `POST /v1/embeddings` — an OpenAI-shaped contract backed by local inference or a broker-owned
  OpenAI-compatible, Cohere, Voyage, or Google adapter;
- `POST /v1/rerank` — the versioned Graphit contract backed by local inference, native
  Cohere/Voyage/Jina adapters, or embedding-simulated OpenAI and Google Gemini adapters;
- `/admin/` — the OIDC/local-password UI for read-only configuration, resource grants, system roles,
  role assignments, local-identity lifecycle, and service credentials.

Only the broker knows AI API keys, upstream models, and the permanent S3 credentials used to call
STS. After authenticating Graphit, it selects the route from current grants for the requested scope and returns that route's
bucket, region, endpoint, root prefix, and short-lived STS credentials. Graphit renews them before
expiry and accesses S3 directly; anonymous callers never receive storage credentials.

For HTTP MCP, Graphit validates the end user's OIDC bearer and preserves it for every broker call.
The default direct-relay mode uses one shared MCP/broker audience. If the IdP supports RFC 8693,
Graphit may instead exchange the MCP token for a short-lived broker-audience token. The broker
validates the final token independently in both modes; exchange failure never downgrades to relay
or anonymous access.

## Persistence and authorization

`config.yaml`, after environment expansion, is the sole configuration authority. Changes are
applied by deployment/restart and the administration API exposes only a redacted read-only view.
SQL stores local identities and Argon2id verifiers, normalized resource grants, grant revision,
system roles and assignments, login flows, sessions, and HMAC-protected local tokens—but never raw
passwords/tokens, the configuration document, pepper, or resolved deployment secrets. SQLite is
the default single-node deployment; PostgreSQL and MySQL use the same domain model.

Resource grants are created through the UI or administration API. A new database has no grants and
therefore denies every consumer operation.

There is deliberately no migration, compatibility loader, dual read/write, or fallback path in
this development version. Recreate the database when the schema version changes.

Local identities live in SQL. Set `authentication.token_pepper` from a secret manager, then run
`graphit-broker --config config.yaml --bootstrap-admin` (or `--bootstrap-admin-stdin`) once on an
empty database. The command reads only a temporary password, creates the fixed first username `admin`, and
refuses to overwrite any existing local user. Passwords require at least 15 Unicode characters;
the user must replace the temporary password and enroll TOTP MFA at first login. The QR code works
with Google Authenticator and compatible applications; administrative MFA reset forces safe
reenrollment after a lost device. Failed checks are rate-limited per username, and concurrent
Argon2id work plus its bounded admission
queue are configurable. Optional adaptive CAPTCHA can use Cloudflare Turnstile or Google reCAPTCHA
v2 Checkbox when concurrent local authentication reaches a configured multiple of the Argon2id
worker limit; a zero multiplier protects every attempt and positive fractions can start earlier. It
is disabled by default. See [configuration](docs/configuration.md) and
[administration bootstrap](docs/administration.md).

Passwords are accepted only at browser/device login and are never reusable API Bearers. Desktop
CLI login uses the Broker as a standard OpenID Provider with Authorization Code, PKCE, nonce and
EdDSA ID-token verification; headless login uses Device Authorization, and
automation uses passwordless service identities with independently expiring/revocable credentials.

RBAC applies throughout the broker. Every authenticated OIDC or local principal receives the
built-in `user` role by default; `admin` and custom roles add system actions. Resource grants remain
the independent, deny-by-default authorization layer for project capabilities:

- roles control system/UI actions; optional verified OIDC claim roles override SQL assignments;
- resource grants control which verified consumer may use `hub`, `s3`, `embeddings`, and
  `rerank`, for which exact projects and S3 operations/routes/prefixes.

## Quick start with Docker

Requirements: Docker 24+, the unified OIDC client when browser login is used, an
`authentication.token_pepper` of at least 32 bytes when administration/local users are enabled,
a bootstrapped local administrator (or an OIDC role/assignment yielding `admin`), and credentials for
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

When an enabled service has `upstream.protocol: onnx`, startup downloads and initializes only that service's
model. On a host with the NVIDIA Container Toolkit, expose GPUs through the same Compose file. The
same image is used in both modes; `device: auto` prefers CUDA when exposed and falls back to CPU:

```bash
GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia docker compose up --build -d
```

Local ONNX models use manifest bundles under the persistent `broker-models` volume. Each service’s
`upstream.model` selects a preset or custom ID; each manifest controls verified
`on_demand`, explicit `setup`, or installed-only `never` acquisition and the complete inference
semantics. See the [local model catalog](docs/models.md) for all fields and examples.

Native releases for Linux amd64, macOS arm64, and Windows amd64 are single self-contained
executables. Linux and Windows embed the ONNX core plus shared/CUDA providers; macOS embeds the
CoreML-capable ONNX dylib. They extract atomically under
`${GRAPHIT_GLOBAL_DIR:-~/.graphit}/broker/runtime/onnxruntime` on first execution; subsequent starts use a
small completion marker and file metadata only. `device: auto` prefers CoreML on macOS, CUDA on
Linux/Windows when visible, and otherwise CPU.

Install a native release on Linux amd64 or macOS arm64:

```bash
curl -fsSL https://raw.githubusercontent.com/graphit-labs/graphit-broker/main/install.sh | sh
```

On Windows amd64, use PowerShell:

```powershell
irm https://raw.githubusercontent.com/graphit-labs/graphit-broker/main/install.ps1 | iex
```

If you cloned the repository, run the local script instead. Review the remote script's source
before using a one-line installer. The installers verify the release archive checksum and install
only the executable (by default in `$HOME/.local/bin` or `$env:LOCALAPPDATA\Graphit\bin`); they do
not set up configuration, a database, or a service. For a pinned release or another destination, see
[native installation and configuration](docs/binary.md). A tagged installation supports
`graphit-broker self-update`; restart an active broker service afterward.

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
