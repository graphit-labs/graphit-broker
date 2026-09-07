# Graphit Auth Broker

Graphit Auth Broker is the server-side trust boundary for Graphit installations. It validates
OIDC access tokens (or explicitly configured service keys), evaluates deny-by-default ACLs, and
exposes three independently deployable capabilities:

- OpenAI-compatible embeddings at `POST /v1/embeddings`;
- Graphit rerank v1 at `POST /v1/rerank`;
- per-operation S3 pre-signed requests at `POST /v1/s3/presign`, including anonymous grants.

It also includes an OIDC-protected control plane at `/admin/`. Administrators can edit the complete
broker configuration, publish global/anonymous/authenticated/user/team/organization/subject grants,
and assign action-based roles without restarting the process. SQLite persists configuration,
administrative sessions and role assignments in a Docker-mountable volume. Configuration changes
use revision-based compare-and-swap and are activated atomically in the running broker.

The broker exclusively owns upstream AI credentials, model selection, bucket/region/endpoint,
storage prefixes, direct S3 signing credentials and cache policy. A Graphit
user authenticates once with the named provider and sends only the resulting access token. The
client cannot select or override the broker's upstream model or storage topology, and never
receives cloud credentials.

Storage can define multiple named routes. ACL rules select a route dynamically per trusted
principal/project/operation, so one broker can isolate organizations across different accounts,
buckets, regions or S3-compatible services without changing any Graphit provider or profile.

## Quick start

Requirements: Docker 24+ (recommended), or Go 1.26+ for a source build.

Before starting, register a confidential OIDC web application whose exact callback is
`https://YOUR-BROKER/admin/auth/callback`, identify the immutable `sub` claim for the first owner,
and place that value in `BROKER_SUPERADMIN_SUBJECT`. On an empty database no other identity can
open administration; the superadmin can then assign the built-in `admin` role or create narrower
roles in the UI.

```bash
cp config.example.yaml config.yaml
cp .env.example .env
# Fill administration OIDC, upstream API and S3 values in .env/config.yaml.
docker compose -f docker-compose.example.yml up --build -d
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/.well-known/graphit-broker
# Then open https://YOUR-BROKER/admin/ and sign in through OIDC.
```

Validate before deploying:

```bash
docker build -t graphit-auth-broker:local .
docker run --rm --env-file .env \
  -v "$PWD/config.yaml:/etc/graphit-auth-broker/config.yaml:ro" \
  graphit-auth-broker:local --check-config
```

The named `broker-state` volume contains `/var/lib/graphit-auth-broker/broker.db`. After its first
successful start, SQLite is authoritative for mutable settings; `config.yaml` is the seed for a new
database. `administration.database_path` and `BROKER_SUPERADMIN_SUBJECT` remain deployment-owned
bootstrap controls. See the administration and operations guides before backing up, restoring or
rotating secrets.

SQLite (including its WAL/SHM companions) is the broker's only mutable persistence. ACLs, complete
configuration, roles, assignments, OIDC login flows and admin sessions are all tables in that
database. AI caches are deliberately memory-only and signed URLs are never persisted. There is no
legacy file loader, compatibility mode or database migration path in this development version.

For a harmless smoke test with every external capability disabled:

```bash
docker build -t graphit-auth-broker:local .
docker run --rm -d --name graphit-broker-smoke -p 18080:8080 \
  -v "$PWD/examples/health-only.yaml:/etc/graphit-auth-broker/config.yaml:ro" \
  graphit-auth-broker:local
curl --fail http://127.0.0.1:18080/healthz
docker rm -f graphit-broker-smoke
```

## Documentation

- [Configuration](docs/configuration.md)
- [OIDC integration](docs/oidc.md)
- [HTTP API contracts](docs/api.md)
- [Deployment and AWS](docs/deployment.md)
- [Security and ACL model](docs/security.md)
- [Operations and troubleshooting](docs/operations.md)
- [Administration UI and access policy](docs/administration.md)

## Development

```bash
make fmt
make test
make vet
make build
```

All unit tests are hermetic: OIDC and upstream AI are represented by in-process fakes; S3 signing
uses synthetic route credentials and performs no network request.
