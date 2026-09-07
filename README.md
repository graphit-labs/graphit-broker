# Graphit Auth Broker

Graphit Auth Broker is the server-side trust boundary for Graphit installations. It validates
OIDC access tokens (or explicitly configured service keys), evaluates deny-by-default ACLs, and
exposes three independently deployable capabilities:

- OpenAI-compatible embeddings at `POST /v1/embeddings`;
- Graphit rerank v1 at `POST /v1/rerank`;
- per-operation S3 pre-signed requests at `POST /v1/s3/presign`, including anonymous grants.

It also includes a separately protected ACL console at `/admin/`. Administrators can publish
global, anonymous, authenticated, user, team, organization and subject grants without restarting
the process. Changes use revision-based compare-and-swap and an atomically persisted policy file.

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

```bash
cp config.example.yaml config.yaml
cp .env.example .env
# Fill the IdP, upstream API and AWS values in .env/config.yaml.
docker compose -f docker-compose.example.yml up --build -d
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/.well-known/graphit-broker
```

Validate before deploying:

```bash
docker build -t graphit-auth-broker:local .
docker run --rm --env-file .env \
  -v "$PWD/config.yaml:/etc/graphit-auth-broker/config.yaml:ro" \
  graphit-auth-broker:local --check-config
```

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
