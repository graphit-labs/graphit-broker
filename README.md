# Graphit Auth Broker

Graphit Auth Broker is the server-side trust boundary for Graphit installations. It validates
OIDC access tokens (or explicitly configured service keys), evaluates deny-by-default ACLs, and
exposes three independently deployable capabilities:

- OpenAI-compatible embeddings at `POST /v1/embeddings`;
- Graphit rerank v1 at `POST /v1/rerank`;
- short-lived, prefix-scoped S3 credentials at `POST /v1/s3/credentials`.

The broker owns upstream AI credentials, model selection, AWS access and cache policy. A Graphit
user authenticates once with the named provider and sends only the resulting access token. The
client cannot select or override the broker's upstream model.

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

## Development

```bash
make fmt
make test
make vet
make build
```

All unit tests are hermetic: OIDC, upstream AI and STS are represented by in-process fakes.
