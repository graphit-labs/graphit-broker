# Deployment

## Container

The Dockerfile produces a static, non-root image with CA certificates, a health check, and a
private SQLite directory. The example Compose service uses a read-only root filesystem, drops all
capabilities, enables `no-new-privileges`, mounts configuration read-only, and persists the
database directory.

```bash
cp config.example.yaml config.yaml
cp .env.example .env
docker compose -f docker-compose.yml up --build -d
```

Bind only to loopback when a reverse proxy owns public TLS. Forward the original host/scheme
correctly and register the public `/admin/auth/callback` URL exactly with the IdP.

## Database selection

SQLite needs the named `broker-state` volume and exactly one writable broker. PostgreSQL or MySQL
should use a secret-injected DSN and database network policy; several stateless broker replicas may
share the remote database. See [database backends](database.md).

The first process creates the current schema and seeds configuration. Start one replica for a new
database, verify it, then scale. There are no migrations: an incompatible schema requires an
explicit recreate/restore for the matching build.

## S3 routes

Create least-privilege credentials per private route. A route needs permission only for its
`bucket/base_prefix` and operations that grants can authorize. Multiple routes may target
different AWS accounts, regions, buckets, or S3-compatible services.

The broker performs SigV4 locally and returns only an opaque signed request. Graphit does not
configure bucket/topology and cannot override the selected route. For write/delete grants, use
object versioning, retention, and audit controls appropriate to the data.

Named routes can provide logical staging/production separation inside one broker when exact
projects and distinct deployment principals deterministically select each route. This still
shares one broker process, administration boundary, configuration store, and grant database. For
strong environment isolation, deploy separate brokers with separate databases, credentials,
buckets/accounts, and administration configuration:

```text
Graphit staging    -> broker staging    -> database/S3 staging
Graphit production -> broker production -> database/S3 production
```

Prefer the separate-broker model when a configuration mistake, compromised administrator, or
credential exposure in staging must not be able to affect production. If one broker owns both
environments, make every environment grant name its route explicitly and test that staging
principals and project IDs cannot match production grants.

## AI upstreams

The broker owns upstream endpoint, model, API key, timeouts, limits, and cache. Allow egress only to
configured upstreams. Change the embedding revision whenever model, tokenizer, dimensions, or
other vector-space semantics change; Graphit uses it to isolate incompatible indexes.

## OIDC

Use:

- a native/public Graphit login client using Authorization Code + PKCE;
- a broker API audience/resource for consumer access;
- optionally RFC 8693 token exchange when MCP and broker audiences differ;
- a confidential broker administration web client.

Grant only required scopes and map stable claims. Do not use email as the immutable superadmin key.

## Rollout

1. Back up the database and deployment secrets.
2. Validate the new config with `--check-config`.
3. Start one instance and wait for `/readyz`.
4. Inspect discovery and its authorization revision.
5. Test anonymous denial, one allowed user, one denied user, Hub discovery, S3 read/write as
   applicable, embeddings, rerank, and admin login.
6. Add remote-database replicas only after the single instance is healthy.

Configuration changes through the UI are built before commit and atomically replace the runtime.
Grant changes are independent SQL transactions and apply on the next consumer operation.

## Kubernetes outline

Use a Deployment with a Secret-backed environment, read-only ConfigMap mount, non-root security
context, readiness/liveness HTTP probes, NetworkPolicies, and PostgreSQL/MySQL for multiple
replicas. SQLite should instead use one replica and a ReadWriteOnce persistent volume. Protect
`/admin/` at the same TLS boundary as the consumer API; do not rely on an ingress login page as a
replacement for the broker's own OIDC/RBAC.
