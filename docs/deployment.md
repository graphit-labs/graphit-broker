# Deployment

## Container

The Dockerfile produces one non-root image with CA certificates, a health check, ONNX Runtime, and
CUDA libraries. Model weights are not included. The example Compose service uses a read-only root
filesystem, drops all capabilities, enables `no-new-privileges`, and persists configuration,
database state, and downloaded model files in separate named volumes.

```bash
cp .env.example .env
docker compose -f docker-compose.yml up --build -d
```

Docker seeds the empty `broker-config` volume from `/etc/graphit-broker/config.yaml` in the image.
The mounted YAML is deployment bootstrap configuration; after it initializes an empty SQL database,
changes made through the administration UI are stored in `broker-state` (or the configured remote
database). To initialize the volume from a customized file:

```bash
cp config.example.yaml config.yaml
# Edit config.yaml, then:
docker compose create broker
docker compose cp config.yaml broker:/etc/graphit-broker/config.yaml
docker compose up -d
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

## AI services

The broker owns upstream endpoint, model, API key, timeouts, limits, and cache. It supports the
Graphit Code provider set: OpenAI-compatible, Cohere, Voyage, and Google embeddings; Cohere,
Voyage, and Jina rerank; plus local CodeRankEmbed and BGE rerank inference. Allow egress only to
configured upstreams and, when local models are activated, to their pinned Hugging Face artifact
URLs.

At startup, each enabled `backend: local` service resolves only the ID selected by
`models.embedding` or `models.rerank`; an upstream or disabled service does not touch the catalog.
`on_demand` manifests download missing verified artifacts before the listener starts. `setup`
manifests use `--setup-models`, while `never` manifests require a fully populated bundle and perform
no network access. Cached bundles survive restarts in `broker-models`. See the
[local model catalog](models.md) for every manifest field and complete examples.

One way to seed that named volume without another Compose file is to create the service, copy the
artifacts, and then start it:

```bash
docker compose create broker
docker compose cp ./models/custom-embedding broker:/var/cache/graphit-broker/models/custom-embedding
docker compose up -d
```

The copied directory must include `manifest.json` and every required artifact, and be readable by
the image's non-root broker user. Run a controlled prefetch without another Compose file via
`docker compose run --rm broker --config /etc/graphit-broker/config.yaml --setup-models`.

Default Compose runs on CPU. On an NVIDIA host with the Container Toolkit installed, expose GPUs
through the same file; `device: auto` prefers CUDA and falls back to CPU using the same image:

```bash
GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia docker compose up --build -d
```

Set `device: cpu` to force CPU or `device: cuda` to require CUDA. The resolved manifest and artifact
identity is appended to each local revision automatically; an embedding identity change requires
reindexing because Graphit isolates incompatible vector spaces.

The Compose environment selects the container runtime, not the inference device policy. Keep
`local.device: auto` to prefer an exposed GPU or use `cuda` when startup must fail unless it is
usable. `GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia` requires the NVIDIA Container Toolkit to have
registered the `nvidia` runtime with Docker. Confirm host visibility with `nvidia-smi`; the broker
logs the chosen `cuda` or `cpu` device when each local model becomes ready.

For native installation, see [running the native binary](binary.md). CPU and macOS CoreML do not
require CUDA or cuDNN; native CUDA selection does.

The image's self-contained broker extracts its embedded GPU-capable ONNX payload into
`/var/lib/graphit-broker/.graphit`, which is already covered by the persistent `broker-state`
volume. Native Linux and Windows releases embed the same ONNX shared/CUDA provider libraries but
load them only when CUDA is selected. macOS embeds CoreML in its main ONNX dylib.

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
