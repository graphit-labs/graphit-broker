# Deployment

## Container

Each tagged release publishes a Linux amd64 image to
`ghcr.io/graphit-labs/graphit-broker`. For `v0.1.1`, the available tags are `0.1.1`, `0.1`, `0`, and
`latest`; image tags never include the Git tag's `v` prefix. The release workflow builds the image
from the same self-contained Linux binary it publishes as a release artifact. The runtime image
does not download a binary or contain a Go toolchain.

The image runs as `graphit` (UID/GID 10001), includes CA certificates, CUDA libraries, and a
readiness health check, but no model weights. The example Compose service uses a read-only root
filesystem, drops all capabilities, enables `no-new-privileges`, and mounts configuration,
database state, downloaded model files, and the embedded runtime beneath one persistent Graphit
broker directory.

```bash
cp .env.example .env
cp config.example.yaml config.yaml
# Fill .env and edit config.yaml before continuing.
docker compose -f docker-compose.yml pull
docker compose -f docker-compose.yml create broker
docker compose -f docker-compose.yml cp config.yaml broker:/home/graphit/.graphit/broker/config.yaml
docker compose -f docker-compose.yml up -d
```

Set `GRAPHIT_BROKER_IMAGE` to pin another published tag. For a local image, run
`make build VERSION=dev && docker build -t graphit-broker:local .`, then set
`GRAPHIT_BROKER_IMAGE=graphit-broker:local` before starting Compose.
The mounted YAML chooses the SQLite DSN, whether it references an environment variable, and that
variable's name. `config.example.yaml` selects `BROKER_DATABASE_DSN` with a portable
`~/.graphit/broker/broker.db` fallback; this name is not built into the executable or image.

The image intentionally contains no operational YAML. The entrypoint requires
`/home/graphit/.graphit/broker/config.yaml` to exist as a regular file readable by UID 10001 and
refuses to start otherwise. The mounted YAML, after environment expansion, is always authoritative.
It is never stored in SQL; edit or replace the deployment file/secrets and restart to apply changes.

Bind only to loopback when a reverse proxy owns public TLS. Forward the original host/scheme
correctly. Set `server.public_url` to the externally visible HTTPS origin; that exact value becomes
the Broker's OpenID issuer. When upstream OIDC browser login is enabled, register the public
`/oauth/oidc/callback` URL exactly with the upstream IdP.

Local development may use `server.public_url: http://localhost:8080` (or a loopback IP) with
`administration.cookie_secure: false`. HTTP public URLs on remote or private-network hosts are rejected.

If adaptive local-login CAPTCHA is enabled, `server.public_url` must be the exact origin whose
hostname is registered with the selected provider. Allow browser CSP access and backend egress only
to `challenges.cloudflare.com` for Turnstile, or to Google's documented reCAPTCHA origins and
`www.google.com` Siteverify for reCAPTCHA v2. Store the provider secret in the secret manager; only
the site key is public. The CAPTCHA threshold is per process, so multiple replicas multiply both
the local admission capacity and the number of attempts possible before each replica requires a
challenge. Use load-balancer/WAF controls when a cluster-wide abuse envelope is required.

## Database selection

SQLite uses `broker/broker.db` in the named `broker-global` volume and needs exactly one writable
broker. PostgreSQL or MySQL
should use a secret-injected DSN and database network policy; several stateless broker replicas may
share the remote database. See [database backends](database.md).

The first process creates the current SQL schema. Start one replica for a new database, verify it,
then scale. There are no migrations: an incompatible schema requires an
explicit recreate/restore for the matching build.

## S3 routes

Create a least-privilege assumable role and broker signing identity per private route. The role
needs permission only for its `bucket/base_prefix` and operations that grants can authorize. The
signing identity needs `sts:AssumeRole` for that role. Multiple routes may target different AWS
accounts, regions, buckets, or S3-compatible services, but the matching grants for each requested
storage scope must select exactly one route.

The broker signs `AssumeRole`, intersects the role/user permissions with its generated session
policy, and returns temporary credentials plus the selected topology. Graphit identifies the
project, user-memory, or Hub-metadata scope but cannot override the route, roots, or policy. Its S3,
LanceDB, and Ladybug traffic then goes directly to object storage. For
write/delete grants, use object versioning, retention, and audit controls appropriate to the data.

Named routes can provide logical staging/production separation inside one broker when exact
projects and distinct deployment principals deterministically select each route. This still
shares one broker process, administration boundary, deployment configuration, and grant database. For
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
[Graphit Code](https://github.com/graphit-labs/graphit-code) provider set: OpenAI-compatible, Cohere, Voyage, and Google embeddings; Cohere,
Voyage, and Jina rerank; plus local CodeRankEmbed and BGE rerank inference. Allow egress only to
configured upstreams and, when local models are activated, to their pinned Hugging Face artifact
URLs.

At startup, each enabled `upstream.protocol: onnx` service resolves its `upstream.model` from
`upstream.directory`; an HTTP or disabled service does not touch the catalog.
`on_demand` manifests download missing verified artifacts before the listener starts. `setup`
manifests use `--setup-models`, while `never` manifests require a fully populated bundle and perform
no network access. Cached bundles survive restarts under `broker/models` in `broker-global`. See the
[local model catalog](models.md) for every manifest field and complete examples.

One way to seed that named volume without another Compose file is to create the service, copy the
artifacts, and then start it:

```bash
docker compose create broker
docker compose cp ./models/custom-embedding broker:/home/graphit/.graphit/broker/models/custom-embedding
docker compose up -d
```

The copied directory must include `manifest.json` and every required artifact, and be readable by
the image's non-root broker user. Run a controlled prefetch without another Compose file via
`docker compose run --rm broker --setup-models`.

Default Compose and local ONNX inference run on CPU. On an NVIDIA host with the Container Toolkit
installed, set `upstream.device: auto` explicitly for each local service that should try CUDA,
then expose GPUs through the same Compose file. `auto` falls back to CPU using the same image:

```bash
GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia docker compose up -d
```

Omit `device` or set `device: cpu` to use CPU; set `device: cuda` to require CUDA. The resolved
manifest and artifact identity is appended to each local revision automatically; an embedding
identity change requires reindexing because Graphit isolates incompatible vector spaces.

The Compose environment selects the container runtime, not the inference device policy. Set
`upstream.device: auto` to prefer an exposed GPU or use `cuda` when startup must fail unless it is
usable. `GRAPHIT_BROKER_CONTAINER_RUNTIME=nvidia` requires the NVIDIA Container Toolkit to have
registered the `nvidia` runtime with Docker. Confirm host visibility with `nvidia-smi`; the broker
logs the chosen `cuda` or `cpu` device when each local model becomes ready.

For native installation, see [running the native binary](binary.md). CPU and macOS CoreML do not
require CUDA or cuDNN; native CUDA selection does.

The image's self-contained broker extracts its embedded GPU-capable ONNX payload into
`/home/graphit/.graphit`, with its `broker` subdirectory persisted by the `broker-global` volume at
`/home/graphit/.graphit/broker`. That same directory is the image's working directory.
`GRAPHIT_GLOBAL_DIR` may select another path, but it must be readable, writable, and traversable by
UID 10001; the entrypoint refuses to start otherwise. `GRAPHIT_BROKER_CONFIG` selects the YAML path,
and `GRAPHIT_BROKER_HEALTHCHECK_URL` can override the default readiness probe at
`http://127.0.0.1:8080/readyz`. Native Linux and Windows releases embed the same ONNX shared/CUDA
provider libraries but load them only when CUDA is selected. macOS embeds CoreML in its main ONNX
dylib.

## OIDC

The Broker has two distinct OIDC roles that share one deployment configuration:

1. It is the OpenID Provider consumed by Graphit Code. Its issuer is `server.public_url`; it
   publishes standard discovery, authorization, token, JWKS, userinfo, revocation, introspection,
   and end-session endpoints. The configured `authentication.local.tokens.cli_client_id` is a
   public/native client using Authorization Code, PKCE S256, state, nonce, and a dynamic loopback
   redirect whose path is `cli_redirect_path`.
2. It may be an OIDC client of multiple upstream organization IdPs. Browser-client fields on each
   `authentication.oidc` entry enable a named method and use the exact public
   `/oauth/oidc/callback`. The same issuer entries validate consumer bearer tokens; there is no
   administration-specific OIDC block.

Graphit Code first reads `/.well-known/graphit-broker`, then uses only the standard OpenID Provider
metadata and endpoints. The Broker-owned authorization page offers local login and every named
upstream OIDC provider that is configured, shows only local when that is the sole method, and
redirects immediately only when exactly one upstream provider is the sole method. An upstream token
is never returned to Graphit Code: after successful
authentication, the Broker issues its own EdDSA ID/access JWTs and an opaque rotating refresh token.
The access JWT is audience-bound and verifiable through the Broker JWKS; offline validators accept
an already issued token until `exp`, even after Broker-side revocation.

Grant only required upstream scopes and map stable claims. Claim mappings accept exact top-level
keys or RFC 9535 JSONPath. If `authentication.oidc[].role_claim` is enabled, its additional roles
replace SQL assignments for that canonical identity; every authenticated principal still receives
`user`. Bootstrap a new database with `--bootstrap-admin` after configuring the single
`authentication.token_pepper` when OIDC does not already provide an administrator.

Changing the pepper is not a routine signing-key rollover. It changes the Broker signing and
encryption keys and derived subjects, invalidates all local passwords/tokens/sessions/flows, and
requires a coordinated whole-deployment recovery. This development version has no migration or
compatibility reader for prior database/authentication schemas.

## Rollout

1. Back up the database and deployment secrets.
2. Validate the new config with `--check-config`.
3. Start one instance and wait for `/readyz`.
4. Inspect discovery and its authorization revision.
5. Verify both discovery documents and JWKS; test every enabled login method through a complete
   Graphit Code Authorization Code exchange and refresh rotation. Also test anonymous denial, one
   allowed user, one denied user, Hub discovery, S3 read/write as applicable, embeddings, rerank,
   and admin login.
6. Add remote-database replicas only after the single instance is healthy.

Configuration changes require a deployment update and broker restart. Grant changes are
independent SQL transactions and apply on the next consumer operation.

## Kubernetes outline

Use a Deployment with a Secret-backed environment, read-only ConfigMap mount, non-root security
context, readiness/liveness HTTP probes, NetworkPolicies, and PostgreSQL/MySQL for multiple
replicas. SQLite should instead use one replica and a ReadWriteOnce persistent volume. Protect
`/admin/` at the same TLS boundary as the consumer API; do not rely on an ingress login page as a
replacement for the broker's own OIDC/RBAC.
