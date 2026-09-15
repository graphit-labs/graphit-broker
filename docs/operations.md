# Operations and troubleshooting

## Observability

`/healthz` reports process liveness and `/readyz` reports readiness. Every request receives an
`X-Request-ID`; provide one for cross-service tracing. AI responses expose cache hit/miss and
effective revision. Discovery, Hub resolution, and S3 responses expose the current authorization
revision.

Monitor latency/error rates separately for OIDC discovery/JWKS, SQL, token exchange, Hub resolve,
STS issuance, object storage, embeddings, and rerank. Never log bearer tokens, temporary S3
credentials, bodies, or upstream secrets.

## Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| startup rejects schema | database belongs to another development build | version 9 upgrades to 10 automatically; for other versions restore a matching backup or recreate |
| startup cannot connect | driver/DSN/TLS/network/credentials | YAML `database.driver`/`database.dsn` and their explicit ENV references, database policy, CA |
| every consumer gets 403 | empty/mismatched resource grants | Resource grants UI, exact project, capability, access scope |
| valid user gets 401 | issuer/audience/signature/expiry/scope mismatch | OIDC discovery, API audience, clocks |
| UI identity gets 403 | default `user` or assigned/claimed roles do not permit the action | unified OIDC `role_claim`, canonical-subject assignments |
| grant write gets 409 | another admin changed the ACL revision | reload and reapply |
| Hub outage does not use projects.json | expected secure behavior | selected broker is sole authority |
| S3 credentials gets 401/403 | missing authenticated identity or matching S3 grant | bearer, grant and route |
| S3 credentials gets 400 | missing/invalid scope, unsafe project ID, or unknown request field | send exactly `project` + project ULID, `user`, or `hub` |
| S3 credentials gets 502 | STS trust, role, signing key, endpoint, duration, or 2048-byte policy limit | route and STS logs |
| token exchange fails | IdP lacks RFC 8693 or target/client unauthorized | provider strategy, endpoint, audience/resource |
| embedding index mismatch | broker embedding revision/dimensions changed | deploy a new revision and re-embed/namespace |
| embedding cache misses unexpectedly | provider endpoint, model, revision, dimensions, or input type changed | compare the active embedding configuration and effective local-model identity; these changes intentionally create a new cache namespace |
| startup is slow with local AI | first-time model download and ONNX session initialization | broker logs, model-volume free space, artifact egress |
| local AI cannot download | artifact egress, cache permissions, disk space, or digest mismatch | `broker/models` in the `broker-global` volume and broker error response |
| GPU is visible but local ONNX uses CPU | `upstream.device` was omitted (CPU is the default) or set to `cpu` | set `upstream.device: auto` to try GPU with CPU fallback, or `cuda` to require it |
| `device: cuda` fails | GPU not exposed, driver/toolkit mismatch, or invalid device ID | NVIDIA runtime selected in the same Compose file, `nvidia-smi`, `upstream.device_id` |
| `device: coreml` fails | non-macOS host, unsupported model graph, or CoreML initialization failure | macOS version, broker platform, startup provider error |
| `device: auto` uses CPU | CoreML/CUDA unavailable, provider initialization failed, or an inference exhausted accelerator memory | provider/recovery warning, macOS support, NVIDIA runtime selection, GPU memory pressure |

## Backup

Back up SQL authorization/session state and separately retain deployment configuration and secret
manager definitions. SQL does not contain expanded configuration secrets, but it does contain live
session metadata; encrypt and restrict backups.

- SQLite: stop the writer or use an online SQLite backup that captures WAL consistently.
- PostgreSQL/MySQL: use the platform's transactionally consistent backup tooling and verify restore.

Restore into the exact schema-compatible broker build. Start one replica, verify admin and consumer
flows, then scale.

The SQL `embedding_cache` table stores vectors keyed by input SHA-256 and a compatibility
fingerprint; it stores no input text. Its composite primary key supports indexed lookups as the
table grows. Entries have no TTL or automatic eviction, so monitor database size and include the
table in backup capacity planning. Changing the embedding revision prevents reuse of old vectors
but does not delete their rows. A partially failed embedding batch can still leave successful
vectors in this table for later reuse. A full cache hit avoids the model call; a mixed batch sends
only distinct missing inputs to the provider.

## Rotation

- Upstream OIDC validation keys follow the upstream issuer's JWKS rotation.
- The Broker OpenID Provider's Ed25519 signing key, internal protocol key, and stable-subject
  derivation are separate keys derived from `authentication.token_pepper`. The current development
  implementation publishes one signing key and has no online key ring: changing the pepper rotates
  all three at restart and deliberately invalidates every Broker-issued token, local credential,
  administration session, pending flow, and derived Broker subject.
- Upstream OIDC issuer/browser-client changes should be updated in unified authentication
  configuration and tested before removing old IdP values.
- S3 route keys/roles can be rotated by updating the route; already issued STS credentials remain
  valid until their short expiry unless revoked by the storage platform.
- AI API keys are rotated at the provider/secret manager, followed by a deployment restart.
- Local passwords use SQL Argon2id verifiers and the deployment-wide
  `authentication.token_pepper`. Change individual passwords in the Local users UI. Pepper rotation
  invalidates every local password, administration session, local access/refresh token, and service
  credential and requires a coordinated recovery.
- Grant revocation is reflected in the next credential issuance and increments the revision.
  Already issued STS credentials retain their bounded session policy until expiry or platform revocation.

## Incident response

For a leaked upstream OIDC token, revoke or expire it at that upstream IdP. For a leaked
Broker-issued OIDC access or refresh token, call `/oauth/revoke`; refresh-token reuse also revokes
its complete family. Broker endpoints enforce that state immediately, but services performing
offline JWKS validation accept an access JWT already issued until `exp`; keep `access_ttl` short.
Revoke a service credential through administration. Changing or disabling the
owning local identity increments its revision and invalidates its existing sessions and tokens.
For a leaked S3 or AI key, rotate it at the upstream, update deployment secrets, and restart. For
database exposure, invalidate live admin sessions, reset local passwords, and restore trusted
users/grants/roles. Deployment secrets are not stored in SQL; rotate the authentication pepper if compromise may include both SQL
and deployment secret access.

If SQL is unavailable, the broker fails authorization closed. Do not introduce a cached-grant or
`projects.json` fallback during recovery. Restore the selected authority instead.
