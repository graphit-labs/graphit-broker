# Operations and troubleshooting

## Observability

`/healthz` reports process liveness and `/readyz` reports readiness. Protected service adapters expose request identifiers for cross-service tracing; retain the identifier returned by the affected endpoint. AI responses expose cache hit/miss and
effective revision. Discovery, Hub resolution, and S3 responses expose the current authorization
revision.

Monitor latency/error rates separately for OIDC discovery/JWKS, SQL, token exchange, Hub resolve,
STS issuance, object storage, embeddings, and rerank. Never log bearer tokens, temporary S3
credentials, bodies, or upstream secrets.

## Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| startup rejects schema | database belongs to another development build | stop writers, preserve a backup and select the matching build/schema; no automatic migration or reset |
| startup cannot connect | backend/path/TLS/network/credentials | explicit `database.backend` mapping and ENV references, database policy, CA |
| every consumer gets 403 | empty/mismatched resource grants | Project access UI, exact project, capability, access scope |
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
| startup is slow with local AI | explicit artifact validation or GGUF model initialization | configured GGUF bundle, disk access and lifecycle budget; no automatic download |
| local AI configuration fails before readiness | missing/invalid bounded manifest or declaration | explicit model ID, bundle/manifest paths and integrity; provision outside the Broker |
| GPU is visible but local GGUF uses CPU | `upstream.device` was omitted (CPU is the default) or set to `cpu` | set `upstream.device: auto` to try GPU with CPU fallback, or `cuda` to require it |
| `device: cuda` fails | GPU not exposed, driver/toolkit mismatch, or invalid device ID | NVIDIA runtime selected in the same Compose file, `nvidia-smi`, `upstream.device_id` |
| `device: metal` fails | non-macOS host, unsupported model graph, or Metal initialization failure | macOS version, broker platform, startup provider error |
| local AI fails on first uncached use | missing/corrupt artifacts or unavailable requested device | provision the declared bundle and inspect the typed failure |
| `device: auto` uses CPU | Metal/CUDA unavailable, provider initialization failed, or no supported accelerator was registered | registered device/fallback metadata, macOS support, NVIDIA runtime selection, GPU memory pressure |

## Backup

Back up SQL authorization/session state and separately retain deployment configuration and secret
manager definitions. SQL does not contain expanded configuration secrets, but it does contain live
session metadata; encrypt and restrict backups.

- SQLite: stop the writer or use an online SQLite backup that captures WAL consistently.
- PostgreSQL: use transactionally consistent backup tooling and verify restore. MySQL library users follow their separately configured owner.

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
- Supply the native Ed25519 signing key through `auth.pkcs8_file` and its configured key ID, independently of `auth.pepper`. There is no online key-ring rotation command. Coordinate configured trust, restart and token/session recovery with consumers.
- Upstream OIDC issuer/browser-client changes should be updated in unified authentication
  configuration and tested before removing old IdP values.
- S3 route keys/roles can be rotated by updating the route; already issued STS credentials remain
  valid until their short expiry unless revoked by the storage platform.
- AI API keys are rotated at the provider/secret manager, followed by a deployment restart.
- Local passwords use SQL Argon2id verifiers and the deployment-wide
  `auth.pepper`. Change individual passwords in the Local users UI. Pepper rotation
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
