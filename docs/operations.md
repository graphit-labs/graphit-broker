# Operations and troubleshooting

## Observability

`/healthz` reports process liveness and `/readyz` reports readiness. Every request receives an
`X-Request-ID`; provide one for cross-service tracing. AI responses expose cache hit/miss and
effective revision. Discovery, Hub resolution, and S3 responses expose the current authorization
revision.

Monitor latency/error rates separately for OIDC discovery/JWKS, SQL, token exchange, Hub resolve,
S3 pre-sign, object storage, embeddings, and rerank. Never log bearer tokens, signed URLs, bodies,
or upstream secrets.

## Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| startup rejects schema | database belongs to another development build | restore matching backup or recreate; no migration exists |
| startup cannot connect | driver/DSN/TLS/network/credentials | `BROKER_DATABASE_*`, database policy, CA |
| every consumer gets 403 | empty/mismatched resource grants | Resource grants UI, exact project, capability, access scope |
| valid user gets 401 | issuer/audience/signature/expiry/scope mismatch | OIDC discovery, API audience, clocks |
| UI identity gets 403 | no configured or database role permits the action | API-key `roles`, OIDC `role_claim`, assignments |
| grant write gets 409 | another admin changed the ACL revision | reload and reapply |
| Hub outage does not use projects.json | expected secure behavior | selected broker is sole authority |
| pre-sign gets 403 | missing S3 capability/operation/project/prefix | grant and route |
| pre-sign gets 400 | unsafe key/project mismatch or ambiguous routes | logical key and matching grants |
| token exchange fails | IdP lacks RFC 8693 or target/client unauthorized | provider strategy, endpoint, audience/resource |
| embedding index mismatch | broker embedding revision/dimensions changed | deploy a new revision and re-embed/namespace |
| startup is slow with local AI | first-time model download and ONNX session initialization | broker logs, model-volume free space, artifact egress |
| local AI cannot download | artifact egress, cache permissions, disk space, or digest mismatch | `broker-models` volume and broker error response |
| `device: cuda` fails | GPU not exposed, driver/toolkit mismatch, or invalid device ID | NVIDIA runtime selected in the same Compose file, `nvidia-smi`, `local.device_id` |
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

## Rotation

- OIDC signing keys follow issuer JWKS rotation.
- Consumer/OIDC/admin client changes should be updated in deployment configuration and tested before removing
  old IdP values.
- S3 route keys can be rotated by updating the route; already issued URLs remain valid until their
  short expiry.
- AI API keys are rotated at the provider/secret manager, followed by a deployment restart.
- Local passwords in `authentication.api_keys` use per-identity peppers and Argon2id verifiers;
  rotate the pepper and verifier together, then restart in coordination with callers. Existing
  local UI sessions are invalidated by either change.
- Grant revocation is immediate on the next request and increments the revision.

## Incident response

For a leaked end-user token, revoke/expire it at the IdP and remove affected grants if necessary.
For a leaked S3 or AI key, rotate it at the upstream, update deployment secrets, and restart. For
database exposure, invalidate live admin sessions and restore trusted grants/roles. Deployment
secrets are not stored in SQL; rotate the external token pepper if compromise may include both SQL
and deployment secret access.

If SQL is unavailable, the broker fails authorization closed. Do not introduce a cached-grant or
`projects.json` fallback during recovery. Restore the selected authority instead.
