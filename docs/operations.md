# Operations and troubleshooting

## Observability

The broker writes structured JSON logs to stdout. Every request gets an `X-Request-ID`; the same ID
appears in logs and safe error bodies. Record latency, status and path at the edge. Alert on repeated
401/403, 502, readiness failure, STS latency and cache-miss spikes.

`X-Graphit-Cache: HIT|MISS` is returned for AI requests. Caches are bounded by `max_entries`, expire
after `ttl`, and are per process. They are an optimization only; no correctness depends on them.

## Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| 401 | token absent/expired, issuer, signature, audience or scope mismatch | IdP discovery reachability and JWT claims |
| 403 | valid principal but no matching ACL | normalized username/org/teams and conjunctive selectors |
| 404 `capability_disabled` | service disabled | discovery and `services.*.enabled` |
| 400 from S3 exchange | invalid project/operation | safe project segment and supported operation |
| 502 AI | upstream timeout/error/invalid response | broker logs by request ID; upstream credentials/model/dimensions |
| 502 S3 | STS denied or malformed response | runtime role, target trust, duration and inline-policy size |
| Graphit asks for reindex | embedding route revision/width changed | expected rollout; rebuild vectors |
| Docker unhealthy | listen port differs from 8080 | override healthcheck or keep `server.address: :8080` |

## Rotation

- AI keys: update the secret and restart/roll the broker; users receive no new credential.
- Local broker keys: add new hash, update profiles, then remove old hash.
- OIDC signing keys: let the IdP publish overlapping JWKS during rotation.
- AWS role: deploy trust/permission changes before broker configuration that depends on them.
- ACL: increment `authorization_revision` for an auditable rollout. New STS exchanges use the new
  rules; old sessions expire naturally.

## Backup and scaling

The broker is stateless except for in-memory caches. Back up the secret-managed configuration and
deployment definitions, not container filesystems. Replicas can scale horizontally without shared
state. Expect lower hit rate because caches are not distributed; use a broker-external cache only
if it preserves principal/organization/revision isolation.
