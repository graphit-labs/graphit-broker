# Operations and troubleshooting

## Observability

The broker writes structured JSON logs to stdout. Every request gets an `X-Request-ID`; the same ID
appears in logs and safe error bodies. Record latency, status and path at the edge. Alert on repeated
401/403, 502, readiness failure, S3 rejection and cache-miss spikes.

`X-Graphit-Cache: HIT|MISS` is returned for AI requests. Caches are bounded by `max_entries`, expire
after `ttl`, and are per process. They are an optimization only; no correctness depends on them.

## Common failures

| Symptom | Likely cause | Check |
|---|---|---|
| 401 | token was supplied but is malformed/expired or issuer, signature, audience or scope mismatches | IdP discovery reachability and JWT claims |
| 403 without a token | no explicit anonymous grant matches | `access: anonymous`, project, operation and full prefix |
| 403 | valid principal but no matching ACL | normalized username/org/teams and conjunctive selectors |
| 404 `capability_disabled` | service disabled | discovery and `services.*.enabled` |
| 400 from S3 presign | invalid project/operation/key binding | safe project segment, supported operation, and matching `v2/projects/<project>/...` key |
| 502 AI | upstream timeout/error/invalid response | broker logs by request ID; upstream credentials/model/dimensions |
| S3 rejects a signed request | wrong route credential/topology, expired URL, object-store policy, or clock skew | route endpoint/region/bucket, key permissions, broker clock and request ID |
| 409 saving UI policy | another admin changed the revision | reload, reconcile, save with the new ETag |
| Graphit asks for reindex | embedding route revision/width changed | expected rollout; rebuild vectors |
| Docker unhealthy | listen port differs from 8080 | override healthcheck or keep `server.address: :8080` |

## Rotation

- AI keys: update the secret and restart/roll the broker; users receive no new credential.
- Local broker keys: add new hash, update profiles, then remove old hash.
- OIDC signing keys: let the IdP publish overlapping JWKS during rotation.
- S3 route keys: add the replacement secret, roll/restart the broker, verify signed operations, then revoke the old key.
- ACL: UI saves increment the persistent policy revision automatically. New pre-signs use it;
  already issued URLs expire naturally.

## Backup and scaling

The broker is stateful only when administration is enabled: back up `administration.state_file`
plus secret-managed configuration/deployment definitions. Replicas that expose writes must share a
store with real cross-process compare-and-swap semantics; a plain shared filesystem does not make
the in-process mutex distributed. Prefer one writer/admin replica and any number of read-only
consumer replicas until an external policy store is introduced. Caches remain per-process.
