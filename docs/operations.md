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
| 401 on admin callback | state/nonce/code expired, callback mismatch, client authentication failed, or ID token verification failed | administration IdP registration, broker clock, issuer/client ID/secret and exact callback |
| 403 in administration | valid OIDC identity lacks the endpoint action | exact `sub`, `BROKER_SUPERADMIN_SUBJECT`, role definitions and assignments |
| Admin settings revert unexpectedly | a different/empty SQLite volume was mounted | `administration.database_path`, volume identity and startup logs |
| Graphit asks for reindex | embedding route revision/width changed | expected rollout; rebuild vectors |
| Docker unhealthy | listen port differs from 8080 | override healthcheck or keep `server.address: :8080` |

## Rotation

- AI keys: use the complete configuration UI/API to replace the redacted placeholder; the new
  runtime is active after the atomic save.
- Local broker keys: add the replacement key/hash in the UI, update profiles, then remove the old
  entry in a second revision.
- OIDC signing keys: let the IdP publish overlapping JWKS during rotation.
- Administration OIDC secret: rotate it at the IdP and save the replacement in the full configuration
  editor during the provider's overlap window. Existing broker sessions remain valid until logout or
  `session_ttl`; new logins use the new secret.
- S3 route keys: save the replacement access key/secret, verify newly signed operations, then revoke
  the old key. Clients and Graphit providers do not change.
- ACL: UI saves increment the persistent configuration revision automatically. New pre-signs use it;
  already issued URLs expire naturally.

## Backup and scaling

When administration is enabled, back up `administration.database_path` and deployment definitions.
SQLite contains configuration secrets, roles, assignments and live sessions, so encrypt backups,
limit readers and apply the same retention policy as other credential stores.

Two safe backup procedures are supported operationally:

1. **Offline:** gracefully stop the broker, then copy `broker.db` and any adjacent `broker.db-wal`
   and `broker.db-shm` files as one unit. Restore only while the broker is stopped and preserve
   ownership/mode (`65532:65532`, directory `0700`, files `0600`).
2. **Online:** use a trusted maintenance container/tool with SQLite's online backup command against
   the mounted database, for example `sqlite3 /state/broker.db ".backup '/backup/broker.db'"`.
   Do not use a plain file copy while writes may be active.

After restore, start one broker instance, sign in as the environment-defined superadmin, verify the
reported configuration revision/role assignments, exercise negative ACL cases, and rotate secrets
if the backup crossed a trust boundary.

SQLite is a single-node control-plane database. Run one writable broker process per database on a
local block-backed volume. Do not share it across concurrent replicas using NFS. Let the platform
restart that instance for availability. Caches remain process-local and are intentionally absent
from the database.

The current development contract has no schema migration or legacy state import. If a development
build introduces an incompatible schema, export any settings you still need through the redacted
administration API, stop the broker, and start the new build with a deliberate empty volume; do not
expect automatic conversion.
