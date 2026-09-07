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
| admin gets 403 | wrong superadmin `sub` or no role | deployment subject and assignments |
| admin write gets 409 | another admin changed the revision | reload and reapply |
| Hub outage does not use projects.json | expected secure behavior | selected broker is sole authority |
| pre-sign gets 403 | missing S3 capability/operation/project/prefix | grant and route |
| pre-sign gets 400 | unsafe key/project mismatch or ambiguous routes | logical key and matching grants |
| token exchange fails | IdP lacks RFC 8693 or target/client unauthorized | provider strategy, endpoint, audience/resource |
| embedding index mismatch | broker embedding revision/dimensions changed | deploy a new revision and re-embed/namespace |

## Backup

Back up the authoritative SQL database and separately retain deployment configuration and secret
manager definitions. The database contains secrets and sessions; encrypt and restrict backups.

- SQLite: stop the writer or use an online SQLite backup that captures WAL consistently.
- PostgreSQL/MySQL: use the platform's transactionally consistent backup tooling and verify restore.

Restore into the exact schema-compatible broker build. Start one replica, verify admin and consumer
flows, then scale.

## Rotation

- OIDC signing keys follow issuer JWKS rotation.
- Consumer/API/admin client changes should be updated in configuration and tested before removing
  old IdP values.
- S3 route keys can be rotated by updating the route; already issued URLs remain valid until their
  short expiry.
- AI API keys can be replaced through redacted configuration.
- Service API keys in `authentication.api_keys` should prefer digest storage and coordinated
  caller rotation.
- Grant revocation is immediate on the next request and increments the revision.

## Incident response

For a leaked end-user token, revoke/expire it at the IdP and remove affected grants if necessary.
For a leaked S3 or AI key, rotate it at the upstream and update broker configuration. For database
exposure, treat every stored secret and live admin session as compromised: rotate secrets, restore
trusted grants/roles, and restart sessions.

If SQL is unavailable, the broker fails authorization closed. Do not introduce a cached-grant or
`projects.json` fallback during recovery. Restore the selected authority instead.
