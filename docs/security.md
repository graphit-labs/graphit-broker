# Security model

## Trust boundaries

The client is not trusted with identity attributes, authorization decisions, upstream AI keys, or
storage topology. The broker accepts only a bearer credential or an anonymous request, derives the
principal itself, reads current SQL grants, and performs the requested capability only after a
match.

Graphit never receives S3 access/secret keys. The broker returns one opaque pre-signed HTTP request
for one operation, key/prefix, condition, and short expiry. Bucket, region, endpoint, base prefix,
route credentials, and signing implementation remain private.

## Authentication

OIDC access tokens are checked for signature, issuer, audience, expiry, and required scopes.
Username, organization, and teams come only from verified exact-key or RFC 9535 JSONPath claim
selectors; canonical identity is
`iss|sub`. Invalid credentials return `401` and are not treated as anonymous.

Configured API keys are constant-time compared against a stored SHA-256 digest. Use them only for
service/local identities. Anonymous access requires an explicit `anonymous` grant.

For HTTP MCP, Graphit first validates the end-user token for its MCP audience and preserves that
bearer in request context. The broker validates it again. When Graphit uses RFC 8693 exchange, the
broker receives a short-lived broker-audience token instead. Exchange failure has no relay
fallback.

## Authorization

Resource grants are normalized SQL state and are re-read for each Hub resolution, S3 pre-sign,
embedding, and rerank call. No match is deny. Matching S3 rules must agree on one private route.
Every grant mutation and revision increment is atomic.

Administrative roles protect control-plane actions and never imply resource access. When an
administration `role_claim` is configured, its verified token values replace all database role
assignments for that OIDC subject; missing/invalid values fail closed. API-key identities use
database assignments, and the deployment superadmin remains an explicit recovery bypass. Cookie
sessions require CSRF on state changes. The deployment superadmin is an explicit emergency
bootstrap subject.

When `graphit-hub-access-v1` is selected, broker SQL is the only Hub ACL source. There is no
`projects.json` read, synchronization, or fallback. A provider without that protocol uses
`projects.json` outside this broker.

## Data at rest

The SQL database contains sensitive configuration, upstream/API/S3 secrets, identities, roles,
grants, OIDC flow state, and live sessions. Encrypt storage/backups and restrict database/network
access. SQLite parent/file modes are `0700`/`0600`; PostgreSQL/MySQL access must be protected by
database roles and TLS/network policy.

Configuration API responses replace secrets with `[configured-secret]`. Logs and public errors
do not include bearer tokens, request bodies, upstream response bodies, signed URLs, or secrets.
AI cache entries are bounded, in memory, and scoped by route/revision/principal; signed URLs are
never cached by the broker.

## Deployment hardening

- terminate TLS at the broker or a trusted reverse proxy;
- allow only the required ingress paths and database/upstream egress;
- run as a non-root user with a read-only root filesystem;
- mount only the configuration and SQLite volume required;
- inject secrets from a secret manager;
- use short pre-sign expiries and least-privilege S3 credentials per route;
- use exact project grants instead of `*` wherever possible;
- rotate OIDC/admin/upstream/S3 credentials and invalidate affected sessions;
- alert on repeated 401/403, exchange failures, database errors, and presign failures.

## Threat outcomes

- forged claims: rejected because claims are read only after JWT verification;
- stolen token: bounded by token expiry, audience, scope, and current grants;
- stale admin write: rejected by ETag compare-and-swap;
- ACL race: the revision changes transactionally and in-flight mismatch fails closed;
- compromised Graphit client: cannot obtain direct S3 or upstream provider credentials;
- broker database outage: consumer authorization fails closed;
- name-glob ambiguity before metadata: avoided by broker grants accepting exact project IDs or all.
