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

Configured local/API-key passwords are HMAC-prehashed with a per-identity external pepper and then
verified against salted Argon2id PHC verifiers. The pepper is not embedded in the PHC. A credential
selects the username first, so each request performs at most one expensive KDF. System-generated
OIDC state and administration session tokens are stored as HMAC-SHA-256 values using an external
deployment pepper and separate domains. Anonymous access requires an explicit `anonymous` grant.

Password preprocessing uses a dedicated domain and
`HMAC-SHA-256(pepper, domain || 0x00 || password)`;
Argon2id then receives that fixed-size result and a random per-verifier salt. A pepper must contain
at least 32 bytes. It may be written literally in YAML because deployment configuration is the
operator's responsibility, but an ENV/secret-manager reference gives better separation from the
PHC. If both locations leak, treat the password as exposed to offline guessing. Losing or rotating
the pepper requires generating a new PHC, and either a pepper or PHC change invalidates existing
local administration sessions.

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
database assignments unless the identity declares authoritative `roles` in configuration. Cookie
sessions require CSRF on state changes. There is no superadmin bypass: bootstrap uses a local
Argon2id identity with `roles: [admin]`.

When `graphit-hub-access-v1` is selected, broker SQL is the only Hub ACL source. There is no
`projects.json` read, synchronization, or fallback. A provider without that protocol uses
`projects.json` outside this broker.

## Data at rest

The SQL database contains identities, roles, grants, HMAC-protected OIDC flow state, and
HMAC-protected live session keys. It does not contain `config.yml`, resolved OIDC/upstream/S3
secrets, local password peppers, or password hashes. Encrypt storage/backups and restrict database/network access. SQLite parent/file modes are
`0700`/`0600`; PostgreSQL/MySQL access must be protected by database roles and TLS/network policy.

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
- attempted configuration write: rejected because the endpoint is read-only;
- ACL race: the revision changes transactionally and in-flight mismatch fails closed;
- compromised Graphit client: cannot obtain direct S3 or upstream provider credentials;
- broker database outage: consumer authorization fails closed;
- name-glob ambiguity before metadata: avoided by broker grants accepting exact project IDs or all.
