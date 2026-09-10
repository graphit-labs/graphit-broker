# Security model

## Trust boundaries

The client is not trusted with identity attributes, authorization decisions, upstream AI keys, or
permanent storage credentials. The broker derives the principal from the bearer, reads current SQL
grants, and performs the requested capability only after a match.

For S3, Graphit receives the selected topology and an access key, secret, and session token minted
by STS with a short expiry. The inline policy is derived only by the broker and intersects the
route role/user policy. Permanent route credentials and the policy-generation boundary remain
private. Anonymous callers never receive storage credentials.

## Authentication

OIDC access tokens are checked for signature, issuer, audience, expiry, and required scopes.
Subject, username, organization, and teams come only from verified exact-key or RFC 9535 JSONPath
claim selectors; canonical identity is `issuer|subject`. Subject is stable and distinct from the
mutable username. Invalid credentials return `401` and are not treated as anonymous.

SQL-backed local passwords are HMAC-prehashed with the single external
`authentication.token_pepper` and then verified against salted Argon2id PHC verifiers. The pepper
is not embedded in SQL or the PHC. Password verification occurs only at the local administrative,
Authorization Code, or Device Authorization login boundary and performs at most one expensive KDF.
A password is never accepted by the API Bearer authenticator. System-generated upstream OIDC state,
administration sessions, Broker OIDC grants/token identifiers, and service credentials are stored as
HMAC-SHA-256 values using an external deployment pepper and separate domains. Anonymous access
requires an explicit `anonymous` grant.

Local passwords contain at least 15 Unicode characters and have no composition rules. Failed
checks are rate-limited per username; unknown/disabled usernames follow the same dummy-verification
and failure-accounting path. Five failures in one minute cause a five-minute lockout by default.
There is deliberately no cross-username failure lockout. At most two Argon2id checks execute
concurrently per process by default, bounding memory and CPU cost. A bounded admission queue holds
at most `max_concurrent * saturation_multiplier` running and waiting calls—eight with the defaults
of two and four. Further calls are rejected before the KDF and do not count as password failures.

Optional adaptive CAPTCHA adds an external proof before Argon2id when an admitted password attempt
reaches `max(1, ceil(max_concurrent * trigger_multiplier))`; the default multiplier is `1.5`, while
the feature itself is disabled by default. An explicit multiplier of `0` protects every attempt;
positive fractions can activate protection before all Argon2id workers are occupied. Cloudflare
Turnstile validates success, hostname, and a flow-specific action. Google reCAPTCHA v2 Checkbox
validates success and hostname. Tokens are
accepted only through server-side Siteverify, are bounded to 2048 bytes, and rely on the provider's
expiry and single-use enforcement. The Broker never sends `remoteip`, because forwarded addresses
cannot be trusted without an explicit trusted-proxy boundary. Missing proof does not cause an
outbound request. Siteverify executes while holding one bounded authentication admission, uses a
short timeout, follows no redirects, and fails closed without reaching the KDF. The secret key is
redacted from administrative configuration responses.

This threshold and the saturation queue are process-local, not cluster-global. Each replica must
use the same provider/hostname policy, but an attacker can distribute load across replicas. For a
multi-replica Internet deployment, complement the Broker with load-balancer/WAF controls and
provider analytics. Enabling CAPTCHA adds browser JavaScript/iframe and backend egress dependencies
on the selected provider. Provider outage affects only overloaded local-password login; OIDC and
already-issued credentials do not depend on Siteverify.

Human local identities require TOTP MFA by default. Password success creates only an opaque,
short-lived, one-time SQL challenge bound by HMAC to the exact administration, Broker OIDC, or
device flow; it does
not create a session, authorization code, or device approval. A temporary password must be changed
before MFA. The TOTP secret is encrypted at rest with AES-256-GCM using a domain-separated key
derived from `authentication.token_pepper` and subject-bound authenticated data. Recovery codes are
random, shown once, and stored only as subject-bound HMAC-SHA-256 values. Accepted TOTP time steps
are persisted to reject replay, and MFA failures use an independent per-username limiter.

An administrative MFA reset deletes the factor and recovery codes and increments the local identity
revision, invalidating existing sessions, tokens, grants, and unfinished challenges before forcing
reenrollment. TOTP does not protect against a real-time phishing proxy or theft of an already
authenticated browser session; phishing-resistant MFA would require a future WebAuthn/passkey flow.
Queued calls recheck per-username lockout before KDF work. Successful checks do not consume failure
quota.

The Broker's public/native OpenID Connect client registration requires Authorization Code with PKCE S256,
unpredictable state and nonce, and an exact loopback callback path with a nonzero dynamic port.
The mature ZITADEL Go OIDC provider library owns protocol parsing, discovery, authorization, token,
JWKS, userinfo, introspection, revocation, and end-session behavior. Request objects are disabled,
CORS is disabled, and ID tokens are signed with an Ed25519 key derived in a dedicated pepper domain.
The stable Broker `sub` is an HMAC-derived identifier over the canonical underlying issuer/subject,
so local and upstream identities cannot collide and username changes do not change authorization identity.
The Broker issuer is `server.public_url`. Graphit Code bootstraps its public client settings from
Broker discovery and thereafter follows only standard OIDC discovery/endpoints; it never receives
the upstream issuer configuration, client secret, password, or IdP token. Headless login remains a
separate OAuth Device Authorization flow and does not issue an ID token or refresh token. Browser
OIDC access tokens are opaque, audience- and
scope-bound, and expire after ten minutes by default. Optional refresh tokens rotate on each use;
reuse revokes the whole family. Automation uses passwordless service identities with independent,
expiring credentials that can be listed by metadata and revoked individually. All local tokens are
bound to the current identity revision, so password/attribute changes, disablement, or deletion
invalidates them. A short-lived access token remains replayable if stolen during its lifetime;
HTTPS and secret-safe clients remain mandatory. DPoP and mTLS are not claimed by this implementation.

Password preprocessing uses a dedicated domain and
`HMAC-SHA-256(pepper, domain || 0x00 || password)`;
Argon2id then receives that fixed-size result and a random per-verifier salt. A pepper must contain
at least 32 bytes. An ENV/secret-manager reference separates it from the SQL verifier. If both SQL
and deployment secrets leak, treat local passwords as exposed to offline guessing. Rotating the
pepper invalidates all local passwords, administration sessions, Broker OIDC grants/tokens, and
service credentials; set new passwords and issue new credentials through a controlled recovery
procedure. Pepper rotation also rotates the Broker signing/encryption keys and derived subjects, so
it is an explicit whole-deployment credential and identity reset rather than an online key rollover.

For HTTP MCP, Graphit first validates the end-user token for its MCP audience and preserves that
bearer in request context. The broker validates it again. When Graphit uses RFC 8693 exchange, the
broker receives a short-lived broker-audience token instead. Exchange failure has no relay
fallback.

## Authorization

Resource grants are normalized SQL state and are re-read for each Hub resolution, S3 credential issuance,
embedding, and rerank call. No match is deny. Matching S3 rules must agree on one private route.
Every grant mutation and revision increment is atomic.

RBAC applies to system and control-plane actions and never implies resource access. Every
authenticated identity receives the built-in `user` role. When an authentication OIDC `role_claim`
is configured, its verified additional values replace database role assignments for that canonical
subject; local users always use SQL assignments. Cookie sessions require CSRF on state changes.
There is no superadmin bypass: the one-time CLI bootstrap inserts a normal local user and `admin`
assignment in SQL.

Upstream browser OIDC login additionally binds each state to a 256-bit secret held in an `HttpOnly`,
`SameSite=Lax` per-flow cookie. Administration cookies are `Secure` by default; disabling that
attribute requires explicit development configuration. SQL stores only a domain-separated HMAC of that binding. A callback
without the matching browser cookie fails without consuming the valid state, which prevents login
CSRF/session swapping and permits independent concurrent login flows.

When `graphit-hub-access-v1` is selected, broker SQL is the only Hub ACL source. There is no
`projects.json` read, synchronization, or fallback. A provider without that protocol uses
`projects.json` outside this broker.

## Data at rest

The SQL database contains local identities and Argon2id PHCs, roles, grants, HMAC-protected upstream
OIDC state, Broker authorization requests/token identifiers, service credentials, and live session keys. It does not contain
raw passwords, raw codes/tokens, `config.yml`, or resolved OIDC/upstream/S3
secrets, plaintext passwords, or the authentication pepper. Encrypt storage/backups and restrict database/network access. SQLite parent/file modes are
`0700`/`0600`; PostgreSQL/MySQL access must be protected by database roles and TLS/network policy.

Configuration API responses replace secrets with `[configured-secret]`. Logs and public errors
do not include bearer tokens, request bodies, upstream response bodies, STS session credentials,
or secrets. AI cache entries are bounded, in memory, and scoped by route/revision/principal. The
broker does not cache temporary S3 credentials.

## Deployment hardening

- terminate TLS at the broker or a trusted reverse proxy;
- allow only the required ingress paths and database/upstream egress;
- run as a non-root user with a read-only root filesystem;
- mount only the configuration and SQLite volume required;
- inject secrets from a secret manager;
- use short STS durations and least-privilege assumable roles/S3 signing identities per route;
- use exact project grants instead of `*` wherever possible;
- rotate OIDC/admin/upstream/S3 credentials and invalidate affected sessions;
- alert on repeated 401/403/429 responses, exchange failures, database errors, and STS failures.

## Threat outcomes

- forged claims: rejected because claims are read only after JWT verification;
- stolen token: bounded by token expiry, audience, scope, and current grants;
- attempted configuration write: rejected because the endpoint is read-only;
- ACL race: the revision changes transactionally and in-flight mismatch fails closed;
- compromised Graphit client: cannot obtain direct S3 or upstream provider credentials;
- broker database outage: consumer authorization fails closed;
- name-glob ambiguity before metadata: avoided by broker grants accepting exact project IDs or all.
