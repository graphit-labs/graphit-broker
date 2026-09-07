# Security model

## Trust boundaries

The CLI is untrusted for authorization decisions. It may request a project and operation, but the
broker derives identity from a cryptographically verified bearer token and evaluates server-side
ACLs before signing exactly one storage operation. AI API keys and S3 route credentials never
leave the server.

Authentication and authorization failures are deliberately different: invalid credentials return
401; an authenticated or anonymous principal without a grant receives 403. An absent header is
anonymous, while an invalid present header never falls back to anonymous. Public error bodies never include
upstream response bodies, tokens, policies or credentials. Detailed failures remain in server logs
under a request ID.

## OIDC

- HTTPS issuer discovery and JWKS are mandatory.
- Signature, issuer, audience, expiration and configured scopes are verified.
- ACL claims come only from the verified JWT.
- Keep access-token lifetimes short and rotate signing keys through normal JWKS procedures.
- Restrict refresh-token issuance and revocation in the IdP; the broker never receives a refresh
  token.

## API keys

Use long random values and store only `token_sha256`. Comparison is constant-time. An API key maps
to a fixed normalized principal and then passes through the same ACL engine as OIDC. Rotate by
adding the replacement, rolling clients, then removing the old entry.

## ACL semantics

There are no implicit grants. Each rule has one canonical access level and, for user/team/
organization/subject, one exact verified principal. Project/capability patterns within the rule are
additional constraints. Broad wildcards are powerful; prefer a narrowly scoped access principal and
project/prefix set. Treat claim-mapping changes as security changes and test both positive and
negative cases.

For S3, the broker resolves the ACL-selected route, verifies the logical project, operation and
prefix, prepends the private route `base_prefix`, and signs only that method and object/list prefix.
The route key's object-store policy is the independent upper bound. Because there is no per-user
credential exchange, make every route key least-privilege for its bucket/base prefix and use
separate routes and keys for distinct tenant or security boundaries.

The access levels mirror Graphit Hub visibility: global reaches everyone; anonymous only the
unauthenticated principal; authenticated every verified principal; user/team/organization/subject
use exact verified identity values. Anonymous is deny-by-default and should normally receive only
read operations on deliberately public prefixes.

In pre-signed mode the broker re-evaluates current ACL for every operation and signs only that
method/key/prefix. Revocation therefore blocks issuance immediately, although an already-issued URL
remains usable until its short expiry. Treat signed URLs as secrets: redact query strings in proxy,
application and tracing logs, never store them, and keep expiry as short as practical.

An ACL rule may choose one named storage route. The route contains bucket, region, endpoint, base
prefix and direct signing credential. Multiple matching rules that choose different routes are rejected rather
than selecting nondeterministically. Route changes are invisible to clients and take effect on the
next presign request.

## Administration plane

Administration uses a separate OIDC Authorization Code client. Login state and nonce are one-time
and expiring; PKCE S256 is used even with a confidential client secret. ID tokens are checked for
signature, exact issuer, administration client audience and expiration. The browser session is an
opaque random value stored only as a SHA-256 hash in SQLite and delivered as `HttpOnly`,
`SameSite=Lax`, and (under HTTPS) `Secure`. Cookie-backed mutations also require a per-session CSRF
token. Logout deletes the server-side session.

Authorization is action-based RBAC. The environment-defined exact superadmin subject always has all
administration actions; unassigned subjects have none. With no role assignments, this leaves only
the superadmin. The built-in `admin` role grants every current action, and narrower roles can be
created without weakening authentication. Protect `roles.write` carefully because it delegates
administrative authority.

SQLite uses a `0700` parent and `0600` database. It contains the mutable full configuration,
including actual AI/S3/API-key/OIDC client secrets, plus roles, assignments and sessions. Read APIs
replace populated secrets with `[configured-secret]`, but a filesystem reader can recover them;
encrypt and access-control the volume and backups accordingly. Configuration saves validate and
prepare a complete new runtime before compare-and-swap persistence and atomic activation.

Protect `/admin/` with HTTPS and preferably an additional network boundary. Use a dedicated
administration OIDC client, short sessions, IdP MFA/conditional access, exact subject assignments,
and regular role review. Never reuse a consumer API key as an administration credential.

## AI and cache isolation

Cache keys include canonical subject, organization, route revision and normalized request. A cache
entry cannot be reused across principals or organizations. Caches are bounded and in memory; a
restart drops them. The user-supplied `model` field is ignored, preventing model and cost bypass.

## Deployment controls

- Terminate TLS at the broker or a trusted reverse proxy; never expose plain HTTP over an
  untrusted network.
- Keep configuration and environment readable only by the service account.
- Run the supplied non-root, read-only container with dropped capabilities.
- Restrict broker egress to OIDC discovery/JWKS, configured AI upstreams, object storage and required DNS.
- Do not log authorization headers or JSON response bodies.
- Put request-rate and body-size limits at the edge as well as in the process.
- Use separate route keys/buckets and broker instances when stronger tenant isolation is required.
