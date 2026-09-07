# Security model

## Trust boundaries

The CLI is untrusted for authorization decisions. It may request a project and operation, but the
broker derives identity from a cryptographically verified bearer token, evaluates server-side ACLs
and reduces AWS permissions with an inline session policy. AI API keys and the broker's base AWS
credentials never leave the server.

Authentication and authorization failures are deliberately different: invalid credentials return
401; an authenticated principal without a grant receives 403. Public error bodies never include
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

There are no implicit grants. Every non-empty selector category on a rule is conjunctive; values
inside a category are alternatives. A broad wildcard is therefore powerful and should be paired
with organization/team selectors. Treat claim-mapping changes as security changes and test both
positive and negative cases.

For S3, grants become an inline STS policy containing:

- `GetBucketLocation` on the configured bucket;
- `ListBucket` limited by authorized prefixes;
- object actions selected by operation on only `prefix/*` resources.

The assumed role's own IAM policy is an additional upper bound; session policy cannot expand it.
Keep STS duration short because removing an ACL rule cannot revoke a session already issued.

## AI and cache isolation

Cache keys include canonical subject, organization, route revision and normalized request. A cache
entry cannot be reused across principals or organizations. Caches are bounded and in memory; a
restart drops them. The user-supplied `model` field is ignored, preventing model and cost bypass.

## Deployment controls

- Terminate TLS at the broker or a trusted reverse proxy; never expose plain HTTP over an
  untrusted network.
- Keep configuration and environment readable only by the service account.
- Run the supplied non-root, read-only container with dropped capabilities.
- Restrict broker egress to OIDC discovery/JWKS, configured AI upstreams, STS and required DNS.
- Do not log authorization headers or JSON response bodies.
- Put request-rate and body-size limits at the edge as well as in the process.
- Use separate roles/buckets and broker instances when stronger tenant isolation is required.
