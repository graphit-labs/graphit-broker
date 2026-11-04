---
title: Native federated administrative bearer sessions
references:
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9a99, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-064d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Native federated administrative bearer sessions

For explicit SQLite composition, [SqliteAdminUpstreamSessions](rust-sqlite-admin-session.md) uses the same F1 verifier and bounded profile validation, then resolves current roles and permission in SQLite. A configured claims selector, including an empty selected list, excludes database assignments; both paths add implicit `user`. Unknown roles remain inert and cannot grant an action. The existing HTTP session wire is shared; global Server backend selection and other administrative readers remain separate.

The native server uses the common `auth.oidc` provider set for administrative
resource JWTs. Add this section to `auth` in the [server configuration](rust-broker-server.md).
The root `oidc` section configures the Broker's own OpenID Provider and remains
separate. The release configuration named `authentication.oidc` is documented in
[OIDC integration](oidc.md); it is not the native YAML schema.

```yaml
auth:
  oidc:
    - id: corporate
      enabled: true
      issuer: https://issuer.example.test
      audiences: [graphit-broker-resource]
      required_scopes: [admin:session]
      allowed_algorithms: [EdDSA]
      access_policy:
        type: resource_audience
        id_token_audiences: [broker-browser]
      predicates:
        - selector: client_id
          value: broker-resource-client
      claims:
        subject: sub
        username: preferred_username
        name: name
        email: email
        organization: organization.id
        teams: "$.groups[*].name"
        scope: scope
      limits:
        token_bytes: 16384
        response_bytes: 65536
        keys: 16
        selector_bytes: 512
        claim_string_bytes: 2048
        profile_json_bytes: 8192
        teams: 32
      request_timeout: 5s
      cache_max_age: 5m
      min_refresh_interval: 100ms
      allow_loopback_http: false
      ca_file: issuer-ca.pem
      ca_bytes: 8192
```

All enabled provider fields above are explicit. `predicates` and optional claim
selectors may be omitted. Omit both CA fields to use normal TLS trust; provide
both to add a bounded PEM CA bundle to this provider's client. Certificate
verification remains enabled. HTTP is accepted only for a loopback URL when
`allow_loopback_http` is explicitly true. Discovery and JWKS requests never
follow redirects. `enabled: false` skips discovery and bearer admission; an
inactive entry needs only its unique ID and explicit enabled value.

Provider IDs and declared issuers are unique. An upstream issuer cannot equal
the native issuer. A decoded `iss` only selects one configured authority;
signature and claims verification establish authentication. Unknown issuer,
invalid token, or failure of the selected provider never retries another issuer.
[LOCAL JWT and opaque bearer admission](rust-admin-local-bearer-session.md) uses
its existing private verifier and current LOCAL identity binding. A nonempty
administrative cookie takes precedence over every bearer mode.

Resource audiences must be disjoint from declared ID-token client audiences.
After signature verification, a resource token containing any declared ID-token
audience is rejected, including a mixed resource/client audience array. For an
issuer whose access tokens intentionally use mixed audiences, select
`access_policy.type: signed_marker` with an exact signed JOSE `typ`, a signed
claim predicate, or both. For example:

```yaml
access_policy:
  type: signed_marker
  typ: at+jwt
  claim:
    selector: token_use
    value: access
```

The configured resource audiences still apply. Additional client or resource
predicates compare exactly one verified string; they never inherit the native
`auth.resource`. Required scopes must all occur in the configured scope claim,
as an OAuth whitespace-separated string or an array of strings. There is no CSV
conversion. Symmetric and unsigned algorithms are rejected.

Selectors beginning with `$` use the mature RFC 9535 JSONPath parser. Other
selectors first check the exact top-level key, including namespaced keys and
literal dots; dotted object traversal applies only when that key is absent.
Subject and username select exactly one nonempty string. Optional single fields
may be absent, but selected nulls, arrays and wrong types fail authentication.
Teams and roles flatten strings or string arrays, trim, deduplicate and sort;
mixed types and nested arrays fail. The subject remains literal UTF-8, bounded
by the SQL identity limits. Username is profile data and never maps a federated
identity to a LOCAL account.

Every authenticated identity receives `user`. Without `claims.roles`, additional
roles come from current SQL assignments for `issuer|subject`, and `role_source`
is `database`. With a configured roles selector, verified claim roles replace
SQL assignments, and `role_source` is `claims`; missing or empty claim roles
leave only `user`. Unsafe roles fail authentication; unknown roles grant no
permissions. Both modes use current SQL role definitions from one read-only
statement and require `session.read` or `*`. The result retains its genuine
private authentication proof through the known COMMIT and response encoding.
An uncertain COMMIT remains an unavailable outcome even if the token expires.

The response, GET/HEAD behavior, request ID and cache headers follow the
[native session endpoint](rust-admin-session-http.md). No cookie or CSRF token is
issued by this bearer endpoint. Missing permission returns 403, invalid bearer
401, corrupt SQL state and SQL storage failures 500, trusted provider/closed-store
or uncertain COMMIT failures 503, and the
captured request deadline 504. Public errors contain no token or driver details.

Fresh cached keys verify tokens without network requests. A missing key may refresh within the original request budget and
the configured refresh interval. Invalid signatures with a known cached key return 401 without network requests,
including while the issuer is offline. Same-key-ID replacement is observed when
the explicit cache maximum age requires a refresh. Expired cache is never used
as a fallback.
Federated tokens remain valid until the OP's signed `exp`, checked against both
UTC and an immutable monotonic deadline; there is no per-request UserInfo,
introspection or revocation ledger. The native Broker access TTL remains 600s.

This endpoint does not deliver browser login, cookie/CSRF/logout, administrative
CRUD, or upstream authorization-code and refresh grants.

The affected integration target uses a Rust HTTPS issuer with real Ed25519 keys,
TLS PostgreSQL with a NOSUPERUSER owner, and the actual Broker executable:

```text
cargo test --locked -p broker-server --test admin_session -- --ignored --exact broker_admin_upstream_bearer_http_contract --test-threads=1
```

The existing project runner invokes this target before audit and later persistence
phases. Its saved cross-platform entry points remain:

```text
cargo run --locked --quiet -p xtask -- hook pre-commit
cargo run --locked --quiet -p xtask -- qualify
```

## Shared upstream browser producer

The programmatic [browser login producer](rust-upstream-browser-login.md) uses
this same configured provider, metadata/JWK cache, transport and pure mapping.
The [native browser adapter](rust-admin-upstream-login.md) accepts those policies
in `auth.oidc[].browser_clients`, sharing the exact resource verifier owner. The
[federated cookie consumer](rust-admin-federated-cookie.md) borrows this common owner;
upstream OP consumers remain a separate delivery. Resource audiences,
scopes, namespace and access policy stay mandatory for this Bearer endpoint;
profile-only tokens from a code exchange cannot enter it.
