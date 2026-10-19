---
title: Native administrative upstream browser login
doc_type: reference
references:
  - target: {type: task, id: tsk-7204, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7aaf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-06cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-9548, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native administrative upstream browser login

The PostgreSQL binary composes the [H1 OIDC browser producer](rust-upstream-browser-login.md)
with the [H2 federated cookie producer](rust-admin-federated-cookie.md).
Open `/admin/`, choose a configured provider and authenticate there. On success
the browser returns to `/admin/` with an opaque administrative session cookie.
Its profile, permissions, catalog and [administrative reads](rust-admin-read.md)
come from the real session and current SQL policy. The [shared callback](rust-oidc-browser-callback.md) also completes protected
OAuth continuations without administrative session ownership.

The explicit [SQLite administrative browser composition](rust-sqlite-admin-upstream-login.md) supplies the same Admin/OAuth callback through `sqlite_upstream_login_router` and the shared LOCAL/provider page through `sqlite_admin_local_login_router_with_upstream`. Global SQLite Server configuration and startup remain pending under the SQLite integration delivery.

## Configure one provider owner

Merge this `auth.oidc` entry into the [native server configuration](rust-broker-server.md).
Enable the [administrative cookie transport](rust-admin-cookie-session.md) as well.
Register the exact callback with the upstream provider. The native `auth.oidc`
resource verifier and browser clients share their transport, issuer trust,
selectors and discovery/JWK cache. The root `oidc` section is the distinct
Broker OpenID Provider surface.

```yaml
auth:
  oidc:
    - id: workforce
      enabled: true
      issuer: https://issuer.example.test
      audiences: [graphit-broker-resource]
      required_scopes: [admin:session]
      allowed_algorithms: [EdDSA]
      access_policy:
        type: resource_audience
        id_token_audiences: [graphit-admin, graphit-admin-confidential]
      predicates: []
      claims:
        subject: preferred_username
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
      min_refresh_interval: 10ms
      allow_loopback_http: false
      ca_file: browser-ca.pem
      ca_bytes: 8192
      browser_clients:
        - display_name: Workforce
          client_id: graphit-admin
          redirect_url: https://broker.example.test/oauth/oidc/callback
          scopes: [profile, email]
        - display_name: Workforce confidential
          client_id: graphit-admin-confidential
          client_secret: "${BROKER_BROWSER_CLIENT_SECRET:?required}"
          redirect_url: https://broker.example.test/oauth/oidc/callback
          scopes: [profile, email]
          require_nonce: true
          claims_source: id_token
          id_token_additional_audiences: []
```

Browser field defaults and validation are the existing [H1 contracts](rust-upstream-browser-login.md).
Only explicit `claims_source: userinfo` supplements missing primary profile
attributes through UserInfo; the default `id_token` mode does not fetch it.
Omitting `browser_clients` means no browser choices for that provider; an explicit
`null`, unknown fields or invalid clients fail configuration. Active browser
clients require an active administrative cookie owner or enabled native OIDC.
Administrative routes still require their cookie owner; [federated OAuth grants](rust-oidc-federated-grants.md)
can use the common upstream verifier without administration. Their [shared browser OAuth callback](rust-oidc-browser-callback.md) dispatches by the
matching SQL purpose; the [public authorize/login journey](rust-oidc-browser-authorization.md) consumes the same owner. Preparation and
`--check-config` validate types and local files without KDF work, network or SQL.
The read-only configuration view projects browser metadata and replaces a
configured client secret with `[configured-secret]` before moving private owners.

## HTTP journey

| Route | Behavior |
|---|---|
| GET/HEAD `/admin` and `/admin/` | Existing embedded HTML, no-store, no-referrer, nosniff, frame denial and the sourced CSP with only the configured CAPTCHA origins. HEAD has no body. |
| GET/HEAD `/admin/api/v1/login-options` | Ordered browser `{id,name}` choices, LOCAL availability and the existing pure CAPTCHA occupancy observation. Resource-only providers do not become browser buttons. |
| GET `/admin/auth/login?provider=ID` | Real H1 begin; acknowledged flow INSERT COMMIT and final gates precede the binding cookie and 302 to the SDK authorization URL. |
| GET `/oauth/oidc/callback` | Matching SQL state and browser binding, one-use consume, real code/PKCE/nonce exchange, H2 cookie issue and 303 to `/admin/`. |

`/admin/auth/options` is removed. The maintained HTML uses the canonical
`login-options` route directly. GET-only begin/callback reject HEAD rather than
starting a login as a side effect of HEAD.

Each flow uses a separate `graphit_oidc_flow_` cookie followed by the lowercase
SHA256 hex of the raw state. Secure policy adds `__Host-`. Cookies have Path `/`,
HttpOnly, SameSite=Lax and the configured Secure policy. The expiry is the H1
flow's existing ten-minute expiry; time spent preparing the flow does not renew
it. Parallel login attempts keep separate bindings. Successful or known-consumed
callbacks clear only their binding cookie; this is distinct from emitting
the authentication cookie. A wrong browser does not consume the valid flow.

Missing or wrong state/binding before a known matching consume yields 401 JSON
`invalid_state`. After a known Admin consume, identity/protocol/policy failures
redirect to `/admin/#login_error=invalid_identity|oidc_error|invalid_state|admin_forbidden`
with a form-encoded safe `request_id`. No callback parameter selects an issuer,
continuation or external redirect. SQL/clock/infrastructure errors remain finite
500/503 responses, uncertain COMMIT remains 503 without automatic retry, and the
Original deadline remains 504. No auth cookie is emitted on those failures.

The existing positive `server.body_bytes` cap also bounds the aggregate raw query
and Cookie bytes for begin/callback, before decoding, copying protocol inputs,
crypto or SQL. `administration.response_json_bytes` bounds options and redirect
output. Admin uses one `administration.request_timeout` Original from callback arrival;
OAuth uses its own `oidc.request_timeout` from that same ingress point. The state
prefix only hints which budget to select; SQL proves purpose before dispatch. No
phase renews it or masks COMMIT uncertainty with a generic timeout. Existing
runtime owners handle cancellation and shutdown.

The session cookie works with the current GET/HEAD session and seven reads, and
with the [existing CSRF/logout protocol](rust-admin-cookie-session.md). Current
configuration and SQL roles are checked on later requests. This creates no LOCAL
username alias, JWT blacklist, resource grant from profile data or UserInfo poll
for ongoing session validity. LOCAL password/MFA, opaque LOCAL credentials and
configured bearer verification keep their own genuine producers.
The session identity remains `issuer|mapped_subject` from the configured verified
subject selector. Raw signed `sub` independently binds ID/access/UserInfo and is
not substituted for that selector; UserInfo cannot replace the subject or roles.

## Qualify the H3 administrative browser adapter

The Linux Native fixture uses the actual binary, PostgreSQL TLS with a
NOSUPERUSER owner, a real Rust HTTPS issuer and the mature Reqwest cookie Jar.
The Jar proves HTTP/cookie behavior; a separate run of the existing HTML in a
real browser is required to prove its JavaScript journey and loaders.
That additional browser fixture explicitly enables the supported HTTP loopback
policy and a real credential form on the same owned issuer. It retains real
code/PKCE/nonce/token verification and SQL TLS without changing the product HTML
or bypassing a browser TLS warning. The three HTTP contracts below retain their
HTTPS issuer. The interactive fixture's lifecycle result alone is not JavaScript
or browser proof; record the observed DOM journey separately.
Its form CSP permits only itself and the origin of the exactly registered
callback, so the browser can follow the genuine code redirect across the two
owned loopback ports. Stopping the fixture closes the server, issuer and SQL
fixture before asserting exchange and logout observations.

```text
cargo test --locked --offline -j4 -p broker-server --test admin_upstream_login -- --ignored --exact broker_admin_upstream_login_http_contract --test-threads=1
cargo test --locked --offline -j4 -p broker-server --test admin_upstream_login -- --ignored --exact broker_admin_upstream_login_uncertainty_contract --test-threads=1
cargo test --locked --offline -j4 -p broker-server --test admin_upstream_login -- --ignored --exact broker_admin_upstream_login_configuration_contract --test-threads=1
```

These are scoped delivery checks. They do not complete the migration or qualify
upstream OP grants, administrative writers, other consumers or other platforms.
