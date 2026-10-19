---
type: document
title: SQLite administrative upstream browser login
status: implemented
description: Shared Admin and OAuth browser callback composition over genuine SQLite H1 login and H2 administrative cookie producers.
references:
  - target: {type: task, id: tsk-7204, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7aaf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite administrative upstream browser login

Backend integrators can connect the existing administrative login page to the
[SQLite upstream login producer](rust-sqlite-oidc-federated.md) (H1) and the
[federated administrative cookie/session producer](rust-sqlite-admin-session.md)
(H2). The shared callback dispatches both administrative login and OAuth through
the persisted, verified continuation. This is the H3 HTTP composition; global
SQLite server configuration and startup remain under the separate server
integration.

## Compose the real owners

`sqlite_upstream_login_router(Arc<SqliteControlStore>,
Option<Arc<UpstreamBearerVerifier>>, UpstreamLoginHttpConfig)` is the SQLite
counterpart of `upstream_login_router`. The private backend dispatch shares the
same parsers, renderer, wire errors and response gates with PostgreSQL.

`UpstreamLoginHttpConfig.administration` enables `/admin/auth/login` and its
administrative callback budget/cookie policy. `oidc` enables the OAuth callback
consumer. An absent mode is explicitly disabled. When both are present there is
still exactly one `/oauth/oidc/callback` route. A missing verifier does not create
an identity or silently choose LOCAL authentication.

Use `sqlite_admin_local_login_router_with_upstream(store, config, local,
upstream)` for the existing `/admin`, `/admin/` and
`/admin/api/v1/login-options` consumers. Provider options come from the captured
verifier, preserving configured provider/client order and the public `{id,name}`
shape. Resource-only
providers have no browser option. LOCAL availability and CAPTCHA behavior still
come from the actual optional LOCAL runtime. The existing LOCAL-only factory
remains used by LOCAL-only consumers. The page and loader keep their current UI.

Pass the same configured verifier owner to H1, H2 and the session router. The
upstream proof is bound to the configured browser/trust owner, not the physical
identity of a store instance. Configuration, metadata and a cookie name confer
no authority. `cookie_secure` and the administrative cookie policy must agree;
factory validation retains the existing positive limits and timeout checks.

The existing `sqlite_oidc_upstream_login_router` is the OAuth-only composition
used by its current caller. It delegates to the same dispatcher with Admin
disabled. Do not merge that factory with another router defining the same
callback. When composing Admin and OAuth, use the full shared factory once,
alongside the existing OAuth authorization/browser routes and
`sqlite_admin_session_router_with_cookie`.

## Browser journey and observable result

1. Open the existing administrative page. Its login-options request supplies
   configured browser providers and current LOCAL availability.
2. Select a provider. `GET /admin/auth/login?provider=...` begins H1 with a real
   `FlowContinuation::Admin`, saves the flow through the SQLite owner, and returns
   302 to the provider only after the issued result passes its gates.
3. The provider completes its actual code, PKCE and nonce exchange. The callback
   checks the state-specific browser binding and consumes the corresponding
   persisted flow. Its state prefix selects only the request budget; SQL and the
   verified continuation determine the actual purpose.
4. An Admin continuation passes its genuine `VerifiedUpstreamLogin` to H2. The
   callback emits the administrative cookie only after issuance is confirmed and
   the result/response gates pass, then returns 303 to `/admin/`.
5. The CookieJar can use `GET` or `HEAD /admin/api/v1/session`. Current identity,
   permissions and cookie selectors follow the existing H2 contract. Reads do
   not renew the cookie or emit `Set-Cookie`.
6. Use the session response's CSRF token for `POST /admin/auth/logout`. Known
   successful logout clears the cookie. Wrong CSRF is denied; own logout does
   not gain a new `session.read` requirement.

An OAuth continuation follows the existing authorization response renderer,
preserves the requesting client's state and returns its authorization result.
It does not mint an administrative cookie. Public, confidential Basic/Post and
ID-token/UserInfo browser clients retain their existing verifier rules. UserInfo
supplements required profile fields absent from the verified ID token; selecting
that mode does not require an extra request when the profile is already complete.

Flow cookies are per state, using the existing SHA256 name and optional
`__Host-` prefix. They retain Path `/`, HttpOnly, SameSite=Lax, explicit Secure
policy and the H1 expiry. Administrative cookie expiry and CSRF follow H2;
neither phase renews the callback's Original deadline.

## Failure, consumption and recovery

| Condition | Observable behavior |
|---|---|
| Missing, replayed or wrong browser state/binding | 401 `invalid_state`; no administrative cookie. A wrong binding does not consume another browser's flow. |
| Known consumed Admin provider/identity failure | 303 to `/admin/#login_error=...` with the existing finite error code and safe request correlation. |
| H2 denies administrative authorization | No administrative cookie; the existing `admin_forbidden` redirect applies. |
| Unconfirmed flow consumption | Do not clear its binding cookie or infer success. |
| H1 consumption confirmed, later H2 fails | The consumed flow binding can be cleared; this is not proof of an administrative session. |
| SQL/transport outcome is uncertain | Existing 503 classification; do not replay or infer a committed administrative login. |
| Original expires | Existing 504 classification; no new budget for H1, H2 or rendering. |
| Owner closed/unavailable | Existing finite service error; no fallback identity. |
| HEAD on begin/callback | Rejected without creating or consuming a flow or issuing an authentication cookie. |

Responses preserve no-store/no-cache, request correlation and the callback's
privacy headers. The aggregate raw query plus all Cookie bytes are bounded
before decode or SQL. An uncertain response is not an instruction to retry the
same flow; follow the existing [browser login contract](rust-admin-upstream-login.md)
and inspect the available session through its authenticated API.

## Sources and qualification

The productive consumers are
[shared upstream login](../crates/broker-presence/src/admin_upstream_login.rs)
and [LOCAL page/options](../crates/broker-presence/src/admin_local_login.rs).
The [H3 HTTP target](../crates/broker-presence/tests/sqlite_admin_upstream_login.rs)
uses actual SQLite files, HTTPS issuer/code/JWKS operations, an ordinary
CookieJar, and the existing H1/H2 producers. It covers options and
public/confidential login, session/logout, flow isolation and rejection,
Admin/OAuth callback coexistence, SQL locks, the Original deadline and closure.

The target's altered-state case is an ingress denial, not an independent proof
of every persisted-purpose check. The existing H1 proof remains authoritative
for that matrix. Likewise, native lock/expiry tests and unchanged physical
COMMIT/ACK qualification have distinct scopes; a source review or error mapping
is not a newly executed physical uncertainty test.

The portable affected-target command is:

```text
cargo test --locked --offline -j4 -p broker-presence --test sqlite_admin_upstream_login -- --ignored --test-threads=1
```

Only directly affected LOCAL/OAuth consumers need regression runs. Unchanged H1/H2, password/crypto and PostgreSQL tests need not be replayed for an adapter change. This library composition alone does not establish browser UI, complete SQLite server, CRUD or all administrative reads.
