---
title: Native shared upstream callback and OAuth responses
doc_type: reference
references:
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-06cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native shared upstream callback and OAuth responses

The explicit [SQLite public callback](rust-sqlite-oidc-federated.md) is composed by
`sqlite_oidc_upstream_login_router` and
`SqliteOidcUpstreamLoginHttpConfig { input_bytes, cookie_secure, oidc }`. It exposes
only the OAuth callback, consumes the genuine SQLite H1 producer and retains
these response/cookie contracts. SQLite Admin upstream and global Server dispatch
remain separate integration work.

For server integrators and operators of the [native PostgreSQL Broker](rust-broker-server.md).
The shared GET `/oauth/oidc/callback` consumes a genuine [H1 browser flow](rust-upstream-browser-login.md)
and completes either an [administrative cookie](rust-admin-upstream-login.md) or a
[federated OAuth authorization](rust-oidc-federated-grants.md). OAuth does not require
Administration, an administrative session or an administrative authentication cookie.
The [public authorize/login journey](rust-oidc-browser-authorization.md) now consumes
this callback. Discovery remains a separate native delivery. This callback alone does not establish a Graphit Code Web session.

## Configure the existing owners

Use the native `auth.oidc[].browser_clients` configuration documented in the
[administrative upstream reference](rust-admin-upstream-login.md), and enable the
root [`oidc` section](rust-oidc-token-exchange.md) for OAuth completion. The callback
is mounted once independently of the administrative router. The two journeys share
the configured verifier, HTTPS transport, discovery/JWK cache and SQL store.

`administration.cookie_secure` also controls the flow cookie when Administration
is disabled or absent. It defaults to true. An explicit false is accepted only
with an HTTP loopback `server.public_url`; it does not require an administrative
session policy or session TTL. The existing `auth.digest.token_bytes` must fit
the complete49-character upstream state whenever a browser client is active.
There is no new quota or fallback to another credential domain.

A server adapter starts an OAuth flow from a genuine pending authorization ID
with `FlowContinuation::OAuth`. `begin` returns an issued authorization only
after acknowledged SQL COMMIT and final time checks. Encode its binding using
`upstream_login_flow_cookie(&issued, secure)` and retain its SDK location.
`upstream_login_flow_cookie_name` returns cookie-name DATA, never flow authority.
These APIs support composition; they do not themselves mount an authorize/login page.

## State, binding and the callback

An upstream state is `admin.` or `oauth.` followed by43 unpadded Base64url
characters from32 random bytes. Nonce and binding keep their32-byte contracts,
and the PKCE verifier keeps48 random bytes. The prefix is an unauthenticated
budget hint. The handler captures arrival before bounded ingress/parsing and
chooses that journey's existing request_timeout from that arrival. It does not
apply the shorter or longer timeout globally and does not restart the clock.

SQL hashes the **complete state** and binding in the existing distinct domains.
A changed prefix, even with a correspondingly renamed cookie, cannot match the
original key. The one-use SQL consume must commit before the handler compares
the hint with the persisted purpose, calls the upstream token endpoint or
dispatches a protected continuation. A hint never selects an issuer, request ID,
redirect, Admin cookie or grant. Development states without the prefix are rejected.

The existing `server.body_bytes` bounds raw query plus all Cookie bytes before
decode/copy/SQL. Duplicate state/code/error fields, multiple Cookie headers,
missing or incorrect binding and noncanonical state fail locally. Wrong binding
does not consume the valid flow. HEAD never begins or consumes a login.
Each flow retains its separate HttpOnly/SameSite=Lax/Path=/ cookie, ten-minute
expiry and SHA256 name derived from the complete state; Secure adds `__Host-`.
Only a known matching consume permits clearing that flow's cookie. Another flow
or an administrative authentication cookie is not cleared.

## Protected response destinations

On success, W3 consumes the genuine proof and returns
`AuthorizedOidcAuthorization` only after current trust/client/redirect checks,
known COMMIT and final Original/expiry checks. The renderer consumes this result;
a profile or raw code DTO cannot create a successful response.

On a known upstream ProviderError/InvalidIdentity, only the protected OAuth
continuation supplies the pending request ID. `load` revalidates the current
client and literal registered redirect before `access_denied` can be returned.
`OidcAuthorizationRequestInfo::response_target(original)` produces a private-field
view with the existing expiry, monotonic cutoff and parsed HTTP origin. Its
checks surround response construction; its origin is CSP/display DATA, not a
replacement for the literal redirect. Initial unvalidated request parameters
do not produce this target.

| Stored response mode | Success or known protocol failure |
|---|---|
| query | 303 Location retains the registered URI/query and adds form-encoded code or error plus state. |
| fragment | 303 Location retains the registered URI/query and adds code or error plus state in the fragment. |
| form_post | 200 HTML form posts code or error plus state to the exact validated destination, with static auto-submit and a keyboard-operable Continue button. |

All state bytes representable by the chosen transport are preserved. Query and
fragment can encode NUL/CR/LF; HTML form submission cannot echo those bytes
without browser transformation. The FormPost renderer therefore rejects such
a target locally without exposing a code or altering the echo. P2's library
admission remains literal. The public Web admission delivery must reject those
three characters specifically for form_post before SQL/effects; this callback
delivery does not claim that entry route already exists. If rendering fails
after a known completion, that is not a database rollback or permission to replay.

The FormPost template is embedded and controlled, rendered by MiniJinja 2.24.0
with explicit HTML autoescape and no runtime filesystem/user loader. CSP permits
only its hashed static script and the protected destination origin as form-action,
with default-src/base-uri/frame-ancestors denial. No data enters JavaScript.
Privacy headers include no-store, Pragma no-cache, no-referrer, nosniff and DENY.
No new aggregate HTML quota is introduced: fixed template structure and concrete
input bounds remain distinct from received-body limits.

## Failures and recovery

An invalid/unconsumed state has no protected response destination. Changed or
revoked clients/redirects and expired/completed pending requests also remain
local. SQL, clock and infrastructure failures retain finite errors; an uncertain
COMMIT is 503 and Original deadline is 504. Neither becomes an OAuth error redirect
that falsely concludes the transaction. Known Admin failures retain their
existing local `/admin/#login_error=...` journey.

A callback is one-use. After failure, start a new sign-in from the application;
do not replay a callback URL, reconstruct a proof or retry code issuance after an
uncertain COMMIT. Existing runtime Drop/shutdown owners drain the request/store.
The flow-cookie clear acknowledges only known H1 consumption, not successful
OAuth completion or an administrative session.

## Source and focused validation

Control owns `service/upstream_login.rs`, `oidc_authorization/response.rs` and
the existing W3 producer. Presence owns `admin_upstream_login.rs`,
`oauth_response.rs` and `templates/oauth/form_post.html`; Server owns config/runtime
composition. The page follows the canonical Graphit authentication design, with
the existing mark, light surface, destination context and a single focused action.

The real native fixture registers a Web client with an exact mixed HTTPS/loopback
callback set, creates pending/H1 flows through their genuine producers and tests
HTTP callback→code→token/refresh. That fixture setup is not proof of a public
authorize entry page. Browser qualification independently checks actual HTML
parsing, CSP, POST values and keyboard behavior. Run the affected callback and H1
contracts through their saved portable commands:

```text
cargo test --locked --offline -j4 -p broker-server --test oidc_browser_callback -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-control --test postgres_upstream_login -- --ignored --test-threads=1
```

For the optional interactive proof, set the fixture environment variable
`GRAPHIT_BROKER_FORM_POST_UI` to a local JSON index path before invoking the
same callback command. Open its `preview` URL for layout/focus and submit
Continue with the keyboard, then open `automatic` for the unchanged native
script/CSP path. The preview creates a fresh genuine authorization on each GET;
its existing 60-second lifetime still applies. Only the preview tightens CSP to
block automatic submission. Both browser POSTs must pass the real RP's literal
state, PKCE, signature/claims and refresh assertions. The index contains only
local URLs/status, never codes or tokens; `status: passed` is written after
both results and native shutdown. To cancel safely, create the index path with
its extension replaced by `.stop`; cancellation cleans up and fails the test.
Ordinary unattended runs omit this variable and still exercise all three modes.

The callback command is the focused pre-push phase; fast checks remain pre-commit.
A full hook/integration run is coordinated separately and never authorizes push.
Only executed checks may be reported passed.
