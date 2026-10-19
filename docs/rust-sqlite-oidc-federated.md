---
type: document
title: SQLite federated browser grants and UserInfo
description: Genuine upstream browser login, Broker grants and explicit profile lookup over the physical SQLite owner.
references:
  - target: {type: task, id: tsk-7204, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# SQLite federated browser grants and UserInfo

For Broker integrators composing public application sign-in over the private [SQLite store](rust-sqlite-control.md). These explicit Control and Presence APIs extend the [LOCAL browser](rust-sqlite-oidc-browser.md), [LOCAL grants](rust-sqlite-oidc-local-grants.md) and [Device](rust-sqlite-device-authorization.md) compositions.

The [SQLite administrative browser composition](rust-sqlite-admin-upstream-login.md) now shares the verified callback with public OAuth and composes genuine H1 login with H2 cookie issuance. The explicit OAuth-only factory below remains available; use `sqlite_upstream_login_router` when composing both continuations. Global SQLite Server selection, remaining SQL families and startup configuration still require integration.

## Application sign-in

Prerequisites are a configured upstream OAuth browser client, its explicit Broker
callback URI, the real startup trust owner, and an admitted Broker application
request with an exact registered redirect, resource and S256 challenge. The
[upstream login](rust-upstream-browser-login.md),
[browser callback](rust-oidc-browser-callback.md) and
[federated grant](rust-oidc-federated-grants.md) contracts remain authoritative.

1. Start sign-in from the application. The Broker shows the application origin
   and the configured organization providers. LOCAL sign-in appears only when
   its actual startup owner is present.
2. Choose **Continue with** the configured provider. With one provider and LOCAL
   disabled, this step redirects directly to that provider. The Broker persists the
   one-use login flow and sets its state-specific, HttpOnly, SameSite=Lax binding
   cookie before redirecting to the configured upstream authorization endpoint.
3. Complete the provider's sign-in. The matching callback consumes the stored
   state and browser binding, and the existing OIDC SDK verifies the code,
   PKCE, ID token, nonce and configured claims before a Broker code is committed.
4. The application receives the Broker code through its admitted `query` or
   `form_post` response mode. Exchange it with the original redirect, S256
   verifier, client and resource at `/oauth/token`.
5. Verify the signed Broker JWT locally. If the admitted request included
   `offline_access`, keep the returned refresh token private and rotate it through
   the same endpoint. UserInfo is an explicit profile request when needed.

On a provider denial, the Broker may return `access_denied` only after known
matching flow consumption and revalidation of the pending application and its
redirect. Malformed state, wrong binding, storage failure and expired deadlines
produce finite local errors. Restart from the application when the flow cannot
continue; a code, flow or uncertain mutation must not be replayed blindly.

The organization provider selector reuses the maintained server-rendered OAuth
views: the existing navy/cobalt tokens, Public Sans/system font stack, single
column, escaped provider names, links with visible keyboard focus and 44px hit
areas. The same password, MFA, recovery and error states remain server-selected.
There is no separate SQLite page design or client-side authentication branch.

## Compose the real startup owners

Retain one `Arc<SqliteControlStore>` and the configured policies, signing issuer,
JWT verifier and `Arc<UpstreamBearerVerifier>`. The store supplies its existing
HMAC digester and bounded physical transaction executor; requests cannot replace
these owners with profile DATA or a boolean grant.

| API | Required owners and behavior |
| --- | --- |
| `store.upstream_logins(&verifier)` | Borrowed `SqliteUpstreamLogins`; `begin(continuation, original)` and `complete(state, binding, callback, original)` persist/consume the actual SQLite flow and use the existing upstream SDK. |
| `store.browser_oidc_authorizations(policy)` | Borrowed service; `complete_upstream(login, verifier, original)` consumes the genuine proof by value and retains the same verifier `Arc`. |
| `store.oidc_token_exchange(authorization, token_policy, issuer)` | Borrowed native code exchange; `.with_upstream(verifier)` enables current trust checks for federated snapshots. LOCAL still reads the current SQL identity. |
| `store.oidc_refresh(authorization, token_policy, issuer)` | Borrowed native rotation; `.with_upstream(verifier)` applies the same trust contract before effects and reuse revocation. |
| `store.oidc_userinfo(authorization, access_verifier)` | Borrowed `SqliteOidcUserInfo`; `.with_upstream(verifier).profile(raw_access, original)` verifies JWT plus the exact persisted access grant. |

Use these explicit routers, merging their distinct paths:

- `sqlite_oidc_browser_router(store, browser_config, local, upstream)` receives
  `OidcBrowserHttpConfig`, optional `Arc<SqliteLocalLoginRuntime>` and mandatory
  real upstream owner. It serves `/oauth/authorize` and `/oauth/login`.
- `sqlite_oidc_upstream_login_router(store, upstream, callback_config)` receives
  `SqliteOidcUpstreamLoginHttpConfig { input_bytes, cookie_secure, oidc }`, where
  `oidc` is `OidcUpstreamLoginHttpConfig`. It serves only GET
  `/oauth/oidc/callback`; it accepts no administrative configuration.
- `sqlite_oidc_token_router(store, issuer, authorization, token_policy, config)`
  requires `OidcTokenHttpConfig::with_upstream(upstream)` and serves POST
  `/oauth/token`. Optional `.with_device(device_policy)` retains the actual
  [LOCAL Device polling](rust-sqlite-device-authorization.md) producer; upstream
  login does not create a Device grant, refresh token or Device ID token.
- `sqlite_oidc_userinfo_router(store, access_verifier, authorization, upstream,
  config)` receives `Option<Arc<UpstreamBearerVerifier>>` and
  `OidcUserInfoHttpConfig`. `None` supports LOCAL and rejects federated profiles.

The explicitly LOCAL constructors `sqlite_local_oidc_browser_router` and
`sqlite_local_oidc_token_router` retain their purpose. The LOCAL token constructor
rejects an attached upstream owner. The federated token constructor rejects a
missing owner. Both validate real issuer/policy owners and preserve their Device
policy when supplied. There is no constructor that silently ignores upstream.

Configured request timeouts and positive byte bounds are required. API audience
must match the signing issuer/JWT verifier. `cookie_secure` controls the existing
Secure cookie policy; the configured callback URI is not derived from Host or
Forwarded headers. No configuration file or personal trust store is modified by
these APIs.

## Proof, trust and transaction boundaries

The H1 proof has no DATA constructor. A crate-private producer creates the
consumed-flow marker only after real matching SQLite consumption has a known
outcome. Network discovery and token exchange run outside the SQL worker using
the existing SDK. The proof retains its owner, OAuth continuation, Original,
UTC expiry and monotonic expiry.

Completion applies `min(caller_original, login.original())` to the actual worker
wait before SQL starts. It retains the owned proof and same verifier through the
IMMEDIATE transaction and final acknowledgment. It revalidates the protected
pending request, current client, redirect and policy before committing the
one-use code. Admin-purpose evidence and an equivalent but different proof owner
cannot complete it.

The grant stores the literal authenticated upstream issuer, mapped subject and
username, profile and authenticated roles plus implicit `user`. Its LOCAL
revision is zero. The Broker subject is the existing HMAC pseudonym of literal
issuer and mapped subject; the JWT issuer remains the Broker. SQL LOCAL role
assignments do not replace the authenticated upstream snapshot, and these claims
do not grant PROJECT access.

Current trust requires the literal issuer to remain enabled with at least one
OAuth browser client and the same role selector. Removing the last channel,
changing the issuer or adding/changing/removing the selector invalidates
completion, code exchange, refresh and UserInfo. Removing one channel while
another remains preserves an existing grant's eligibility. This snapshot check
makes no upstream request. Proof-owner identity is a separate condition at H1
completion and is never relaxed by equivalent configuration.

Exchange preserves S256, exact bindings and one-use code deletion. Refresh
preserves current client/resource/scope checks, rotation, family reuse revocation,
absolute family expiry and original `auth_time`. Initial ID-token AMR is
`federated`; refreshed AMR is `oidc`. Trust and current bindings precede all token
inserts/deletes and the committed reuse-denial branch.

SQLite IMMEDIATE serializes writers across physical owners. Code or token output
is returned only after known COMMIT and final proof/time gates. A deadline or
uncertain acknowledgment does not authorize another write attempt or expose a
successful code/token result.

LOCAL password change and MFA enrollment retain the existing revision-positive
invalidation. Federated revision-zero tokens and genuine federated authorization
requests with the same raw subject survive. Invalid JSON syntax encountered
while scanning requests aborts the whole mutation, including staged password,
revision, factor/recovery, token and challenge changes. The existing classifier
validates complete JSON syntax; a syntactically valid object without the required
federated discriminator is not preserved as federated authority.

## Explicit UserInfo

The [UserInfo contract](rust-oidc-userinfo.md) applies unchanged. GET and POST
accept exactly one Bearer credential from the Authorization header, query or form.
An invalid header never falls through to another credential. Duplicate or combined
transports, malformed form/UTF-8 and disallowed bodies fail locally. HEAD is
rejected before profile lookup. Responses carry `no-store` and `no-cache`.
Declared-origin CORS remains the existing outer Server composition; these
explicit Presence constructors do not install a new CORS policy. The unchanged
Server layer and its prior native CORS evidence are reused, without claiming a
native SQLite Server journey.

The native producer verifies the Broker access JWT and bounded b75d snapshot:
JTI/domain-11 HMAC, subject/pseudonym, client, audience/resource, exact expiry,
scopes, principal and revision. LOCAL loads current enabled identity/profile and
roles; federated uses its authenticated snapshot and current trust. UserInfo does
not add a current DCR lookup, `openid` gate or profile/email scope filter, and it
does not call upstream UserInfo/discovery/token endpoints. `last_used_at` changes
only within the admitted transaction, with proof gates and known COMMIT.

Invalid access tokens return 401 `invalid_token`; malformed credential transport
returns 400 `invalid_request`. Deadlines return 504, closed/uncertain storage 503,
and malformed/capped SQL snapshots 500. These are profile-request outcomes;
local JWT consumers are not required to call UserInfo as a revocation gate.

## Verification and boundaries

The focused portable invocations are:

```text
cargo test --locked --offline -p broker-control --test sqlite_oidc_federated -- --test-threads=1
cargo test --locked --offline -p broker-control --test sqlite_oidc_federated -- --ignored --test-threads=1
cargo test --locked --offline -p broker-presence --test sqlite_oidc_federated_http -- --ignored --test-threads=1
```

The tests use private temporary SQLite databases, actual physical owners, native
Argon2/MFA, real HTTPS authorization/token endpoints and native Axum TCP routes.
They are controlled test environments, not evidence of native Server backend
selection, an installed agent host journey or a deployed external provider.
Linux
results do not prove Windows/macOS execution.

Implementation: Control `sqlite/flow/upstream_login.rs`,
`oidc_authorization/federated.rs`, `oidc_token_exchange.rs`, `oidc_refresh.rs` and
`oidc_userinfo.rs`; Presence `oauth_browser.rs`, `admin_upstream_login.rs`,
`oauth_token.rs` and `oauth_userinfo.rs`. Shared proof construction, principal and
snapshot decoders remain with their existing owners.
