---
type: document
title: SQLite LOCAL OIDC grants
description: Native file-backed pending requests, genuine LOCAL completion, code exchange and absolute refresh rotation.
references:
  - target: {type: task, id: tsk-e8dd7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# SQLite LOCAL OIDC grants

For native Broker integrators using the [SQLite Control owner](rust-sqlite-control.md).
This library path composes genuine LOCAL authentication, S256 code exchange and
refresh rotation with an explicit `POST /oauth/token` router. The [public SQLite browser](rust-sqlite-oidc-browser.md) composes
`/oauth/authorize` and `/oauth/login` as a separate consumer. Server backend
configuration/dispatch remains separate integration work. SQLite upstream remains separate. The Device grant has its own explicit producer and policy described in the [SQLite Device guide](rust-sqlite-device-authorization.md).

## Integrate actual owners

Open `SqliteControlStore` with the existing file configuration and digester.
Retain one `Arc<OidcAuthorizationPolicy>`, `Arc<OidcTokenExchangePolicy>` and
`Arc<BrokerAccessIssuer>` from startup. The factories borrow the store and retain
those actual owners; there is no signing-key clone or callback authority:

```rust,ignore
let authorizations = store.browser_oidc_authorizations(authorization.clone());
let pending = authorizations.create(input, original).await?;
// Obtain a real password proof and complete the LOCAL OAuth stages with
// LocalAuthBinding::OauthAuthorize(pending.request().as_bytes()).
// Take recovery codes before constructing PreparedOidcLogin.
let prepared = PreparedOidcLogin::try_from(completed_login)?;
let code = authorizations.complete(pending.request(), prepared, original).await?;
let exchange = store.oidc_token_exchange(authorization.clone(), policy.clone(), issuer.clone())?;
let tokens = exchange.exchange(token_input, original).await?;
let refresh = store.oidc_refresh(authorization.clone(), policy.clone(), issuer.clone())?;
let next = refresh.rotate(refresh_input, original).await?;
```

The snippets show application sequencing, not a password or consent transport.
Use the [native SQLite LOCAL stages](rust-sqlite-local-auth.md) and their prepared value;
client-provided principal JSON, an authorization code or a LOCAL row alone is
not an authentication proof. `load` returns a still-live pending request or
`None` after completion/expiry. It does not consume or extend the request.
`admit_browser` returns either pending metadata or a sealed protocol rejection
whose redirect was admitted against the current client. No trusted redirect is
created before known COMMIT acknowledgement and the final deadline check.

Pending admission uses the shared [OIDC authorization policy](rust-oidc-authorization.md),
including the configured CLI loopback redirect policy, actual registered DCR
client, six requested scopes, resource rules, state/nonce and oxide-auth S256.
Canonical dynamic IDs retain Base64URL `-` and `_` prefixes. The stored client
scope list is validated as registration metadata, not an additional grant-scope
constraint. Byte/type checks bound SQLite text and JSON before copying it.

Completion verifies the exact OAuth request binding of `PreparedOidcLogin`.
Within one transaction it checks current human identity, enabled state,
password-change state and revision, then reads current profile, normalized teams
and assigned `local|subject` roles plus implicit `user`. `auth_time` is fresh and
no earlier than the genuine login observation. Initial AMR records the private
verified factors, `pwd` or `pwd` with `otp`.

## Code and refresh state

The code exchange consumes the existing authorized codec, oxide-auth S256 state
machine and configured issuer. Client, literal admitted redirect, resource,
current identity and current client checks precede code consumption. A wrong
verifier leaves the code usable. Access and optional initial refresh rows plus
code deletion commit atomically. Access audiences are the Broker API and optional
resource; ID audiences also include the client. The actual issuer owns nonce,
`at_hash`, `c_hash` and signing behavior. The retained digester derives the
pseudonymous subject.

Refresh consumes the shared strict principal/scope codec and SDK state machine.
Every generation retains the original family, `auth_time` and absolute UTC refresh
expiry. No sliding lifetime is added. Missing scope preserves the current scope;
present scope must be a nonempty subset. Repeated valid scope names follow the
shared producer's deduplication. Removing `offline_access` does not prevent the
existing family from rotating. Refresh AMR is `local-token`, not a claim of newly
verified password/OTP; refresh ID tokens omit nonce and code hash.

Current identity/client/resource/scope guards precede effects. Already revoked
grants return `invalid_grant`. Valid reuse of a consumed refresh revokes every
still-active access/refresh row in that family and acknowledges COMMIT before
returning `invalid_grant`, even when that consumed ancestor has expired. An unused
expired refresh is denied without mutation. SQLite IMMEDIATE transactions serialize
these writers across stores; no PostgreSQL advisory-lock parallelism is promised.
Persisted revocation prevents later grant/refresh operations. Signature verification
of an already issued access JWT remains valid until its expiry and does not become
a blacklist check.

One bounded Original deadline covers admission, lock wait, signing, SQL and
known acknowledgement. Issuer/digester work runs inside that same SQLite
transaction on retained Arc owners. Tokens, codes and trusted redirects are
returned only after known COMMIT and final temporal checks. A lost acknowledgement
is `OutcomeUncertain`; do not blindly replay an old code or refresh. Obtain a new
genuine authorization when the caller cannot know which credential committed.

## HTTP consumer and errors

`sqlite_local_oidc_token_router(store, issuer, authorization, policy, config)`
uses the shared form parser, body limits, public-client Basic handling and wire.
Its constructor rejects `config.with_upstream(...)`. With an explicit
`config.with_device(...)` policy it validates and retains the actual
[SQLite Device producer](rust-sqlite-device-authorization.md). Without that policy,
Device keeps the existing 503 `temporarily_unavailable` response. The PostgreSQL constructor and its active
upstream/Device paths retain their existing behavior.

Successful code/refresh responses contain `access_token`, `id_token`, optional
`refresh_token`, `token_type: Bearer`, `expires_in` and `scope`. Both success and
errors use `Cache-Control: no-store` and `Pragma: no-cache`. Expiry and Original
are checked before and after response serialization, including the refresh
family cutoff carried privately by the result.

| Condition | HTTP result |
| --- | --- |
| Missing/duplicate/malformed parameter, UTF-8 or body bound | 400 `invalid_request` |
| Invalid public-client Basic credentials | 401 `invalid_client` with Basic challenge |
| Unknown/expired/revoked grant or valid consumed-refresh reuse | 400 `invalid_grant` |
| Wrong resource or disallowed requested scope | 400 `invalid_target` / `invalid_scope` |
| Original deadline | 504 `temporarily_unavailable` |
| Closed owner or uncertain COMMIT | 503 `temporarily_unavailable` |
| Corrupt metadata, storage or signing failure | 500 `server_error` |

Errors do not echo bearer values, codes, refresh secrets or principal JSON.

## Focused qualification

Run the actual file/Argon2 and TCP tests, with the repository's coordinated Cargo
window and existing target directory:

```text
cargo test --locked --offline -j4 -p broker-control --test sqlite_oidc_grants -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_oidc_token_http -- --ignored --test-threads=1
```

Source: Control `src/sqlite/flow/oidc_authorization.rs`, its `completion.rs`,
`oidc_token_exchange.rs`, `oidc_refresh.rs`, `oidc_tokens.rs`, and Presence
`src/oauth_token.rs`. Tests obtain authorized codes through native Argon2 and
LOCAL preparation; authorized grants are never inserted as synthetic SQL data.
The [PG code](rust-oidc-token-exchange.md) and [refresh](rust-oidc-refresh.md)
contracts remain the protocol authority. Local Linux evidence does not establish
Windows/macOS execution, public browser deployment or Server dispatch.

## Public browser consumer

The [SQLite public OIDC browser](rust-sqlite-oidc-browser.md) now composes these
pending/completion/token/refresh APIs with the real shared LOCAL runtime and
existing renderer. This is a separate qualified consumer; the grant APIs retain
their authority and transactional boundaries. Native Server backend dispatch
and SQLite upstream remain separate work. Device is an independent
[SQLite consumer](rust-sqlite-device-authorization.md).
