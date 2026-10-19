---
type: document
title: SQLite LOCAL Device authorization
description: Device codes, genuine LOCAL consent and access-only polling over the physical SQLite owner.
references:
  - target: {type: task, id: tsk-68a5, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e672, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-2080, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# SQLite LOCAL Device authorization

For Broker integrators composing Device sign-in over the private
[SQLite Control store](rust-sqlite-control.md) and actual
[LOCAL runtime](rust-sqlite-admin-local-http.md).
The normative [Device contract](rust-device-authorization.md) also applies here.
This explicit producer/router API does not select SQLite in the native Server,
change configuration/discovery or complete the migration.

## Compose the startup owners

`store.device_authorizations(authorization, device_policy, issuer)` returns a
borrowed `SqliteDeviceAuthorizations`. Each policy and issuer is an actual `Arc`
startup owner; the authorization API audience must equal the signing issuer's API
audience. The physical store supplies its existing HMAC digester and transaction
executor. The view exposes no connection, proof constructor or wire serializer.

`DeviceAuthorizationPolicy::new` requires explicit code TTL, initial polling
interval and access TTL. Existing ranges are 5–30 minutes, 1–30 seconds and 1–60
minutes respectively; code TTL and polling interval require whole seconds. There
is no SQLite default or additional enable switch. Use the configured access TTL.

Compose `sqlite_local_oidc_device_router(store, config, local)` with the same store,
`OidcDeviceHttpConfig` and optional `Arc<SqliteLocalLoginRuntime>`. The config
retains the authorization policy, Device policy, issuer, explicit absolute
verification URI, body bound and request timeout. The URI must have HTTP(S)
scheme/host, path `/oauth/device`, and no userinfo or query. It is never derived
from Host or Forwarded headers. `None` leaves LOCAL unavailable with finite 503.

Merge the existing `sqlite_local_oidc_token_router` with
`OidcTokenHttpConfig::with_device(device_policy)` only when Device is available.
This router retains and validates the genuine Device policy and polls the concrete
SQLite producer. Without that policy its Device grant returns finite 503. Code
and refresh retain their [qualified LOCAL contract](rust-sqlite-oidc-local-grants.md).
SQLite upstream options remain rejected at construction. PostgreSQL factory
signatures, parsers and templates retain their existing contracts.

## Headless client and consent

1. POST `/oauth/device/authorize` as a form with the configured static CLI
   `client_id`. Omit scope or supply the literal empty string. Every nonempty
   string, including whitespace, `openid` and `offline_access`, fails
   `invalid_scope` before SQL or code generation. The row stores `[]`.
2. Success returns exactly `device_code`, `user_code`, `verification_uri`,
   `verification_uri_complete`, integer `expires_in` and integer `interval`.
   Keep the `gb_dc_` device secret private. The displayed user code has eight
   symbols in a 4-4 layout. Normalization trims surrounding whitespace, removes
   hyphens and uppercases the existing ASCII alphabet.
3. Visit the configured verification URI and compare the displayed user code with
   the requesting device. Credentials and challenges belong only in POST bodies;
   the user code remains in the query. GET never authenticates or decides.
4. Complete actual LOCAL password authentication and any mandatory password
   change, CAPTCHA, enrollment or MFA. The runtime fixes purpose `DeviceApprove`
   and binds the normalized eight-character code. Admin cookies, bearer headers,
   upstream providers and caller-supplied principal data cannot replace this proof.
5. `prepare` consumes the genuine completed login, checks the current eligible
   human identity/revision and returns protected review data after known COMMIT.
   Login and review rendering leave Device pending. Enrollment recovery ownership
   is transferred once and the existing page renders the codes before Review and
   the Allow/Deny buttons. The secret cannot be borrowed while that recovery
   ownership remains in `DeviceConsent`.
6. Submit Allow or Deny with the exact client, user code and protected one-use
   consent secret. `decide` revalidates current identity, revision, binding,
   pending state and expiry, consumes the challenge and changes state atomically.
   Another code/client/purpose, tamper, replay or identity invalidation fails closed.
7. Poll `/oauth/token` using form grant
   `urn:ietf:params:oauth:grant-type:device_code`, CLI `client_id` and original
   `device_code`. Success contains only `access_token`, `token_type: "Bearer"`,
   `expires_in` and `scope: ""`. There is no ID token, refresh token or family.

The access JWT uses the existing signing owner and current LOCAL profile/roles.
It authenticates for the Broker API, with resource absent and empty scope. A valid
JWT grants no PROJECT permission; the current SQL resource policy remains separate.
Consumers verify JWTs locally until expiry. SQL revocation does not blacklist an
already emitted JWT, and expiry requires a new Device sign-in.

## Persistence, cadence and failures

Only purpose-separated HMAC digests of the device, user and consent secrets enter
the existing Device/challenge tables.
No schema, seeds or NativeFormat changes are required. Text/type/JSON bounds are
checked in SQLite projections before owned decoding; nonempty stored scopes and
inconsistent status, revision, interval or timestamps fail closed.

The existing physical executor uses a real IMMEDIATE transaction across current
identity, consent and redemption, including concurrent owners on the same file.
Polling precedence is expiry, denial, cadence, pending, then approved redemption.
Expired and denied rows are consumed after known COMMIT. Pending polls persist
`last_poll_at`; early polls persist a five-second interval increase and return
`slow_down`. Reopen retains that cadence. These protocol denials are committed
outcomes, rather than errors that roll back the updates.

Approved redemption reads the current eligible human identity and profile, signs
with the existing issuer, inserts the native `oidc_access` row and deletes the
Device row in the same transaction. There is one winning redemption. No emulated
PostgreSQL advisory lock, external transaction callback or automatic replay is used.

One Original deadline is bounded by the real store budget without renewal. Known
COMMIT/ACK and final expiry/deadline gates precede returning secrets or tokens.
An uncertain COMMIT returns no success credential, even if effects became durable.
Neither a deadline nor a finite failure proves rollback. Shutdown uses the existing
owned executor/admission/engine lifecycle; unchanged physical cancellation and ACK
proofs are reused from the [store qualification](rust-sqlite-control.md).

The existing forms reject duplicate recognized fields, invalid UTF-8, incompatible
credentials/actions and authority in the wrong location. Unknown extensions remain
bounded data. Device combined query/body input is capped at the smaller of the
configured bound and 16 KiB; HEAD returns 405 without effects. Existing no-store,
no-cache, CSP, no-referrer, nosniff, DENY and autoescape protections remain.
Device errors use the [same finite wire/status mapping](rust-device-authorization.md).
Secrets, passwords and factor codes are not reflected in error messages or URLs.

## Focused qualification

```text
cargo test --locked --offline -j4 -p broker-control --test sqlite_device -- --test-threads=1
cargo test --locked --offline -j4 -p broker-control --test sqlite_device -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_device_http -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_oidc_token_http -- --ignored --test-threads=1
```

The first command exercises quick SQL/HMAC contracts. The ignored targets require
native Argon2/TOTP work. Genuine tests use file SQLite, actual runtime/consent
producers, TCP and signature-verified JWTs; identity metadata fixtures do not prove
authentication.
Linux results do not qualify Windows/macOS or native Server backend dispatch.
