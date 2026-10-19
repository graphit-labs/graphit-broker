---
type: document
title: SQLite public OIDC browser
description: Public authorize and login routes over genuine SQLite LOCAL and OIDC producers.
references:
  - target: {type: task, id: tsk-9cfb, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# SQLite public OIDC browser

For native Broker integrators composing public browser sign-in with the private
[SQLite Control store](rust-sqlite-control.md). This path uses the existing
[LOCAL runtime](rust-sqlite-admin-local-http.md) and [OIDC grants/token router](rust-sqlite-oidc-local-grants.md).
Server backend selection and dispatch
remain separate integration work. This router alone does not enable SQLite in the
native Server or implement SQLite upstream/Device families.

## Compose the actual startup owners

Use `sqlite_local_oidc_browser_router(store, config, local)` with an
`Arc<SqliteControlStore>`, `OidcBrowserHttpConfig` and optional
`Arc<SqliteLocalLoginRuntime>`. `config` supplies the existing authorization policy,
aggregate query/body byte bound, request timeout and cookie-security choice.
The factory validates finite positive timeout/body bounds and the actual LOCAL
password-admission view for `OauthAuthorize`. There is no runtime default,
callback authority or substitute password engine. `None` explicitly disables
LOCAL; the public sign-in channel then returns finite 503 without another backend.

Merge the existing `sqlite_local_oidc_token_router` using the same policy/store
and startup issuer/token-policy owners. The public route obtains pending requests
and completions through the qualified grant producers, and the token route consumes
those genuine one-use codes. Neither a profile DTO nor client principal JSON can
authenticate or authorize this flow. The PostgreSQL router signature and its
upstream channels retain their existing contracts.

## Browser journey

1. The client sends GET or POST `/oauth/authorize` with its admitted client ID,
   literal redirect, `response_type=code`, scope including `openid`, state, nonce,
   S256 challenge/method and any required resource. It may select query, fragment
   or form_post response mode under the shared authorization policy.
2. A known committed pending result redirects to `/oauth/login?id=...`.
   The page offers the current real LOCAL password/CAPTCHA presentation.
3. POST credentials to that login URL. The request ID stays in the query; password,
   challenge and action fields belong only in the form body. Purpose is always
   `OauthAuthorize`, with the exact request binding, never a form parameter.
4. Complete required password change, MFA or enrollment through the same actual
   runtime's engine, logical admission, factor policy and limiter. A current human
   identity, enabled state, password-change state and revision are checked by the
   authentication and grant completion producers.
5. After known completion and final temporal gates, follow the existing protected
   Query/Fragment redirect or FormPost response. Exchange the resulting code with
   its original verifier at `/oauth/token`; the existing grant path signs access/ID
   tokens and handles absolute refresh rotation/narrowing/reuse.

The public browser does not use an administrative SSO cookie, bearer fallback or
request-supplied runtime/policy. HEAD returns 405 before parsing or SQL. Metadata
requests and challenge IDs are not identity proofs. The existing
[public browser contract](rust-oidc-browser-authorization.md) owns all form fields,
status mappings, redirect rules and privacy behavior.

## Password change, CAPTCHA and recovery

Mandatory password change uses the existing admitted guard's `complete_sqlite`
operation, before factors. Passwords must differ, match confirmation, contain at
least 15 Unicode characters and fit the existing 4096-byte bound. MFA/enrollment
and recovery verification use the real SQLite LOCAL service and shared limiter.
They cannot be replaced by stored principal JSON or a presentation flag.

CAPTCHA availability and public challenge data come from the actual runtime
owner's `next_password_challenge(OauthAuthorize)` or its genuine `CaptchaRequired`
feedback. The private view input carries display data only. Existing templates,
static fragments, autoescape, labels, forms, CSS and renderer remain unchanged.
Provider action/site key/proof-field selection and CSP use the actual configured
provider; the unchanged fixed-provider HTTPS verifier retains its own proof.

Enrollment exposes the producer's QR/setup data and requires a genuine factor.
Recovery codes are taken synchronously from the completed login before constructing
`PreparedOidcLogin`. The existing SQL completion is the only code issuer. Known
COMMIT plus Original and expiry gates precede the one-time recovery presentation.
Query/Fragment use a manual final link; FormPost uses a manual final form without
autosubmit. There is no recovery holder/cache, intermediate URL, fresh TTL or
boolean acknowledgement. Save the codes before continuing. Later login may consume
each recovery code once as a factor for that user. The challenge and completed
login proof cannot be transplanted to another request or purpose.

## Strict forms, privacy and failure

Authorize merges query/form values and rejects repeated known scalars. Login keeps
ID in query and credentials/actions in the body, rejecting duplicates, mixed actions,
invalid decoded UTF-8 and overflow before authentication. Nonempty POST requires
`application/x-www-form-urlencoded`. Unknown fields remain bounded data.

Only sealed producer outputs supply trusted destinations. Invalid client or
malicious redirect yields a local error; semantic rejection may use the existing
closed OAuth error codes only after the current target was admitted. FormPost
rejects NUL/CR/LF state in the final response, including when a pending came
from the direct grant API. Such a pending can display the login page and complete
authentication; the renderer withholds the invalid response after the genuine code
completion. This does not roll back that committed code or expose it to the client.

Responses retain no-store, no-referrer, nosniff, DENY, autoescape and the protected
form-action/CAPTCHA CSP. Passwords, factor codes and CAPTCHA proofs are not reflected;
LOCAL emits no administrative session cookie. Invalid credentials/factors use 401,
required CAPTCHA 403, rate protection 429, invalid forms/targets 400, unsupported
media 415, unavailable/closed/uncertain completion 503 and Original deadline 504.
An unavailable LOCAL channel also returns 503 when handling an invalid provider
selection; with LOCAL available the invalid selection returns 400.

One Original deadline covers body parsing, SQL, KDF, factors and rendering per
request. Pending/challenge UTC lifetimes are not renewed. No trusted code redirect
or recovery page follows an expired budget, uncertain COMMIT or failed final guard.
A finite failure does not undo an already committed password/factor change or
code completion. Restart
sign-in from the application rather than replaying an uncertain completion.

## Focused qualification and boundary

```text
cargo test --locked --offline -j4 -p broker-presence --test sqlite_oidc_browser_http -- --ignored --test-threads=1
```

The target uses actual TCP, file SQLite, native Argon2, the shared LOCAL runtime,
TOTP/recovery, S256 and signature-verified JWTs through the real browser/token
routers. Authorized grants are never seeded through SQL. Fixture user/client
metadata alone is not claimed as authentication evidence. Native Server dispatch,
release cutover and other hosts/platforms require their own evidence.

Source: Presence `src/oauth_browser.rs`, `src/oauth_browser/views.rs`,
`src/sqlite_local_login.rs`, the shared OAuth renderer/forms, and Control's
qualified [SQLite OIDC grant APIs](rust-sqlite-oidc-local-grants.md). Ownership of
central exports, validation phase, Server config/runtime dispatch remains separate.
