---
title: Native public OAuth browser authorization
description: Public authorize/login composition with bound LOCAL challenges, upstream sign-in and one-time recovery presentation.
doc_type: reference
references:
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7db9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native public OAuth browser authorization

For application integrators and operators of the [native PostgreSQL server](rust-broker-server.md).
The public browser transport composes [initial admission](rust-oidc-browser-admission.md),
[shared LOCAL authentication](rust-local-login-runtime.md) and the genuine
[upstream begin/callback chain](rust-oidc-browser-callback.md). It issues no administrative
session and needs no Admin cookie. [Native discovery](rust-oidc-discovery.md) advertises
the productive endpoints; this page does not claim a Graphit Code Web session or completion of the migration.

## Enable and start sign-in

Enable the existing [native OIDC section](rust-oidc-token-exchange.md) and configure
at least one method: LOCAL through auth.local.login.enabled, or an active
[upstream browser client](rust-admin-upstream-login.md). The same LOCAL runtime,
password admission, CAPTCHA policy and MFA limiter serve their existing consumers.
No independent engine, retry counter, key or session store is added by the page.

| Method and path | Observable result |
|---|---|
| GET/POST /oauth/authorize | Admit the current client and exact redirect, then redirect a genuine pending request to login; return only a sealed protocol rejection to its admitted target |
| GET /oauth/login?id=… | Observe the existing request, present methods, or forward to the only upstream when LOCAL is absent |
| POST /oauth/login?id=… | Consume an initial LOCAL password, one bound LOCAL continuation, or an explicitly selected upstream method |
| HEAD on either route | 405 before parsing, SQL, authentication or flow creation |
| Either route with OIDC absent/disabled | 404 |

The authorization request retains the existing P2 client/redirect, scopes, resource,
PKCE S256, state, nonce and response-mode policy. Unknown/empty response modes keep
the policy's Query result. Unknown resources do not become defaults. A genuine
pending request is required before any method selection or credential attempt.
An unavailable method set returns a finite local 503.

## Form wire and bounds

Authorize GET reads query parameters. POST merges query and form body, rejecting
known scalar duplicates within or across those origins. Repeated resource fields
reach the authorization policy together. A nonempty POST body requires
application/x-www-form-urlencoded; an empty body can use query parameters without
Content-Type. Invalid decoded UTF-8 is rejected. Unknown fields remain bounded DATA.
The existing oidc.body_bytes caps the aggregate raw query and body before admission;
Control applies its existing decoded parameter/JSON bounds.

Login GET accepts id, login_method and provider from query. Login POST accepts id
only from query and actions/credentials only from body. A body id, a repeated known
field, credentials in query or conflicting actions return local 400. Login's raw
query/body limit is the smaller of 16 KiB and configured oidc.body_bytes.

The active form names are login_method (local or oidc), provider, username, password,
challenge_token, new_password, confirm_password, code, cf-turnstile-response and
g-recaptcha-response. Request IDs and LOCAL challenges are distinct secrets; neither
supplies a purpose, policy, role or arbitrary continuation from the caller.

## LOCAL stages and recovery

A verified password enters the existing [LOCAL stage machine](rust-local-auth.md),
bound to that exact OAuth request. Mandatory password change comes before MFA or
enrollment. New passwords must differ from the previous password, match their
confirmation, contain at least 15 Unicode characters and fit 4096 UTF-8 bytes.
Factor/recovery input is capped at 64 bytes. Invalid input re-renders only an
observed genuine pending stage; it does not renew or recreate the challenge.
Passwords, factor codes and submitted CAPTCHA proofs are never reflected.

For enrollment, the page shows the producer's actual QR, setup key and otpauth
link, then requires a real factor. The completed login's recovery codes are taken
synchronously before creating the P2 completion future. They remain owned only by
that request across the await. Known completion plus Original and UTC/monotonic
gates precede the single presentation page. Query/Fragment provide a manual final
link; FormPost provides a manual final form, with no automatic submit. Save the codes
before continuing. There is no intermediate recovery URL, retained holder, cache,
plaintext SQL, new TTL, replay or acknowledgement protocol.

A later SQL failure, expired request, caller drop or invalid FormPost state discards
that presentation owner and returns a finite local error. Such an error does not
assert rollback of an already committed password/factor change. Restart sign-in
from the application instead of replaying an uncertain completion.

## Responses, errors and privacy

Only the Control producer's sealed rejection/authorized result can supply the
client destination. Query, Fragment and FormPost preserve the registered redirect
literal and state. An empty initial-error state is omitted. FormPost rejects
NUL/CR/LF in state, including the manual recovery path for pendings created through
the direct P2 API. Parsed origins supply CSP/context; they never replace redirects.

| Condition | Local HTTP result |
|---|---|
| Invalid form/client/redirect or unavailable pending request | 400, with no untrusted OAuth destination |
| Unsupported content type on nonempty POST | 415 |
| Invalid LOCAL credentials/challenge/factor | 401 |
| Missing/rejected required CAPTCHA | 403, with public challenge DATA |
| Shared username/factor rate protection | 429 and ceiling Retry-After seconds |
| Capacity, dependency failure or unconfirmed COMMIT | 503 |
| Original deadline | 504 |

Semantic protocol rejections with an admitted client target use the producer's
closed invalid_request, invalid_scope, login_required and invalid_target codes.
Infrastructure, expired budget and unconfirmed COMMIT do not become conclusive
OAuth redirects. Original is never renewed across body parsing, SQL, KDFs, H1 or HTML.

HTML uses the existing Graphit authentication mark, light tokens, focused forms,
650px column and mobile reflow. MiniJinja uses static compile-time fragments and
HTML autoescape with its already enabled features. There is no runtime loader or
external font. Responses set no-store, no-referrer, nosniff and DENY. CSP limits
login/stage form submissions to self and the protected destination origin, including
the final Query/Fragment redirect chain, and loads CAPTCHA origins only when
required. Local failures without an admitted target retain self-only forms.
Widgets request the providers’ compact size and remain inside an overflow-contained
region at 320px. This is a presentation choice; site keys, action and proof names
retain the producer contract. See the official [Turnstile widget options](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/)
and [reCAPTCHA display options](https://developers.google.com/recaptcha/docs/display).
An OAuth upstream flow uses its own HttpOnly/SameSite cookie; its callback clears
only that consumed flow and cannot create an Admin authentication cookie.

## Focused qualification

The focal command is:

~~~text
cargo test --locked --offline -j4 -p broker-server --test oidc_browser_authorization -- --ignored --test-threads=1
~~~

It uses the actual native executable, TLS PostgreSQL with a NOSUPERUSER application
account, DCR, LOCAL stages, genuine HTTPS IdP/callback and native token/refresh.
Real browser QA separately checks responsive layout, keyboard/focus, stages and
manual recovery continuation. Test fixtures are not an external Auth implementation.

For the optional interactive harness, set GRAPHIT_BROKER_PUBLIC_BROWSER_UI to a
private temporary JSON index path and run only the mfa_recovery focal. It starts
the native server and a disposable loopback RP. The index exposes login, CAPTCHA
and RP addresses. Stage previews relay actual native HTTP representations once,
with the original privacy/CSP headers and no cookies or framing; they qualify
read-only layout/keyboard, not another execution of the stage. Native HTTP tests
prove credential changes. The browser completes real query/fragment/form_post
journeys through the native server; the RP exchanges each actual code with PKCE,
verifies signed tokens and refreshes. The browser IdP fixture explicitly uses
allow_loopback_http, while the normal focal retains the real HTTPS IdP proof.
Its form CSP explicitly allows the disposable RP origin as well as the native
callback origin so the browser can follow the OAuth redirect chain. The shared
issuer fixture keeps its existing CSP unless that test-only origin is supplied;
there is no wildcard or change to the Broker’s production CSP.
After the three distinct response-mode callbacks, the manual recovery callback
and the visual checks, create the index’s
.stop sibling to finish; timeout/cancellation without all four distinct callbacks fails.
For a focused rerun of only the LOCAL modes after a presentation correction, also
set GRAPHIT_BROKER_PUBLIC_BROWSER_UI_LOCAL_ONLY; the same RP then requires all three
distinct response modes without requiring another manual recovery callback. This
does not qualify upstream or recovery; retain their separate executed evidence.
Fixture addresses, codes, challenges and recovery values must not be committed.

CAPTCHA proof is explicitly composed: native Server tests cover render/fields,
limits, 403 and token forwarding; Control's real HTTPS Siteverify fixture proves
vendor protocol parsing, admission and OAuth purpose. That fixture's DNS/trust
injection is internal to the producer test. It does not run inside the external CLI,
validate a third-party service or justify a test endpoint/TLS bypass in production.

Whole-system integration and other platforms require their own tests; discovery has its [focused contracts](rust-oidc-discovery.md). No check authorizes a push.

## SQLite LOCAL public browser

The explicit [SQLite public browser router](rust-sqlite-oidc-browser.md) reuses
these forms, templates, renderer and response/recovery contracts with the actual
SQLite LOCAL runtime and committed OIDC grant producers. It does not enable
SQLite upstream or Device, nor select SQLite in native Server configuration.
