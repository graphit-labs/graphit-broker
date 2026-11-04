---
title: Native Device authorization
references:
  - target: {type: task, id: tsk-e672, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-2080, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: corrects
  - target: {type: task, id: tsk-50e3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: memory, id: 01M54JD071T72432Z78W9EF4GV, scope: project, scope_id: 01M1YEAE1WYMWG9KJKV1XQC4T4}
    relation: derived_from
---

# Native Device authorization

The Broker exposes Device authorization through HTTP discovery and LOCAL browser authentication.
Graphit Code uses the shared Auth consumer for its CLI Device login.

The native grant issues an access JWT through the existing
[Broker signing owner](rust-broker-access-issuer.md). A valid JWT does not grant PROJECT access;
the [current SQL authorization policy](api.md) is separate.
This Device profile authenticates the LOCAL user and static CLI for the Broker API. It grants
no scope-based capabilities and returns no refresh or ID token. Omit `scope` or send an empty
value: the documented default is an empty grant, persisted as `[]` and signed as `scope: ""`.
This default is documented following [OAuth 2.0 §3.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3).
Any nonempty request, including whitespace, `openid`, `profile`, `offline_access` or a custom
name, returns `InvalidScope` before SQL or code generation. Existing Code-grant OIDC scopes
and offline-access renewal remain unchanged. An API requiring nonempty `required_scopes`
rejects a Device token; identity claims do not replace that check or PROJECT/RBAC policy.
The access JWT lifetime and the Device-code lifetime are configured independently. Each defaults
to ten minutes.

## Headless-client and browser journey

Enable the native `oidc` section and the existing `auth.local.login.enabled` runtime.
No separate Device enable flag exists. With OIDC disabled the routes are absent (404).
With OIDC enabled and LOCAL disabled, Device routes return 503 `temporarily_unavailable`
(the browser renders a finite local error); discovery omits Device.
The OpenID discovery document advertises `device_authorization_endpoint` and the Device
grant only when both are operational. Endpoints use configured `server.public_url`,
never Host or Forwarded headers. See [native configuration](rust-oidc-token-exchange.md).

1. POST `/oauth/device/authorize` as `application/x-www-form-urlencoded` with
   `client_id=graphit-cli` (or the configured static CLI ID), omitting `scope`.
   A 200 response contains `device_code`, `user_code`, `verification_uri`,
   `verification_uri_complete`, `expires_in` and `interval`.
   Preserve the device secret privately; show the user code and verification URI.
2. Open `verification_uri_complete`, or visit `verification_uri` and enter the code.
   Compare the displayed code with the requesting device, then sign in using the
   LOCAL account. Mandatory password change, authenticator enrollment, MFA and
   adaptive CAPTCHA use the existing sign-in policy.
3. If enrollment occurred, save the ten recovery codes shown above the review section.
   The request remains pending while this page is displayed. Check the code and application
   ID, then choose **Allow sign-in** or **Deny sign-in**. Login alone never approves a device.
   Only the protected, one-use consent form changes the request.
4. Poll `POST /oauth/token` with form fields
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `client_id` and `device_code`.
   Wait at least the returned interval; after `slow_down`, increase it by five seconds
   for all subsequent polls. `authorization_pending` means keep waiting.
   `access_denied` and `expired_token` are terminal; start a new request if needed.
5. Success 200 contains `access_token`, `token_type: "Bearer"`, `expires_in` and
   `scope: ""`. There is no `id_token` or `refresh_token`; after access expiry, start
   a new Device sign-in. API authentication and current PROJECT/RBAC authorization remain separate.

Forms reject duplicate recognized fields, recognized authority in query parameters,
invalid UTF-8 and incompatible credentials/grant parameters. Unknown OAuth extensions
are ignored. Device requests admit no Basic/client secret, resource or dynamically
registered client. A nonempty `scope` fails `invalid_scope` before SQL.
The browser keeps user code in the URL and passwords, factor challenges and consent
secrets only in POST bodies. It does not use administrative cookies or upstream SSO.
Its combined query/body cap is the smaller of `oidc.body_bytes` and 16 KiB.
Responses use no-store/no-cache; browser pages add the common CSP and privacy headers.

Protocol error JSON has one field: `{"error":"authorization_pending"}`, for example.
Pending, slow_down, expired_token, access_denied, invalid_request, invalid_grant and
invalid_scope return 400; invalid_client returns 401. Deadline returns 504, unavailable
or uncertain SQL outcome returns 503, and malformed stored state returns 500.
Do not infer rollback from an uncertain outcome or automatically repeat a consent mutation.
The browser shows a local error and a path to start a new device request.

The UI reuses the maintained Graphit authentication tokens and server templates:
Public Sans/system fallback, navy header, blue actions, a focused single-column form,
persistent labels, alert errors, 44px controls and visible keyboard focus. Recovery
codes are rendered before the consent buttons with HTML autoescaping.

## State and authentication

`PostgresControlStore::device_authorizations` borrows the existing PostgreSQL store,
`OidcAuthorizationPolicy`, `DeviceAuthorizationPolicy` and `BrokerAccessIssuer`. The issuer
and API audience must agree. The static CLI is the only admitted client. This profile targets
the Broker API without an additional resource, dynamically registered client or upstream login.

The policy constructor requires explicit code TTL, initial poll interval and access TTL.
Code TTL accepts 5–30 minutes and polling accepts 1–30 seconds; both must be whole seconds.
Access TTL accepts 1–60 minutes. The primitive supplies no defaults. Startup supplies
`oidc.device_code_ttl` (default `10m`, range `5m`–`30m`) and
`oidc.device_poll_interval` (default `5s`, range `1s`–`30s`), both whole seconds.
The access JWT uses exactly the existing `oidc.access_ttl` (default `10m`).

1. `issue(client_id, scope, Original)` produces a new 256-bit device secret and an eight-character
   user code from a 32-symbol alphabet, displayed as `ABCD-2345`. Only purpose-separated HMACs
   enter `oauth_device_codes`. The row starts pending, with no subject and revision zero.
   Scope is absent or empty; requested nonempty names are rejected rather than copied into
   granted claims. Stored nonempty scope arrays fail closed as malformed state before consent
   or redemption.
2. The browser authenticates through the existing LOCAL password/change/MFA/CAPTCHA producers,
   using `LocalAuthBinding::DeviceApprove` with the normalized eight-character user code.
   `prepare` consumes the resulting `CompletedLocalLogin`, revalidates the current human user,
   revision and binding, and stores a one-use consent secret in `local_auth_challenges`.
   The exclusive `device_consent` stage cannot be accepted as an MFA challenge.
3. `prepare` returns protected consent presentation data after known COMMIT. It does not approve
   the Device row. Enrollment recovery codes move into that result once. Its consent secret
   cannot be borrowed until recovery ownership has been transferred to the presentation caller.
   Taking codes is an ownership operation; the HTTP owner must actually render them before
   exposing the continuation. Codes cannot be reconstructed by a later request.
4. `decide(user_code, client_id, consent_secret, allow, Original)` validates the exact pending
   request and current LOCAL identity again, consumes the consent secret and atomically changes
   the request to approved or denied. User code, client or another login purpose cannot replace
   the protected continuation. Existing LOCAL invalidators remove the consent row.
5. `poll` accepts the original device secret and client. Approved redemption revalidates the
   current LOCAL identity, signs through `BrokerAccessIssuer::sign_access`, persists the existing
   native `oidc_access` representation and deletes the Device row in one transaction. There is
   one winning redemption and no automatic retry after an uncertain result.

Expired and denied requests are terminal: a poll consumes the row and returns `expired_token`
or `access_denied` after known COMMIT. Cadence does not mask these terminal results. Pending
polls update `last_poll_at` and return `authorization_pending`. Polling early persists a
five-second interval increase and returns `slow_down`; later requests use that increased
interval, as required by [RFC 8628 §3.5](https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5).
An initial pending observation that becomes approved while waiting for its row returns pending;
the next client poll obtains locks in the required order before redemption.

## Transaction and failure boundary

The issuer, HMAC credential domains, current principal reader, native token-row insertion and
[pair writer barrier](rust-oidc-end-session.md) are reused. Approved polling takes the shared
pair lock before the user and Device row. Consent operations take the user before Device and
challenge rows, matching LOCAL invalidators, and never wait for the pair lock.

Stored text/JSON is bounded in SQL before owned decoding. Invalid status, shape, dates,
revision, interval or binding fails closed. Every asynchronous operation keeps the caller's
Original deadline within the store budget. Cancellation closes the owned connection rather
than returning an unchecked handle. A lost COMMIT acknowledgement returns `OutcomeUncertain`,
even when the token row and consumed code are already durable. Neither that result nor a
deadline is evidence that retrying the mutation is safe.

JWT consumers continue local verification until expiry. Revoking a SQL row does not blacklist
an already emitted JWT. Current PROJECT authorization still reads its separate SQL policy.
The grant type is not an authentication method: native LOCAL principal metadata remains
`local-token`; MFA evidence comes from the genuine LOCAL completion, never from merely finding
an enrolled factor.

## Maintained verification

From the Broker root:

```text
cargo test --locked -p broker-control --test postgres_device -- --ignored --test-threads=1
```

The four contracts use the actual PostgreSQL TLS fixture and ordinary SQL role, real Argon2 password verification, native TOTP enrollment and protected recovery codes. They exercise one-use redemption, purpose/client/code isolation, granted-scope admission and JWT claims, terminal states, persisted `slow_down`, local verification, separate PROJECT denial, malformed rows, SQL privilege rollback, concurrency, cancellation and a durable COMMIT whose TLS acknowledgement is withheld. These targets do not establish Auth client persistence or another operating system/backend.

The standard Cargo suite runs the four Device HTTP tests. Run the affected target alone with
`cargo test --locked --offline -p broker-server --test oauth_device`. Each test starts the real
Broker on loopback with a private temporary SQLite database. They cover discovery and availability,
malformed requests, LOCAL password and MFA, consent, polling cadence, signed access, and
PROJECT denial. The Auth journey uses the same production Device consumer as Graphit Code
and verifies the resulting identity against the signed token. It needs neither Docker nor a
separately built Code executable. Code's own `auth_cli::device_tests` covers CLI events and
account publication, inspection and logout.

## SQLite LOCAL producer and HTTP consumer

The explicit [SQLite Device API](rust-sqlite-device-authorization.md) composes the
physical store and actual LOCAL runtime through consent and access-only polling.
The Broker selects this producer for its private SQLite configuration. The HTTP contract
preserves literal empty scope, recovery before Review, one-use consent, persisted cadence,
and the existing forms.
