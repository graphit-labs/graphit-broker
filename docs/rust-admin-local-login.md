---
title: Native LOCAL administrative login
description: Genuine native password, bound challenge, MFA and committed administrative cookie composition.
tags: [rust, administration, authentication, postgresql]
references:
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-10ef, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-587f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-32a8, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-d03f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e15d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-1404, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native LOCAL administrative login

Audience: maintainers and operators composing native administrative login.
The router consumes genuine [password admission](rust-local-password-admission.md),
[bound LOCAL challenges](rust-local-auth.md) and the [administrative cookie producer](rust-admin-cookie-session.md).
The native executable serves this LOCAL login flow.
The [native administrative reads](rust-admin-read.md) independently authorize each read after login.
The [native browser OIDC adapter](rust-admin-upstream-login.md) shares the existing options and cookie owners. Administrative writes remain separate; this flow
does not establish full Broker migration completion.

## Trusted configuration and startup

The native schema uses `auth.local`. An absent block or absent/false
`login.enabled` leaves LOCAL browser login disabled. Enabled LOCAL uses the [shared runtime](rust-local-login-runtime.md): it requires
either active administration with its native cookie transport or the native OIDC
server. The Admin consumer itself still requires its cookie; without it, Admin
receives no LOCAL owner and reports LOCAL unavailable. A configuration with neither
consumer is rejected before the engine, SQL or serving HTTP. Existing native bearer,
JWT, federated session and cookie read/logout configuration is preserved.

```yaml
auth:
  local:
    login:
      enabled: true
    rate_limit:
      max_failures: 5
      window: 1m
      lockout: 5m
      max_concurrent: 2
      saturation_multiplier: 4
    mfa:
      required: true
      issuer_label: Graphit Broker
      challenge_ttl: 10m
    captcha:
      enabled: false
```

The values shown for rate/MFA are sourced defaults. Limits/durations remain
positive and checked; challenge TTL is 2–30 minutes. Explicit `mfa.required: false`
is the configured password-only exemption. CAPTCHA defaults disabled. When
enabled it requires provider `turnstile` or `recaptcha`, public site key, protected
secret key and the configured server public URL. The omitted trigger uses 1.5
and omitted verification timeout 3 seconds; explicit trigger 0 is supported and
timeout must be 500ms–10 seconds. No provider endpoint is configurable.

Store digester, challenge digester, password hasher and MFA protector use the same
configured `auth.pepper`, at least 32 bytes and within the configured digest cap.
No MFA key file or secret default is added. One physical password engine creates
its native dummy at startup; requests reuse that engine and one admission owner.
MFA uses its separate purpose/subject limiter with the sourced 4096 capacity.
`check-config` performs no password KDF, SQL operation or network request.
It validates trimmed issuer/presentation parameters with the checked native
TOTP SDK builder using only public placeholder DATA. It generates no OTP, URI,
QR, RNG output or authentication proof and consumes no real factor secret.
Actual account presentation remains validated by the SDK during the real flow.

Request JSON uses the server's positive body cap and administration request budget.
One Original cutoff covers decode, admission, HTTPS CAPTCHA, KDF, SQL, factor
completion, cookie issuance and response/header gates. A synchronous decode or
response-cap rejection checks Original before exporting its error; an expired
cutoff returns 504 rather than an earlier schema or encoding failure. Shutdown closes logical
admission, finishes or cancels request owners, joins actual SDK workers and only
then closes SQL. Partial startup and bind failure also drain the password owner.

## Options and credential input

GET/HEAD `/admin/api/v1/login-options` reports the exact public frame:
`{"oidc_providers":[],"local":true}`. It adds `captcha` only when the next password
attempt reaches the shared admission threshold. Observation reserves no work.
Options, CSP selection and password verification explicitly use `AdminLogin` on
the shared admission owner, so Turnstile continues to require `admin-login`.
Purpose-bound OAuth producers do not change this administrative action.
The provider list contains only implemented browser capabilities; F1 resource
access providers do not create browser buttons. The [native browser adapter](rust-admin-upstream-login.md) supplies configured browser choices from the same verifier; the empty list applies when no browser client is configured. Admin disabled leaves the routes unmounted 404. Admin enabled
with LOCAL disabled returns 503 `administration_unavailable` for both password
POST routes without KDF or CAPTCHA work.

POST `/admin/auth/local` accepts one JSON object with required string `username`
and protected `password`, plus optional string `captcha_token`. Unknown or
duplicate fields, wrong types/null and malformed JSON are rejected. Username
trim preserves case and its native 128-byte rules; passwords are never trimmed.
Invalid/empty/oversize initial credentials are denied before password work.
The password verifier produces genuine current SQL evidence, which is consumed
by value by `begin(..., AdminLogin, Original)`. Input cannot choose identity,
role, purpose, stage or binding. A password is never a bearer credential.

## Bound continuation and cookie

Pending responses are 200 with `status` equal to `password-change`, `mfa`, or
`mfa-enrollment`, and native `challenge_token`. Enrollment also returns actual
SDK `secret`, `otpauth_uri` and `qr_code_data_url`. Pending state emits no cookie
and grants no authentication. Keep these secret presentations out of logs, URLs,
arguments and stored diagnostic artifacts.

POST `/admin/auth/local/continue` accepts required string `challenge_token` and
exactly one nonempty `new_password` or `code`. Null, wrong type, duplicate/unknown
fields and ambiguous selections are rejected. New password creation requires
15 Unicode characters and at most 4096 bytes, preserves exact content and uses
shared guarded verification/hash work. It performs no CAPTCHA or initial-password
guess charge. Native SQL checks current challenge, human/revision/flags and
invalidates prior subject credentials/sessions before advancing the stage.

Code continuation uses actual TOTP/enrollment or a one-time native recovery code
and its separate limiter. A present MFA row is not verified-factor evidence.
Known completed AdminLogin is consumed synchronously into `PreparedAdminLogin`;
protected enrollment recovery codes are explicitly taken and held by the caller.
The cookie producer revalidates current SQL and `session.read` in its transaction.
Only known cookie COMMIT and final gates permit `Set-Cookie`.

Completion without new recovery codes is 204 with an empty body. Enrollment
completion is 200 `{"status":"complete","recovery_codes":[...]}` after confirmed
cookie issuance. Codes are presented once and never reloaded. Current cookie
read and CSRF/logout continue through the existing native routes and policy.

## Errors and recovery

Wrong credentials are 401 `local_login_failed`; invalid or consumed challenge,
wrong context and oversized factor code are 401 `local_login_step_failed`.
An actual false factor check or previously consumed recovery code keeps the
native 200 Pending(Mfa) challenge for another attempt. It creates no cookie or
authentication, deletes no other recovery code and follows the separate limiter.
This is the existing producer 1404 contract, not a completed-login response. Admission/lockout is 429 with rounded-up `Retry-After`.
Required CAPTCHA is 403 `captcha_required` with only public provider/site key/action.
Provider failures do not start a KDF or charge a password guess. Full tracked
capacity fails 503 `authentication_unavailable`. Storage errors are finite 500,
unavailable/uncertain COMMIT 503 and Original expiry 504. Responses are no-store,
carry a bounded request reference and never echo passwords, codes, provider
diagnostics or protected configuration.

Failures emit no cookie or partial recovery output. A failed or uncertain request
may already have consumed a challenge/recovery code or committed state: it is
not a rollback promise. Start a new login with current credentials; never replay
the mutation automatically or recreate already generated recovery codes.

## Source and executable verification

Source: `crates/broker-presence/src/admin_local_login.rs`, the shared response
helpers in `admin_session.rs`, and native server `config.rs`/`runtime.rs`.
The native executable/PostgreSQL TLS NOSUPERUSER contracts cover:
password→cookie→current session/CSRF/logout, genuine SDK TOTP enrollment and
one-time recovery, mandatory password replacement/current revision, disabled
routes, lockout/saturation/CAPTCHA denial, real SQL faults, bounded body/password/
username rejection, current service/unknown identity denial and a genuinely
issued challenge denied after its persisted UTC expiry. The bounded Original/cancel contract retains an actual TLS COMMIT ACK after SQL has committed and requires HTTP 503 without a cookie while SQL contains the new session.
The native check-config matrix covers sourced defaults and rejects SDK-invalid issuer/configuration before SQL/listener connections.

Run the same exact contracts with the project runner's portable Cargo commands:

```text
cargo test --locked --offline -p broker-server --test admin_local_login -- --ignored --exact broker_admin_local_login_http_contract --test-threads=1
cargo test --locked --offline -p broker-server --test admin_local_login -- --ignored --exact broker_admin_local_login_failure_contract --test-threads=1
cargo test --locked --offline -p broker-server --test admin_local_login -- --ignored --exact broker_admin_local_login_uncertainty_contract --test-threads=1
cargo test --locked --offline -p broker-server --test admin_local_login -- --ignored --exact broker_admin_local_login_configuration_contract --test-threads=1
```

These commands are selected in qualification after password/CAPTCHA producers and before
PROJECT/Presence/audit. The [shared runner guardrails](rust-sql-schema.md#active-development-guardrails)
check selector order and failure propagation. The native targets above verify
login behavior.
