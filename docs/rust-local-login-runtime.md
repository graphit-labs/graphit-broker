---
title: Shared native LOCAL login runtime
doc_type: reference
description: One configured password, CAPTCHA, MFA and admission owner for Admin and OAuth consumers.
references:
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-10ef, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Shared native LOCAL login runtime

The native server prepares one `LocalLoginRuntime` from `auth.local`.
It holds the existing password engine, password admission/CAPTCHA owner,
credential digester, MFA protector/policy and MFA attempt limiter.
The [Admin HTTP consumer](rust-admin-local-login.md) and genuine
[LOCAL OAuth completion](rust-oidc-authorization.md) borrow these owners;
creating a purpose-specific view creates no independent capacity or failure map.
The runtime itself mounts no HTTP route. The
[public OAuth transport](rust-oidc-browser-authorization.md) composes these owners and
request-owned recovery presentation. Discovery remains a separate delivery.

## Configuration and consumers

An absent or disabled `auth.local.login.enabled` leaves the runtime absent.
When enabled, at least one existing consumer must be configured:

| Native OIDC server | Active Admin with native cookie | LOCAL preparation |
|---|---|---|
| enabled | either | accepted |
| disabled | yes | accepted |
| disabled | no | rejected before engine, SQL or serving |

Here native OIDC means the root `oidc.enabled` setting. Upstream providers in
`auth.oidc` alone are not a LOCAL consumer. An absent or disabled Admin section,
or active Admin without its native cookie, does not prevent LOCAL+OIDC startup.
Admin without a cookie receives no LOCAL runtime in its router: options report
`local: false` and its credential POST routes return the existing finite `503`.
Disabled/absent Admin leaves those routes unmounted `404`. The global configuration
still reports the true LOCAL setting; it does not imply Admin-cookie availability.

The existing digest bounds must represent generated values. LOCAL challenges
require `auth.digest.token_bytes >= 43`. With LOCAL and native OIDC enabled,
`binding_bytes >=43` must also represent the literal pending request secret.
These are the producer's 32-byte Base64url values. The [upstream callback](rust-oidc-browser-callback.md)
uses a 49-character prefixed state and a 43-character binding; its existing checks
remain separate. No quota, key, schema or default is added.

`--check-config` validates this matrix and all existing CAPTCHA/TOTP/digest
settings without creating the engine or contacting SQL/listening on HTTP.

## Borrowed APIs and authority

Presence owns `src/local_login.rs`. Trusted startup supplies its six existing
owners to `LocalLoginRuntime::new`; fields stay private and Debug is redacted.
Consumers call:

- `passwords(store, purpose)` to borrow the genuine password admission view,
  explicitly choosing `AdminLogin` or `OauthAuthorize`;
- `authentication(store)` to borrow the existing bound challenge service;
- `admit_password_change(original)` to reserve the same existing work capacity;
- `limiter()` and `policy()` to borrow the same factor limiter and policy;
- `challenge(purpose)` and `next_password_challenge(purpose)` for public
  CAPTCHA DATA, without reserving work or authenticating a request.

[Admission semantics](rust-local-password-admission.md) remain shared across
purposes: capacity, username failures and lockout are not copied. Turnstile's
Admin/OAuth actions remain purpose-specific. Factories do not expose keys, build
proofs from DTOs, renew a deadline or change SQL transaction behavior.

After genuine password verification, the [LOCAL service](rust-local-auth.md)
consumes that proof with the consumer's protected binding. Admin retains its
existing bound password-change/MFA/enrollment/recovery and cookie journey.
OAuth binds to the exact pending request, then prepares `PreparedOidcLogin`
and completes the authorization through the existing current-SQL/known-COMMIT
producer. An Admin completion or a different request binding cannot authorize
that pending request. Retained recovery codes still prevent preparation; runtime
sharing does not prove browser presentation of those codes.

## Shutdown and failures

`stop_admission` closes the one logical owner for both consumers. `close`
then joins its existing SDK password workers before SQL shutdown. The native
server preserves the same ordering on partial startup, bind failure and normal
shutdown. No transport-specific second engine or independent limiter is created.
Original deadlines, persisted UTC, finite errors and uncertain-commit behavior
remain the existing producers' contracts.

## Focused validation

The new real contracts cover 20 native check-config cases with SQL/HTTP listener
sentinels, and shared-runtime Admin-cookie/OAuth-code consumers on PostgreSQL TLS
with a NOSUPERUSER application account. OAuth codes are exchanged and refreshed
through the native executable under Admin absent, disabled and active-without-cookie
configurations. Wrong binding leaves the request usable for a genuine fresh
completion; both views share saturation, username lockout and admission closure.
No helper bypasses the runtime to fabricate its completed login.

Run the saved phase and affected Admin regression unchanged on each platform:

```text
cargo test --locked --offline -j4 -p broker-server --test local_login_runtime -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-server --test admin_local_login -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p xtask --test guardrails local_login_runtime -- --test-threads=1
```

The recurring pre-push runner includes the new phase; its failure oracle runs
both failing Rust contracts and requires later phases to remain blocked.
Fast gates remain pre-commit. Whole-system integration and other platforms are
coordinated separately; no gate authorizes push.
