---
type: document
title: SQLite LOCAL administrative HTTP login
status: implemented
description: Native LOCAL password and factor login through current SQLite administrative cookie session and confirmed logout.
references:
  - target: {type: task, id: tsk-ceed, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-8802, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# SQLite LOCAL administrative HTTP login

Broker integrators can compose the native administrative page, LOCAL password/factor login, current cookie session and confirmed logout over a private SQLite catalog. This explicit HTTP consumer is qualified on Linux under tsk-ceed. It consumes the qualified [SQLite LOCAL authentication](rust-sqlite-local-auth.md) and [LOCAL cookie lifecycle](rust-sqlite-admin-cookie-session.md).

These factories do not select the Server database backend. Final server configuration and dispatch remain separate work. PostgreSQL/OAuth runtime APIs and other authentication transports keep their existing entrypoints.

## Own the trusted runtime

SqliteLocalLoginRuntime::new takes six existing Arc owners, in order:

~~~text
Arc<LocalPasswordEngine>
Arc<LocalPasswordAdmission>
Arc<CredentialDigester>
Arc<LocalMfaProtector>
Arc<LocalAuthPolicy>
Arc<LocalMfaAttemptLimiter>
~~~

The runtime retains these owners across requests. It neither reconstructs the KDF engine nor clones cryptographic keys. The existing admission owner remains tied to the genuine engine and CAPTCHA configuration; invalid owner combinations fail through the underlying producer contract. Startup policy, authentication purpose and factor limits are supplied by trusted code.

Its passwords and authentication views call the real SQLite producers. An admitted password change consumes AdmittedLocalPasswordChange::complete_sqlite, retaining the existing engine lease and Original deadline. The same MFA limiter and policy serve every continuation. stop_admission closes new admission; close then joins the native password engine. Stop HTTP acceptance, drain/join owned requests, join the runtime and then close SQL using the existing lifecycle.

## Mount the existing routes

~~~text
sqlite_admin_local_login_router(
    store: Arc<SqliteControlStore>,
    config: AdminLocalLoginHttpConfig,
    local: Option<Arc<SqliteLocalLoginRuntime>>,
) -> Result<Router, ControlError>

sqlite_local_admin_session_router(
    store: Arc<SqliteControlStore>,
    config: AdminSessionHttpConfig,
    local_bearer: Option<AdminLocalBearerHttpConfig>,
    cookie: Option<AdminCookieHttpConfig>,
) -> Result<Router, ControlError>
~~~

The first factory preserves these existing paths:

| Method | Path | Result |
| --- | --- | --- |
| GET/HEAD | /admin and /admin/ | Existing administrative HTML and security headers |
| GET/HEAD | /admin/api/v1/login-options | Current LOCAL availability and CAPTCHA challenge; empty upstream provider list |
| POST | /admin/auth/local | Begin genuine LOCAL password authentication |
| POST | /admin/auth/local/continue | Consume a bound password-change or MFA challenge |

Some(runtime) requires valid cookie configuration and validates admission against the genuine store/engine. None is a real disabled state: login-options reports local:false and password/continue returns finite 503 administration_unavailable. No supplied runtime or upstream argument is silently ignored; the SQLite factory accepts no upstream owner.

For this password/factor cycle, configure the second factory with `None` for bearer and `Some(cookie)` for the genuine cookie consumer. It requires valid matching cookie/session limits and mounts GET/HEAD /admin/api/v1/session and POST /admin/auth/logout. The same router can explicitly enable [LOCAL opaque bearer admission](rust-sqlite-admin-local-bearer-session.md); a nonempty known cookie always takes precedence and any failure denies without fallback. These explicit factories add no upstream login, OAuth endpoint, administrative CRUD or resource authorization.

## Complete password and factor login

The shared strict JSON input admits username/password and optional captcha_token. Continuation admits challenge_token with exactly one nonempty new_password or code. Duplicate known fields, extra fields, null secret fields, malformed JSON and body overflow retain their existing finite errors. Clients never supply purpose, policy, cookie lifetime or role authority.

Every initial and continuation operation uses server-defined AdminLogin purpose/binding. Pending responses are 200 with status password-change, mfa or mfa-enrollment and a protected challenge token. Enrollment uses the existing secret, otpauth_uri and PNG data URL from the mature MFA producer. Secrets stay in bodies rather than URLs.

A completed genuine login retains one-time recovery codes while PreparedAdminLogin and the cookie producer validate current authority and commit. Completion without codes returns 204 with no response body. New recovery codes return 200 with status complete and recovery_codes exactly once. A wrong, foreign-purpose or replayed challenge cannot issue a cookie; a consumed recovery code returns the current pending MFA state without a new cookie or codes.

Only the genuine committed IssuedAdminCookie reaches the shared header serializer. It checks the protected result before and after serialization/header preparation. Set-Cookie retains HttpOnly, SameSite=Lax, Path=/, trusted explicit Secure, SDK absolute Expires and remaining Max-Age. Reading a session does not refresh expiry or emit another cookie.

## Read current identity and end the session

GET/HEAD /admin/api/v1/session consumes the canonical native cookie and the qualified SQLite current observer. Success returns the existing subject/name/email/username/organization/teams/roles/role_source/permissions/csrf_token wire, with current SQL profile and RBAC. Revision, enabled state, password-change state and current permissions are checked on each read. The protected observation remains alive through serialization, with gates before and after it. HEAD has no body.

POST /admin/auth/logout parses one CSRF header and calls the existing cookie producer. Active sessions require canonical constant-time CSRF; missing or wrong active CSRF returns 403 csrf_failed without deletion or clear-cookie. Valid expired or confirmed absent sessions do not require a valid CSRF value. Logout remains possible after role loss or disabled user state denies reads.

Only confirmed Revoked, Expired or Absent results and final Original checks permit 204 plus the shared empty cookie/Max-Age=0 header. An absent or malformed browser secret clears only the guest browser value, without claiming SQL revocation. Corrupt SQL metadata, closed store, deadline or uncertain COMMIT never clear the cookie. A repeated confirmed logout observes absence and can clear again.

## Errors, deadlines and cancellation

The shared handlers preserve no-store, Pragma:no-cache and request ID for both success and errors. Error bodies carry finite codes/messages and omit credentials, SQL, driver diagnostics and private paths.

| Condition | HTTP outcome |
| --- | --- |
| Invalid LOCAL credentials/challenge | 401 local_login_failed or local_login_step_failed |
| Invalid current cookie/binding or expired session | 401 admin_unauthorized |
| Missing current session.read | 403 admin_forbidden |
| Active logout CSRF rejected | 403 csrf_failed |
| Invalid JSON/schema or body size | Existing 400/413 invalid_request |
| Original deadline exhausted | 504 administration_unavailable |
| Closed store or uncertain commit | 503 administration_unavailable |
| Corrupt metadata or finite SQL failure | Existing 500 authorization_failed |

One Original end covers each handler's input/admission/KDF/SQL/serialization work; continuations are separate HTTP requests with their own captured end. No stage renews its current request's budget. No outer timeout wraps SQL, and no automatic replay is introduced. Cancellation and KDF/worker retention reuse the physical producer guarantees; dropping a peer does not prove that SQL rolled back.

## Sources and qualification

- crates/broker-presence/src/sqlite_local_login.rs
- crates/broker-presence/src/admin_local_login.rs, shared handlers with concrete PostgreSQL/SQLite backends
- crates/broker-presence/src/admin_session.rs, explicit LOCAL cookie backend
- crates/broker-presence/tests/sqlite_admin_local_http.rs

~~~text
cargo test --locked --offline -j4 -p broker-presence --test sqlite_admin_local_http -- --ignored --test-threads=1
cargo clippy --locked --offline -j4 -p broker-presence --lib --test sqlite_admin_local_http -- -D warnings
~~~

The native test is ignored in the common test run because it uses real Argon2 and MFA. Its maintained barrier extends the existing LOCAL phase. Cookie/session, HTTP and CAPTCHA have their own focused tests. Linux execution does not establish Windows/macOS support.
