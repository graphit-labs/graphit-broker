---
title: Read the native Rust administrative session
doc_type: operations
references:
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-b7a4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-cd2c, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Read the native Rust administrative session

The explicit [SQLite session adapter](rust-sqlite-admin-session.md) serves this same GET/HEAD contract through `sqlite_admin_session_router_with_cookie`. It composes native Broker access JWT, optional opaque LOCAL credentials, configured upstream resource bearer and optional LOCAL/federated cookie. The router uses current SQLite authority through its producers; it does not select a backend in Server. Cookie precedence, no fallback, response projection and errors remain the shared transport contract.

The PostgreSQL [native executable](rust-broker-server.md) can enable
`GET /admin/api/v1/session` and its equivalent `HEAD`. This first administrative
transport accepts a native Broker **access JWT for a current LOCAL identity**.
Use an access token actually issued by [native code exchange](rust-oidc-token-exchange.md)
or [refresh rotation](rust-oidc-refresh.md). ID tokens and principal/profile JSON
cannot authenticate. It does not require a new session row or a call to UserInfo.

An optional [LOCAL opaque access/service transport](rust-admin-local-bearer-session.md)
can serve this same endpoint with its own explicit audience and required scopes.
The JWT authentication and binding rules below continue to apply to JWT requests.

## Enable the route

Append this section to the native YAML. These bounds and timeout are illustrative
operator choices, not defaults. Every field is required when `enabled: true`.
An absent section or `enabled: false` does not install the route.

```yaml
administration:
  enabled: true
  request_timeout: 3s
  username_bytes: 128
  subject_bytes: 512
  role_bytes: 128
  roles: 16
  rows: 128
  profile_json_bytes: 8192
  grants_json_bytes: 65536
  response_json_bytes: 65536
```

The existing `auth` issuer, API audience, optional resource, key ID and configured
verification key apply. The same verifier, digester, PostgreSQL pool and listener
are shared with the runtime. Enabling this route does not require enabling the
token HTTP endpoint if the native issuer has already supplied the access token.
`--check-config` validates explicit bounds, SQL row sentinel and allocation
representability before opening SQL, volumes or sockets. Unknown/duplicate fields,
zero or unrepresentable limits and missing enabled fields fail configuration.

## Read the current session

Send one `Authorization: Bearer <native-access-JWT>` header over the configured
transport. An optional `X-Request-ID` is trimmed and retained if nonempty and at
most 128 bytes; otherwise the server generates an opaque CSPRNG correlation ID.

```text
GET /admin/api/v1/session
Authorization: Bearer <native-access-JWT>
X-Request-ID: admin-session-read
```

Success returns JSON with `subject`, `username`, `name`, `email`, `organization`,
`teams`, `roles`, `role_source`, `permissions` and `csrf_token`. `subject` is the
current raw LOCAL subject. Profile fields come from current SQL, not stale JWT
profile claims. Teams are trimmed, deduplicated and sorted. Roles and permissions
are current, unique and sorted; `role_source` is `database`, and `csrf_token` is
empty for this Bearer transport. `HEAD` has the same status and response headers
with no body. Responses carry `X-Request-ID`, `Cache-Control: no-store` and
`Pragma: no-cache`; this endpoint does not set a cookie or create a session.

The signed `preferred_username` is only a SQL locator. The store must match the
JWT's pseudonymous `sub` against its existing domain-15 derivation of
`local` and the user's current raw subject. Missing username, missing/disabled
LOCAL user or a different subject denies administrative admission. Human and
service LOCAL kinds are understood; no new kind restriction is introduced here.
Revision is checked for SQL integrity, not compared to an absent JWT mint revision.
Password-change state is not an additional check on an already authentic JWT.

Administrative access requires `session.read` or `*` from current SQL role
definitions and assignments under `local|<raw-subject>`, including implicit `user`.
JWT role/permission claims and bare raw-subject assignments confer no Admin or
PROJECT permission. A single bounded read-only SELECT observes profile, identity,
assignments and role definitions together. Profile JSON, row and role bounds
fail closed rather than truncate successful data.

## Authentication and failure boundaries

JWT verification remains local until its actual expiry. Current SQL authorizes
this operation and its LOCAL binding; it does not prove token validity through
an access ledger, refresh family or blacklist. Revoking an opaque refresh family
does not invalidate an already signed JWT before Exp. Administrative permission
and identity changes still affect the next session read. The producer's UTC and
monotonic authentication expiry pair is preserved. SQL acquisition, streaming,
COMMIT and final serialization also obey the captured request deadline, without
renewal or a new session lifetime. The SQL wait also uses the original authentication
monotonic expiry. Negative/error results receive the same final gates: an expired
authentication cannot become a late 403. Actual COMMIT uncertainty retains its 503
classification when another cutoff also passes.

A nonempty `graphit_admin_session` cookie takes precedence over Bearer. The explicit [native Cookie transport](rust-admin-cookie-session.md) can authenticate a
genuine LOCAL session or a [federated cookie](rust-admin-federated-cookie.md)
under its current common issuer/selector policy; without that transport a nonempty known cookie is rejected
with 401. The server never retries it as Bearer. An empty known
cookie permits Bearer. Duplicate known cookies or multiple Cookie headers are
rejected; other cookies do not supply authority. GET/HEAD require no CSRF token.

Errors use `{"error":{"code":"...","message":"..."},"request_id":"..."}`
with static messages. Authorization/Cookie headers are sensitive, raw bearer
storage is zeroizing, and errors do not echo credentials, SQL or principal data.

| Status | Code | Condition |
| --- | --- | --- |
| 401 | `admin_unauthorized` | Missing/invalid/expired access JWT, ID token, invalid trust/claims or unsupported cookie admission |
| 403 | `admin_forbidden` | Authentic JWT with no current LOCAL binding or current `session.read`/`*` permission |
| 504 | `administration_unavailable` | Original request/SQL deadline exhausted |
| 503 | `administration_unavailable` | Closed store, uncertain COMMIT or unavailable correlation-ID entropy |
| 500 | `authorization_failed` | Corrupt/oversized identity/profile/RBAC or storage failure |

An uncertain COMMIT never proves rollback or permits an automatic retry of a
mutation. This route reads only and returns success after a known COMMIT.

## Remaining administrative delivery

[Session metadata persistence](rust-admin-sessions.md) remains data-only. The [genuine LOCAL cookie producer, current session read and confirmed CSRF/logout](rust-admin-cookie-session.md) compose this metadata with current SQL. [Native HTTP LOCAL login with MFA/recovery](rust-admin-local-login.md) now consumes genuine
password/challenge/factor proofs. Other cookie mutations,
federated browser HTTP, config read, users/roles/grants/reset/CAS/last-admin,
and the administrative UI/setup journeys remain required separate deliveries.
This session endpoint does not establish full Admin or Broker migration parity.

Native JWT verification uses real TLS PostgreSQL with a NOSUPERUSER owner, genuine
LOCAL/P2b/P3 credentials, the actual native executable and its configured key.
The project runner includes the PostgreSQL `postgres_admin_broker_session` target
and the exact `broker_admin_session_http_contract` phase before audit.

For external resource JWTs, configure the [common native `auth.oidc` provider set](rust-admin-upstream-session.md). Its verified profile uses `issuer|subject` for current SQL roles, or authoritative signed claim roles when configured, and shares the same cookie priority, GET/HEAD response and request deadline.
