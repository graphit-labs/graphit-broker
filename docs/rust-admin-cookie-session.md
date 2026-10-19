---
title: Native LOCAL administrative cookies
doc_type: reference
references:
  - target: {type: task, id: tsk-9569, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-d03f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-32a8, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# Native LOCAL administrative cookies

The [SQLite administrative ingress](rust-sqlite-admin-session.md) adds the common `SqliteAdminCookieSessions` facade with genuine LOCAL and upstream issuance, current cookie read and own logout. The original LOCAL-only factory remains available. Its explicit Presence session router applies the existing cookie precedence and CSRF logout contract; bearer credentials do not rescue an invalid cookie. Global Server backend selection remains separate.

The native PostgreSQL Broker composes a genuine [completed LOCAL login](rust-local-auth.md)
with current SQL authorization to issue an administrative cookie. This server unit
provides the private producer, current GET/HEAD session read and confirmed logout.
[Native HTTP password/MFA begin/continue](rust-admin-local-login.md) now consumes this producer
with genuine challenge and factor proofs. The [native administrative reads](rust-admin-read.md)
use the same genuine cookie with each endpoint's current SQL action. The
[native upstream browser adapter](rust-admin-upstream-login.md) composes federated
HTTP issuance and the existing HTML consumers. Administrative writers remain separate.
Session metadata or profile JSON cannot issue a cookie.

## Enable cookie admission

Use the [native server configuration](rust-broker-server.md), then replace its
administration section with the following. Byte/count bounds and request timeout
are illustrative operator choices; all cookie bounds are required when enabled.

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
  session_ttl: 8h
  cookie_secure: true
  cookie:
    enabled: true
    text_bytes: 2048
    csrf_bytes: 43
    team_bytes: 512
    max_teams: 16
    teams_json_bytes: 8192
    roles_json_bytes: 8192
```

Absent/false `administration.cookie.enabled` retains the configured Bearer dispatcher
and does not mount cookie logout. Missing/false administration leaves all Admin routes
unmounted. `session_ttl` defaults to 8 hours and accepts 5 minutes through 168 hours;
`cookie_secure` defaults to true. Explicit false is allowed only for a loopback HTTP
`server.public_url`. The configured digest token cap must accept the native 43-byte
secret; the CSRF cap must be at least 43. Invalid enabled configuration fails before
SQL, sockets or storage effects. Stored lifetime validation always uses the maximum
168 hours, so lowering the issuance TTL does not invalidate previously issued cookies.

## Consume a genuine login

The trusted LOCAL consumer first takes any protected one-time recovery codes from
`CompletedLocalLogin`, retaining them until issuance is confirmed. Synchronous
`PreparedAdminLogin::try_from` accepts only AdminLogin purpose; wrong purpose or
pending recovery codes returns the entire protected login through `into_login`.
These owners have no clone, default, deserialization or public field constructors.

`PostgresControlStore::admin_cookie_sessions(limits, policy, None).issue_local(prepared,
local_auth_policy, original)` verifies the owner's domain-13 purpose binding, a
nonfuture completion timestamp and the genuine factor when required. In one transaction
it locks the current human user, checks enabled state, raw subject, username, revision
and cleared password-change flag, then observes current profile, role assignments and
definitions in one bounded SQL statement. Implicit `user` and canonical
`local|<raw-subject>` assignments apply. `session.read` or `*` is mandatory.

The same transaction inserts the parent/principal metadata. Cookie and CSRF use two
independent fallible 256-bit OS CSPRNG draws encoded by the mature base64url SDK;
raw cookie never enters SQL. SQL stores its domain-1 credential digest and recoverable
protected CSRF metadata. LOCAL has no persisted claimed roles. Only known COMMIT and
final Original/UTC/monotonic gates return `IssuedAdminCookie`; uncertain COMMIT returns
no cookie or replay instruction. A late known COMMIT cannot export a credential. Absolute expiry must also fit the
resolved HTTP-date SDK range (epoch through the end of year 9999); invalid clock
range returns finite Clock error before issuance SQL instead of panicking during
header conversion.

`broker_presence::admin_cookie_header(&issued, secure)` accepts only this private proof
and checks it before and after serialization. It emits `graphit_admin_session` with
Path=/, HttpOnly, SameSite=Lax, configured Secure, absolute SDK HTTP-date Expires and
remaining Max-Age. Max-Age never extends the stored expiry. Header diagnostics are
sensitive. Lower-level consumers must supply trusted startup policy and transport;
request fields never choose lifetime, MFA policy, issuer or permissions.

## Read the current session

Send the known cookie to GET or HEAD `/admin/api/v1/session` on the same listener/store.
The mature Cookie parser rejects multiple Cookie headers and duplicated known names.
A nonempty known cookie owns admission and never falls back to any Bearer transport.
Absent, empty or literal `""` permits the existing [JWT](rust-admin-session-http.md),
[opaque](rust-admin-local-bearer-session.md) and [federated access](rust-admin-upstream-session.md)
dispatcher. Only canonical native 43-byte secrets reach digest/SQL lookup.

Read locks the LOCAL user before the session parent, matching password-change lock
order, and rechecks its binding after the parent lock. Joined metadata is capped and
canonical; corruption is preserved and denied. Current human/enabled/revision/password
state and current SQL role definitions/assignments authorize each read. [Federated cookie reads](rust-admin-federated-cookie.md) use the same factory
with the current common upstream owner and its closed identity branch. Their
producer consumes a genuine upstream Admin login; browser HTTP wiring remains
a separate delivery.

Success uses the existing session wire with current profile, roles, permissions,
`role_source: database` for LOCAL and stored `csrf_token`. Federated cookies
project `claims` for an active matching role selector or `database` for current
assignments. GET/HEAD need no CSRF request header.
Responses use no-store, Pragma and request ID; HEAD has no body. Reading never emits
Set-Cookie or renews expiry. Its private `AdminCookieReadSession` remains alive through
SQL and serialization, holds one captured UTC/monotonic expiry and Original, and is
only a session.read observation, never a permission lease for a later write.

## Log out

POST `/admin/auth/logout` needs no administrative role or session.read permission.
An active matching cookie requires exactly one canonical `X-CSRF-Token`. The same
transaction locks the parent and compares decoded CSRF bytes in constant time before
DELETE/cascade. Identity or role changes that deny GET do not prevent valid own logout.
Federated logout likewise requires no current issuer trust or session.read gate.
Wrong/missing/duplicate CSRF returns 403 `csrf_failed` without delete or Set-Cookie.
Corrupt metadata returns 500 and remains stored.

Known COMMIT yields Revoked, Absent or Expired and then 204 with the same cookie
attributes, empty value, Unix-second-one Expires and Max-Age=0. Absent/empty browser
cookie or malformed native format can clear only the guest browser value, without
claiming SQL revocation. A canonical unknown token needs confirmed SQL absence;
expired matching metadata needs confirmed cleanup. Bearer-only logout does not revoke
JWT or opaque credentials. No new Origin/Referer allowlist or credentialed Admin CORS
is introduced; fixed CSRF, Lax and the existing separate OP CORS remain the contract.

## Failure and verification

401 `admin_unauthorized` covers invalid/expired cookie and invalid current LOCAL binding;
403 `admin_forbidden` covers missing current session.read. Corruption/storage yields
500 `authorization_failed`; closed/uncertain/entropy yields 503
`administration_unavailable`; Original exhaustion yields 504 with that code.
Uncertain COMMIT stays 503 even after another cutoff passes, never proves rollback,
and never clears or emits the cookie. Errors contain static messages and request ID,
without raw credentials, CSRF, driver text or SQL.

The proportional real fixtures run with native Argon2/LOCAL/MFA, PostgreSQL TLS,
NOSUPERUSER ownership and the actual Rust server executable:

```text
cargo test --locked -p broker-control --test postgres_admin_cookie postgres_admin_cookie_contract -- --ignored --exact --nocapture
cargo test --locked -p broker-server --test admin_cookie broker_admin_cookie_http_contract -- --ignored --exact --nocapture
```

Source ownership: `broker-control` private cookie proofs/service and shared metadata/current
LOCAL SQL observer; `broker-presence` Cookie admission/header/logout; `broker-server`
configuration/runtime. The affected existing SQL metadata and Bearer dispatcher suites
also qualify their extraction/composition changes. This unit does not establish full
Admin or Broker migration completion.
