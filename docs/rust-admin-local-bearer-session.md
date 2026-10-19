---
title: Read the native administrative session with LOCAL opaque credentials
doc_type: operations
references:
  - target: {type: task, id: tsk-fea7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-064d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# Read the native administrative session with LOCAL opaque credentials

Operators and API consumers can explicitly enable LOCAL access and service
credentials on the PostgreSQL [native Broker](rust-broker-server.md) session
endpoint. This transport uses the [raw-bearer verifier](rust-local-bearer-verifier.md)
and current SQL administrative permissions. It serves the same `GET` and `HEAD`
`/admin/api/v1/session` as the [native access JWT](rust-admin-session-http.md).

## Enable and read

Use this administration section in the native YAML. The audience, scopes, timeout
and limits are illustrative operator choices, not defaults. Every common field
is required for administration; every local field is required when its own
`enabled` is true. An explicit empty scope list requires no additional scope,
but still requires current SQL `session.read` or `*`.

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
  local_bearer:
    enabled: true
    audience: explicit-admin-api
    identity_json_bytes: 8192
    required_scopes: [admin:session]
```

Absent or disabled `local_bearer` preserves the JWT transport. Absent or disabled
administration leaves the entire route unmounted. The native config rejects
unknown/duplicate fields, missing enabled fields, blank audiences, invalid scope
entries and zero or unrepresentable limits before SQL, volumes or listener startup.
The opaque audience is independent of the native JWT audience and is never inferred
from a request. `--check-config` validates this same configuration.

Send one Bearer header using an existing valid credential over your configured
transport. The exact `gb_at_` and `gb_sc_` prefixes select the LOCAL SQL authority
only when enabled. Failure does not try JWT or federation. Other envelopes use
the existing JWT verifier; refresh credentials do not authenticate.

```text
GET /admin/api/v1/session
Authorization: Bearer <LOCAL-access-or-service-credential>
X-Request-ID: opaque-session-read
```

Success is the existing session JSON: current raw `subject`, `username`, `name`,
`email`, `organization`, normalized `teams`, ordered unique `roles` and
`permissions`, `role_source: database`, and empty `csrf_token`. `HEAD` returns the
same status and headers without a body. Responses carry `Cache-Control: no-store`,
`Pragma: no-cache` and the correlation `X-Request-ID`. No cookie or session row
is created by this read.

## Current identity and permission

Actual raw possession is verified against the configured HMAC domain and current
SQL credential, audience, exact required scopes, expiry and revocation. Human
access and service credentials both work. Old stored principal/profile/roles
cannot supply administrative authority. The consumer retains the genuine private
authentication value and obtains current profile and roles together in one bounded
read-only SQL statement. It checks current username, raw subject, revision,
kind and enabled state against that observation.

Every authenticated identity receives the implicit SQL `user` role. Additional
assignments use `local|<raw-subject>`, not a bare subject or username. Current SQL
role definitions must grant `session.read` or `*`. Scopes are an authentication
condition and do not grant administrative permissions. Removing and restoring a
permission changes the next request with the same credential.

The original request deadline and authentication UTC/monotonic expiry are retained
through SQL waits and serialization. There is no expiry renewal or authorization
lease for CRUD or a later request. LOCAL access/service verification writes no
usage metadata. Success follows a known read-only COMMIT. Actual COMMIT
uncertainty retains its unavailable classification even when a cutoff also passes.

## Failure and recovery

A nonempty known `graphit_admin_session` cookie selects the current native
[LOCAL cookie](rust-admin-cookie-session.md) or
[federated cookie](rust-admin-federated-cookie.md) verifier and never retries
Bearer after failure. An empty known cookie permits Bearer; duplicate known
cookies or multiple Cookie headers reject admission. GET/HEAD require no CSRF
token. The same enabled LOCAL opaque transport also serves the
[seven administrative data reads](rust-admin-read.md), each with its own current
SQL action. Federated browser HTTP callbacks, administrative writes and Web
administration remain separate deliveries.

| Status | Code | Meaning and next action |
| --- | --- | --- |
| 401 | `admin_unauthorized` | Missing/invalid/revoked/expired credential, audience/scope/current-identity failure or unsupported cookie; obtain valid authentication for this audience. |
| 403 | `admin_forbidden` | Authentic credential lacks current SQL `session.read`/`*`; an authorized administrator must change the role policy. |
| 504 | `administration_unavailable` | Original request or SQL operation deadline passed; diagnose the bounded operation before retrying the read. |
| 503 | `administration_unavailable` | Store closed, actual COMMIT uncertain or correlation entropy unavailable; no successful admission or rollback is established. |
| 500 | `authorization_failed` | Corrupt/oversized stored identity/profile/RBAC or storage failure; inspect server/database health without collecting credentials. |

The existing JWT path preserves its own current LOCAL binding rules, including
403 for unavailable binding, and validity until signed Exp without a token ledger
blacklist. Opaque revocation does not revoke an already valid native JWT.

## Implementation and verification

`broker-control` owns `AdminLocalBearerSession` and its raw consumer in
`src/service/admin_local_bearer_session.rs`. Its private actual-proof input shares
the current profile/roles statement in `src/service/admin_broker_session.rs`
with the JWT consumer. `broker-presence/src/admin_session.rs` owns dispatch and
response projection; `broker-server` owns strict configuration and the shared mount.
No additional SQL schema, signing key or dependency is introduced.

Affected real contract targets are
`postgres_admin_local_bearer_session_contract` in
`crates/broker-control/tests/postgres_admin_local_bearer_session.rs` and
`broker_admin_local_bearer_http_contract` in
`crates/broker-server/tests/admin_session.rs`, plus the changed JWT consumers.
These use actual TLS PostgreSQL with a NOSUPERUSER owner, real HMAC verification,
SQL policy changes and the native executable; metadata does not fake a proof.
This endpoint does not establish
complete Admin, Broker or migration parity.

The explicit [SQLite administrative session integration](rust-sqlite-admin-local-bearer-session.md)
uses the same protected result and wire through the existing session router.
This SQLite slice serves session reads; other administrative data reads and
Native Server backend selection remain separate integrations.
