---
title: Native Rust OAuth token revocation
references:
  - target: {type: task, id: tsk-b75d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5528, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-1564, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Rust OAuth token revocation

The native PostgreSQL server exposes `POST /oauth/revoke` when its
[OIDC section](rust-oidc-token-exchange.md) is enabled. This is an explicit
[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html) credential-disposal
operation using the same SQL owner and signing trust as code exchange and
[refresh rotation](rust-oidc-refresh.md). It does not add a network request or
blacklist to JWT authentication.

## Dispose of an issued credential

Discover `revocation_endpoint` and its public-client authentication method
`none` through [native discovery](rust-oidc-discovery.md). Send a form with
the actual current client ID and the raw access or refresh token:

```text
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded

client_id=<actual-client-id>&token=<URL-encoded-raw-token>&token_type_hint=refresh_token
```

Both configured CLI and currently registered public clients use `none`.
Basic credentials or a body client secret cannot authenticate these clients.
A family ID, JTI, SQL row ID or credential digest is not a replacement for
the raw token. `token_type_hint` is optional and advisory: a wrong or unknown
hint cannot change which credential is recognized. Unknown form extensions
are ignored. Known scalar duplicates and protocol fields in the query are
rejected.

After recognizing the current client, success and invalid, unknown, expired,
already revoked or other-client tokens return the same empty HTTP 200
response. A response never echoes the token or reveals whether a matching
grant existed. A consumed but still-future refresh can dispose of its
descendants. An identity becoming disabled or changing revision does not
prevent ending its old grant, and federation disposal needs no upstream
network/profile request.

## Understand the SQL effect

| Credential | Confirmed SQL effect |
|---|---|
| Raw refresh | Mark its entire bound family revoked, including stored access rows and all refresh generations. Further refresh is denied. |
| Raw access JWT | Mark only its matching stored access row revoked. Its refresh remains usable. |

Already issued JWTs remain locally authenticatable until `exp`, including
after their SQL row is revoked. Resource authorization independently uses
current SQL grants for each consequential operation. Revocation does not
alter access/refresh lifetimes or invalidate a JWT through an implicit
UserInfo/introspection call. [Explicit UserInfo](rust-oidc-userinfo.md) checks SQL for profile retrieval; [explicit introspection](rust-oidc-introspection.md) checks the caller's access grants with Bearer authorization. Neither is a request-path gate for local JWT verification.

Access disposal verifies the actual signature, issuer, API audience, expiry
and access-token shape. Only its verified JTI derives the domain-11 ledger
digest. Only the canonical native JTI format can match this ledger; other
verified JTIs remain unknown, including values above a configured digest cap.
The update binds client, stable OIDC subject and the exact expiry converted
from JWT seconds to SQL microseconds; an unrepresentable expiry cannot match. The
operation can dispose of this issuer's access token for another resource.
This does not relax `auth.resource` in the public API verifier.
Refresh possession derives the existing domain-5 digest; no raw credential
is stored.

## Atomicity, concurrency and recovery

Refresh disposal follows the same order as rotation: bounded initial row,
shared pair barrier first, then the LOCAL user lock when present or existing
federated family advisory lock,
current client, locked token reread, immutable bindings, family update and
known COMMIT. This serializes ancestor disposal with descendant insertion.
The managed identity lifecycle removes LOCAL grants before deleting the
user; absence of that user still requires a token reread. Restoring orphan
records through external SQL is outside this lifecycle contract.

A failure before COMMIT rolls back. An issued COMMIT with an ambiguous
acknowledgement returns HTTP 503, even when SQL later proves the revocation
durable; the server does not report rollback, manufacture HTTP 200 or retry
the operation automatically. Recover through a fresh genuine authorization
when the credential state is uncertain.

## Configuration and errors

The route shares the existing OIDC `request_timeout`, `body_bytes`,
`parameter_bytes` and declared CORS policy. It introduces no new setting,
quota, signing key, pool or default. Disabled OIDC leaves the route unmounted
(404) and publishes no revocation metadata. Successful and failed mounted
responses use `Cache-Control: no-store` and `Pragma: no-cache`.

| Status | Meaning |
|---|---|
| 200 | Disposal accepted, including a token invalid for this recognized client. Empty body. |
| 400 `invalid_request` | Missing/malformed required input, duplicate scalar, invalid transport or conflicting/unsupported assertion authentication. |
| 401 `invalid_client` | Unknown current client or credentials that cannot authenticate the public client. |
| 504 `temporarily_unavailable` | Original deadline elapsed before a COMMIT was issued. |
| 503 `temporarily_unavailable` | Closed store or uncertain COMMIT outcome. |
| 500 `server_error` | Corrupt stored metadata or storage/credential failure. |

## Implementation and focused verification

Control owns `service/oidc_revocation.rs`; Presence owns the HTTP route and
shared mature form transport; the server mounts it alongside token exchange
and advertises the productive endpoint. The verifier retains JTI privately
rather than treating decoded metadata as authority.

The affected checks are executable without a new test framework:

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_oidc_revocation -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-control --test postgres_oidc_federated -- --ignored --exact postgres_oidc_federated_revocation_contract --test-threads=1
cargo test --locked --offline -j4 -p broker-server --test oauth_revocation -- --ignored --test-threads=1
```

These tests use genuine LOCAL/H1 grants, actual PostgreSQL TLS under NOSUPERUSER, native HTTP processes, observed SQL locks, rollback/cancellation/deadlines and a durable COMMIT whose TLS acknowledgement is withheld. They also retain local JWT validity after revocation. The explicit `make qualify` suite runs these focused commands. The [native CI/container workflow](deployment.md) consumes the maintained Rust gate. A library or one operating-system result does not establish complete Broker integration.

[End-session](rust-oidc-end-session.md) instead requires a signed ID hint and
disposes all SQL OIDC families of that subject/client, including after DCR removal.
This does not change the raw-token/current-client contract of this endpoint.

## Explicit SQLite composition

The additive `sqlite_oidc_revocation_router` and borrowed
`SqliteControlStore::oidc_revocation` implement raw-token disposal for a current
public SQLite client: access-row-only or refresh-family revocation, including a
still-future consumed ancestor. Current LOCAL/trust is not disposal authority.
See [SQLite OIDC inspection and disposal](rust-sqlite-oidc-lifecycle.md) for the
retained Arc pair, IMMEDIATE/known-ACK boundary.
PostgreSQL signatures, wire and historical qualification remain unchanged.
