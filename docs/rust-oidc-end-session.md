---
title: Native Broker RP-initiated end-session
doc_type: reference
description: Signed ID-hint disposal of all SQL OIDC grants for one subject and client, without redirects.
references:
  - target: {type: task, id: tsk-b75d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5528, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native Broker end-session

For relying parties and operators of the native PostgreSQL server. With OIDC
enabled, discovery advertises `end_session_endpoint` at `/oauth/end-session`.
The native server and explicit Web process fixture mount the same productive
route. OIDC disabled leaves the endpoint and its metadata absent.

## Request and result

Send the Broker-issued ID token returned by genuine code exchange or refresh
as `id_token_hint`. A GET supplies query parameters and an empty body; a POST
supplies `application/x-www-form-urlencoded` and no recognized query fields.
For example, this schematic POST body uses placeholders, not live credentials:

```text
id_token_hint=<percent-encoded-signed-ID-token>&client_id=<its-client-id>
```

The hint is required. An optional `client_id` must match its signed client
literally. The signature, trusted key ID, issuer, API/client audiences, ID-token
shape, hashes, AMR and temporal ordering are checked locally. Expired ID hints
remain acceptable exclusively for disposal. The ordinary access verifier keeps
requiring an unexpired access JWT and never accepts an ID hint as authentication.
The mature JWT verifier keeps `exp` mandatory and typed while disabling only its
elapsed-time check in the private hint path; see [Validation](https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html#structfield.validate_exp).

A successful request returns **204 with an empty body**, including when no grants
remain. It atomically sets the revocation timestamp on every unrevoked stored
OIDC access/refresh grant for the signed subject/client and configured API
audience, across its families and resources. It preserves other pairs and
already recorded revocation timestamps. Repeating the request is idempotent.

An ID hint from a client whose DCR row was removed can still dispose its signed
pair. Current LOCAL enabled/revision state, upstream trust/profile and network
availability are not disposal authority. A bounded stored principal is decoded
with the same strict OIDC codec used by issuance, solely to validate its identity
binding and acquire the optional LOCAL user lock.

Bearer, Basic and administrative cookies cannot replace the hint or enlarge its
pair. Administrative sessions and the relying party's own browser session have
separate lifecycles. The server performs no upstream logout or redirect.

## Transport, limits and errors

The route rejects any presence of `post_logout_redirect_uri`, even an empty
value. `state`, `ui_locales` and `logout_hint` are recognized bounded extensions
with no redirect or authority effect. Repeated recognized fields, ambiguous
query/form transport, invalid UTF-8, missing/empty/bad hints, conflicting clients
and invalid media types return 400 `invalid_request`. Unknown fields follow the
existing OAuth form parser's ignored-extension behavior.

The existing OIDC `parameter_bytes` bounds the raw query before decoding and
the sum of recognized decoded values. Existing `body_bytes` bounds the received
body; the configured verifier's token cap applies independently. There is no
new lifetime, cap default or automatic enlargement. Keep hints and complete
request URLs out of logs and public receipts.

| Condition | Response |
|---|---|
| Valid hint and known successful COMMIT, including no matching rows | 204, empty |
| Invalid request or ID hint | 400 `invalid_request` |
| Stored corruption, read cap, SQL permission/storage or clock failure | 500 `server_error` |
| Original deadline before COMMIT starts | 504 `temporarily_unavailable` |
| Closed store or unknown COMMIT result | 503 `temporarily_unavailable` |
| Other methods | 405; `Allow: GET, POST` |

Mounted responses carry `Cache-Control: no-store` and `Pragma: no-cache`,
including method errors. Configured common CORS origins apply without
credentials; their ordinary OPTIONS preflight is handled by that layer.
Errors expose no token, SQL or credential. An unknown COMMIT result never
becomes 204, even when another connection can already observe durable disposal.

## Concurrent issuance and disposal

Code exchange, refresh/reuse and explicit refresh disposal hold the shared
transaction pair barrier described in [refresh coordination](rust-oidc-refresh.md#pair-coordination).
End-session acquires its exclusive counterpart first, then the optional LOCAL
user row, then updates the pair in one READ COMMITTED transaction. Its two-int
namespace is separate from the one-bigint refresh-family locks. There is no
lock upgrade or serializing of independent families by shared writers.

A refresh that commits first has its child included in disposal. A refresh
that enters after disposal rereads the revoked grant and fails. A valid
authorization code can issue a new family after disposal; this operation does
not invalidate outstanding authorization codes or add a blacklist/session cache.
LOCAL password/deletion invalidators keep user-before-token order and never
wait for the pair barrier. Original/calendar are rechecked around SQL waits
and known COMMIT; cancellation retains the existing rollback/connection guard.
A late error can follow a known committed effect and must not be interpreted
as proof of rollback.

Issued access JWTs remain locally valid until their existing `exp`.
[UserInfo](rust-oidc-userinfo.md), [introspection](rust-oidc-introspection.md)
and refresh observe SQL disposal when explicitly called. PROJECT/resource
policy remains a separate decision. No per-request network gate is introduced.

## Implementation and focused verification

Control owns `broker_access.rs` (private hint proof),
`service/oidc_end_session.rs` (bounded identity, locks and transaction) and
`service/oidc_tokens.rs` (pair keys). Presence owns `oauth_end_session.rs`;
Server runtime and discovery compose it. This implements the disposal subset
of [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html),
with explicit required hint and redirect rejection; it does not claim OP certification.

```text
cargo test --locked --offline -j4 -p broker-server --test oauth_end_session -- --ignored --test-threads=1
```

Four contracts use the native executable and genuine LOCAL/H1 code/token
producers against PostgreSQL TLS with a NOSUPERUSER owner: wire/pair isolation
and elapsed ID expiry; upstream closed and trust/DCR removed; SQL ordering,
corruption/caps/permission/cancellation/deadline and LOCAL invalidation;
and durable multi-row COMMIT with its ACK withheld. The maintained Rust
pre-push runner includes this exact phase; four deliberately failing compiled
Rust cases verify that each contract failure stops later phases.

Compilation alone does not validate the runtime contracts, other platforms or the complete Broker migration.

## Explicit SQLite composition

The additive `sqlite_oidc_end_session_router` and borrowed
`SqliteControlStore::oidc_end_session` dispose the signed subject/client pair
across SQLite OIDC access/refresh families. Expired ID hints and removed DCR
clients remain eligible for this disposal-only operation. See
[SQLite OIDC inspection and disposal](rust-sqlite-oidc-lifecycle.md) for retained
owners, bounded snapshot validation, IMMEDIATE/known ACK. Native Server backend composition remains separate; the existing
PostgreSQL endpoint are preserved.
