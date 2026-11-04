---
title: Native Broker OAuth token introspection
description: Bearer-authorized access-grant inspection restricted to the caller's client and subject.
doc_type: reference
references:
  - target: {type: task, id: tsk-b75d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-662f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native Broker OAuth token introspection

Clients of the [native server](rust-broker-server.md) can explicitly inspect a
Broker OIDC access grant. Enable OIDC, obtain a real access token through
[code exchange](rust-oidc-token-exchange.md), and follow
`introspection_endpoint` from [discovery](rust-oidc-discovery.md).
Use HTTPS outside loopback.

## Authorize and query

Send `POST /oauth/introspect` with exactly one
`Authorization: Bearer <caller-access-token>` header and an
`application/x-www-form-urlencoded` body. The optional `token` field contains
the access token to inspect. `token_type_hint` is advisory and ignored.
Missing or empty `token` returns inactive after authorization.
Repeated recognized fields, query transport for those fields, invalid UTF-8,
invalid form media type, or existing body/parameter limits return
`400 invalid_request`. Unknown extensions are ignored. The target uses the
configured OIDC form/parameter caps; the authority uses the separately
configured access-verifier token cap. These explicit limits are independent.

The authority must be a signed, unexpired Broker access JWT with its active,
exactly bound SQL access row. An ID token, opaque refresh token, missing or
repeated Authorization header, invalid Bearer or Basic returns
`401 invalid_token` with a Bearer challenge. A public client ID and empty Basic
password do not prove authority. Query/body credentials never replace the
Authorization header.

The queried token must have the same signed `client_id` and OIDC `sub` as the
caller and pass its own JWT/SQL binding. Other clients or subjects, refresh/ID
tokens, invalid, unknown, expired and revoked tokens produce exactly:

```json
{"active":false}
```

An active response contains only `active`, `client_id`, Unix-second `exp` and
the granted scopes joined by spaces. Empty scopes omit `scope`; there is no
extra `openid` requirement. No subject, audience, resource, profile or roles
are returned. For example, with illustrative values:

```json
{"active":true,"client_id":"registered-client","scope":"openid profile","exp":2000000000}
```

All route responses use `Cache-Control: no-store` and `Pragma: no-cache`.
Other methods return405. The common configured-origin CORS layer applies
without browser credentials. OIDC disabled means404 and no OIDC discovery
advertisement. Metadata advertises
`introspection_endpoint_auth_methods_supported: ["Bearer"]`: RFC8414
permits registered OAuth access-token types in this field, and Bearer is the
[IANA-registered type](https://www.iana.org/assignments/oauth-parameters#token-types).
See [RFC7662](https://www.rfc-editor.org/rfc/rfc7662.html) and
[RFC8414 §2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2).

## SQL state, concurrency and errors

Both authority and target bind signature, issuer, API audience, access use,
canonical JTI, exact expiry/scopes and the literal API/resource audience set
to their SQL rows. The JTI digest uses the existing stored-access HMAC domain;
the principal snapshot must match its canonical pseudsubject and revision.
All selected text and JSON are bounded. No raw bearer is persisted.

One READ COMMITTED statement observes at most the two access rows without row
locks. Authority is admitted from that statement snapshot. A concurrent
revocation can occur afterward; revocation committed before it is visible.
An active candidate then locks only its own target row, rereads immutable
fields (excluding last-used), and revalidates after waiting. A changed,
revoked or expired target detected at this reread returns inactive after
confirmed rollback, without a confirmed usage update. Only a revalidated target updates `last_used_at`.
Success requires known COMMIT and Original/deadline/expiry rechecks. If validity
ends after that COMMIT, the response can be inactive or unauthorized even though
usage admitted earlier has already persisted.

This operation acquires no user, separate authority or family row lock after
the target lock. It therefore introduces no two-token lock cycle against
refresh-family revocation/reuse or LOCAL invalidation. A positive result
requires conservative target revalidation after authority admission; negative
results can reflect a later revocation.

Storage failures are real finite errors, never fabricated inactive results:
operation deadline504; closed store or unknown COMMIT outcome503; SQL,
credential, clock, malformed state and read-cap failures500. Responses
use `temporarily_unavailable` or `server_error` without raw SQL or credentials.
An uncertain COMMIT may have persisted usage; it never reports success.

There is no independent current LOCAL profile/revision, dynamic-client or
federated trust lookup and no upstream request. Managed identity changes
still invalidate their access rows through their existing writers.
[UserInfo](rust-oidc-userinfo.md) retains its separate current-profile/trust
rules. [Revocation](rust-oidc-revocation.md) blocks explicit grant operations;
already issued JWTs remain locally verifiable until `exp`. Code/Auth do not
call introspection on each request.

## Implementation and qualification

Control owns `service/oidc_introspection.rs` and the internal bounded
`service/oidc_access_snapshot.rs` shared with UserInfo. The existing public
`service/oidc_access_grant.rs` reader is preserved. Presence owns
`oauth_introspection.rs`; Server composes it with its real store/verifier
and productive discovery. The [Web process fixture](rust-hub-storage-fixture.md)
mounts that same router.

The focused portable command is:

```text
cargo test --locked --offline -j4 -p broker-server --test oauth_introspection -- --ignored --test-threads=1
```

The four real contracts cover LOCAL clients/subjects and wire boundaries,
federated H1 with the upstream closed/current trust changed, SQL caps and
permissions, deadlines/cancellation, two genuine P4 generations contending
with family revocation/reuse and required LOCAL password change, and durable
COMMIT with its ACK withheld. The maintained Rust gate includes this phase:

```text
cargo run --locked --offline -p xtask -- qualify
```

The guardrails execute four deliberately failing compiled Rust test cases to verify that each failure blocks later phases. UserInfo/discovery/revocation are affected regressions. These tests do not establish hosted CI, other platforms or complete Broker integration.

## Explicit SQLite composition

The additive `sqlite_oidc_introspection_router` and borrowed
`SqliteControlStore::oidc_introspection` implement the same Bearer/active-row
contract for genuine LOCAL SQLite grants. Authority is admitted before a
distinct target is decoded within one IMMEDIATE transaction. The policy/verifier
Arc pair is retained by the worker. See [SQLite OIDC inspection and disposal](rust-sqlite-oidc-lifecycle.md)
for APIs, acknowledgement/error boundaries.
This does not change the PostgreSQL server or its historical qualification.
