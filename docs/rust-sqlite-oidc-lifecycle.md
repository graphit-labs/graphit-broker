---
title: SQLite OIDC grant inspection and disposal
doc_type: reference
description: Explicit SQLite introspection, raw-token revocation and signed ID-hint end-session routers.
references:
  - target: {type: task, id: tsk-b75d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---

# SQLite OIDC grant inspection and disposal

Consumers of the [SQLite LOCAL grant producer](rust-sqlite-oidc-local-grants.md) can compose three explicit Presence routers over the same physical SQLite store: `POST /oauth/introspect`, `POST /oauth/revoke`, and `GET|POST /oauth/end-session`. Library and router tests do not establish whole-backend integration.

These operations inspect or dispose issued LOCAL grants. SQLite UserInfo with
federated production, native Server backend dispatch/configuration and the full
backend migration remain separate. Runtime Device integration is independent.
The existing PostgreSQL endpoints remain unchanged.

## Compose with real retained owners

`SqliteControlStore` exposes borrowed factories taking
`Arc<OidcAuthorizationPolicy>` followed by `Arc<BrokerAccessVerifier>`:

| Factory | Result |
| --- | --- |
| `oidc_introspection` | `Result<SqliteOidcIntrospection<'_>, OidcIntrospectionError>` |
| `oidc_revocation` | `Result<SqliteOidcRevocation<'_>, OidcTokenExchangeError>` |
| `oidc_end_session` | `Result<SqliteOidcEndSession<'_>, OidcTokenExchangeError>` |

Each rejects a policy/verifier API-audience mismatch. Their async operations are
`introspect(&self, authority: &str, token: Option<&str>, original: Instant)`,
`revoke(&self, input: OidcRevocationInput<'_>, original: Instant)`, and
`end_session(&self, input: OidcEndSessionInput<'_>, original: Instant)`.
Introspection returns `Result<OidcIntrospection, OidcIntrospectionError>`;
the two disposal operations return `Result<(), OidcTokenExchangeError>`.
Introspection and end-session expose the existing `parameter_bytes()` cap.

The additive Presence factories are `sqlite_oidc_introspection_router`,
`sqlite_oidc_revocation_router` and `sqlite_oidc_end_session_router`. Each takes
`Arc<SqliteControlStore>`, `Arc<BrokerAccessVerifier>`,
`Arc<OidcAuthorizationPolicy>`, then respectively
`OidcIntrospectionHttpConfig`, `OidcRevocationHttpConfig` or
`OidcEndSessionHttpConfig`, returning
`Result<Router, OidcTokenHttpConfigurationError>`.
Concrete private PostgreSQL/SQLite dispatch preserves the existing HTTP parser
and wire. Retained Arc owners and bounded `Zeroizing` credentials enter the
SQLite worker; genuine verifier proofs are constructed there, rather than
serialized or replaced by caller-created authority. No current upstream-trust
argument is required for credential disposal.

## Inspect with a Bearer and its active stored grant

Send one `Authorization: Bearer` header and a form body. An optional `token`
selects the target; `token_type_hint` is advisory. Authority requires both the
genuine unexpired access JWT and its active SQL access row. Trusted signature,
issuer, key, audiences, token use, temporal fields and canonical JTI are checked.
The row must match the token's domain-separated HMAC, JTI, subject/client,
resource, audience, scopes, expiry and immutable principal/revision snapshot.
Current LOCAL enabled/revision state, current DCR and current federated trust
are not substitutes for that stored binding or extra current-identity checks.

The worker reads and admits authority before decoding a distinct target. It
reads at most two bounded rows within one IMMEDIATE transaction; the same hash
reuses the authority row. Thus a revoked authority is rejected before malformed
unrelated target data can become the response cause. An admitted authority with
malformed target storage receives a causal error, not inactive.

Before an owned target copy, the real verifier applies its independent token
byte cap and classifies the raw target. Invalid classification becomes no target;
the SQL authority must still be admitted first. Form/body input caps remain
separate. Targets must belong to the same signed client and pseudonymous subject.
Missing/empty, invalid, unknown, revoked, expired, other-client/subject, ID and
refresh targets return exactly `{"active":false}` after authority admission.
An admitted active target returns only `active:true`, `client_id`, Unix-second
`exp`, and space-joined `scope` when nonempty. No profile, subject, resource or
role payload is added. Only that active admitted target updates `last_used_at`,
with a one-row update and known COMMIT acknowledgement. Authority-only and
inactive queries do not update it. Authority failure is HTTP 401 with the Bearer
challenge; SQL corruption, caps, clock and storage errors are never inactive.
See the shared [introspection wire contract](rust-oidc-introspection.md).

## Revoke a raw token for a current public client

`POST /oauth/revoke` requires form `client_id` and a nonempty raw `token`.
Configured and currently registered public clients use authentication method
`none`; Basic/body secrets and assertions are rejected. Unknown current clients
receive 401 `invalid_client`; malformed client input receives 400
`invalid_request`. A family identifier, digest or row identifier is not a token.
A wrong or unknown hint does not change token recognition.

A recognized refresh token uses its existing refresh HMAC domain and revokes
its whole family. A consumed ancestor whose expiry is still in the future can
revoke descendants. A genuine access JWT uses the private resource-free
revocation verifier and stored-access HMAC domain, binding its JTI, signed
client/subject, audience and expiry; it revokes only that access row. Public JWT
verification remains unchanged. Invalid, unknown, expired, already revoked or
other-client tokens return the same empty HTTP 200 after current-client
recognition. No current LOCAL identity/trust or network call is needed.
See the shared [revocation contract](rust-oidc-revocation.md).

## Dispose the signed subject/client pair

End-session requires `id_token_hint`; an optional `client_id` must match its
signed client literally. The genuine ID-token verifier checks signature, issuer,
audiences, shape and temporal ordering. Expired hints are accepted exclusively
for disposal, without an invented maximum age. Access/refresh tokens, unsigned
hints and wrong/future claims do not become disposal authority.

The signed pair remains disposable after its DCR row is removed, without current
LOCAL/trust, administrative-cookie or UserInfo authorization. One bounded stored
principal snapshot is validated before the update. Within one IMMEDIATE
transaction, every unrevoked OIDC access/refresh grant for the configured API
audience and signed subject/client is revoked across families/resources.
Existing revocation timestamps and other pairs are preserved. Empty/already
revoked pairs return empty HTTP 204 after the final checks. An admitted refresh
serialized before disposal is included; one after it observes revocation. A
valid later code exchange may create a new family. Codes, Device grants and
unrelated LOCAL credentials are outside this update.

GET uses query parameters and an empty body. POST uses a form without recognized
query fields. Presence of `post_logout_redirect_uri`, even empty, is rejected;
there is no redirect. `state`, `ui_locales` and `logout_hint` extensions do not add
effects. See the shared [end-session contract](rust-oidc-end-session.md).
Disposal changes stored grant availability; it does not blacklist an already
issued access JWT in local signature verification before its expiry.

## Original request, storage and errors

Presence captures the original `Instant` before reading the body. Existing body,
parameter and verifier caps apply; mature form/header parsers retain strict
UTF-8, scalar duplicate, transport and media-type handling. Unsupported methods
return 405 with Allow. Responses are no-store/no-cache. These bare Presence
routers do not qualify Server CORS composition: the Server prepares that policy
inline rather than through a shared Presence helper. Native Server/Main routing
and CORS integration remain separately owned and unqualified here. Errors and
Debug output do not expose raw credentials, SQL, principal data or physical paths.

SQLite uses its existing owner and IMMEDIATE transaction, serializing writers
without PostgreSQL advisory locks or an emulated snapshot framework. Physical
type and byte checks precede owned snapshot copies, followed by the shared
immutable grant/principal validation. There is no alternate principal codec.
The existing executor's `Work::commit` and known acknowledgement precede a
positive committed result. Original deadlines and genuine proofs are checked
at operation boundaries and after acknowledgement; they are never renewed.
A post-commit error does not establish rollback. `OutcomeUncertain` remains
uncertain and must not be automatically replayed. These boundaries do not
promise continuous atomicity between authentication, the clock and SQLite.

Malformed requests map to 400; invalid clients or introspection authority map
to their specified 401 responses. Deadline is 504; closed/uncertain work is 503
`temporarily_unavailable`; corruption, storage, credential, cap and clock errors
are causal 500 `server_error` responses. A successful empty disposal or inactive
response never hides a failed SQL operation. The [SQLite control contract](rust-sqlite-control.md)
owns native cancellation, acknowledgement, WAL/files and shutdown semantics.

## Implementation and focused validation

The implementation is in Control's
`sqlite/flow/oidc_{access_snapshot,introspection,revocation,end_session}.rs` and
Presence's `oauth_{introspection,revocation,end_session}.rs`.
The crate-private `service/oidc_access_snapshot.rs` shares pure binding and
principal validation with PostgreSQL while each backend keeps its physical row
decoder. The public PostgreSQL access-grant reader is preserved.

The new Control fixture target is
[sqlite_oidc_lifecycle.rs](../crates/broker-control/tests/sqlite_oidc_lifecycle.rs);
the real TCP Presence target is
[sqlite_oidc_lifecycle_http.rs](../crates/broker-presence/tests/sqlite_oidc_lifecycle_http.rs).
They execute genuine issuance, three disposal scopes, row corruption/caps,
Original/locking, genuine UTC expiry, independent owners and HTTP parser/wire
scenarios.

The 18 component units are three principal codec/parser units, one empty-scope
minimal DTO unit, twelve access-verifier units, one subject-domain unit and one
contract checking all fourteen credential domains. They are separate from the
lifecycle journeys. The compile-fail examples belong to
`SqliteOidcIntrospection`, `SqliteOidcRevocation` and `SqliteOidcEndSession`.

Focused commands retain locked/offline execution and the coordinated existing
target, with four build jobs:

```text
cargo test --locked --offline -j4 -p broker-control --test sqlite_oidc_lifecycle -- --test-threads=1
cargo test --locked --offline -j4 -p broker-control --test sqlite_oidc_lifecycle -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_oidc_lifecycle_http -- --ignored --test-threads=1
cargo clippy --locked --offline -j4 -p broker-control -p broker-presence --lib --test sqlite_oidc_lifecycle --test sqlite_oidc_lifecycle_http --test sqlite_oidc_grants --test sqlite_oidc_token_http --no-deps -- -D warnings
cargo test --locked --offline -j4 -p broker-control -p broker-presence --doc
```

The existing `SQLITE_LOCAL_AUTH` phase includes both focal Control/Presence targets. Native Server routing/CORS, federated UserInfo, Runtime Device integration and other-platform runtime behavior require separate tests.
