---
type: document
title: Native Rust OIDC refresh rotation
description: Productive PostgreSQL refresh rotation, reuse revocation and original grant lifetime.
references:
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5528, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1564, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5897, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-6eee, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Rust OIDC refresh rotation

The PostgreSQL [native server](rust-broker-server.md) supports `refresh_token`
at the same enabled `POST /oauth/token` endpoint as
[authorization-code exchange](rust-oidc-token-exchange.md). No additional
configuration, key, pool or per-request network lookup is introduced. The input
must be an unexpired opaque `gb_rt_` refresh actually issued by the native code
producer after genuine LOCAL authentication or [federated H1 OAuth completion](rust-oidc-federated-grants.md).
Grant JSON or a principal DTO is
not authentication evidence. Browser authorization and the remaining OP
operations are separate required integrations.

## Rotate a genuine grant

POST `application/x-www-form-urlencoded`. A static CLI request can omit resource:

```text
grant_type=refresh_token&client_id=graphit-cli&refresh_token=<opaque-native-P3-refresh>
```

A dynamically registered public client sends its actual `client_id` and the
single `resource` bound to the original authorization. Presence is required for
that client. A nonempty trimmed resource must be accepted by configuration and
exactly match the stored target. An empty value carries the existing target;
it cannot create, replace or widen it. CLI omission keeps the original target,
including absence. The configured verifier's independent `auth.resource` trust
binding remains unchanged.

Omitting `scope` keeps the refresh's current scopes. A nonempty explicit scope
must be a literal subset of them. Duplicate valid tokens are deduplicated, in
input order. `scope=` and empty elements produced by leading, trailing or repeated
ASCII spaces return `invalid_scope`; malformed whitespace or widening also fails.
For example, `scope=openid%20profile` narrows a grant that already contains both.
The next refresh carries this narrower scope. Removing `offline_access` does
not disable rotation of a refresh that was already issued.

Known scalar duplicates in the form or known token parameters in the URI,
unsupported client assertions and multiple authentication mechanisms are
`invalid_request`. Unknown form extensions are ignored. Current static CLI and
registered clients use authentication method `none`. Basic credentials cannot
authenticate these public clients and return HTTP 401 `invalid_client` with
`WWW-Authenticate`. Body secrets supply no authority. The existing 32768-byte
form default, configured caps, captured request deadline and declared CORS policy
apply to both grants.

Success returns access, ID and a new opaque refresh token, `token_type: Bearer`,
positive actual remaining `expires_in`, and the current scope. Responses use
`Cache-Control: no-store` and `Pragma: no-cache`. Replace the old refresh with the
new one; do not retry the consumed old value. A lost or ambiguous COMMIT response
requires a new genuine authorization, not an assumption that the old credential
remains usable.

## Lifetime, identity and signing

Every rotation preserves the same family and the original refresh UTC expiry.
There is no sliding refresh lifetime. Original `auth_time` also remains fixed.
The access and ID lifetime follows configured `access_ttl`, default **600 seconds**,
rather than the SDK's internal grant default. A refresh close to expiry does not
silently shorten the access lifetime; final output still requires that the
original refresh cutoff is future. Its private cutoff survives the SQL return
and is checked before and after HTTP serialization alongside the original
request deadline, access expiry and captured issuance-time rewind guard.

The LOCAL branch revalidates current human identity, enabled/revision and
password-change state and current profile/teams/roles. The federated branch keeps
the authenticated snapshot, checks current issuer/browser-client availability and
literal role selector, and never queries a fabricated LOCAL user. Both revalidate
the actual current Broker client; canonical 32-byte dynamic IDs retain every
Base64URL prefix, including `-` and `_`.
It uses the configured [shared signing key](rust-broker-access-issuer.md).
Access audiences remain API plus optional original resource; ID audiences add
the client, with `azp` and `client_id`. ID `at_hash` binds the newly minted access
JWT. Refresh ID tokens omit `nonce` and `c_hash`: there is no new authorization
code. Their AMR is the principal method, `local-token` for LOCAL and `oidc` for
federation, and does not
claim a new password or OTP verification. Original factors cannot be inferred
from current MFA rows. Profile omission and trimming follow the code producer's
access/ID distinction. ID tokens cannot authenticate as access bearers.

## Atomic rotation and reuse

One READ COMMITTED transaction first acquires a shared pair barrier, then
acquires the LOCAL user `FOR UPDATE` before the
shared identity reader, current client and exact refresh row. This strong lock
serializes rotation of a descendant against reuse of its ancestor. Federation uses
an exclusive PostgreSQL transaction advisory lock shared by the generations
of that existing family, instead of a LOCAL row. Immutable
metadata is compared against the initial bounded observation; consumed/revoked
state is read fresh under lock. Native typed decoders reject malformed, duplicate,
unknown and trailing principal data. The store's private digester owns domain-5
raw-refresh hashes and domain-11 access JTI hashes. SQL stores neither raw bearer,
raw refresh, authorization code nor private key.

The mature oxide-auth refresh state machine runs against the genuine stored
grant. Current identity/client/resource/scope guards run before mutation. For an
unused future refresh, the old consumption and new access/refresh pair commit
atomically. Trigger failure or cancellation before COMMIT rolls everything back.
Only known COMMIT and final temporal gates expose owned zeroizing tokens.
An issued COMMIT whose outcome is ambiguous returns finite unavailable status;
storage errors are never disguised as successful rollback.

Valid reuse of a consumed refresh revokes every still-active access and refresh
row in its family in one confirmed transaction, then returns `invalid_grant`
without issuing tokens. Wrong client, resource or scope cannot cause this
revocation. Already revoked grants are denied. A concurrent duplicate request
has one rotation winner, then the other performs reuse revocation. A family
revocation cannot finish ahead of a descendant insertion and leave an active
refresh behind. Other families remain usable.

SQL family revocation prevents further refresh/grant operations. Already issued
access JWTs remain locally verifiable until expiry and are subject to current SQL
ACL authorization. It does not create a per-request blacklist, mandatory
UserInfo, introspection or network call. [Explicit token revocation](rust-oidc-revocation.md)
uses the same family serialization. [Explicit UserInfo](rust-oidc-userinfo.md) retrieves profiles; [explicit introspection](rust-oidc-introspection.md) observes the caller's access grants without changing refresh-family writers or local JWT verification.

## Errors and qualification

Missing required parameters use HTTP 400 `invalid_request`; wrong, unknown,
expired or revoked grants and valid reuse use `invalid_grant`; target mismatch
uses `invalid_target`; invalid scope uses `invalid_scope`. Invalid public-client
Basic credentials use 401. Deadline maps to 504 `temporarily_unavailable`; closed
store or uncertain COMMIT to 503; corrupt metadata/signing/storage failures to
500 `server_error`. Errors do not echo credentials or stored JSON.

Focused commands require actual TLS PostgreSQL fixtures and the native executable:

```text
cargo test --locked --offline -p broker-control --test postgres_oidc_refresh -- --ignored --exact postgres_native_oidc_refresh_rotation_contract --test-threads=1
cargo test --locked --offline -p broker-server --test oauth_token -- --ignored --exact broker_oidc_refresh_http_contract --test-threads=1
```

Affected code-exchange regressions, ordinary suites, Rustdocs, strict Clippy,
formatting and runner failure barriers accompany this unit. Linux qualification
does not qualify Windows or macOS. Browser OAuth authorization and discovery
are qualified separately; see [the native server](rust-broker-server.md).
[Token introspection](rust-oidc-introspection.md) is qualified separately.
Device HTTP, remaining databases, full platform release and final coordinator
integration remain required. This token endpoint is not the complete Broker migration.

## Pair coordination

Code exchange, refresh rotation/reuse and explicit refresh disposal first
acquire the same shared transaction advisory lock for their admitted
`(oidc_subject, client_id)` pair, before user, family, client, request or token
locks. The JSON tuple encoding avoids ambiguous concatenation. PostgreSQL
uses its two-integer keyspace (namespace 4750302 plus the tuple hash), separate
from the existing one-bigint family advisory locks. Pair hash collisions only
share a barrier; SQL bindings still identify the actual pair.

Writers take shared locks without upgrading them, so distinct federated
families of the same pair keep making progress independently. LOCAL user and
federated family ordering, current identity/client/trust validation, replay
revocation and known-COMMIT rules stay in effect. Original is checked around
the new SQL wait; timeout or cancellation retains the existing rollback and
connection-guard behavior. JWT verification remains local until expiry.

The real SQL contract uses genuine P3, P4 and refresh-disposal operations
against an exclusive barrier, deadline/cancellation and separate PostgreSQL
keyspaces. The existing federated contract also holds one family while another
of the same pair rotates. Run the new focused contract with:

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_oidc_refresh -- --ignored --exact postgres_native_oidc_shared_pair_contract --test-threads=1
```

The maintained Rust qualification runner already includes the refresh test binary;
[end-session](rust-oidc-end-session.md) uses the matching exclusive barrier to
dispose all families of the signed pair.

## SQLite LOCAL rotation

The explicit [SQLite LOCAL grant path](rust-sqlite-oidc-local-grants.md) reuses
the principal/scope codec, SDK and absolute family cutoff. SQLite IMMEDIATE
transactions serialize its current-identity guards, rotation and ancestor reuse;
no PostgreSQL advisory-lock parallelism is claimed. Valid consumed-refresh reuse
still commits family revocation before `invalid_grant`, even for an expired
ancestor, after the current identity/client/resource/scope guards.
