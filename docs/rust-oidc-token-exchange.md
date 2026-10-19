---
type: document
title: Native Rust OIDC authorization-code exchange
description: Productive PostgreSQL code exchange, shared configured signing key and native HTTP transport.
references:
  - target: {type: task, id: tsk-5528, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6eee, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-d3b9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6414, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-5897, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---
# Native Rust OIDC authorization-code exchange

For native server integrators and operators. The PostgreSQL `graphit-broker`
executable can enable `POST /oauth/token` for `authorization_code`. Its input is
an unexpired code returned by the genuine [native LOCAL completion](rust-oidc-authorization.md)
producer. The producer admits the request through P2a, verifies LOCAL password
and required factors, then completes P2b. Pending or manually constructed JSON
is not authentication evidence. The [public browser transport](rust-oidc-browser-authorization.md)
and [native discovery](rust-oidc-discovery.md) now compose these producers; this endpoint alone
is not a complete OP or release cutover.

## Enable the productive endpoint

Add this fragment to the clean YAML in the [native server runbook](rust-broker-server.md).
The existing `auth` key/issuer/audience/pepper and PostgreSQL pool remain its
owners. These byte bounds and timeout are illustrative operator choices; they
have no hidden library defaults.

```yaml
oidc:
  enabled: true
  cli_client_id: graphit-cli
  cli_redirect_path: /oauth/callback
  device_code_ttl: 10m
  device_poll_interval: 5s
  accepted_resources: [https://broker.example.test/v1]
  dynamic_registration: true
  json_bytes: 8192
  parameter_bytes: 8192
  request_timeout: 10s
  allowed_origins: [https://ui.example]
```

An absent section or `enabled: false` leaves `/oauth/token` unmounted and retains
no unused private signer. Enabled configuration requires every admission setting,
JSON/parameter cap and request timeout above. Constructors check limits and
arithmetic before pool/socket/volume creation. `--check-config` validates the
actual configured PKCS8 DER key, CA, policies and CORS configuration without
network or SQL effects.

Defaults confirmed from the active protocol are authorization TTL **60 seconds**
(range 30–600 seconds), access and ID TTL **600 seconds** (range 60–3600 seconds),
refresh TTL **30 days** (at least access TTL, at most 90 days), and token form body
**32768 bytes**. Override `authorization_ttl`, `access_ttl`, `refresh_ttl` and
`body_bytes` in this section. Device uses `device_code_ttl` (default 10m, range 5–30 minutes)
and `device_poll_interval` (default 5s, range 1–30 seconds), both whole seconds; its access
JWT reuses `access_ttl` exactly. See the [Device journey](rust-device-authorization.md). Durations are positive strings. The token form cap
is independent of storage JSON and streaming filesystem upload limits.

Configured `auth.resource` remains the verifier's explicit trust binding.
Absent resource permits API-audience-only CLI tokens; a configured resource
requires that audience when a token reaches existing protected APIs. Enabling
OIDC never rewrites verifier trust. No resource is synthesized for the CLI.

## Exchange a genuine code

POST `application/x-www-form-urlencoded`, with one value per known scalar:

```text
grant_type=authorization_code
client_id=graphit-cli
code=<committed-native-P2b-code>
redirect_uri=http://localhost:49152/oauth/callback
code_verifier=<the-original-S256-verifier>
```

The redirect must equal the admitted literal, including its exact spelling.
The public static CLI can omit `resource`; a dynamically registered client must
include its single target in the POST. A nonempty repeated target, after trimming,
must equal the previously authorized resource. Empty target text does not replace
or widen the stored target. Body duplicate known scalars (including duplicate
resource), known token parameters in the URI, duplicate Authorization headers,
unsupported assertions and multiple authentication mechanisms fail closed.
Unknown form extensions are ignored. These clients use authentication method
`none`; confidential client secrets are not silently introduced. A body secret
alone is ignored by the SDK's disabled credentials-in-body mechanism and supplies
no authority. Supplied Basic credentials cannot authenticate a public `none`
client.

A successful JSON response contains `access_token`, `id_token`, `token_type:
"Bearer"`, positive remaining `expires_in`, and the admitted `scope`. With
`offline_access`, it also contains an opaque `gb_rt_` initial `refresh_token`.
Responses use `Cache-Control: no-store` and `Pragma: no-cache`.
The remaining lifetime is bounded by the minted interval. A UTC clock reading
before the captured issuance time, expiry or exhaustion of the original request
deadline prevents output; the server never inflates `expires_in` after a rewind.
[Native refresh rotation](rust-oidc-refresh.md) consumes the committed initial
grant, preserves its original UTC expiry and revokes the family on valid reuse.
Do not advertise unsupported grants in discovery.

Finite errors contain only `error`: malformed input uses `invalid_request`,
invalid code/PKCE/redirect/current LOCAL identity uses `invalid_grant`, a
replacement or required missing target uses `invalid_target`, and unsupported
grants use `unsupported_grant_type` (HTTP 400). Invalid Basic/public-client
credentials use HTTP 401 `invalid_client` with `WWW-Authenticate`. Deadline,
closed store and uncertain COMMIT map to finite unavailable errors; corrupt
stored metadata/signing/storage failures map to `server_error`. Diagnostics
never include code, verifier, password, bearer, pepper, key or stored JSON.

A wrong verifier or other denial does not consume the code. Correct exchange
consumes it once; replay fails. A client that loses the response after COMMIT
must not assume the transaction rolled back or retry the code as a recovery
protocol. Obtain a new genuine authorization through the owning flow.

## Current authority, signing and storage

`PostgresControlStore::oidc_token_exchange(&authorization_policy, &token_policy,
&issuer)` borrows the actual store's private digester and shared owners. It does
not accept a second pepper, fake principal, externally signed grant or callback
issuer. The factory checks that policy and signing API audiences agree.

One READ COMMITTED transaction reads bounded native `authorized` DATA, acquires
the shared pair barrier described in [refresh concurrency](rust-oidc-refresh.md#pair-coordination),
then locks the current human LOCAL user when applicable → current client → exact request, and revalidates
LOCAL identity revision, enabled/password-change state and current profile/roles, or
[federated snapshot and current issuer/selector trust](rust-oidc-federated-grants.md), plus literal
request bindings, original authorization TTL and UTC expiry. The mature
oxide-auth 0.6.1 `AccessToken` state machine and required S256 PKCE extension run
before any code deletion. The native decoder rejects arrays, duplicate/unknown
fields and trailing JSON. AMR and original authentication time come from genuine
P2b metadata, not inferred presence of MFA rows.

The same configured [Ed25519 owner](rust-broker-access-issuer.md) signs access and
ID tokens. Access audiences are configured API plus optional authorized resource;
ID audiences add the client once. ID claims include `azp`, `client_id`, original
`auth_time`, factor AMR, nonce and current asserted profile. Access name/email/org
are trimmed and omitted when empty. ID name/email preserve nonempty literal
profile text and omit empty strings; organization is trimmed for both. Actual access JWT and
code bind `at_hash` and `c_hash`: SHA-512's first 32 bytes, base64url without
padding for EdDSA. The ID token has no access `token_use` and cannot authenticate
as an access bearer. Signature serialization uses jsonwebtoken/AWS-LC, not a
custom JWS implementation.

The transaction inserts native `oidc_access` metadata (domain-11 digest of JTI),
optional initial refresh metadata (domain-5 digest of opaque refresh), and deletes
the exact locked code row. It persists no raw JWT/code/private key. All changes
roll back together before COMMIT; only a known successful COMMIT and final
Original/UTC gates return owned zeroizing secrets. An ambiguous issued COMMIT is
`OutcomeUncertain`, without fabricated rollback or output. Concurrent exchanges
have one winner. [Stored grant observations](rust-oidc-access-grants.md) remain
DATA, not authority or a mandatory gate on each access request.

Existing JWT consumers verify locally until actual expiry and apply current SQL
ACL authorization. They do not require UserInfo, introspection, token-row
revocation lookup or a network request for each access bearer. [Explicit UserInfo](rust-oidc-userinfo.md) retrieves profile data and [authorized introspection](rust-oidc-introspection.md) explicitly observes access grants; remaining OP operations retain their own migration work.

## CORS, lifecycle and qualification

Nonempty `allowed_origins` install mature tower-http CORS on this endpoint:
GET/POST/OPTIONS, Authorization/Content-Type/Accept/Origin, expose WWW-Authenticate,
no credentials. Literal and first-wildcard declarations follow the existing
origin policy. Empty declarations install no CORS layer; unmatched Origin gets
no CORS grant. Origin is never authentication authority and does not independently
reject an otherwise authorized request.

The endpoint shares the server's pool, captured request Original, key owner,
HTTP listener and existing shutdown. It adds no pool, task abandonment controller,
fallback key or filesystem body cap. The server is still PostgreSQL-only.

Focused qualification commands (actual TLS PostgreSQL container required):

```text
cargo test --locked --offline -p broker-control --test postgres_oidc_token_exchange -- --ignored --exact postgres_native_oidc_authorization_code_exchange --test-threads=1
cargo test --locked --offline -p broker-server --test oauth_token -- --ignored --exact broker_oidc_authorization_code_http_contract --test-threads=1
```

Affected ordinary suites, strict Clippy, docs and hook gates accompany this unit.
Linux execution does not qualify other platforms. Browser flow and discovery have their
linked native qualifications. [Explicit revocation](rust-oidc-revocation.md) disposes of committed grants, [UserInfo](rust-oidc-userinfo.md) retrieves profiles and [authorized introspection](rust-oidc-introspection.md) observes access grants. The Linux Device HTTP qualification is recorded in the [Device guide](rust-device-authorization.md); remaining OP endpoints/backends, full platform release and final coordinator integration remain required work.

Federated codes use `with_upstream` on the same producer; the server supplies its
existing common verifier even with administration disabled. Initial AMR is
`federated`, with fresh completion `auth_time`; the JWT issuer remains the Broker
and `sub` is its domain-15 issuer/mapped-subject HMAC. Native DCR and administrative
transports, public browser authorization and discovery have separate delivered contracts; full OP
cutover remains integration work. See [federated grants](rust-oidc-federated-grants.md).

## SQLite LOCAL token consumer

The explicit [SQLite LOCAL code/refresh path](rust-sqlite-oidc-local-grants.md)
uses the same SDK, issuer and HTTP form contract through
`sqlite_local_oidc_token_router`. Its constructor rejects upstream and Device
configuration. This does not select SQLite in the native Server dispatch.
