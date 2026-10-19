---
type: document
title: Native Rust OAuth dynamic client registration
description: Public DCR metadata admission, committed PostgreSQL client catalog and native HTTP integration.
references:
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4546, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7568, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-5ff3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Rust OAuth dynamic client registration

Server operators and OAuth client integrators can register a public client through
`POST /oauth/register` on the [native PostgreSQL server](rust-broker-server.md).
A 201 response identifies a client actually committed to the native SQL catalog.
The [authorization service](rust-oidc-authorization.md) can then admit its
Authorization Code request with S256 and an explicit accepted resource.

Registration creates client metadata. It does not authenticate a person, authorize
a project, issue tokens or complete an OAuth Web session. The [native discovery](rust-oidc-discovery.md)
now advertises this endpoint only when DCR is enabled; [public authorize/login](rust-oidc-browser-authorization.md)
provides the browser integration. The [federated grant
backend](rust-oidc-federated-grants.md) composes genuine H1 proof with this catalog.
The existing [code exchange](rust-oidc-token-exchange.md) and
[refresh rotation](rust-oidc-refresh.md) retain their own proof requirements.

## Enable and register

Enable the existing `oidc` section from the [code-exchange configuration](rust-oidc-token-exchange.md#enable-the-productive-endpoint)
with `dynamic_registration: true`. It reuses the configured authorization policy,
JSON/parameter limits, request timeout, SQL pool and allowed-origin CORS layer.
An absent/disabled OIDC section or `dynamic_registration: false` leaves this route
unmounted: POST and GET return 404 without a client-catalog operation.

Send JSON to the Broker base URL:

```json
{
  "redirect_uris": [
    "https://app.example/callback",
    "http://localhost:8123/callback"
  ],
  "client_name": "Example application",
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email offline_access"
}
```

No bearer or client secret is required for this public registration. The transport
reads JSON directly without adding a Content-Type requirement. The body has a
fixed 32768-byte cap, independent of the token form cap. The pinned
`openidconnect 4.0.1` metadata types and serde perform parsing, including rejection
of duplicate known fields, malformed types and trailing JSON. Unknown metadata
extensions are ignored; the server does not fetch their URLs.

Only authentication method `none` is supported. Omitted, empty or trimmed `none`
is accepted. Grant types may be absent/empty or contain only `authorization_code`
and `refresh_token`. Response types may be absent/empty or contain only `code`.
The response declares those supported values. Confidential authentication is
rejected rather than supplying credentials.

Scope defaults to `openid profile email offline_access` when omitted or empty.
A supplied whitespace-separated value may contain only those four, with duplicates
removed in first-occurrence order. Metadata containing just `profile` is valid:
registration does not add an `openid` requirement. This metadata catalog differs
from [authorization admission](rust-oidc-authorization.md#protocol-admission),
which preserves six active scopes and requires `openid`.

The name is trimmed, may be empty, must contain no NUL and must fit 256 Unicode
characters and 1024 UTF-8 bytes, as well as the explicit scalar limit. Redirect
scalars and the scope string fit the existing parameter cap; each serialized
redirect/scope JSON column fits `oidc.json_bytes`. Invalid metadata is rejected
before SQL insertion.

## Redirect catalog and use

At least one redirect is required. Each literal is trimmed and duplicates are
removed before persistence. Registered HTTP URLs must use an original loopback
IP address or localhost; registered HTTPS URLs must use a nonloopback authority.
Userinfo, fragments and port zero are rejected. Scheme classification ignores
ASCII case. The URL SDK validates the address while original IRI components
prevent normalization from turning `127.1`, hexadecimal or octal IPv4 into
loopback authority.

The server derives `web` if any registered URL is HTTPS, otherwise `native`.
The input `application_type` supplies no authority and cannot override this.
A mixed catalog is valid. Both its HTTPS and HTTP-loopback entries are usable
by the Web client through **exact full-literal equality**. Changing host case,
port, path, query encoding or other literal bytes is denied.

A Native client retains its existing loopback callback rule: loopback host,
scheme and port may vary when the percent-decoded path bytes and literal query
match a registered loopback entry. This flexibility does not apply to Web clients.
The full admitted callback remains exact at later code exchange.

A dynamic client must still supply one accepted `resource`, valid state/nonce
and S256 challenge to the authorization service. The static CLI client remains
configured separately; a dynamic registration cannot replace it.

## Response and finite failures

A successful SDK response contains `client_id`, `client_id_issued_at`,
`redirect_uris`, `client_name`, `scope`, derived `application_type`,
`token_endpoint_auth_method: none`, supported grant types and response type.
The public ID is 43 characters from 32 CSPRNG bytes, Base64URL without padding.
The issued-at wire timestamp is epoch **seconds**; SQL `created_at` stores positive
UTC **microseconds**.

It never returns `client_secret`, `client_secret_expires_at`,
`registration_access_token` or `registration_client_uri`. Active endpoint
responses use `Cache-Control: no-store` and `Pragma: no-cache`.

| Status / error | Meaning |
| --- | --- |
| 201 | Client metadata committed and released. |
| 400 / invalid_client_metadata | Invalid metadata, duplicate known fields, body or column/scalar limits. |
| 404 | OIDC or dynamic registration is disabled; route absent. |
| 504 / temporarily_unavailable | Original deadline exhausted before COMMIT began. |
| 503 / temporarily_unavailable | Store closed or COMMIT confirmation uncertain. |
| 500 / server_error | Other finite randomness, clock or storage failure. |

Active errors contain only `{"error":"static_code"}`, without a client ID,
request contents, driver details or SQL/DSN. Uncertain COMMIT is not reported as
a successful registration and is not automatically retried. A lost response
does not prove that the client row rolled back; a registration-management or
credential-recovery protocol is not synthesized.

## Server and SQL contract

`PostgresControlStore::oidc_registration_service(&OidcAuthorizationPolicy)`
borrows the actual pool and policy. `register(raw_json, original: Instant)`
returns a serializable `RegisteredOidcClient` only after confirmed COMMIT.

The transaction inserts exactly the existing six columns of
`public.oauth_dynamic_clients`: `client_id`, `client_name`,
`redirect_uris_json`, `scopes_json`, `application_type`, `created_at`.
No upsert, overwrite, compatibility importer, schema change or Go fallback is
introduced. Redirect and scope arrays are deduplicated and satisfy the qualified
current-client reader.

One Original deadline includes body read, admission, queue/lock waits, SQL and
COMMIT; the store may shorten it by its existing operation budget. Known COMMIT
precedes response release. Cancellation and uncertainty use the existing
connection guard, closing an unconfirmed connection. The server creates no second
pool or runtime for DCR.

Sources: `crates/broker-control/src/oidc_registration.rs`,
`service/oidc_registration.rs`, `crates/broker-presence/src/oauth_registration.rs`,
and the existing OIDC configuration/runtime composition.

## Verification

The affected native contracts run unchanged across command shells:

```text
cargo test --locked --offline -p broker-server --test oauth_token -- --ignored --exact broker_oidc_registration_http_contract --test-threads=1
cargo test --locked --offline -p broker-server --test oauth_token -- --ignored --exact broker_oidc_registration_uncertainty_contract --test-threads=1
cargo test --locked --offline -p broker-control --test postgres_oidc_authorization -- --ignored --test-threads=1
```

They use the native executable, TLS PostgreSQL with a NOSUPERUSER application
owner, current-client create/load and the existing TLS COMMIT-ACK relay.
The recurring Rust pre-push plan includes the two DCR HTTP contracts before
audit. Focused runner fault tests verify that an actual failed DCR contract
stops later phases. Command portability alone does not establish Windows/macOS execution.

Every generated ID encodes all 32 CSPRNG bytes as canonical Base64URL without
padding. Its first character may be `-` or `_`; current catalog admission and
refresh accept those exact IDs. They are not usernames, and the consumer never
adds a prefix, retries generation or reduces entropy to satisfy username grammar.
