---
title: Native Broker OIDC UserInfo
description: Explicit profile retrieval from native access tokens and their SQL grants.
doc_type: reference
references:
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native Broker OIDC UserInfo

The explicit [SQLite UserInfo composition](rust-sqlite-oidc-federated.md) reuses
the same bounded grant snapshot and current LOCAL/federated rules through
`sqlite_oidc_userinfo_router`. Its producer retains actual `Arc` policy/verifier
owners in the IMMEDIATE worker and returns after known COMMIT. This library
composition does not change native Server backend selection or discovery.

Clients of the [native server](rust-broker-server.md) can retrieve profile data with a Broker-issued OIDC access token. Enable OIDC, complete [code exchange](rust-oidc-token-exchange.md), and follow `userinfo_endpoint` from [discovery](rust-oidc-discovery.md).

[Explicit introspection](rust-oidc-introspection.md) separately reports minimal access-grant metadata for the Bearer caller's client/subject. It reuses the bounded JWT/SQL snapshot binding, while current LOCAL profile and federated trust checks below remain specific to UserInfo. Neither endpoint becomes a network requirement for local JWT consumers.

Use HTTPS outside loopback. Prefer `GET /oauth/userinfo` with `Authorization: Bearer <access-token>`. POST with that header also works. The RFC 6750 `access_token` query parameter and POST `application/x-www-form-urlencoded` body are supported; prefer the header so credentials do not enter URLs or access logs. Supply one credential through exactly one transport. An invalid Authorization header never falls back to query/form. Repeated headers/parameters, mixed credentials, invalid UTF-8, GET bodies and invalid form media types return `400 invalid_request`. Unknown extensions are ignored. Existing OIDC body, parameter, stored-JSON and request timeout limits apply.

Success is `200 application/json`. The response always includes the stable `sub`; compare it with the verified ID token. Available fields are `preferred_username`, `name`, `email`, `organization`, `groups` and `roles`. Empty optional values are omitted. The active profile contract has no additional `profile`/`email` scope filter or `openid` requirement here. Roles in this response are profile data and grant no administrator, PROJECT, Hub or S3 authority.

LOCAL fields and roles come from current SQL identity data. Missing, disabled, revised or otherwise unavailable identities deny the lookup. Federated profiles retain the authenticated grant snapshot and require the same current upstream issuer, login channel and role selector. They make no upstream network requests and do not replace snapshot roles with current SQL assignments. Removing DCR registration alone does not revoke an existing access grant.

## Authentication, storage and errors

The native verifier requires the configured issuer, trusted EdDSA key, API audience, access `token_use`, valid time and Original deadline. A private profile path accepts the OP's signed resource binding without relaxing the public verifier's `auth.resource`. The SQL access row must match signed JTI, subject, client, audience, resource, exact expiry and scopes; the stable subject must match the stored principal.

Unknown, expired, revoked or mismatched grants return `401 invalid_token`. ID/refresh tokens and unrelated credentials cannot authenticate. Missing credentials return a Bearer challenge without error details. Responses use `Cache-Control: no-store` and `Pragma: no-cache`. Existing declared-origin CORS exposes `WWW-Authenticate` without credentialed browser access.

The PostgreSQL operation locks LOCAL user before token, rereads immutable token data, updates `last_used_at` and returns only after known COMMIT and another proof/deadline check. SQL, malformed stored data and read-limit failures return `500 server_error`; deadline returns `504 temporarily_unavailable`; closed storage or uncertain COMMIT returns `503 temporarily_unavailable`. Failure responses contain no credentials, profile or SQL diagnostics.

UserInfo is an explicit profile operation. JWT consumers keep local verification until `exp`; [revocation](rust-oidc-revocation.md) does not make UserInfo an authentication gate. Current resource grants remain separate checks on consequential operations. OIDC disabled gives `404` for this route and both well-known documents. [Introspection](rust-oidc-introspection.md) is a separate productive grant operation. End-session still needs its native delivery.

## Implementation and focused checks

Control owns `service/oidc_userinfo.rs`, the shared strict principal parser and current LOCAL identity reader. Presence owns `oauth_userinfo.rs`; Server runtime mounts it with the common store/verifier/upstream trust owner and advertises only the productive route.

The existing Rust qualification runner includes the same invocation across supported operating systems:

```text
cargo test --locked --offline -j4 -p broker-server --test oauth_userinfo -- --ignored --test-threads=1
```

The fixture uses the actual executable, configured signing key, PostgreSQL TLS NOSUPERUSER, genuine LOCAL and HTTPS upstream grants, SQL failures, deadline/cancellation, and durable COMMIT with withheld ACK. A runner guardrail proves actual failing Rust tests block later phases. A maintained command alone does not prove every platform ran it.
