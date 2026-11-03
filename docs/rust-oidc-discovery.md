---
title: Native Broker OIDC discovery
description: Public literal issuer, exact capabilities and discovery-driven native OAuth endpoints.
doc_type: reference
references:
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7568, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native Broker OIDC discovery

Operators and client integrators of the [native PostgreSQL server](rust-broker-server.md)
can discover its configured public issuer and productive OAuth endpoints. Enable the
existing [OIDC configuration](rust-oidc-token-exchange.md#enable-the-productive-endpoint);
no separate discovery switch, signing key or SQL store is created.

| Route | OIDC enabled | OIDC absent/disabled |
|---|---|---|
| GET/HEAD `/.well-known/graphit-broker` | Public Graphit JSON | Services-only Graphit JSON when a service is enabled, otherwise 404 |
| GET/HEAD `/.well-known/openid-configuration` | Public OpenID JSON | 404 |
| GET/HEAD `/v1/oidc/keys` | Existing public verification keys | Existing public verification keys |

Graphit discovery advertises enabled embeddings, rerank and S3 credential services
independently of OIDC. With OIDC disabled, its JSON uses the configured public URL as
`issuer` and omits `authentication`. Enabled storage advertises STSv3 at
`/v1/s3/credentials`. The endpoint still requires authentication and authorization.

Both discovery responses use the static JSON GET behavior: HEAD200 has matching headers
and no body. Equality covers application headers, including Content-Type/CORS and any cache
or security headers. Date and message framing are checked separately: the existing timeout
layer produces chunked GET responses, while HEAD omits transfer framing, as permitted by
[RFC9110 section9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2) and
[RFC9112 section6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1).
They capture only public configuration and do not access SQL, authenticate
a request, create a grant or renew a lease. The [authorize/login transport](rust-oidc-browser-authorization.md)
has different semantics: HEAD405 prevents effects. Public values come from validated
configuration, including behind a reverse proxy; Host and the listen address do not
select the issuer or advertised endpoints. No new cache TTL is introduced.

## Configure one literal issuer and explicit resources

With OIDC enabled, `auth.issuer` must equal `server.public_url` byte for byte. A trailing
slash, host case change or explicit default port is a mismatch even when a URL parser
would consider the origins equivalent. Startup and `--check-config` fail before SQL or
listeners with `OIDC requires auth.issuer to equal server.public_url literally`. Correct
the two settings to the same intended public origin; the server does not rewrite tokens
or normalize configuration to accept a mismatch. The URL must be a safe configured origin:
HTTPS, or HTTP on localhost/loopback, without userinfo, path beyond `/`, query or fragment.
When OIDC is disabled, the Native issuer can remain independent of the public URL.

`oidc.accepted_resources` is required when enabled. Each item must already be a nonempty,
unpadded, unique resource accepted by the authorization policy. Startup rejects empty
items, leading/trailing whitespace and duplicates with a diagnostic naming that setting.
The literal empty list `[]` is valid. Discovery publishes this accepted list unchanged as
`authentication.mcp_resources`, in configured order. Neither metadata nor the server
injects its own `/v1` resource. The direct P2 library policy retains its existing semantics
for other callers, including requests without an extra resource.

The Web consumer derives its resource as `endpoint.trim_end_matches('/') + "/v1"`.
For an endpoint `https://broker.example.test/`, explicitly include
`https://broker.example.test/v1` in `accepted_resources` if that consumer will request it.
An unconfigured resource remains `invalid_target`; discovery is not authorization.

The Graphit Rust consumer reads the Graphit document first and the OpenID document second,
without substituting one for the other. For configured CLI `graphit-cli`, callback
`/oauth/callback`, audience `storage-api`, and the one explicit resource above, Graphit JSON is:

```json
{
  "version": "1",
  "issuer": "https://broker.example.test",
  "authentication": {
    "type": "oidc",
    "issuer": "https://broker.example.test",
    "client_id": "graphit-cli",
    "scopes": ["openid", "profile", "email", "offline_access"],
    "audiences": ["storage-api"],
    "access_token_audience": "storage-api",
    "redirect_uri_path": "/oauth/callback",
    "mcp_resources": ["https://broker.example.test/v1"]
  }
}
```

Only the Broker's own configured API audience is advertised. Upstream verifier audiences
are separate trust and are not combined into this list. CLI ID and callback path come from
the same configured policy; discovery supplies no new defaults.

## Follow the productive endpoints

The OpenID document retains that exact issuer. Endpoint construction removes only trailing
`/` from the configured public URL and appends these productive paths:

| Field | Path | Availability |
|---|---|---|
| `authorization_endpoint` | `/oauth/authorize` | OIDC enabled |
| `token_endpoint` | `/oauth/token` | OIDC enabled |
| `end_session_endpoint` | `/oauth/end-session` | OIDC enabled; signed ID hint disposal |
| `revocation_endpoint` | `/oauth/revoke` | OIDC enabled; public-client authentication `none` |
| `jwks_uri` | `/v1/oidc/keys` | Existing Native key owner |
| `registration_endpoint` | `/oauth/register` | OIDC and dynamic registration enabled |

When DCR is disabled its field is absent and the registration route returns404. The document
advertises productive [UserInfo](rust-oidc-userinfo.md) at `/oauth/userinfo` and [introspection](rust-oidc-introspection.md) at `/oauth/introspect`. Introspection advertises `introspection_endpoint_auth_methods_supported: ["Bearer"]`, the registered access-token type allowed by RFC 8414. [End-session](rust-oidc-end-session.md) is advertised at `/oauth/end-session`, with mandatory signed ID hint and no redirects. Its [revocation endpoint](rust-oidc-revocation.md)
uses `revocation_endpoint_auth_methods_supported: ["none"]`. Advertised
capabilities are `code`, Query/Fragment/FormPost modes, `authorization_code` and `refresh_token`,
public subjects, EdDSA ID tokens, token client authentication `none`, and S256. The advertised
scopes are the four CLI/DCR scopes above; the six internally admitted P2 scopes do not enlarge
that public list. No RS256, implicit flow or complete OP certification is claimed.

Use the discovered registration URL for [DCR](rust-oidc-registration.md), then the discovered
authorization URL for genuine [LOCAL or upstream sign-in](rust-oidc-browser-authorization.md).
Redeem its code with the same PKCE verifier and requested resource at the discovered token
URL. [Refresh rotation](rust-oidc-refresh.md) uses that same endpoint. Fetch the announced JWKS
and verify EdDSA, exact expected issuer, configured API audience, time and relevant claims;
do not infer the trusted issuer from the token being verified. JWKS shares the configured
signer and exposes public keys without private `d` material.

## Focused qualification

The native fixture uses the actual Rust executable, PostgreSQL TLS with a NOSUPERUSER owner,
real LOCAL password admission and signature verification from HTTP-fetched JWKS. It reads both
documents in order, follows their URLs through DCR, authorize/login, code, token and refresh,
and then removes its PostgreSQL service before repeating static GET/HEAD reads. Separate
profiles cover OIDCoff with independent Native issuer/JWKS, DCRoff and literal empty resources.
The ordinary native `--check-config` matrix covers literal issuer differences and invalid
resource lists without SQL/listener effects. This is server proof; external Auth integration,
other OP deliveries and whole-system release qualification remain with their owners.

Run the ordinary matrix and focused native journeys:

```text
cargo test --locked --offline -j4 -p broker-server --test oidc_discovery -- --test-threads=1
cargo test --locked --offline -j4 -p broker-server --test oidc_discovery -- --ignored --test-threads=1
```

The existing `xtask` pre-commit phase includes ordinary tests; its pre-push sequence saves the
second invocation before audit. A runner oracle uses a real failing Rust test for each native
journey and checks that failure prevents later phases. The focal invocation is the same on
Linux, Windows and macOS; executed Linux evidence does not qualify the other platforms. No
test or saved gate authorizes a push.

## Device availability

When the native OIDC and LOCAL login runtimes are operational, OpenID discovery also
publishes `device_authorization_endpoint` as the configured absolute `/oauth/device/authorize`
URL and includes `urn:ietf:params:oauth:grant-type:device_code` in `grant_types_supported`.
LOCAL disabled omits both while preserving Code and refresh. Disabling OIDC removes OpenID discovery and device authorization. See [Device sign-in](rust-device-authorization.md) for empty scope,
explicit consent, access-only tokens and qualification status.
