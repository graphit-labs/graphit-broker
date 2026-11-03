---
title: Rust upstream browser login producer
doc_type: reference
references:
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-06cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-a729, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9a99, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Rust upstream browser login producer

The explicit [SQLite H1 composition](rust-sqlite-oidc-federated.md) uses the same
protected proof and SDK over matching physical SQLite flow consumption. It does not select SQLite in Server or provide SQLite Admin upstream login.

For server integrators using `broker-control`.
This library authenticates an upstream browser identity through a real OIDC
code exchange and a matching one-use PostgreSQL flow. Its private proof is the
input for the [federated cookie consumer](rust-admin-federated-cookie.md). The current native executable
supports [federated resource bearer sessions](rust-admin-upstream-session.md)
and [LOCAL browser login](rust-admin-local-login.md). The [native browser HTTP adapter](rust-admin-upstream-login.md)
accepts `auth.oidc[].browser_clients` and composes this proof with H2 cookie issuance.
The [shared callback](rust-oidc-browser-callback.md) also dispatches genuine OAuth flows
to the native federated grant producer; public authorize/login pages and discovery
remain separate deliveries.

## Configure one trust owner

Construct `UpstreamProviderConfig` for each configured issuer and pass its
`browser_clients: Vec<UpstreamBrowserClient>` to `UpstreamBearerVerifier::new`.
Browser clients borrow the same provider, Reqwest transport, discovery/JWK cache
and claim selectors as resource authentication. There is no second registry or
fallback issuer. Browser client configuration is data, not authenticated authority.
All existing provider byte/count limits, timeouts and TLS policy are explicit;
see [the bearer provider reference](rust-admin-upstream-session.md).

| Browser field | Contract |
|---|---|
| `display_name` | Trimmed label, 1–80 Unicode characters in letter, mark, number, punctuation, symbol or space-separator categories. Control characters fail preparation. |
| `client_id` | Exact protocol client ID, nonempty after trim and without NUL. |
| `client_secret` | Optional confidential client secret. Its owned string is zeroized on drop and Debug is redacted. |
| `redirect_url` | Exact registered HTTPS callback, or HTTP on a loopback host. Credentials, fragment and untrusted URLs fail preparation. |
| `scopes` | Configured ASCII OAuth scope tokens; the authorization URL always includes `openid`. Omission supplies no extra scopes. |
| `require_nonce` | Defaults to `true`: send and compare nonce. Explicit `false` omits both, retaining SQL state, browser binding and S256 PKCE. |
| `claims_source` | Defaults to `id_token`; accepts `id_token`, `access_token` or `userinfo`. Every mode requires a verified ID token. |
| `id_token_additional_audiences` | Explicit additional ID-token audiences trusted by this browser client. Omission is the SDK's strict policy with no extra audience. |

The defaults above apply to typed deserialization; a Rust struct literal supplies
its fields explicitly. Unknown fields, invalid types and duplicate browser IDs
fail before network or SQL work. Options preserve configured order and expose only `id` and `name`.
The public ID is `oidc_` followed by unpadded base64url of the first 12 SHA256
bytes over trimmed issuer without trailing `/`, NUL, and trimmed client ID.
This identifies a configured browser choice; it never selects trust from an
untrusted callback issuer parameter.

## Begin, then consume the matching flow

Borrow `let logins = store.upstream_logins(&verifier)` from an opened
[PostgreSQL control store](rust-postgres-control.md). Choose a configured option
with `verifier.browser_options(original)`, then call
`begin(FlowContinuation::Admin { provider_id }, original)`. `original` is the
caller's absolute monotonic deadline. The OAuth continuation also carries a
protected request ID for the OP callback consumer; H1 itself does not create a grant.

`begin` obtains fallible OS entropy: 32 bytes each for state, nonce and browser
binding, and 48 bytes for the PKCE verifier. State adds an `admin.` or `oauth.`
budget hint before its 43-character random suffix. The complete 49-character
state is hashed and consumed; binding and nonce retain their existing sizes.
The hint never proves a purpose: the matching SQL continuation must agree before
SDK exchange or dispatch. See [the shared callback contract](rust-oidc-browser-callback.md). It uses mature OAuth URL/PKCE
builders and the existing ten-minute `OidcFlow` SQL contract. The internal nonce
still exists when nonce policy is false. Raw state and binding are digested in
separate credential domains before persistence; nonce and verifier reside in the
protected SQL row. Owned Rust nonce/verifier/state/binding strings are zeroizing;
this does not promise wiping database or SDK/driver copies.

Only an acknowledged INSERT COMMIT and final time gates return
`IssuedUpstreamAuthorization`. This private, non-Clone value exposes the
location, state, browser binding, expiry and `check()`. The [native HTTP adapter](rust-admin-upstream-login.md) must
retain the genuine binding and continuation and deliver the authorization URL
within those gates.

Call `complete(state, browser_binding, UpstreamLoginCallback::Code(code), original)`
for a successful callback, or the typed `ProviderError` variant for an upstream
error. A matching SQL row is locked, validated and consumed by one acknowledged
DELETE COMMIT before the SDK exchange starts. Wrong binding preserves the row;
replay and concurrent callbacks have at most one consumer. No caller can turn
an isolated `OidcFlow`, profile JSON or fabricated metadata into a proof.

## Verify protocol and identity

The authorization request uses S256 PKCE. Token exchange and ID verification use
`openidconnect =4.0.1`. Confidential authentication is selected once from
advertised Basic/Post methods; public clients use their exact client ID without
secret. There is no client-authentication retry or automatic code replay.
Discovery, token and UserInfo use the common bounded transport with certificate
verification and no redirects. Provider policy permits upstream HTTP only for
explicit loopback trust.

The ID token must have an allowed asymmetric algorithm, valid trusted signature,
exact issuer, required client audience, configured nonce policy and valid
`exp`/`iat`/`nbf`. A present `azp` must match the client; multiple audiences require
matching `azp`. Extra audiences require the explicit trust list. A present
`at_hash` is verified through the mature SDK. Without `kid`, CoreOIDC selects one
eligible key and rejects multiple eligible keys as ambiguous; no custom bypass
of that SDK policy exists. The shared provider cache retains trusted JWKs without `kid`; unrelated
algorithms do not make those keys eligible for an ID token. The mature SDK
selects a unique eligible key, preserving its ambiguity rejection. Identified
keys keep the existing duplicate-ID rejection and rotation selector. Unknown keys may refresh the same configured cache,
respecting its refresh interval, without repeating token exchange.

For `access_token`, the JWT is exclusively the token returned by this successful
PKCE exchange. Its signature, allowed asymmetric algorithm, issuer, temporal
claims and raw `sub` are verified against the same trusted provider keys. Raw
subject must match the verified ID token. With no `kid`, only the bounded set
of trusted eligible keys is tried. Its profile-service audience is not inferred
from a Graphit resource audience or browser client ID: flow, endpoint and ID
client binding establish this producer's purpose. This private path cannot admit
a caller-supplied resource Bearer or grant resource permissions; F1 resource
policy remains strict.

For `userinfo`, query the discovered endpoint once only if selected profile
attributes are missing from the verified ID token. Username, name, email,
organization and teams may be supplemented; present values are retained, and
invalid present values fail before fetching. Raw subject must match the ID token.
Subject and claim roles always come from the verified ID token or configured
verified access JWT, never UserInfo. There is no profile fetch during session
GET, renewal, revocation or validity checks.

Mapping reuses the common selectors and byte/count caps. `profile.subject` is
the mapped subject; the canonical RBAC identity combines the configured issuer
with that mapped subject as `issuer|subject`. Raw `sub` only binds token sources.
No external username maps an identity to a LOCAL account. Selected role labels
are checked, but this producer does not assign permissions or create sessions.

## Proof, errors and recovery

A successful `VerifiedUpstreamLogin` has private fields and no Clone, Default,
Serialize or Deserialize implementation. It retains protected purpose,
continuation, binding, issuer, mapped profile/attributes/roles and expiry. Data
getters do not manufacture a new proof. A private marker retains the producing
trust owner identity; issuer/client strings cannot substitute another owner with
different keys or claim policy. Consumers must call its final `check(&verifier)`
and consume the genuine value according to their own authorization contract.

Its observed UTC/monotonic expiry pair is captured after ID verification and
bounded by relevant ID/access/flow expiry plus the flow's immutable monotonic
limit. The original caller deadline remains unchanged. Slow token issuance can
produce legitimate fresh `iat`; future `iat`/`nbf` remains invalid. Later I/O never
extends proof lifetime or grants a new budget. Consumer cookie lifetime is a
separate contract, not the upstream token expiry or an implicit renewal.

Failures are finite: `InvalidProvider`, `InvalidState`, `InvalidIdentity`,
`ProviderError` or `Control(ControlError)`. Debug and Display omit tokens and
credentials. A continuation is returned only after known matching flow
consumption, enabling the callback adapter to select a protected error destination. No authority
is returned on error. Missing supplementary profile data is an infrastructure/
data failure; invalid identity claims remain identity failures.

`OutcomeUncertain` takes priority once SQL COMMIT was sent without a known ACK.
The row may already exist or be consumed. Never infer rollback, repeat the SDK
exchange, or recover authority from metadata. Start a new login flow through the
normal producer after checking service health. Cancellation drops the leased
physical connection; shutdown joins the owned store under its existing budget.

## Executable verification

These saved commands run from the Broker project on Linux, Windows or macOS;
Docker and usable PostgreSQL/TLS fixtures are required. A missing runtime is a
failure, not a skipped success.

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_upstream_login -- --ignored --exact postgres_upstream_login_contract --test-threads=1
cargo test --locked --offline -j4 -p broker-control --test postgres_upstream_login -- --ignored --exact postgres_upstream_login_uncertainty_contract --test-threads=1
```

The owned Rust HTTPS issuer performs real browser authorization, one-use code,
public/Basic/Post client authentication, PKCE verification, signed ID/access
JWTs, discovery/JWKS and UserInfo. The ordinary SQL role is NOSUPERUSER. Tests
cover ID/access/missing-profile flows, nonce false, explicit audience trust,
rotation, invalid trust/claims/types, caps, insecure discovery, wrong binding,
replay and concurrent consumption. The uncertainty case withholds TLS replies
only after PostgreSQL reports the exact connection's COMMIT idle and committed
row state, then checks absence of authority/SDK replay and healthy recovery.
It also exercises caller Drop, Original deadline and expiry during UserInfo.

The two exact commands are saved before PROJECT/Presence/audit phases in xtask pre-push. The runner's adversarial fixture uses real failing Rust tests to verify later phases do not execute. Run the hook through `cargo run --locked --offline -p xtask -- hook pre-push` only for a scheduled full integration; invoking a hook never authorizes `git push`. Affected ordinary/doc tests, Clippy, fmt, F1 native HTTP and link checks accompany this adapter. Linux execution does not establish other-platform runtime support or complete integration.

Implementation owners: `crates/broker-control/src/upstream_login.rs`,
`crates/broker-control/src/service/upstream_login.rs` and
`crates/broker-control/src/upstream_oidc.rs`. Runtime contract fixture:
`crates/broker-control/tests/postgres_upstream_login.rs`.
