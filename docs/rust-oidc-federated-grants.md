---
type: document
title: Native Rust federated OAuth grants
description: Genuine upstream proof, Broker code, token exchange and refresh trust.
references:
  - target: {type: task, id: tsk-a225, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-06cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native Rust federated OAuth grants

The explicit [SQLite federated composition](rust-sqlite-oidc-federated.md) now
connects genuine H1 proof to its IMMEDIATE authorization/code/refresh producers.
It retains actual `Arc` trust owners, revision-zero snapshots, current trust and
absolute refresh-family semantics. Its public HTTP journey does not establish native Server SQLite selection or SQLite Admin upstream login.

The PostgreSQL server composes genuine [upstream browser proof](rust-upstream-browser-login.md)
with [Broker authorization](rust-oidc-authorization.md), code exchange and refresh
at `POST /oauth/token`. The [shared upstream callback](rust-oidc-browser-callback.md) connects genuine H1
OAuth flows to this producer and protected query/fragment/form_post responses,
independently of Administration. Public authorize/login pages and discovery
remain separate integration work.

## Complete authentication

Create a pending request with the actual Broker client, redirect, resource, state,
nonce and S256 challenge. H1 stores the protected OAuth continuation and performs
its own state/browser-binding/PKCE/nonce/ID verification. Then call:

```text
service.complete_upstream(login, &upstream_verifier, original)
    -> Result<AuthorizedOidcAuthorization, OidcAuthorizationError>
```

The by-value `VerifiedUpstreamLogin` must belong to that verifier owner, have
purpose OAuth and remain unexpired. The service takes the request exclusively
from the proof. It locks and revalidates the current Broker client and exact
pending request. A conditional update, known COMMIT and final proof/UTC/Original
checks precede code output; concurrent completion has one winner. Effective
Original cannot exceed the proof deadline or the store operation budget.

The upstream browser client and the public OAuth client registered at the Broker
have separate bindings. H1 preserves its channel checks. Broker grants do not
persist an upstream channel identifier or replace their local client/resource/redirect.

## Identity, roles and trust

Federated mapped subject and username preserve authenticated H1 bytes, including
Unicode and external spaces: nonempty after trim, without NUL, within actual H1,
document/SQL and configured digester bounds. LOCAL retains canonical identities
and its existing 512-byte subject rule. No normalization changes identity.

Raw mapped subject stays in the private stored identity fields. Code and JWT use
the existing domain-15 HMAC with separately framed issuer and subject. LOCAL
supplies issuer `local`; federation supplies the literal upstream issuer. JWT
`iss` remains the configured Broker issuer. LOCAL and two upstream issuers with
the same mapped subject have distinct native subjects. PROJECT uses verified
Broker issuer/native subject, never an unverified profile DTO.

Roles retain the authenticated claim snapshot plus implicit deduplicated `user`.
No selector and an authenticated empty result both yield `user` only, retaining
distinct provenance. SQL assignments do not supply fallback roles for this journey.
Administrative session policy remains separate.

Native codecs distinguish LOCAL (`local-token`, positive revision) from federation
(`oidc`, revision zero), rejecting duplicate/unknown/missing/trailing/incoherent
fields. Row subject and revision must match. The [grant reader](rust-oidc-access-grants.md)
remains DATA and never exposes a fabricated current LOCAL user for federation.

Completion, code and refresh require the literal issuer to remain enabled with
at least one OAuth browser client. Removing one while another remains preserves
eligibility; removing the last or disabling the issuer denies new code/refresh.
Adding, changing or removing the literal role selector requires a fresh login.
Profile and roles are not fetched or reinterpreted during refresh.

Library producers attach the borrowed common verifier with `with_upstream`;
without it federated grants are denied. The server reuses its existing upstream
owner. Browser configuration requires an active Admin cookie owner or enabled OIDC.
Token operation works without administration; current Admin routes still require
their cookie owner.

## Tokens, atomicity and LOCAL isolation

Initial ID AMR is `["federated"]`; refresh AMR is `["oidc"]`. Completion captures
fresh UTC `auth_time`; refresh preserves it, the family and absolute refresh expiry.
Access/ID TTL remains 600 seconds by default with existing overrides. No sliding
refresh lifetime or new upstream authentication time is inferred.

Current Broker client/resource/redirect/S256 guards precede code consumption.
Refresh trust, client and narrowing guards precede rotation/reuse effects.
LOCAL retains the strong user-row lock. Federated generations share a PostgreSQL
transaction advisory lock derived from their existing family identifier; hash
collisions only serialize unrelated families. Ancestor reuse cannot finish ahead
of descendant insertion and leave an active child.

LOCAL password changes and MFA enrollment revoke positive-revision LOCAL tokens
and remove LOCAL or untyped requests. Genuine authorized federated requests and
revision-zero grants survive even when raw subjects collide. Syntactically invalid
request JSON produces a finite error and whole-transaction rollback, including
password, revision, factors, tokens and challenges.

Issued access JWTs remain locally verifiable until original expiry. Trust removal
and family revocation do not introduce a blacklist, per-request UserInfo or network lookup.
Existing [HTTP errors/body/CORS bounds](rust-oidc-token-exchange.md) and
[refresh reuse rules](rust-oidc-refresh.md) apply. An ambiguous COMMIT returns
`OutcomeUncertain` with no code/token output; do not infer rollback or replay automatically.

## Qualification boundary

Real contracts reuse PostgreSQL TLS with an ordinary owner, Rust HTTPS H1 issuer
and the native Broker process:

```text
cargo test --locked --offline -p broker-control --test postgres_oidc_federated -- --ignored --test-threads=1
cargo test --locked --offline -p broker-server --test oidc_federated -- --ignored --test-threads=1
cargo test --locked --offline -p broker-control --test postgres_local_auth -- --ignored --exact postgres_local_invalidation_preserves_federated_grants --test-threads=1
```

Valid JSON with escaped NUL in authorization state or nonce remains valid.
LOCAL invalidation reads one relevant TEXT request at a time under SQL row locks;
a minimal borrowed Serde projection identifies the native federated discriminator.
Malformed JSON rolls back the same transaction. The existing Original is checked
between reads and effects; this operation adds no configuration quota or API.
