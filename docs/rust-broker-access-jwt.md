---
title: Rust Broker access JWT authentication
description: Local authentication of Broker-issued Ed25519 access tokens, immutable trust and expiry boundaries.
references:
  - target:
      type: task
      id: tsk-dcdb
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-bf2f
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: implements
  - target:
      type: task
      id: tsk-3582
      scope: project
      scope_id: 01KSH1CRFFG8Z74B5ZS78WW808
    relation: supports
---

# Authenticate a Broker access JWT locally

The server API in [broker_access.rs](../crates/broker-control/src/broker_access.rs)
authenticates the access token using an explicitly configured trusted issuer, API
audience, optional resource audience and Ed25519 public keys. Authentication performs only
local signature, claims, scope, expiry and request deadline checks. It performs no
SQL, UserInfo, introspection, blacklist, discovery or JWKS network request.

The resulting identity is the signed canonical Broker issuer and subject. It does
not recover an upstream identity through a token identifier. A signed, nonempty
client identifier is accepted as the Broker issuer's issuance attestation until
expiry. The Auth Web client independently checks its captured registered client
identifier; endpoint-specific client restrictions remain the endpoint's concern.

## Supply trusted configuration

Construct BrokerAccessVerifier with all five explicit inputs:

~~~rust
use broker_control::{BrokerAccessError, BrokerAccessVerifier};
use jsonwebtoken::jwk::JwkSet;
use std::num::NonZeroUsize;

fn configured(
    issuer: &str,
    api_audience: &str,
    resource: Option<&str>,
    trusted_jwks: &JwkSet,
    token_bytes: NonZeroUsize,
) -> Result<BrokerAccessVerifier, BrokerAccessError> {
    BrokerAccessVerifier::new(issuer, api_audience, resource, trusted_jwks, token_bytes)
}
~~~

The configuration/OP key owner supplies this already resolved, trusted snapshot.
Never pass request-provided keys or fetch URLs from a token header. Issuer, API
audience and key set must be nonempty. Resource is an explicit option:
`Some(resource)` requires a nonempty resource and its exact audience binding;
`None` imposes no resource binding and never substitutes the API audience or
another default resource. API audience validation remains mandatory in both
modes. The byte limit must be nonzero
and no larger than isize::MAX. The verifier defines no default issuer, audience,
TTL, quota or cache.

Every key requires a unique nonempty kid, OKP type, Ed25519 curve, and a Base64
URL no-padding public x of exactly 32 decoded bytes. If present, alg must be
EdDSA, use must be sig, and key_ops must be exactly [verify]. A bad key rejects
the entire configuration; keys are never silently skipped.

Rotation replaces the verifier snapshot at the configuration boundary. An
overlap snapshot may contain old and new keys with distinct identifiers; after
removing the old key, new verifications reject its tokens. An already returned
proof retains its verifier borrow and remains valid until its expiry/deadline.
This library does not implement a configuration watcher, JWKS fetcher or OP
signing-key producer.

## Verify and consume the identity

Call verify(raw_bearer, required_scopes, original_deadline). It returns a
VerifiedBrokerAccess borrowing the verifier. The proof has private fields and no
public constructor, Clone, Default or Deserialize. It stores no bearer or private
key; Debug and the finite errors redact token and identity material.

Readonly accessors expose issuer(), subject(), client_id(), username(),
organization(), teams(), scopes(), expires_at() and authentication_expiry(). Call check() again before
using a retained proof: it checks the captured request deadline and both UTC and
monotonic expiry. Verification never renews either deadline. It rechecks the original deadline before returning either success or a decoding, signature or scope error.

Compact tokens require exactly three nonempty segments. Header alg must be
EdDSA and kid must select a configured key. Header presence of crit, b64, jku,
x5u, jwk or x5c is rejected even when null. JSON object roots and unique root
fields are required in both header and payload, including extension fields;
malformed known fields and trailing JSON are rejected.

The signed payload requires:

| Claim | Contract |
| --- | --- |
| iss | Exact configured Broker issuer string |
| sub | Nonempty canonical Broker subject string |
| aud | Nonempty string, or nonempty array of unique nonempty strings; contains the API audience exactly and also the resource when configured as Some |
| iat, exp | Unsigned integer NumericDates; iat no later than now, exp after now and iat |
| nbf | Optional; when present must be an unsigned integer no later than now; null is invalid |
| token_use | Exactly access |
| client_id, jti | Nonempty strings |
| scope | String; literal scope tokens separated by ASCII spaces |
| preferred_username | Optional string; absent, null or empty becomes None |
| organization | Optional string; absent/null becomes None; an empty string is retained |
| groups | Optional string array; absence becomes empty; null or non-string entries are rejected |

A configured resource is carried in aud; there is no invented resource claim.
With `None`, a scalar audience equal to the API audience or a valid array containing
it is sufficient. With `Some(resource)`, a scalar can satisfy both checks only
when the API audience and resource are identical; an array must contain both
exactly. The verifier never changes signed claims to accommodate configuration.
Unknown extensions are accepted but confer no authority.
In particular, name, email and roles do not grant permissions.

All explicitly required scopes must match signed scope tokens exactly. Write
does not imply read. An empty required list imposes no implicit scope policy.
Empty or ASCII-space-containing required scope items are invalid configuration.

The actual Broker token uses token_use to distinguish access from ID tokens.
The verifier accepts its JWT or absent typ header and does not require an
unissued at+jwt type or claim full RFC 9068 conformance.

## Expiry and authorization are separate

Signature validation uses jsonwebtoken 11.1.0 with aws_lc_rs, EdDSA only, explicit
issuer/audience validation and zero time leeway. Typed NumericDates supplement
the SDK's validation. UTC and monotonic expiry conversions use checked arithmetic.

A valid signed JWT is authenticated locally until exp. Revocation, account
disablement, changed claims or removal of an approved client may take until that
expiry to affect authentication. The observed OP default is ten minutes with a
configurable range of one minute to one hour; this verifier enforces the signed
exp and introduces no independent TTL.

PROJECT authorization must separately read current SQL permissions for each
request and match the authenticated signed identity against the requested
project/module/action. A JWT scope or role never grants PROJECT access.
[Local PROJECT authorization](rust-project-authorization.md) consumes the opaque
identity; [Native Broker PROJECT authorization](rust-broker-project-authorization.md)
combines this signed principal with current SQL permissions. This verifier
alone does not qualify that bridge, OP login/refresh, Records or the full Broker.

## Errors and qualification

| Error | Caller action |
| --- | --- |
| InvalidConfiguration | Repair explicit configuration/key metadata or required scopes before serving requests |
| InvalidToken | Reject the bearer without exposing decoded token or SDK diagnostics |
| Expired | Reject the expired token; let the owning client use its normal renewal flow |
| InsufficientScope | Reject this operation; request the appropriate explicitly issued scope |
| Deadline | Stop the request; do not renew its original deadline |

[The tests](../crates/broker-control/tests/broker_access.rs) generate actual
Ed25519 key pairs with rcgen and sign tokens using jsonwebtoken. Negative codec
cases are signed by the same mature SDK, so duplicate/malformed claims and
forbidden header fields reach the real verification boundary. Tests exercise
wrong signatures, tampering, strict configuration, key rotation, audience,
purpose, optional attributes, scope denial, actual expiry/deadline and raw byte
limits without SQL or network fixtures.

Run these affected commands from the Broker workspace, serially with one Cargo
job when sharing the checkout:

~~~text
cargo test --locked -j1 -p broker-control --test broker_access
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
~~~

Successful affected runs establish the local verifier behavior on their executed
host. They do not establish native PostgreSQL, HTTP JWT integration or other host platforms. Full integration
qualification belongs to the migration coordinator.

The [authentication expiry observer](rust-authentication-expiry.md) exposes the original verifier UTC/monotonic pair so transport consumers can bound waits without reconstructing or renewing it.
