---
references:
  - target: {type: task, id: tsk-6414, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-bf2f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e52a, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---
# Broker access JWT issuer

Audience: Broker server protocol maintainers and native integration maintainers.
BrokerAccessIssuer owns an explicitly supplied PKCS#8 Ed25519 private key,
issuer, API audience and kid. It signs typed access claims and exposes matching
public JWKS. The [public PROJECT fixture](rust-broker-project-authorization-fixture.md)
consumes this implementation immediately; its tokens reach the actual
[local verifier](rust-broker-access-jwt.md) and PROJECT HTTP/SQL authorization.

## Key ownership and public trust

Call BrokerAccessIssuer::new(issuer, api_audience, kid, pkcs8_der). All configuration
strings are required and must not be whitespace-only. Accepted strings are
preserved exactly. The [native server](rust-broker-server.md) supplies the explicit key and kid;
this library performs no file access, generation, pepper derivation, discovery,
rotation controller or public-key retention. The [productive code producer](rust-oidc-token-exchange.md)
uses that shared owner; the complete OAuth provider remains separate work. Production access TTL remains
10 minutes by default, configurable from 1 minute to 1 hour; this primitive
receives explicit NumericDate values and does not apply a test TTL as a default.

The existing jsonwebtoken 11.1.0 AWS-LC backend validates unencrypted Ed25519
PKCS#8 and extracts its public key through SDK key utilities. The public key
builds a typed Jwk with kty=OKP, crv=Ed25519, alg=EdDSA, configured kid, use=sig
and key_ops=[verify]. jwks() borrows one immutable public JwkSet. It contains no
private seed, DER or d field. The owner retains an SDK EncodingKey that zeroizes
its private DER on Drop. The caller remains responsible for its original input
buffer; transient fixture DER is held in Zeroizing. The owner cannot be cloned
or serialized and its Debug output is redacted.

The [official SDK key utilities](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/crypto/aws_lc/mod.rs)
parse PKCS#8 through AWS-LC. Jwk::from_encoding_key in that SDK version assumes
a 48-byte Ed25519 DER representation, so this owner extracts the public key
through the backend and constructs Jwk from a public DecodingKey. It does not
implement ASN.1 or a JWS encoder. SDK encode supplies the JWT signature and
[EncodingKey owns zeroizing private bytes](https://github.com/Keats/jsonwebtoken/blob/v11.1.0/src/encoding.rs).

## Explicit access claims

sign_access(input, original_deadline) accepts BrokerAccessTokenInput, a borrowed
cryptographic data structure. Required fields are subject, client_id, scope,
jti, issued_at and expires_at. Resource is explicit `Option<&str>`: `None` issues
only the API audience; `Some` adds the admitted literal resource. Optional fields are preferred_username,
name, email and organization; groups and roles are explicit string slices.
The input supplies no issuer, API audience, signing algorithm, kid or token_use.
Those come from the configured owner; token_use is access and the header uses
EdDSA and its configured kid. There is no arbitrary extension-claim map.

subject, client_id and jti must be nonempty; a present resource must not be whitespace-only.
Scope is preserved exactly, including an empty string. Audience is an array
containing the configured API audience and optional supplied resource, with one entry
when absent or equal. No additional resource claim or audience is inferred.
Absent optional fields and empty groups/roles slices are omitted; present values
remain signed, including empty organization. An empty preferred_username remains
signed and the existing verifier normalizes it to absence.

issued_at/expires_at are integer UTC seconds. issued_at cannot exceed the current
clock; expires_at must exceed issued_at and the current clock. Checked UTC and
monotonic expiry arithmetic reject overflow. The same captured deadline is
checked before and after CPU work, including rejected inputs. No bearer is
returned if signing crosses its expiry or deadline. Errors are finite
InvalidConfiguration, InvalidClaims, Signing and Deadline with static redacted
messages. A missed deadline takes precedence over the inner result. The returned
String is a bearer credential: keep it private and never persist it in logs,
Task records or qualification receipts.

## Grant admission and concrete consumers

This signer establishes cryptographic integrity only. Its data input is not an
authentication proof, authorization grant or permission to issue tokens. The
[stored OIDC reader](rust-oidc-access-grants.md) also remains DATA. A production
protocol producer must authenticate the principal, authorize the request and
bind the client, redirect, PKCE, resource and negotiated scopes before invoking
this primitive. The subsequent native server path is authenticated grant
admission, confirmed one-time SQL code consumption, then this signer and a typed
OIDC ID-token producer. Those admission/HTTP/startup producers are still pending;
no discovery metadata advertises nonexistent OAuth endpoints.

The current fixture generates a test Ed25519 key with its existing dev-only rcgen,
passes PKCS#8 and the explicit fixture kid to this owner, obtains public JWKS,
and signs its captured issuer/API/client/resource/subject/scope with explicit
time and jti. The actual verifier checks the result before SQL setup. This
changes the implementation used by signed(), while preserving the exact
13-field Ready schema, Start input, configured endpoint, required_scopes=[],
eight PROJECT capability pairs, SQL denial/restoration and confirmed cleanup.
The fixture's rcgen key generation is not a production startup key policy.

## Verification and implementation

Sources: crates/broker-control/src/broker_access_issuer.rs and its narrow lib.rs
exports; crates/broker-presence/examples/project_authorization_fixture.rs::signed.
Tests: crates/broker-control/tests/broker_access_issuer.rs exercises the actual
SDK key/JWKS/signature/verifier, optional claims, audience deduplication, invalid
configuration/claims/time, overflow, deadline, tampering, trust and real expiry.
Affected suites and the existing ordinary PostgreSQL TLS/TCP PROJECT fixture
qualify the changed consumer. From the Broker workspace:

~~~text
cargo test --locked -j1 -p broker-control --test broker_access_issuer
cargo test --locked -j1 -p broker-presence --example project_authorization_fixture project_authorization_fixture_postgres_contract -- --ignored --test-threads=1
~~~

The public IPC procedure remains the [fixture procedure](rust-broker-project-authorization-fixture.md).
A completed signing library or fixture does not qualify the complete provider,
client integration or server startup. Platform and integration
results are recorded separately from the contracts above.

## Qualified native scope

Current tsk-6414 qualification on Linux passed 85 Control fast tests (including
nine issuer SDK tests), 57 Control rustdocs, 17 Presence fast tests and four
Presence rustdocs. After a test-only assertion helper changed, the affected
nine issuer tests were rerun successfully; product code and the fixture were
unchanged. Final formatting and strict Clippy passed. The actual native
PostgreSQL TLS/TCP contract passed in 37.782 seconds. Public IPC passed all
four cases: shutdown with 20 HTTP calls and six events (24.404 seconds), EOF
without shutdown Ack (4.078 seconds), invalid input with exit 1 and no Ack
(5.654 seconds), and initial EOF with no setup/output (0.148 seconds). All
listeners closed; successful shutdown Ack followed confirmed cleanup.
Sanitized receipts and preserved compile/lint failures are in
.build/rust-broker-access-issuer-2026-10-11/. No raw bearer is retained there.

## Shared native ID signing

`sign_id(BrokerIdTokenInput, original)` signs typed ID claims with the same
configured key, issuer and header as access signing. It receives explicit
subject/client/resource, UTC issuance/expiry/authentication time, AMR, optional
nonce, actual access bearer and optional code, and optional profile claims. Admission
still belongs to the [native SQL code producer](rust-oidc-token-exchange.md).
There is no generic arbitrary-claims signer.

ID audience adds the client once to API/optional resource; `azp` and `client_id`
name it. Empty/absent nonce is omitted. `at_hash` and `c_hash` bind the actual
access JWT/code using EdDSA SHA-512's first 32 bytes and base64url without
padding. ID has no access `token_use` and the actual access verifier rejects it.
Authentication time must be positive and cannot exceed the current clock.
Original and expiry guards run before/after the SDK signature. Producer-specific
profile trimming/omission is defined in the code-exchange guide; this signing
primitive continues to preserve explicitly supplied optional values.

The narrow issuer suite now also covers API-only access, matching key IDs,
ID/audience/hash claims, nonce omission, real verifier rejection and invalid
authentication time. Historical tsk-6414 qualification above remains its original
producer/fixture scope; it does not stand in for productive P3 qualification.

The [native refresh producer](rust-oidc-refresh.md) uses `code: None`, so
`c_hash` is omitted. `Some("")` is invalid; code exchange supplies its actual
`Some(code)` and retains the hash binding. Refresh supplies no nonce, preserves
original authentication time and uses canonical `local-token` AMR.
