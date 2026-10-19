---
title: Rust authentication expiry observers
doc_type: reference
references:
  - target: {type: task, id: tsk-13a3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e381, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supplies
  - target: {type: memory, id: 01M4PZK4W52TAWJP76ESCM7E6P, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
---

# Bound waits by the actual authentication expiry

`VerifiedBrokerAccess::authentication_expiry()` and
`VerifiedLocalBearer::authentication_expiry()` return the original
`(SystemTime, Instant)` expiry captured by their actual verifier. This is a
readonly observer on a private authenticated result. It introduces no resource
grant, token renewal, TTL, constructor, cloning or serde authority. Continue to
obtain fresh authentication and current permissions for each consequential
operation; the pair does not freeze SQL revocation or grants.

Keep the operation's Original deadline separately. Before an effect or send,
check that deadline and both actual authentication bounds. Transport waits must
also be bounded by the original monotonic authentication expiry. A wall-clock
rollback cannot extend that stored monotonic bound. Returning the tuple does
not authorize a caller-supplied tuple to impersonate an authenticated proof.

```rust
fn native_expiry(proof: &broker_control::VerifiedBrokerAccess<'_>)
    -> (std::time::SystemTime, std::time::Instant) {
    proof.authentication_expiry()
}
fn local_expiry(proof: &broker_control::VerifiedLocalBearer)
    -> (std::time::SystemTime, std::time::Instant) {
    proof.authentication_expiry()
}
```

The Native getter exposes the pair already captured by the Ed25519 verifier.
It does not reconstruct a monotonic deadline from `expires_at()` or a second
wall-clock sample. [Native authentication](rust-broker-access-jwt.md) still
checks the signed identity, scopes, captured Original and both expiry bounds.

For opaque access/service credentials, the
[PostgreSQL verifier](rust-local-bearer-verifier.md) first reads and validates
current state without writing usage metadata. After those SQL waits, the
producer samples monotonic time immediately before the
final UTC observation and constructs the private result with the checked pair.
It normalizes the same output scopes and preserves current identity metadata.
The final finish checks expiry again; it may update `verified_at()` metadata,
but never renews the captured pair. Equality or expiry during the operation
still denies, and Original still bounds the entire read/finalization.

Do not combine a monotonic sample taken **before the entire SQL verifier** with
`expires_at - verified_at` sampled after it. That subtracts the SQL duration
twice: with a credential expiring in ten seconds and verification taking six
seconds, it computes a deadline at four seconds and rejects the still-valid
credential upon return at six seconds. The producer pair avoids that premature
expiry. Sampling wall clock again to reanchor an already returned proof can
instead extend the bound under rollback; consumers must copy the stored pair.

The [Now channel authorizer](rust-now-channel-authorization.md) and
[Hub storage admission](rust-hub-storage-admission.md) check their actual proof
and copy its pair. They retain their own Original and current authorization
checks. Caller DATA, snapshots, byte caps or `generated_at` never establish an
authentication window. This producer does not implement a WebSocket server or
promise rollback of bytes or SQL effects already committed.

Implementation: `crates/broker-control/src/local_bearer_verifier.rs`,
`src/service/local_bearer_verifier.rs`, `src/broker_access.rs`,
`src/now_channel.rs` and `src/storage_admission.rs` within `broker-control`.
Focused test: `crates/broker-control/tests/authentication_expiry.rs`. It uses
real PostgreSQL TLS with a NOSUPERUSER owner, actual access/service digests,
observed SQL locks and real Ed25519 signatures. The latency scenario returns a
valid proof whose actual pair remains live while the rejected pre-verification
formula is already expired. Private arithmetic tests cover immutable pairing
and rollback without changing the system clock or claiming fake authority as
product evidence.

Run the focused and affected checks from the Broker workspace:

```text
cargo test --locked -j1 -p broker-control --test authentication_expiry -- --ignored --exact authentication_expiry_postgres_contract --test-threads=1
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo clippy --locked -j1 -p broker-control -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

Task records retain executed receipts, failures and the supported environment.
The targeted producer verification does not establish WebSocket/TCP behavior,
Root Runtime integration, Windows/macOS execution or migration completion.
