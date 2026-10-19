---
title: Native LOCAL password verification in Rust
description: RustCrypto password PHC and current PostgreSQL password evidence before mandatory change and MFA.
tags: [rust, password, authentication, postgresql]
references:
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e15d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-32a8, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-1404, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-8470, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-74a7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Native LOCAL password verification in Rust

The [SQLite LOCAL producer](rust-sqlite-local-auth.md) reuses these shared contracts with private file-backed transactions. The native server still selects PostgreSQL; SQLite server dispatch remains a separate delivery.

Audience: Broker server maintainers composing the local login flow. This producer verifies a native password against current PostgreSQL state. A successful result is a **password step**. The server must still complete mandatory password change, configured MFA, browser/purpose binding and the login or consent journey before creating a session or OAuth grant. The [native LOCAL challenge producer](rust-local-auth.md) consumes this password evidence and selects current password-change/MFA/enrollment stages. The same service now confirms enrollment and TOTP/recovery; HTTP handlers and session/consent/grant integration remain separate delivery work.

The [identity reader](rust-postgres-identity.md) continues to return data for an already authenticated caller. This password verifier supplies a genuine credential check; it does not derive authority from identity data, an existing bearer or a JWT.

## Cryptography and native format

`broker_security::LocalPasswordHasher` consumes a `Zeroizing<Box<[u8]>>` pepper of at least32 bytes. Its Debug output is redacted and it exposes neither key material nor Clone. Creation and verification use RustCrypto `argon2=0.6.0`, its PHC parser and SDK constant-time `Output` equality. No handwritten PHC parser or digest comparison is used.

Native prehash is HMAC-SHA256 over the literal domain `graphit-broker/rust-local-password/v1`, one NUL byte, then the exact UTF-8 password. The native password format keeps the fourteen credential-digest domains unchanged.

Creation explicitly selects Argon2id version19, memory65536 KiB, three iterations, four lanes, a CSPRNG salt of16 bytes and output32 bytes. Password creation requires at least15 Unicode scalar values and at most4096 UTF-8 bytes. Verification caps passwords at4096 bytes and never trims them. Caller-owned passwords remain the caller's responsibility.

Before KDF allocation the SDK validates a PHC string bounded to512 bytes, Argon2id/version19 and exactly the m/t/p parameters. Memory must satisfy SDK constraints and be at most1048576 KiB, iterations at most10, lanes at most16. Salt must be16–48 **decoded bytes**:48 is the explicit native SDK limit, while creation uses16. Outputs may be32–64 bytes. Verification sets the Argon2 output length from the parsed output and compares SDK Outputs; it does not rely on the blanket verifier's default32-byte output.

Owned pepper, password/prehash buffers and retained PHC strings use zeroizing owners; the Argon2 zeroize feature protects KDF memory. This does not claim erasure of caller copies, SQLx/OS buffers, compiler temporaries or swap.

## Shared KDF engine and cancellation

`LocalPasswordEngine::new(hasher, workers, original)` creates a genuine native dummy PHC on a blocking worker. `workers: NonZeroUsize` is supplied to the engine by its owner. The native server uses `auth.local.rate_limit.max_concurrent` (sourced default 2) for one shared engine across admitted login and [administrative password writes](rust-admin-users.md). Administration prepares that owner even with LOCAL login disabled; this does not enable LOCAL authentication; the existing disabled-login503 contract remains. Creating an engine per request defeats the shared physical bound.

`hash(password, original)` provides bounded native creation for password-write consumers. `verify(password, optional_phc, original)` is a cryptographic data check; missing or malformed PHC uses the native dummy and returns false. Neither API creates SQL identity or login authority.

Tokio's semaphore controls simultaneous memory-heavy KDFs and `spawn_blocking` keeps the CPU work off async workers. A running SDK KDF cannot be interrupted. Its blocking worker owns the permit, pepper owner and secret inputs until completion, even when the async caller times out or is dropped. Queued admission is cancellable; an expired task does not start a KDF. No late successful result can cross the original deadline.

`LocalPasswordEngine::close().await` closes physical admission and waits for the tracked
SDK workers to exit. Call it before closing SQL. [Shared password admission](rust-local-password-admission.md) retains logical work leases through those same workers. Worker registration and closure are
serialized so a job cannot appear after shutdown has finished waiting. A failed or
expired startup dummy also drains its worker before returning an error. Dropping an
async request alone retains physical ownership but does not perform this shutdown.

## PostgreSQL password evidence

`store.local_password_verifier(&engine)` borrows both owners. Its `verify(username, password, original)` removes surrounding whitespace from the login username before lookup against current `public.local_users`, preserving its case. The resulting username must satisfy the existing safe ASCII segment contract and128-byte bound; empty or internally spaced values are denied. Stored usernames and subjects, and the password itself, remain exact. No lowercase conversion or SQL collation override is introduced. SQL caps selected text before decoding. The eligible row must be human, enabled1, revision positive, and password-change flag0 or1. Subject must be nonempty, at most512 bytes, equal to its own trim result and contain no NUL; values are rejected without normalization.

Absent, disabled, service or malformed rows use dummy KDF and return `Unauthenticated`, as does an incorrect password. Oversized/invalid original input is rejected before SQL or KDF. Storage failures remain finite control errors and must not become an authentication success or fallback.

After the real KDF matches, a READ COMMITTED transaction re-reads the subject with `FOR SHARE`. Username, subject, human/enabled state, revision, PHC and change-required flag must still match the initial row. The row lock is retained until known COMMIT. Authentication SQL ownership therefore requires SELECT and the PostgreSQL UPDATE privilege needed for row locking; the native password producer verification uses an ordinary non-superuser schema owner.

The overall deadline is the earlier of the original caller deadline and the store's operation budget. Acquisition, both SQL observations, KDF, revalidation and COMMIT share it. Cancellation or failure closes the uncertain connection through the existing guard. COMMIT errors and timeouts after COMMIT starts use `OutcomeUncertain`; they never return evidence.

`VerifiedLocalPassword` exposes username, subject, revision, `password_change_required`, observed UTC microseconds and `auth_method()=="local-password"`. Fields cannot be constructed externally and it has no Clone, Default or Deserialize. Debug is redacted. This is an observation for the next login step, not an identity lease: that step must revalidate current revision and enforce password change/MFA before any credential or grant is issued.

This producer covers PostgreSQL. Mandatory password mutation and confirmed factor
completion are documented in [LOCAL login](rust-local-auth.md#mandatory-password-change).
The [genuine LOCAL cookie producer](rust-admin-cookie-session.md) composes completed
login with current SQL. [Shared password admission](rust-local-password-admission.md)
adds running/waiting bounds, genuine password-failure accounting and HTTPS CAPTCHA.
[Native HTTP password/MFA login](rust-admin-local-login.md) consumes these owners;
MySQL and OAuth completion retain their own delivery/integration scope. This password library alone creates no
completed login or HTTP endpoint.

## Verification

Run from the Broker root:

```text
cargo test --locked -j1 -p broker-security
cargo test --locked -j1 -p broker-control
cargo test --locked -j1 -p broker-control --test postgres_password -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-security -p broker-control --all-targets -- -D warnings
```

The native target needs the existing pinned PostgreSQL Docker image and a responsive Docker daemon. It uses real PHC/KDF, ordinary SQL ownership and TLS, and verifies current identity, denial, revision/hash races, deadline/cancel rollback and lifecycle. A real admin transaction holds a pending row update; the verifier first sees committed old data, completes its KDF and waits at the final row lock. Committing the change must deny the old password observation. No fake credential verifier or in-memory authorization store substitutes for SQL.

Password producer verification results are recorded with the delivery after execution. Source: `crates/broker-security/src/password.rs`, `crates/broker-control/src/local_password.rs` and `src/service/local_password.rs`; tests: security `tests/password.rs`, engine module tests and control `tests/postgres_password.rs`.

## Password producer verification of the native password producer

Linux password producer verification for Task `tsk-8470` used the existing warm Cargo target and serial jobs. The package runs covered 14 security tests and5 rustdocs, and89 control tests and59 rustdocs. After test-only worker assertions changed, the two affected engine tests passed again; the final three password integration tests also passed.

After the login-username correction, strict Clippy on both packages/all targets passed in9.888 seconds, formatting passed, and the PostgreSQL native contract passed in145.581 seconds wall time (142.72 seconds test runtime). That one test runs three sequential journeys using one ordinary-owner TLS fixture: current identity and closed denials including ASCII/Unicode username trim and preserved case; hash/revision/enabled/change-flag races; SQL permissions, deadline/cancellation, recovery and explicit store/container cleanup.

The earlier native run with separate fixtures exceeded its300-second external process limit; it did not qualify the whole suite. Its owned process and container were removed, and the fixture lifecycle was consolidated before the successful executions. Initial SQLx/TimestampMicros and test-helper compilation failures were corrected and retained in the failure history. No failed execution is reported as a pass.

Sanitized evidence is under `.build/rust-local-password-2026-10-11/`, including `qualification-receipt.json`, `failure-history.json`, `native-trim.log` and `scoped-audit.json`. These results qualify the password producer and its stated PostgreSQL boundaries. They do not qualify completed login/MFA, OAuth grants, other SQL adapters or other operating systems.
