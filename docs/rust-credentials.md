---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-d3b9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-1404, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-dcfc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Rust server credential digests

Audience: Broker server maintainers and future persistence writers. This contract
describes `broker-security` digest frame v1, introduced by `tsk-9551` in migration
session `ses-c98a`. It is a data library, with no HTTP routes or runtime wiring.
The [native Rust server](rust-broker-server.md) now composes these credential producers through the qualified Control and HTTP consumers. The OIDC client remains a separately owned component.
Completing this library does not complete the Broker migration.

The library uses mature HMAC-SHA256 and hexadecimal implementations. A digest
does not authenticate a caller or grant access. Consumers must still load current
SQL state, validate expiry/revocation, and enforce identity, grants and revisions
as described in the [security model](security.md). The
[Rust SQL contract](rust-sql-schema.md) covers the fresh database representation;
[PostgreSQL upstream flow persistence](rust-postgres-control.md) is the first runtime consumer. Other credential writers and their SQL transactions remain separate work.

## Policy and ownership

`DigestLimits::new` requires five `NonZeroUsize` byte caps, in this order:
pepper, token, browser binding, subject and recovery code. There is no `Default`.
The pepper cap must be at least 32. `CredentialDigester::new` consumes an owned
`Zeroizing<Box<[u8]>>` pepper of 32 bytes through that cap inclusive. On rejection,
the consumed owner is dropped and zeroized. Server startup must separately define
these limits and supply the external pepper; this library invents neither values
nor key generation, configuration or rotation policy.

The digester has a private key and no `Clone`, `AsRef`, serializer or export API.
Its Debug representation and that of `CredentialDigest` contain only `[REDACTED]`.
The input `Zeroizing` wrapper itself permits cloning/access before transfer;
earlier caller copies remain the caller's responsibility. The SDK zeroize features
wipe supported hash/MAC states and buffers on drop; they do not promise to wipe
all compiler temporaries, registers, swap pages or prior copies.

Generic public digest and verify methods validate nonempty fields and their respective
caps before constructing MAC state. Lengths must also fit the frame's unsigned
64-bit representation. Methods borrow inputs without proportional concatenation
or allocation. CPU work is linear in the capped inputs, with fixed MAC state and
32-byte output. This does not define global concurrency quotas or cancellation.
The explicit SQL export allocates exactly 64 output bytes.

The dedicated typed local_auth_binding/verify_local_auth_binding methods preserve
AdminLogin without external binding: domain13, arity2, purpose byte1 and a second
field of length0. This is the only empty-field exception. OauthAuthorize and
DeviceApprove reuse generic nonempty/capped validation and exact input bytes.
The generic binding/verify_binding API remains nonempty for AdminLogin too.
See [native LOCAL challenges](rust-local-auth.md) for the SQL consumer and authority boundaries.

## Closed domains and framing

Frame bytes, in order:

```text
ASCII "graphit-broker/rust-credential-digest/v1"
domain: u8
arity: u8
for each field: byte length as u64 big endian, then field bytes
```

There is no public arbitrary-domain or arbitrary-arity method. The length frame
distinguishes embedded NUL bytes and tuples with equal concatenated bytes. This
is a fresh Rust representation: no Go digest reader, compatibility or importer.

| Domain ID | `TokenKind` or specialized method | Fields |
|---|---|---|
| 1 | `AdminSession` | token |
| 2 | `OidcFlowState` | token |
| 3 | `OidcBrowserBinding` | token |
| 4 | `LocalAccess` | token |
| 5 | `LocalRefresh` | token |
| 6 | `ServiceCredential` | token |
| 7 | `DeviceCode` | token |
| 8 | `DeviceUserCode` | token |
| 9 | `OidcAuthRequest` | token |
| 10 | `OidcAuthorizationCode` | token |
| 11 | `OidcStoredAccess` | token |
| 12 | `LocalAuthChallenge` | token |
| 13 | `binding` / `verify_binding`, typed local_auth_binding/verify_local_auth_binding | purpose byte, browser binding (typed AdminLogin alone permits empty) |
| 14 | `recovery` / `verify_recovery` | subject, normalized recovery code |
| 15 | `oidc_subject` | exact issuer, exact subject |

`LocalAuthPurpose` bytes are 1 `AdminLogin`, 2 `OauthAuthorize`, 3 `DeviceApprove`.
The purpose and subject bind the digest to the intended journey/identity.
`token`/`verify_token` accept one closed `TokenKind` and a borrowed byte slice.
`binding`/`verify_binding` accept a purpose and borrowed browser binding.
`recovery`/`verify_recovery` accept borrowed subject and code slices.

`oidc_subject(issuer, subject)` uses the same mature HMAC-SHA256, pepper and
length framing with domain15, distinct from domains1–14. Both fields must be
nonempty and independently fit the existing subject byte cap. It never joins
them with a delimiter or normalizes their bytes. The mature Base64URL codec
encodes the 32-byte result without padding into exactly43 characters, without
a prefix. `NativeOidcSubject` has private construction, redacted Debug and only
borrowed `as_str()` export; no Clone, Default or Deserialize. This stable native
OpenID Provider subject is DATA, not authentication proof or PROJECT authority.
The [actual LOCAL OIDC completion](rust-oidc-authorization.md#complete-a-local-authorization)
consumer supplies issuer `local` and the current verified SQL subject. Pepper
changes deliberately change this representation; rotation remains a startup
contract, not a compatibility decoder.

Recovery normalization belongs to the [native MFA consumer](rust-local-auth.md), which emits32 SDK base32 symbols from20 random bytes, displays8-8-8-8 and applies bounded ASCII presentation normalization. Here normalized_code remains a caller precondition: this library checks nonempty bytes and caps without normalization or a claim that a code is enrolled and unused. The SQL completion consumer establishes that authority by one-time deletion in its known transaction.

## Persistence and errors

`CredentialDigest` keeps 32 bytes private. `to_sql_hex()` explicitly exports
exactly 64 lowercase ASCII hex characters. `parse_sql_hex(&str)` accepts precisely
that form: uppercase, whitespace, non-ASCII, non-hex and lengths other than 64
are rejected. Both conversions use the mature `hex` codec with a fixed decode
buffer. SQL writers must prove this representation at their actual persistence
boundary; the existing schema fixtures' short `hash` strings do not prove it.

The type has no ordinary equality operation. `verify_token`, `verify_binding`
and `verify_recovery` use the mature MAC library's constant-time `verify_slice`
with a fixed 32-byte expected digest. A parsed digest alone proves no authority.
Errors are static typed variants without inputs, pepper or digest data:

| Error | Condition | Caller action |
|---|---|---|
| `InvalidLimits` | Pepper cap below 32 | Correct explicit startup policy. |
| `InvalidPepper` | Pepper shorter than 32 or above cap | Correct key provisioning; rejected owned input is dropped. |
| `EmptyInput` | A required field is empty | Reject the incomplete request or persistence record. |
| `InputTooLong` | Field exceeds its cap or framing length | Reject before crypto; do not silently truncate. |
| `InvalidSqlDigest` | Stored representation is not canonical | Treat as invalid data, with no alternate decoder. |
| `VerificationFailed` | MAC mismatch | Deny verification; no permissive fallback. |

The compilable example in `crates/broker-security/src/lib.rs` demonstrates the
consume → digest → SQL codec → verify journey with explicitly synthetic limits
and pepper. Compile-fail examples check cloning, private-key access, `AsRef`, and
use of the transferred owner. These examples are exercised by the DOC gate.

## Dependencies and verification

Exact pins in the crate and lockfile are
[hmac 0.13.0](https://docs.rs/hmac/0.13.0/hmac/),
[sha2 0.11.0](https://docs.rs/sha2/0.11.0/sha2/),
[zeroize 1.9.1](https://docs.rs/zeroize/1.9.1/zeroize/) and
[hex 0.4.3](https://docs.rs/hex/0.4.3/hex/), with default features disabled.
HMAC/SHA2 enable `zeroize`; zeroize/hex enable `alloc`. The implementation uses
`Hmac<Sha256>`, whose key-derived hash states receive the selected drop protection.
It does not use `SimpleHmac` with its separate outer-pad key storage.

Private unit tests exercise [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html)
cases 1–3 without exposing a public raw-MAC policy bypass. Independent synthetic
public-API vectors for the three original families can be regenerated with Python's
standard library, independent of RustCrypto:

```python
import hmac, struct
prefix = b"graphit-broker/rust-credential-digest/v1"
for domain, fields in [
    (1, [b"token-fixture"]),
    (13, [bytes([2]), b"browser-fixture"]),
    (14, [b"subject-fixture", b"ABCDEFG234"]),
]:
    frame = prefix + bytes([domain, len(fields)])
    frame += b"".join(struct.pack(">Q", len(field)) + field for field in fields)
    print(domain, hmac.new(bytes(range(32)), frame, "sha256").hexdigest())
```

`tests/credential_contract.rs` checks domains1–14, purpose/subject binding,
wrong keys/values, tampering in each of the 32 bytes, empty/exact/one-over bounds,
embedded-NUL ambiguity, canonical SQL codec and redacted diagnostics.
The domain15 unit regression also proves stable43-character output, changed
issuer/subject/pepper, exact caps, delimiter and NUL ambiguity separation, and
separation from every existing domain. The completion PostgreSQL corpus proves
the real consumer; a digest unit test alone establishes no login authority.
Affected commands:

```text
cargo test --locked -p broker-security --all-targets
cargo test --locked -p broker-security --doc
cargo clippy --locked -p broker-security --all-targets -- -D warnings
cargo test --locked -p broker-store --test schema_contract
cargo test --locked -p xtask --all-targets
cargo fmt --all --check
cargo audit --file Cargo.lock --json
cargo run --locked --quiet -p xtask -- hook pre-commit
cargo test --locked --workspace --doc
```

The [active gates](rust-sql-schema.md#active-development-guardrails) check whitespace and formatting in pre-commit. `make check` runs workspace Clippy, documentation tests and ordinary workspace tests, including the security contracts. `make qualify` runs the native integration phases. The runner stops on a failed command; invoking a hook never initiates a push. Linux execution does not establish Windows/macOS behavior.

The [administrative session service](rust-admin-sessions.md) uses credential kind 1, AdminSession; its PostgreSQL session persistence is qualified on Linux in `tsk-dcfc`.
