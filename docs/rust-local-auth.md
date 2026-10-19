---
title: Native LOCAL login challenges in Rust
description: Current PostgreSQL password stages, bound challenges, verified TOTP and one-time recovery codes.
tags: [rust, authentication, mfa, postgresql]
references:
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e15d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-d3b9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-1404, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6ba7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-798b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8470, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9551, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-74a7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Native LOCAL login challenges in Rust

The [SQLite LOCAL producer](rust-sqlite-local-auth.md) reuses these shared contracts with private file-backed transactions. The native server still selects PostgreSQL; SQLite server dispatch remains a separate delivery.

Audience: Broker server maintainers composing local login. This PostgreSQL producer consumes genuine [password evidence](rust-local-password.md), reads current identity and selects the next stage. It creates or loads a bound challenge and supplies actual encrypted TOTP enrollment with manual secret, otpauth URI and PNG QR.

Mandatory password change, enrollment confirmation and TOTP/recovery completion have real PostgreSQL transactions. [Shared password admission](rust-local-password-admission.md) also guards the two actual password-change KDFs through the same physical engine and Original budget; it adds no CAPTCHA or password-guess charge to continuation. The public challenge procedure retains its current binding/revision checks and signature. [Native administrative cookies](rust-admin-cookie-session.md) compose completed AdminLogin with current SQL and confirmed CSRF/logout. [Native HTTP password/MFA handlers and startup composition](rust-admin-local-login.md) consume these genuine producer steps. OAuth consent/grants have their own consumers and integration. A pending challenge proves no factor. A completed local login observation does not grant a role, administrative permission, session or OAuth code.

The [shared native LOCAL runtime](rust-local-login-runtime.md) exposes purpose-explicit borrowed password/challenge views for Admin and OAuth. It keeps one engine/admission/limiter and accepts native OIDC without an Admin cookie. The Admin transport still requires its own cookie; the [public OAuth browser transport](rust-oidc-browser-authorization.md) consumes the
same stages and presents recovery codes only after known OAuth completion.

## Explicit policy and stages

Construct ` LocalAuthPolicy::new(required, issuer_label, challenge_ttl) `. It trims only the configuration label, rejects an empty result and requires TTL from2 through30 minutes inclusive. It has no Default. The [native startup compositor](rust-admin-local-login.md) preserves sourced MFA required, label Graphit Broker and TTL10 minutes. It validates issuer presentation parameters with the same checked TOTP SDK before effects; invalid labels such as one containing a colon fail configuration. Real account presentation remains SDK-validated and fails finitely without fallback.

` store.local_auth_service(&digester, &mfa, &policy) ` borrows the PostgreSQL store and both cryptographic owners. ` begin(proof, context, original) ` consumes ` VerifiedLocalPassword ` by value. Current SQL identity must remain human, enabled1, positive revision, strict subject and safe username matching the proof. Flags must be0 or1. No PHC, profile, teams or role data is selected here.

| Current state | Result |
|---|---|
| Password change required | Pending PasswordChange, regardless of MFA policy |
| No change, explicitly required=false | Complete CompletedLocalLogin |
| No change, required=true, factor present | Pending Mfa |
| No change, required=true, factor absent | Pending Enrollment |

The required=false result exposes username, subject, revision, observed UTC microseconds and method local-password. Construction and fields are private; there is no Clone, Default or Deserialize. Its purpose and binding digest remain private. ` purpose() ` and constant-time ` verify_binding(digester, context) ` allow the next consumer to check the intended journey without exporting the digest. That consumer must still validate current SQL state and finish its own authorization/consent transaction.

` PendingLocalAuth ` exposes borrowed challenge/enrollment and a closed stage. It has no incidental secret serializer; Debug is redacted. Presentation borrows are explicit secret exports: callers must protect them and their copies.

## Typed journey binding

The [native OIDC completion consumer](rust-oidc-authorization.md#complete-a-local-authorization)
uses `PreparedOidcLogin::try_from(CompletedLocalLogin)` synchronously, before an
async completion future owns the login. Only OauthAuthorize purpose is accepted.
Unextracted enrollment recovery codes produce `RecoveryCodesPending(login)`;
wrong purpose produces `InvalidPurpose(login)`. Both errors preserve the
original protected owner and expose `into_login()` with redacted diagnostics.
Take the codes explicitly, retain and present them through the private caller
continuation, then prepare again. No auto-extraction or acknowledgement flag
exists; absence of codes proves no UI presentation. The prepared owner is
private, has no Clone/Default/Deserialize and owns no recovery-code copy that
cancellation could silently destroy. OIDC still checks exact request binding,
current identity/revision, client, request expiry and its own SQL transaction.

Canonical OIDC principal method `local-token` remains separate from login method
labels and AMR. The consumer derives `otp` solely from the producer's private
verified-factor fact, including real recovery authentication; a present MFA row
does not turn a password-only exemption into verified MFA.

` LocalAuthBinding ` has only AdminLogin, OauthAuthorize(bytes) and DeviceApprove(bytes). AdminLogin preserves the active administrative login's absence of an external binding. Its dedicated digester methods use [frame v1](rust-credentials.md), domain13, arity2, fields purpose byte1 and empty bytes with length0.

The generic binding/verify_binding methods continue to reject empty bytes for every purpose. OAuth and Device typed variants use those generic methods, retaining nonempty validation, configured caps and exact bytes. OAuth callers supply the original authorization request ID. Device callers supply the user code already normalized by the device producer. This layer neither normalizes them nor treats selection of a context as authority. Debug hides binding bytes.

## Native tokens and encrypted enrollment

Challenges contain exactly43 characters: Base64url without padding for32 CSPRNG bytes, without a textual prefix. Load enforces length, mature codec decoding and canonical re-encoding. The database stores only the domain12 LocalAuthChallenge digest, exactly64 lowercase hexadecimal characters. Unknown prefixes are rejected.

` LocalMfaProtector ` consumes an owned zeroizing pepper of at least32 bytes. It derives the AES-256 key through HMAC-SHA256 over the literal bytes:

```text
graphit-broker/rust-local-mfa-key/v1 + one NUL byte
```

AES-GCM additional authenticated data is:

```text
graphit-broker/rust-local-mfa-secret/v1 + one NUL byte
+ subject UTF-8 byte length as u64 big endian
+ exact subject UTF-8 bytes
```

Subjects must be nonempty, no more than512 UTF-8 bytes, equal to their own trim result and free of NUL. Neither whitespace nor subject changes are normalized away.

The sole encrypted format is ` rust-mfa1. ` followed by Base64url without padding of nonce12 bytes, encrypted raw secret32 bytes and authentication tag16 bytes, exactly90 characters altogether. Encryption uses a fresh CSPRNG secret and nonce. Load rejects unknown formats, wrong key/subject and tampering. There is no legacy decoder, importer or alternate parser.

The mature SDKs are aes-gcm0.11.1 and totp-rs6.0.0. AES features enable aes/alloc/getrandom/zeroize; TOTP defaults are disabled and alloc/otpauth/qr/zeroize are enabled, without migration/serde. TOTP presentation explicitly selects SHA1, six digits,30-second period and32 secret bytes. The SDK produces the base32 secret, otpauth URI and real PNG QR; the data URL is the standard base64 encoding of that PNG. No homemade QR or TOTP algorithm is used.

Pepper/derived-key buffers, native secret buffers and retained presentation strings/PNG have zeroizing owners; the SDK cipher and TOTP secret use their zeroize features. Owners have no Clone or key export and redacted Debug. This does not promise erasure of caller copies, SDK/SQLx/OS buffers or compiler temporaries. SDK presentation errors can contain URLs, so they are discarded and mapped to finite errors.

## PostgreSQL transactions and races

Existing tables are public.local_users, public.local_mfa and public.local_auth_challenges. Purpose strings are admin-login, oauth-authorize and device-approve. Stage strings are password-change, mfa and mfa-enrollment. Unknown stored values fail closed. SQL caps potentially large selected text before SDK decoding.

Begin uses READ COMMITTED with locks in order:

1. Current user FOR UPDATE.
2. Optional MFA factor FOR SHARE.
3. Delete existing challenges for subject+purpose, then insert the new challenge.

The user lock serializes replacement for an identity. Other purposes are retained. The transaction stores current revision, purpose/binding digest, stage, ciphertext and UTC creation/expiry microseconds. Ciphertext is empty for password change/MFA, native90-character AEAD for enrollment. Cryptography and QR presentation must succeed before COMMIT. DELETE or INSERT failure rolls back replacement; no partial token or secret is returned.

Load is explicitly non-consuming. Its lock order is initial challenge lookup without a row lock → user FOR SHARE → optional factor FOR SHARE → final challenge FOR SHARE. The initial and final records must match in every field. It verifies both credential/context digests through the constant-time SDK, purpose, positive revision, strict expiry and current identity. PasswordChange requires the current change flag; other stages require it cleared. Mfa requires a present factor; Enrollment requires it absent. Enrollment is reconstituted with AEAD bound to the current subject and the same presentation SDK.

Wrong binding, unknown token, expired or incoherent challenge never deletes or consumes a row. A later completion producer must repeat current state and context checks inside its own one-time mutation transaction; this load result cannot replace those checks.

## Mandatory password change

Call `complete_password_change(&engine, raw_challenge, context, new_password, original)` on the same service. Supply the shared password engine provisioned for login with the same pepper; the service creates no per-request engine or policy default. This method accepts only a current, unexpired PasswordChange challenge and its exact typed journey binding. It returns the same closed LocalAuthStep as Begin; a pending step confirms no factor and a completed observation grants no administrative role, session, consent or OAuth code.

The new password is exact, without trimming, at least 15 Unicode scalar values and at most 4096 UTF-8 bytes. The service validates the current stored PHC through the password SDK before KDF work, rejects malformed hashes as InvalidChallenge, verifies that the proposed password differs from the current password, then hashes it through the shared bounded engine. An equal password returns PasswordUnchanged. Invalid password input returns Password(InvalidPassword). These errors leave the challenge and SQL state intact. Owned PHC/password/hash buffers use zeroizing owners; the physical SDK worker retains its permit and owned inputs until it finishes even if its caller is cancelled.

The READ COMMITTED lock order is initial challenge without lock → current user FOR UPDATE, including bounded PHC → optional factor FOR SHARE → final challenge FOR UPDATE. All initial/final fields must match, along with the current human/enabled identity, positive revision, change-required flag1, stage and bound context. Revision increments through checked arithmetic; overflow denies the operation before mutation. The user lock serializes legitimate completions and replacements. Exactly one concurrent completion can succeed; replay fails after the original challenge is removed.

One transaction performs all of these effects:

1. CAS-update the exact password hash, clear the mandatory flag, increment revision and set UTC updated_at, matching subject, old revision and flag1. Exactly one row must change.
2. Revoke SQL local_tokens for the subject only where local_user_revision is positive and revoked_at is NULL. Federated revision-zero tokens, previously revoked timestamps and unrelated subjects remain intact.
3. Read relevant oidc_auth_requests by identity_subject under row locks and delete LOCAL or untyped requests, preserving native authorized federated requests with issuer/auth-method/revision coherence. Invalid JSON aborts the transaction. Delete every local_auth_challenge for the subject, across purposes.
4. For AdminLogin and OauthAuthorize, delete all oauth_device_codes associated with that subject, regardless of status. DeviceApprove omits this DELETE entirely and preserves every Device row/status. OAuth requests and Device rows still carrying an empty subject remain intact in all journeys.
5. Advance using the new revision, cleared flag and same context. Explicit required=false yields private CompletedLocalLogin/local-password; required=true with a factor yields Mfa; no factor yields native encrypted Enrollment and real SDK QR. Existing MFA and recovery rows are preserved. The shared private advance helper also serves Begin.

The next challenge, native crypto and presentation must succeed before COMMIT. A write, invalidation, insertion or presentation failure rolls back the password, revision and all credential/challenge effects together. The input challenge must remain strictly future in UTC after KDF and immediately before COMMIT. Original covers the whole operation; after known COMMIT the service rechecks Original and the expiry of any new pending challenge before returning. The consumed input is no longer an output authority. A late or uncertain result returns no proof; if the password change committed, recover through a fresh login with the confirmed new password rather than automatically replaying the mutation.

Revoking SQL tokens does not invalidate already-issued offline JWTs immediately; their expiry and the downstream current SQL authorization contracts remain separate. The native test seeds stored OAuth/Device representations solely to prove deletion and preservation. It does not claim real OAuth/Device issuance, consent or grant qualification.

## Confirming MFA and using recovery codes

Call `complete_mfa(&limiter, raw_challenge, context, code, original)` with the same startup-owned cryptographic owners and a shared `LocalMfaAttemptLimiter`. The input is at most64 UTF-8 bytes; an oversized input returns InvalidMfaCode before SQL. Only successful factor verification and a known commit produce a private CompletedLocalLogin whose method is local-password+totp. Recovery authentication has that same established method. Begin and password change under an explicit exemption still report local-password even if a factor row exists. Factor enrollment alone never implies verified authentication.

The READ COMMITTED lock order is initial challenge without lock → current user FOR UPDATE → factor FOR UPDATE → final challenge FOR UPDATE. Every initial/final field and bound context must match; the current user must be enabled/human with a positive matching revision and cleared mandatory-change flag. Enrollment requires no factor and no recovery rows. Recovery rows without a factor are incoherent native state and fail closed; the operation never silently resets or accumulates them. Existing MFA requires a native90-character authenticated ciphertext, last_totp_step at least0 and confirmed_at greater than0. Corruption and ineligible state produce no authority and do not count a wrong-code attempt.

The protector decrypts the subject-bound secret and verifies it with totp-rs6: SHA1, six ASCII digits,30-second period. Peripheral whitespace is trimmed for TOTP. It checks Current, Previous, Next using skew0 SDK checks in that order, skipping steps at or below the persisted last step. The SDK performs its constant-time token comparison and returns the accepted step. Enrollment starts at last step−1. Verification does not build a QR.

Successful enrollment re-encrypts the same verified32-byte secret with a fresh nonce, increments the user revision through a checked CAS and inserts the factor with accepted step and confirmed UTC. It generates ten distinct recovery codes from20 CSPRNG bytes each. SDK base32 yields32 uppercase ASCII symbols, displayed as8-8-8-8. The same transaction inserts ten subject-bound domain14 MACs and applies the password-change invalidation rules above, including the complete DeviceApprove exception. No recovery plaintext is stored in SQL. Failure before commit rolls all effects back.

A successful enrollment result owns an optional `LocalRecoveryCodes` set: zeroizing strings, redacted Debug, no Clone/Default/Deserialize. `take_recovery_codes(&mut login)` removes that set once; its `iter()` exposes explicit protected borrows for delivery to the user. The service cannot re-export stored codes. Callers must protect borrowed values and any copies. Recovery normalization trims peripheral whitespace, applies ASCII uppercase and removes ASCII spaces/hyphens. It accepts only SDK-canonical32-symbol base32 decoding to exactly20 bytes. There is no old-format parser or importer.

For an existing factor, TOTP is checked first. An accepted step is CAS-updated once; otherwise a normalized recovery code deletes exactly its subject-bound MAC. Successful authentication deletes the input challenge by hash and revision in the same transaction. User revision does not change on this path. Recovery reuse and persisted TOTP replay cannot authenticate; wrong codes leave SQL state and the same pending challenge intact.

Original/store timeout and strict input UTC expiry are checked after verification, before COMMIT and after known COMMIT before any strong proof, pending result or recovery set is returned. The strong observation time is fresh after that commit. A late or uncertain result carries no output even if a step/code was consumed. Do not retry the mutation automatically: recover through fresh password login and the authenticator; administrative reset is separate work.

## Shared protection against MFA guesses

Construct `LocalMfaAttemptPolicy::new(max_failures, window, lockout, max_tracked)` explicitly, then `LocalMfaAttemptLimiter::new(policy)` once for all MFA callers in the process. Counts and tracked capacity are nonzero typed values, durations are positive with checked arithmetic; there is no Default. Restart loses this in-memory protection. The [native HTTP startup](rust-admin-local-login.md) shares one MFA owner and applies the separate password admission controls to their relevant operations.

The bounded map uses the public current subject directly. It keeps no extra hash key or universal quota ledger. Only stale, unblocked subjects without an in-flight attempt are pruned after window+lockout. A full map returns MfaCapacity and never admits an untracked attempt. A blocked subject returns MfaRateLimited with its remaining duration; equality with the end of lockout permits admission. A private per-subject guard returns MfaBusy for overlapping admission and remains held across COMMIT until success is recorded, closing the COMMIT→record race.

A wrong code counts within the configured window and the threshold starts lockout. Existing MFA records that result only after known read-only COMMIT and final gates. Enrollment wrong-code failure is recorded before QR presentation, including when presentation or later read-only completion fails; its guard remains held until the call exits. Invalid challenge/context/current state, crypto/storage errors, cancellation and uncertain commit do not add guesses. Guard Drop releases in-flight state without charging those failures. Only successful MFA with known commit and final time gates clears the MFA state. Password verification and password change never reset this separate protection. Mutex failure is finite MfaUnavailable; none of these errors can become success.

## Deadlines, errors and SQL ownership

The earlier of the original caller deadline and store operation budget covers acquisition, SQL, crypto/QR and COMMIT. Every result needs a known COMMIT and a final Original check. Pending results additionally require UTC expiry strictly greater than current time after presentation, immediately before COMMIT and after known COMMIT before returning. Equality or elapsed expiry denies the result; a load denial remains non-consuming.

The existing connection guard closes failed/cancelled/uncertain connections rather than returning them to the pool. COMMIT error or timeout after COMMIT starts reports OutcomeUncertain and returns no proof. An ordinary storage failure remains Control(Storage); closed admission remains Control(Closed). There is no retry, state repair or Go fallback.

Finite errors include Unauthenticated, InvalidChallenge, InvalidPolicy, PasswordUnchanged, InvalidMfaCode, MfaRateLimited, MfaBusy, MfaCapacity, MfaUnavailable, Password, Credential, Mfa and Control. Password carries the finite LocalPasswordError; engine control errors remain Control and are never converted into authentication success. Diagnostics contain no raw token, ciphertext, secret, URI, SQL URL or SDK error payload. Authentication denial and storage failure must remain distinguishable; callers must never convert either into success.

SQL ownership needs SELECT plus the UPDATE privilege required for row locks on users/factors/challenges, and DELETE/INSERT on challenges. Password change additionally needs UPDATE on users and local_tokens, SELECT on the request_hash, identity_subject and request_json columns of oidc_auth_requests, UPDATE on oidc_auth_requests for row locks, and DELETE on oidc_auth_requests/oauth_device_codes. MFA completion additionally needs INSERT/UPDATE on local_mfa and SELECT/INSERT/DELETE on local_mfa_recovery_codes, plus the shared invalidation privileges. No superuser service connection is required. Native qualification uses a TLS connection with VerifyFull and an ordinary non-superuser schema owner, not a fake verifier or privileged service connection.

The third native case uses genuine password evidence and the actual enrollment URI to generate SDK TOTP, confirm the factor, and consume TOTP/recovery once. It covers the three purposes, exact SQL invalidation/preservation, orphan recovery/current/factor denials, shared attempt blocking and capacity, password non-reset, concurrent recovery consumption, real permissions/constraints/deferred-COMMIT rollback, observed row waits, UTC expiry/deadline/cancellation and healthy recovery.

## Verification and boundaries

From the Broker root, run:

```text
cargo test --locked -j1 -p broker-security
cargo test --locked -j1 -p broker-control
cargo test --locked -j1 -p broker-control --test postgres_local_auth -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-security -p broker-control --all-targets -- -D warnings
```

The native test requires the existing pinned PostgreSQL Docker image and responsive Docker. The original case uses one fixture for actual password KDF → Begin/load, three stages and explicit exemption, current identity denials, digest/ciphertext persistence, wrong binding, expiry, initial/final races, replacement, real permission/constraint/deferred-COMMIT failure, row-lock deadline/cancellation, recovery and explicit cleanup. A second case uses its own ordinary TLS fixture for real password evidence → mandatory change → new-password verification and the next stage. It verifies current/input denials, exact SQL invalidation and Device preservation, MFA/recovery retention, replay/concurrent completion, final-record races, real constraint/permission/deferred-COMMIT/SDK-presentation failures with whole-state rollback, UTC expiry across a row wait, timeout/abort recovery and explicit cleanup.

Source owners: security src/local_mfa.rs and src/credentials.rs; control src/local_auth.rs and src/service/local_auth.rs. Tests: security tests/local_mfa.rs, policy/expiry module tests and control tests/postgres_local_auth.rs. Compile-fail rustdocs protect private construction and trait boundaries. Begin/load qualification and failed-run history belong to Task798b and .build/rust-local-auth-2026-10-11/. Mandatory password change and the second native case belong to Task6ba7 and .build/rust-password-change-2026-10-11/.

These commands are identical on supported platforms; execution here qualifies Linux only. Broad workspace/integration qualification remains with the migration coordinator. This producer does not announce an endpoint, session, consent/grant or completed migration.

## Qualification of Begin and non-consuming load

Task tsk-798b qualified the Linux producer using serial warm-target jobs. Security passed17 tests and7 rustdocs (201.182 seconds wall); control passed88 tests and66 rustdocs (111.863 seconds wall). After the independent Admin frame oracle was added, all three affected MFA/codec/binding tests passed again. Strict Clippy on both packages/all targets passed, formatting and scoped diff checks passed, and12 local documentation links resolved. Bounded Source/documentation review found no static fault.

The native ordinary-owner PostgreSQL TLS test passed one case with three sequential journeys in148.48 seconds test runtime. It exercised real password evidence, stage precedence and explicit MFA exemption, AEAD/QR persistence/reconstitution, wrong context and expiry denial without consumption, identity changes, initial/final row races, concurrent replacement, real permission and post-DELETE INSERT failures, deferred-trigger COMMIT failure with conservative OutcomeUncertain, timeout/abort recovery and explicit store/container cleanup. UTC equality is also covered by the shared strict-gate unit test and both pre/post-COMMIT call sites were reviewed. This does not claim a production two-minute TTL elapsed across COMMIT.

The first compilation rejected an implicit Zeroizing-array borrow; an explicit slice corrected it. An earlier strict invocation lacked a retained exit status after tool runtime state was lost; its empty log is not a pass. A separately confirmed recovery invocation supplies the strict result. Actual failure/uncertain history and sanitized receipts are retained under .build/rust-local-auth-2026-10-11/.

All earlier dependency versions, sources and checksums remained intact; normal resolution added29 SDK packages and changed only broker-security and crypto-common dependency edges. Root Cargo, control Cargo and shared SQL support remained byte-identical to the pre-edit snapshots. These observations qualify this leaf only; they do not close MFA completion, HTTP, consent/OAuth, other platforms or the migration.

## Qualification of mandatory password change

Task tsk-6ba7 qualified this Linux consumer with the shared warm target and serial jobs. Control passed 88 ordinary tests and 66 rustdocs in 28.78 seconds wall; security passed 17 ordinary tests and seven rustdocs in 14.904 seconds. Counts include both merged and compile-fail rustdocs, reported separately from ordinary tests.

Both native cases passed together in 253.482 seconds wall. The existing Begin/load journey remained valid after sharing the advance helper. The new ordinary-owner TLS case exercised real password proof and replacement, new-password verification, current/stage/binding/PHC/overflow/expiry denials, the three resulting stages, exact SQL token/request/challenge invalidation, Device preservation across statuses, MFA/recovery retention, whole-state rollback on real SDK presentation/constraint/privilege/deferred-COMMIT failures, one-winner concurrency/replay, final-record races, UTC expiry across a row wait, timeout/abort recovery and explicit cleanup.

Strict Clippy passed in 10.059 seconds; formatting, local links and scoped whitespace checks passed. Bounded static review found no material code fault and corrected a documentation provenance reference. Root/control/security manifests, Broker lockfile and shared SQL support remained byte-identical. Two initial compilation errors and a verification-helper assertion error were corrected and preserved in failure-history.json; none is reported as a passing execution.

The sanitized qualification receipt and logs are under .build/rust-password-change-2026-10-11/. The shared strict UTC gate is tested at equality and completion checks its actual call sites before mutation, before COMMIT and on pending output after known COMMIT. These results do not claim a production two-minute challenge elapsed during COMMIT, immediate offline JWT revocation, completed MFA, consent/grants, HTTP, MySQL or non-Linux qualification.

## Qualification of MFA completion

Task tsk-1404 qualified this Linux producer with serial warm-target jobs. The final affected package runs passed 19 ordinary security tests and nine rustdocs in 29.214 seconds wall, and 90 ordinary control tests and 68 rustdocs in 46.762 seconds. Genuine compile-fail examples protect private authority and recovery-set construction, cloning and serialization boundaries.

All three native PostgreSQL TLS cases passed together in 606.215 seconds wall. After correcting failure accounting and guard lifetime, the MFA case passed again in 188.676 seconds wall, 187.75 seconds test runtime. It verified actual SDK enrollment, exact enrollment-token replay denial, TOTP and one-time recovery, the three purposes, SQL invalidation and Device preservation, current/factor/orphan denials, concurrent consumption, attempt blocking and capacity, real privilege/constraint/deferred-COMMIT failures and cancellation after admission. A deferred COMMIT that finished after UTC expiry consumed a recovery code without returning proof or clearing prior failures. An unsuccessful COMMIT after a wrong recovery guess did not charge the limiter.

Strict Clippy on both affected packages and all targets passed in 16.635 seconds; formatting passed in 2.597 seconds. The last correction replaced an equivalent error extraction in the concurrent test with if-let and was compiled by strict Clippy. No runtime behavior changed after the final native execution. Bounded static review found no remaining fault. Documentation contracts, 14 local links, scoped whitespace and protected-file comparisons passed. Normal full cargo metadata --locked --offline succeeded. All old package versions, sources and checksums remained intact; the only lockfile change is the approved control dependency on the existing totp-rs SDK. Root Cargo, security Cargo and shared PostgreSQL support stayed byte-identical to their pre-edit snapshots.

Initial compilation, SDK-oracle and fixture API failures were corrected. Static review identified failure-accounting/guard defects and a false compile-fail example; these were corrected before the final functional qualification. Strict Clippy also rejected the inline recovery set's large enum variant and the test error extraction; owned boxed recovery storage and if-let corrected them without suppressions. Failed runs remain failures in the history and receipt under .build/rust-mfa-completion-2026-10-11/. These results qualify local MFA only; OAuth authorization, grants, HTTP, administrative reset and final migration integration remain separate work.

## Isolation from federated OAuth grants

Password change and MFA enrollment revoke only positive-revision LOCAL tokens.
They remove LOCAL and untyped authentication requests while preserving genuine
native authorized federated requests and revision-zero grants, even for the same
raw mapped subject. No textual namespace is invented. Syntactically invalid stored
request JSON returns a finite storage error and rolls back the entire LOCAL
transaction, including password/revision, factor/recovery codes, tokens and challenges.
See [federated OAuth grants](rust-oidc-federated-grants.md) for the distinct trust rules.

Valid JSON with escaped NUL in authorization state or nonce remains valid.
LOCAL invalidation reads one relevant TEXT request at a time under SQL row locks;
a minimal borrowed Serde projection identifies the native federated discriminator.
Malformed JSON rolls back the same transaction. The existing Original is checked
between reads and effects; this operation adds no configuration quota or API.
