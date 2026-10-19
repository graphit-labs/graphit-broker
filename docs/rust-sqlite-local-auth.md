---
title: Native SQLite LOCAL authentication
doc_type: reference
description: SQLite password admission, bound LOCAL challenges, password change and MFA.
tags: [rust, sqlite, authentication, password, mfa]
references:
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-3025, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-c055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-4f6e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-7494, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# Native SQLite LOCAL authentication

This reference is for Broker maintainers composing LOCAL authentication over
the private [SQLite Control store](rust-sqlite-control.md). It reuses the shared
[password engine](rust-local-password.md), [admission/CAPTCHA protocol](rust-local-password-admission.md)
and [LOCAL challenge contracts](rust-local-auth.md).

This library supplies no HTTP route, session, cookie, consent, OP grant or administrative/resource permission. Server backend selection is described in the [native Server guide](rust-broker-server.md#select-private-sqlite).

## APIs and actual shared owners

| Store view | Operations and shared results |
| --- | --- |
| local_password_verifier(&engine) → SqliteLocalPasswordVerifier | verify(username, password, original) → VerifiedLocalPassword |
| admitted_local_passwords(&engine, &admission, purpose) → Result<SqliteAdmittedLocalPasswords, ControlError> | authenticate(username, password, captcha_proof, original) → VerifiedLocalPassword |
| local_auth_service(Arc<CredentialDigester>, Arc<LocalMfaProtector>, Arc<LocalAuthPolicy>) → SqliteLocalAuthService | begin, load, complete_password_change, complete_mfa |

The service's async operations retain the existing error types:

- begin(proof, binding, original) consumes genuine password evidence and returns LocalAuthStep.
- load(raw, binding, original) returns PendingLocalAuth without confirming a factor.
- complete_password_change(&engine, raw, binding, new_password, original) returns LocalAuthStep.
- complete_mfa(Arc<LocalMfaAttemptLimiter>, raw, binding, code, original) returns LocalAuthStep.

Proof fields remain private and Debug is redacted. Metadata cannot manufacture
verified evidence. Use one actual engine, logical admission and MFA limiter
across requests. Equal worker counts do not make different engines equivalent.
Arc retains the actual crypto/policy/limiter owners during native work without
cloning key material or resetting limiter history.

AdmittedLocalPasswordChange::complete_sqlite(self, &auth, raw, binding,
new_password) consumes the existing guard with its protected engine, original
deadline and genuine work lease. It exports no lease. KDF and SQL workers
retain that admission while running, including after the async caller is dropped.

## Password and challenge boundaries

Username trimming preserves case; passwords are exact and never trimmed.
Existing limits remain 128 ASCII bytes for safe usernames, 512 bytes for strict
subjects and 4096 UTF-8 password bytes. New passwords require at least 15 Unicode
scalar values. Missing, malformed or ineligible stored credentials use the
real dummy KDF. Invalid admitted input consumes no slot or CAPTCHA request.

Password verification observes bounded current SQL fields, runs the SDK KDF
outside the connection, then rechecks the complete identity/PHC/revision/flags
under BEGIN IMMEDIATE before known COMMIT and password evidence.

Challenges keep the canonical 43-character token, challenge HMAC domain 12,
binding domain 13 and explicit policy TTL of 2–30 minutes. Admin, OAuth and
Device contexts retain exact purpose/binding bytes. No policy default is added.
Retained sensitive buffers use zeroizing owners.

Stage priority is mandatory password change, explicit MFA exemption, existing
MFA, then enrollment. A factor row alone does not make an exempt password-only
login a verified MFA login. Load is non-consuming and rejects changed
identity/revision, incompatible factor state, corruption, wrong context or expiry.

## Password change and factor confirmation

Password change first observes a private bounded challenge/user/PHC snapshot.
The shared engine verifies that the new password differs and computes its hash
outside SQL, retaining the same admission and effective deadline. The final
IMMEDIATE transaction compares the complete original challenge, username,
subject, PHC, revision and change flag before CAS mutation, invalidation and
stage advancement. Conflict returns InvalidChallenge; no blind retry occurs.

MFA/begin/load use one IMMEDIATE transaction with the actual Arc owners in the
blocking worker. No async block_on or replacement executor is introduced.
Enrollment requires no factor and no orphan recovery rows. The existing SDKs
provide subject-bound authenticated 90-character ciphertext, real otpauth
presentation/PNG QR and TOTP verification.

Enrollment confirmation atomically persists the verified factor, accepted
step, ten recovery MACs, revision CAS and invalidation. Recovery plaintext is
not stored. The protected result exports codes once via take_recovery_codes.
Existing-factor TOTP uses step CAS; recovery deletes one matching MAC.
Successful existing-factor authentication consumes its challenge without
incrementing user revision. Replayed steps, codes and challenges cannot authenticate.

Wrong codes retain Pending and durable state, following the existing shared
limiter's stage-specific accounting order. Corruption does not become a wrong
guess or silently reset a factor.

## Invalidation and transaction outcomes

Invalidation is scoped to the affected subject:

- Revoke active LOCAL tokens with positive LOCAL user revision; preserve
  federated revision-zero tokens, previous revocation timestamps and foreign subjects.
- Delete LOCAL/untyped authorization requests, preserving coherent native
  federated requests through the existing canonical parser. Invalid JSON aborts
  all effects.
- Delete the subject's challenges across purposes.
- Admin/OAuth delete associated Device rows. DeviceApprove omits that DELETE
  entirely and preserves every Device status. Empty and foreign subjects remain intact.

All password, factor, recovery, invalidation and advancement effects either
commit together or roll back. SQL/decoding and SDK presentation failures after
staged writes cannot publish a partial change.

Capture min(original, now + operation budget) once for the whole operation.
SQL, KDF and continuation steps use that same end. A known COMMIT remains
committed, while authentication still checks the bounded end and applicable
challenge expiry before releasing proof, Pending or recovery codes.
A late gate can reject delivery after consumption: recover through a fresh
login using current state, never replay the old mutation automatically.

Cancel/drop retains actual SQL/KDF workers, connection, crypto and admission
owners until their work ends. Missing commit acknowledgement returns
OutcomeUncertain without proof or automatic replay. Close admission, join
engine workers, then close SQL through the existing SQLite lifecycle.

The closed SqliteControlError → ControlError conversion preserves PrivateFile
explicitly and uses backend-neutral Configuration/Connection messages.
Authentication failures retain their shared meanings. Errors contain no SQL,
paths, driver text, passwords, PHCs, keys or challenge/recovery contents.

## Executed checks and saved gates

Native tests use physical SQLite files, actual Argon2 PHCs, AES-GCM,
TOTP/QR/recovery, independent connections and real cancellation/SQL failures.
Synthetic persisted OAuth/Device rows prove invalidation only; they do not
qualify real OP issuance.

The expensive native suite is ignored in the ordinary workspace test run.
The saved SQLITE_LOCAL_AUTH pre-push phase runs the LOCAL authentication,
administrative cookie and HTTP targets, together with native LOCAL OIDC grants
and token/browser/Device HTTP tests, full-channel administrative reads and
[role/assignment writes](rust-sqlite-admin-rbac.md), before Audit:

~~~text
cargo test --locked --offline -p broker-control -p broker-presence --test sqlite_local_auth --test sqlite_admin_cookie --test sqlite_admin_local_http --test sqlite_oidc_grants --test sqlite_oidc_token_http --test sqlite_oidc_browser_http --test sqlite_device --test sqlite_device_http --test sqlite_oidc_lifecycle --test sqlite_oidc_lifecycle_http --test sqlite_admin_reads --test sqlite_admin_read_http --test sqlite_oidc_federated --test sqlite_oidc_federated_http --test sqlite_admin_ingress --test sqlite_admin_session_http --test sqlite_admin_upstream_login --test sqlite_admin_grants --test sqlite_admin_grants_http --test sqlite_admin_rbac_write --test sqlite_admin_rbac_write_http --test sqlite_hub_access --test sqlite_hub_access_http --test sqlite_storage_admission --test sqlite_storage_credentials_http --test sqlite_admin_users --test sqlite_admin_users_http --test sqlite_local_presence_now --test sqlite_local_presence_now_http -- --ignored --test-threads=1
~~~

The existing CAPTCHA phase uses the common
_https_local_password_admission_contract filter without --exact, selecting
both PostgreSQL and SQLite native HTTPS cases. SQLite alone:

~~~text
cargo test --locked --offline -p broker-control --lib local_captcha::tests::sqlite_https_local_password_admission_contract -- --ignored --exact --test-threads=1
~~~

The private fixture replaces CA/DNS only inside the test module. Production
CAPTCHA endpoints and hostname/action verification remain fixed; there is no
public bypass configuration. Runner negative/restored proofs are recorded
separately from actual authentication evidence.

Affected checks include Control library/rustdoc tests, xtask tests/guardrails,
strict Clippy, consumer library compilation and owned-file formatting.
Linux results do not establish native Windows/macOS runtime behavior
or complete the server backend.

Sources: [password/admission](../crates/broker-control/src/sqlite/flow/local_password.rs),
[LOCAL stages](../crates/broker-control/src/sqlite/flow/local_auth.rs),
[error conversion](../crates/broker-control/src/sqlite/error.rs),
[admitted guard](../crates/broker-control/src/local_password_admission.rs),
[native tests](../crates/broker-control/tests/sqlite_local_auth.rs).

## LOCAL OIDC consumer

The [SQLite LOCAL grants](rust-sqlite-oidc-local-grants.md) consumer takes
`PreparedOidcLogin` only after OAuth binding and recovery-code presentation.
The grant completion revalidates current identity/profile/roles in the same
SQLite transaction before issuing a code; the password/challenge producers
retain their existing boundaries.

The seven [SQLite LOCAL administrative user and service-credential operations](rust-sqlite-admin-users.md) share the qualified invalidator and password engine. Their long physical SQL/TCP targets are selected explicitly in this existing phase; their ignored status keeps them out of the ordinary workspace test run.

The [SQLite LOCAL inventory and Now family](rust-sqlite-local-presence-now.md) consumes current human/service bearer verification and project policy through explicit routers. Its four Control and four HTTP/WebSocket cases are long ignored targets in this existing phase. These possession fixtures do not establish credential issuance; service issuance has its [separate administrative producer](rust-sqlite-admin-users.md).
