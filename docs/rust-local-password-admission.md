---
title: Native LOCAL password admission
doc_type: reference
references:
  - target: {type: task, id: tsk-9059, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-10ef, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e15d, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-32a8, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-8470, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-1404, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Native LOCAL password admission

The [SQLite LOCAL producer](rust-sqlite-local-auth.md) reuses these shared contracts with private file-backed transactions. The native server still selects PostgreSQL; SQLite server dispatch remains a separate delivery.

This server producer combines shared admission, fixed-provider HTTPS CAPTCHA and
the [genuine PostgreSQL password verifier](rust-local-password.md). Its result is
`VerifiedLocalPassword`, an intermediate password step. The [LOCAL login flow](rust-local-auth.md)
must still enforce mandatory password change, purpose binding and configured MFA
before the [administrative cookie producer](rust-admin-cookie-session.md) can issue
a credential. [Native HTTP password/MFA endpoints and startup](rust-admin-local-login.md) consume
this producer through shared configured owners; this library itself mounts no route.

The [shared native LOCAL runtime](rust-local-login-runtime.md) exposes purpose-explicit borrowed password/challenge views for Admin and OAuth. It keeps one engine/admission/limiter and accepts native OIDC without an Admin cookie. The Admin transport still requires its own cookie; public OAuth authorize/login pages and recovery presentation remain separate work.

## Shared owner and explicit policy

Create one `LocalPasswordEngine` and one `LocalPasswordAdmission` for the process.
The admission constructor validates its physical worker count against the engine
and binds that exact private worker owner. A different engine is rejected even if
its count matches. CAPTCHA worker/threshold policy must match the same owner.
The following are illustrative explicit policy choices, using the sourced values
that the native HTTP configuration uses when those fields are omitted:

```text
LocalPasswordAdmissionPolicy {
    max_failures: NonZeroUsize::new(5).unwrap(),
    window: Duration::from_secs(60),
    lockout: Duration::from_secs(300),
    workers: NonZeroUsize::new(2).unwrap(),
    saturation_multiplier: NonZeroUsize::new(4).unwrap(),
    max_tracked: NonZeroUsize::new(4096).unwrap(),
}
```

There is no policy Default. Durations and count products must be representable,
positive and within the mature semaphore's maximum. The tracked username bound
is the existing 4096-entry bound, not a new configurable capacity default.
One short mutex protects bounded ephemeral attempt state and occupied slots;
it performs no SQL, network or KDF work. Nothing in this map is persisted or logged.

Construct the purpose-bound view with
`store.admitted_local_passwords(&engine, &admission, purpose)?`, then call
`authenticate(username, password, optional_captcha_proof, original)`.
The trusted server route supplies `LocalAuthPurpose::AdminLogin`,
`OauthAuthorize` or `DeviceApprove`; there is no implicit purpose or action
parameter from a credential form. Views borrow the same engine and admission.
Username surrounding whitespace is removed, case is preserved and the existing
safe 128-byte segment contract applies. Passwords remain exact, nonempty and at
most 4096 UTF-8 bytes. Invalid input does
not reserve quota, invoke CAPTCHA or start a KDF.

## Running and queued work

The shared logical bound is `workers * saturation_multiplier`, covering running
and waiting work. Reservation is immediate; saturation yields `RateLimited(1s)`
before CAPTCHA or KDF. Occupancy is captured under the same mutex that reserves
the slot and includes the new slot. Physical KDF concurrency remains the engine's
existing worker semaphore. A queued attempt rechecks its username lock inside
the blocking worker before the actual SDK verification begins.

A private Arc-owned work lease stays in the whole blocking closure. Dropping or
timing out the async request cannot free either its physical or logical slot
while that worker is still running. The outer lease remains through current SQL
revalidation, known COMMIT and final gates. Cancellation before physical work
releases the queued reservation. No generic future wrapper or task-local state
supplies admission or authentication authority.

For mandatory password change, `admission.admit_password_change(&engine, original)`
returns a protected `AdmittedLocalPasswordChange`. Its `complete(auth, challenge,
binding, new_password)` consumes the guard and invokes the actual current
[password-change transaction](rust-local-auth.md#mandatory-password-change).
Both its verification and hash workers retain the same lease. This work shares
capacity but performs no CAPTCHA or initial-password guess accounting. MFA/TOTP
uses its separate attempt limiter and performs no password KDF admission.

Close logical admission, join `engine.close().await`, then close SQL after request
owners have finished. Engine registration and close are serialized, and the
mature TaskTracker waits for actual worker exit. Failed or expired startup dummy
creation also drains its worker. Request cancellation alone is not this shutdown.

## Username failure state

The fixed failure window resets at equality or later. Only an actual false SDK
password result creates private incorrect-password evidence that can increment
the username counter while the Original gate is valid. At the threshold, the
entry is blocked until the monotonic lockout expiry; equality permits admission.
A concurrent false SDK result crossing the failure-window boundary preserves
an independently active lockout; renewing the window does not clear it.
Concurrent attempts for the same username are allowed and retain their entries.

Only genuine `VerifiedLocalPassword` after current SQL revalidation and known
COMMIT clears failures. CAPTCHA rejection, saturation, SQL/crypto errors,
cancelled/expired work, current-revision races and uncertain COMMIT neither charge
nor clear them. Success keeps active entry accounting until all same-username
leases finish, preventing an old lease from decrementing a replacement entry.

Pruning removes only unblocked, inactive entries stale for longer than
`window + lockout`; active work cannot be evicted. After pruning, a full4096-entry
map denies a new username with `Capacity`, mapped by the HTTP consumer to503
`authentication_unavailable`, without CAPTCHA or KDF. It does not silently admit
an untracked guess or raise capacity.

## Fixed HTTPS CAPTCHA protocol

`LocalCaptchaConfiguration::Disabled` requires no provider fields or client and
performs no network request. Enabled configuration requires explicit provider,
public site key, protected secret key, validated public URL hostname, trigger
multiplier and verification timeout. Multiplier must be finite and between0 and
saturation inclusive; the threshold is `max(1, ceil(workers * multiplier))`.
Explicit 0 requires CAPTCHA for the first slot. Native HTTP omission uses the
sourced 1.5 multiplier and 3-second timeout; accepted timeout is 500ms–10s.

`next_password_challenge(purpose)` observes the same occupied work state plus the next
request, without reserving a slot, adding a counter or performing network work.
It yields only public challenge DATA and fails closed once admission is closed.
The [native HTTP options consumer](rust-admin-local-login.md) observes this getter; an options observation does not
reserve work or bypass the authenticated request's own threshold decision.

Only initial password work at or above the captured threshold needs CAPTCHA.
Missing proof performs no outbound request. Proof is trimmed, nonempty and at
most2048 UTF-8 bytes. Below threshold or when disabled, the supplied proof is ignored.

Reqwest uses mature TLS and disables redirects. The endpoints are fixed:

- Turnstile: `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
- reCAPTCHA: `https://www.google.com/recaptcha/api/siteverify`.

The request is a form containing only `secret` and `response`; no `remoteip`
or operator endpoint is accepted. The provider budget and Original cutoff are
captured once and never renewed. A streamed response is capped at64KiB and must
be2xx with one JSON value. `success` must be boolean true and trimmed `hostname`
must match the public hostname ignoring ASCII case. Turnstile additionally
requires the exact action for the trusted purpose: `admin-login` for `AdminLogin`,
`oauth-login` for `OauthAuthorize` and `device-login` for `DeviceApprove`. reCAPTCHA
does not require action. `challenge(purpose)` returns owned public DATA for
that purpose. One observation cannot change another request's action.
CAPTCHA verification and the CaptchaRequired response use the view's same purpose;
capacity and username failure accounting remain shared across all views.

Provider errors, invalid shape, wrong host/action, redirects, oversize bodies and
provider timeout yield `CaptchaRequired` while Original remains valid. Expired
Original yields the finite deadline control error. No failure starts a KDF or
charges a password guess. Provider expiry/single-use rules remain external; the
Broker adds no token cache, replay ledger or fallback. Public challenge DATA
contains provider, site key and Turnstile action, never the secret or provider body.

## Verification commands

The real PostgreSQL tests require the existing pinned PostgreSQL image and
responsive Docker daemon. They use ordinary SQL ownership, TLS and actual
Argon2. The Siteverify fixture owns Rust HTTPS servers and a private test CA
for the fixed provider hostnames; it makes no commercial provider request
and exposes no production client/URL bypass. Policy-only data cannot create
password or completed-login proof.

The following exact phases are saved in the project runner before PROJECT,
Presence and audit. Use the ordinary resource settings agreed by the coordinator.

```text
cargo test --locked --offline -p broker-control --test local_password_admission -- --ignored --exact postgres_local_password_admission_contract --test-threads=1
cargo test --locked --offline -p broker-control --test local_password_admission -- --ignored --exact postgres_admission_commit_uncertainty_contract --test-threads=1
cargo test --locked --offline -p broker-control --lib -- --ignored --exact local_captcha::tests::postgres_https_local_password_admission_contract --test-threads=1
cargo test --locked --offline -p broker-control --lib -- --ignored --exact local_password_admission::tests::postgres_admission_capacity_preserves_active_entries --test-threads=1
```

`cargo test --locked --offline -p xtask` exercises each saved phase with a real
Rust assertion failure and requires it to stop before later phases and audit.
Those adversarial runner fixtures prove the gate, never credential authority.
Normal control tests include the actual fixed-host HTTPS protocol and SDK-worker
retention/closure tests. The existing `postgres_password` and exact
`postgres_password_change_native_contract` targets cover affected previous
public methods. Broad integration and additional platforms remain Main's work.

## Evidence and boundaries

Source: `crates/broker-control/src/local_password_admission.rs`, `local_captcha.rs`,
`local_password.rs`, `service/local_password.rs` and the private password-change
plumbing in `service/local_auth.rs`. Public previous hash/verify/password-change
methods retain their signatures and behavior; new consumers must use the shared
admission owner. Native administrative HTTP startup passes `AdminLogin`
explicitly. OAuth/device browser journeys and other SQL adapters remain separate
work: supporting their
typed CAPTCHA purposes does not expose their browser endpoints.

The PostgreSQL admission contracts exercise current identity/revision, known-success clear, wrong-password locks, guarded mandatory change and an actual COMMIT observed idle while its TLS ACK is withheld. An uncertain result returns no proof and neither charges nor clears the prior failure state.

[Native HTTP password/MFA startup and routes](rust-admin-local-login.md) have their own executable tests; producer tests do not establish full Broker integration or another platform.

Purpose-specific admission tests use real fixed-host HTTPS and PostgreSQL to cover correct and cross-purpose actions, independent challenges, shared capacity/username lockout and genuine Admin/OAuth completed login proofs. Public OAuth browser journeys and discovery have separate tests.
