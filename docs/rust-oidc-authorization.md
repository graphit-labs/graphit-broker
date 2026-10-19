---
type: document
title: Native Rust OIDC authorization
description: PostgreSQL pending requests and atomic completion with genuine LOCAL or upstream OAuth proof.
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7db9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4546, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-d3b9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-7568, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-798b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-5ff3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Native Rust OIDC authorization

Server integrators can admit a public OIDC Authorization Code request with S256
and persist its pending data in the existing [native PostgreSQL schema](rust-sql-schema.md).
A successful `create` returns an opaque request ID after a known COMMIT. `load`
can observe the same pending data repeatedly without consuming or extending it.
Neither create nor load authenticates a person or issues a code. The separate
`complete` transaction consumes a prepared genuine LOCAL login and returns a
committed authorization code. `complete_upstream` consumes genuine H1 OAuth proof for
its protected request, with [federated trust and snapshot rules](rust-oidc-federated-grants.md).
None of these completion operations issues an access token.

The Rust library uses the embeddable **oxide-auth 0.6.1 server state machine**.
The [native server](rust-broker-server.md) now composes this producer with its HTTP adapters and committed identity owners. This producer itself does not expose an HTTP endpoint, perform login or consent, register clients,
render `form_post`, exchange a code, sign an ID token or rotate
refresh grants. These are separate migration deliveries. [Local login](rust-local-auth.md),
[access JWT signing](rust-broker-access-issuer.md) and the
[stored access-grant DATA reader](rust-oidc-access-grants.md) retain their own boundaries.

The [native code-exchange producer and HTTP endpoint](rust-oidc-token-exchange.md)
now consume genuine committed P2b codes, sign access/ID tokens and persist the
initial refresh grant. The P2 APIs here keep their existing pending/completion
boundary; the [public browser transport](rust-oidc-browser-authorization.md) now
composes that journey.
[Native refresh rotation](rust-oidc-refresh.md) is available through its committed
initial grant and retains its independent revalidation/rotation contract.

The [shared native LOCAL runtime](rust-local-login-runtime.md) exposes purpose-explicit borrowed password/challenge views for Admin and OAuth. It keeps one engine/admission/limiter and accepts native OIDC without an Admin cookie. The Admin transport still requires its own cookie; the [public OAuth browser transport](rust-oidc-browser-authorization.md) now consumes
the same stages and request-owned recovery presentation.

The [initial Browser admission producer](rust-oidc-browser-admission.md) now separates genuine pending results from protected semantic rejections after current-client/redirect validation and a known read COMMIT. Its initial targets use only Original; pending targets keep UTC and monotonic expiry. This producer does not mount the public authorize/login journey, and the direct P2 create API and error precedence remain unchanged.

## Configure and call

Startup supplies an `OidcAuthorizationConfiguration` with all six fields:
`cli_client_id`, `cli_redirect_path`, `api_audience`, `accepted_resources`,
`dynamic_registration` and `authorization_ttl`. There is no library `Default`.
Configured CLI ID and API audience are safe ASCII identity segments of at most 128 bytes.
Dynamic IDs also accept every canonical 32-byte Base64URL identifier, including
leading `-` or `_`; registration, admission and refresh retain the exact same ID.
The CLI path starts with `/`, contains neither query nor fragment, and fits the
explicit parameter cap. Its registration is exactly `http://127.0.0.1` plus that
path. Authorization TTL must be between 30 seconds and 600 seconds, inclusive;
conversion to UTC microseconds is checked. Production's active one-minute setting
belongs to startup configuration rather than a library default.

`OidcAuthorizationLimits::new(json_bytes, parameter_bytes)` requires nonzero
limits representable in `usize`, `isize` and SQL `i64`. The JSON cap limits each
stored JSON column. The parameter cap bounds each scalar and the aggregate sum
of present scalar bytes plus **entry bytes + 1 for every resource and prompt**,
including empty entries. Arithmetic overflow and excessive inputs are rejected
before SQL admission. UTF-8 physical bytes are counted rather than characters.

Configured resources are trimmed, deduplicated absolute URI/IRI literals without
fragments, at most 512 bytes each. No resource is added automatically.

```text
PostgresControlStore::oidc_authorization_service(
    &self, &CredentialDigester, &OidcAuthorizationPolicy
) -> PostgresOidcAuthorizationService<'_>

service.create(OidcAuthorizationInput<'_>, original: Instant)
    -> Result<PendingOidcAuthorization, OidcAuthorizationError>
service.load(raw_request: &str, original: Instant)
    -> Result<Option<OidcAuthorizationRequestInfo>, OidcAuthorizationError>
```

The borrowed service cannot outlive its immutable store, digester or policy.
`OidcAuthorizationInput` borrows `client_id`, `redirect_uri`, `response_type`,
`scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method`, optional
`response_mode`, and resource/prompt slices. A future transport must reject
repeated scalar parameters before constructing this decoded DATA input.

On success, `pending.request()` borrows the zeroizing 43-character request
secret, while `pending.info()` returns private DATA fields through getters.
The info includes client, original redirect, scopes, canonical response mode,
original state and nonce, optional resource, and created/expiry UTC microseconds.
Outputs redact Debug, expose no public construction or Deserialize, and the
pending secret cannot be cloned or serialized. Deliver the ID only over the
private continuation path; do not log it or persist it with the request JSON.

## Protocol admission

The SDK executes `Bind → Extend → Negotiate → Ok` for response type `code`.
The registrar binds an already admitted current Broker client to
`RegisteredUrl::Exact(ExactUrl(original))`. It does not use the SDK's ClientMap,
which substitutes all registered scopes, or its localhost port adapter, which
does not reproduce the active IP-loopback behavior.

PKCE requires literal `S256` and a canonical Base64URL value without padding,
encoding exactly 32 bytes. Existing Base64 SDK decoding and re-encoding validate
the challenge, then `Pkce::required().challenge` constructs the real SDK extension.
Plain, missing, noncanonical and malformed challenges fail. There is no verifier
or code-consumption operation in this unit.

The Rust policy explicitly admits **openid, profile, email, phone, address and offline_access**, filters unknown scopes, and requires `openid`. It deduplicates in first-occurrence order and passes the filtered set to SDK Scope parsing. It never adds scopes or derives a restriction from the dynamic client's stored scope subset.

State is trim-nonempty and at most 512 bytes. Nonce is trim-nonempty and fits the
parameter cap. Both preserve the caller's original nonempty whitespace and embedded NUL;
the native JSON codec escapes it. `prompt=none` alone produces `LoginRequired`; combining it with
another prompt produces `InvalidRequest`. Other prompts retain the active fresh
login journey without adding a consent screen or persisted max-age behavior.

Modes `query`, `fragment` and `form_post` are admitted. An omitted or unknown mode
becomes Query, matching the active code-flow SDK behavior. This canonical value
is stored; rendering belongs to the later transport.

Request resource values are trimmed and empty values skipped. There may be only
one nonempty occurrence, even if repeated values are identical. It must be an
absolute, fragment-free literal in the configured catalog. The configured CLI
may omit it; every dynamic client must supply it. URI normalization is never
used for resource equality or to broaden its audience.

## Current clients and original redirects

Only the configured exact CLI ID is recognized without a SQL registration.
Dynamic registration must be explicitly enabled and the current
`oauth_dynamic_clients` row must exist. The schema has no client `enabled` flag.
The reader checks ID, bounded trimmed name (which may be empty; at most 256 Unicode characters and
1024 UTF-8 bytes), positive creation time no later
than now, application type `native` or `web`, and nonempty typed canonical JSON
arrays of redirects and scopes. SQL caps use `OCTET_LENGTH` and `CASE` before
materializing either JSON string. Malformed current data deny admission.
The [native dynamic registration endpoint](rust-oidc-registration.md) now produces
these six catalog fields through a known-COMMIT transaction. The pending APIs
here retain their separate admission/completion boundary.

Registration URLs must use HTTP loopback or HTTPS nonloopback, without userinfo
or fragment. Any HTTPS entry derives application type Web; otherwise the type
is Native. A mixed HTTP-loopback/HTTPS-nonloopback Web catalog is valid. A Web
request must equal an entire registered literal, including an HTTP-loopback entry
in that mixed catalog: changes in host case, port, path or query deny. Native
port flexibility does not apply to Web clients.

A Native request using HTTP or HTTPS loopback can vary host, scheme and port
when some registered loopback URL has the same **percent-decoded path bytes and
literal original RawQuery**. Loopback means original `localhost` ignoring ASCII
case, or an original address accepted by `std::net::IpAddr::is_loopback`.
`127.0.0.2` and `[::1]` qualify; abbreviated, hexadecimal or octal IPv4 spellings
such as `127.1` do not gain loopback authority through URL normalization. An
explicit port must fit `u16` and cannot be zero. Native registrations themselves contain only HTTP loopback URLs; HTTPS
registrations derive Web. Scheme classification ignores ASCII case, while the
complete original literal remains unchanged for Web equality and storage.

IRI-string 0.7.14 reads original authority/path/query slices. Percent-encoding
2.3.2 decodes only the path as bytes: `+` stays plus, `%FF` needs no decoded UTF-8,
and dot segments remain unchanged. Absent and empty query both represent an empty query; otherwise query bytes, encoding spelling and Unicode remain literal.
URL 2.5.8 validates the SDK URL but never supplies normalized matching components.
The full original redirect is retained for later strict code exchange.

## SQL, cancellation and expiry

`create` starts READ COMMITTED, locks the current dynamic client `FOR SHARE`,
admits the request, generates 32 CSPRNG bytes with the existing native opaque
43-character codec, and digests them with `TokenKind::OidcAuthRequest` (domain 9).
The local challenge domain 12 is distinct. No new RNG, parser or cryptographic
implementation is introduced.

Exactly one `oidc_auth_requests` row is inserted: hex64 `request_hash`, empty
`identity_subject`, NULL `code_hash`, native JSON, positive UTC `created_at` and
checked `expires_at = created_at + configured TTL`. JSON contains format
`rust-broker-authorization-v1`, phase `pending`, client ID, API audience,
optional resource, original redirect, state, ordered scopes, canonical mode,
nonce, code challenge and method. It contains neither raw request ID nor code.
The serialization buffer is zeroizing and capped before SQL. Load accepts only
a JSON object; duplicate/unknown fields, trailing input, wrong shapes and
unrecognized format/phase fail closed. No importer or future phase stub
exists.

`load` reads the initial request without a row lock, locks the current client,
then locks the final request `FOR SHARE`, comparing every field including exact
JSON, digest, identity, code and timestamps. It revalidates the pending codec,
current client, SDK admission and configured catalog. Pending creation cannot
be in the future and expiry must match the original configured TTL. Absent,
expired or completed rows return None. Completed JSON belongs to the completion producer
and is not interpreted as pending. Load performs no UPDATE, DELETE, renewal or
repair. Client-before-request lock order remains compatible with later
user-before-client-before-request completion and user-before-request invalidation.

One caller-supplied original `Instant`, capped by the store operation budget,
covers admission, RNG, SQL and COMMIT. Original time and strict UTC expiry
`expires_at > now` are checked before and after known COMMIT before output.
Cancellation closes the borrowed connection through the existing RAII guard.
Once COMMIT starts, timeout or a COMMIT error returns `OutcomeUncertain` without
output or automatic retry. A known but late commit can leave a pending row whose
secret was never returned; the operation does not invent a cleanup job or renew
its TTL. A failure before COMMIT returns no output and cannot become success.

## Errors and qualification

Finite errors are `InvalidConfiguration`, `InvalidLimits`, `InvalidRequest`,
`InvalidClient`, `InvalidRedirect`, `InvalidScope`, `LoginRequired`,
`InvalidTarget`, `MalformedStored`, `ReadLimitExceeded`, `Credential`, `Random`
and `Control`. SDK error payloads are discarded. Control preserves storage,
closed-pool, deadline and uncertain-outcome distinctions. An expired/absent/
completed request is None; malformed stored pending data is an error. Callers
must not infer grant authority from either a digest or an info observation.
Completion additionally returns `InvalidLogin` for an ineligible current human,
stale revision or incorrect proof binding; absent, expired or completed requests
return `InvalidRequest`, rather than load's None.

## Complete a LOCAL authorization

After [native LOCAL login](rust-local-auth.md), synchronously call
`PreparedOidcLogin::try_from(login)`. It accepts only OauthAuthorize purpose and
an owner without unextracted recovery codes. `InvalidPurpose(login)` and
`RecoveryCodesPending(login)` return the original protected owner;
`error.into_login()` recovers it without losing codes or binding evidence. The
caller must take enrollment codes, retain and present them through its own
private continuation, then prepare again. Absence of codes does not prove UI
presentation. No boolean acknowledgement or implicit extraction is used.

`service.complete(raw_request, prepared_login, original)` returns private
`AuthorizedOidcAuthorization` after known COMMIT and final time gates. Its
getters borrow the zeroizing 43-character code, request info and OIDC subject,
and expose AMR and UTC microsecond auth time. It has no Clone, Deserialize,
public construction or incidental serialization; Debug is redacted.

The READ COMMITTED transaction reads bounded pending DATA initially, then locks
the current user FOR SHARE, current dynamic client FOR SHARE, and final request
FOR UPDATE, in that order. Username/subject, human kind, enabled1, positive
matching revision and cleared mandatory-change flag must still hold. The login
must match the exact original request binding and must have been observed at or
after request creation. Final request fields must equal the initial observation;
SDK admission, client registration and resource catalog are revalidated.

Profile values come from current SQL, with VARCHAR512 Unicode semantics and
2048 UTF-8 byte bounds. Teams must be a capped string array: trim, skip empties,
deduplicate in first-occurrence order. Roles use the existing canonical SQL
assignment key `local|subject`, while the principal and request identity retain
the raw subject; a raw-subject assignment is never promoted. Current assigned roles plus implicit
`user` are captured in the canonical human principal. These are DATA for this
authorization, never a PROJECT permission lease. The principal method is
`local-token`; AMR is separately `pwd`, adding `otp` only when the producer's
private fact confirms actual TOTP or recovery verification. Mere factor presence
does not add otp. Auth time is freshly observed at completion and cannot predate
the login observation.

The native OIDC subject uses the existing pepper and [framed domain15](rust-credentials.md),
with separate exact issuer and subject fields. A new 32-byte CSPRNG code uses the
existing native codec; SQL stores only its domain10 hex64 digest. The authorized
JSON retains every original request field, including state, nonce, optional
resource and PKCE, and adds canonical principal, subject, AMR and auth time.
Neither raw request nor raw code is persisted or logged. Serialization has a
zeroizing owner and the same JSON byte cap.

One conditional UPDATE installs identity, authorized JSON and code digest only
on the exact still-pending row. Original created/expiry timestamps and TTL stay
unchanged. No MFA code is consumed again. Concurrent completions serialize on
the request: exactly one can return a code, replay is rejected. Failure before
COMMIT rolls back; cancellation closes the borrowed connection. Once COMMIT
starts, timeout or error is OutcomeUncertain with no output or automatic retry.
A known late commit may leave an authorized row with an unreturned code; the
library does not reset or renew it. Original deadline and strict request UTC
expiry are checked before and after known COMMIT.

The native completion corpus is `tests/postgres_oidc_completion.rs`: ordinary
TLS PostgreSQL, actual password producer and SDK TOTP/recovery, protected code
handoff, current identity/client denial, capped or malformed DATA, unchanged
snapshots, permission/constraint/deferred-COMMIT failures, observed lock waits,
abort, expiry during wait and concurrent one-code issuance. It is separate from
the earlier pending-only qualification below. Run with the same fixture prerequisites:

```text
cargo test --locked -j1 -p broker-security -p broker-control
cargo test --locked -j1 -p broker-control --test postgres_oidc_completion -- --ignored --test-threads=1
cargo clippy --locked -j1 -p broker-security -p broker-control --all-targets -- -D warnings
```

Completion evidence and failed attempts belong in
`.build/rust-oidc-completion-2026-10-11/`. This library still delivers no code
exchange, HTTP rendering, transport recovery, consent UI or final migration
integration. A passing compile or historical pending suite is not completion
runtime qualification.

LOCAL completion qualification on Linux (2026-10-11): Control passed 95 ordinary
tests and 80 Rustdocs, Security passed 20 ordinary tests and 11 Rustdocs in the
combined 56.93-second command. The complete native TLS corpus passed in 217.60
seconds wall time (217.46 fixture runtime). Strict Clippy passed in 51.75 seconds;
formatting and locked offline metadata passed. Nine protected files, including
manifests, lockfile, schema, existing login producer and shared fixture, remain
byte-identical. The 12-path audit validates 19 local links; tracker found no
remaining static fault after the canonical role-key and real Serde-proof fixes.
The retained history records failed test seeds (required timestamp and role FK)
and the fixture's unsupported PostgreSQL jsonb/NUL cast. The corrected corpus
uses Serde and TEXT updates, preserving exact native state/nonce bytes. These
results qualify this completion library, without qualifying HTTP, code exchange
or the final broad integration.

The affected suite is `broker-control`; the real native fixture uses the existing
shared PostgreSQL TLS support, ordinary NOSUPERUSER owner, schema epoch 2,
actual SDK/digester, pool 2 and explicit store/container cleanup. Its corpus
covers original Native/Web redirects, current registration, digest-only pending
rows, repeated nonconsuming loads, malformed/capped data, expiry during a real
observed row wait, cancellation, privileges, constraints and deferred COMMIT
failure. The source unit tests cover SDK policy boundaries and the Rustdocs
prove output privacy/lifetimes by compilation failure.

```text
cargo test --locked -j1 -p broker-control
cargo test --locked -j1 -p broker-control --test postgres_oidc_authorization -- --ignored --test-threads=1
cargo clippy --locked -j1 -p broker-control --all-targets -- -D warnings
cargo fmt --all --check
cargo metadata --locked --offline --format-version 1
```

Qualification results and actual failure history are recorded separately in
`.build/rust-oidc-authorization-2026-10-11/`. The same commands require the project's
Rust/Cargo toolchain and native fixture prerequisites. Linux execution does not
prove Windows/macOS or final broad integration. No code/verifier exchange,
HTTP OpenID Provider, production-minute MFA flow or migration completion is
established by this unit.

Primary protocol provenance: [oxide-auth authorization machine](https://github.com/197g/oxide-auth/blob/v0.6.1/oxide-auth/src/code_grant/authorization.rs),
[PKCE extension](https://github.com/197g/oxide-auth/blob/v0.6.1/oxide-auth/src/code_grant/extensions/pkce.rs),
[exact registration API](https://github.com/197g/oxide-auth/blob/v0.6.1/oxide-auth/src/primitives/registrar.rs),
[original IRI slices](https://github.com/lo48576/iri-string/blob/v0.7.14/src/types/generic/absolute.rs).

Qualification on Linux (2026-10-11): `broker-control` passed 97 ordinary tests
and 70 Rustdocs in 45.857 seconds; the final PostgreSQL contract passed in
28.718 seconds wall time (28.58 seconds fixture runtime). Strict Clippy passed
in 13.184 seconds, formatting in 0.397 seconds, and locked offline metadata in
0.138 seconds. The audit preserved all 276 prior package version/source/checksum
pins, added 26 SDK packages, confirmed seven protected files unchanged and four
local links valid. Tracker's final static delta review found no remaining fault.
Earlier SQLx/test API compilation failures, the READ ONLY/FOR SHARE runtime
failure and the Clippy correction remain in the failure history; earlier passes
are not substituted for final source qualification.

## Protected browser response projection

`OidcAuthorizationRequestInfo::response_target(original)` borrows a sealed,
revalidated observation and preserves its existing Original/UTC/monotonic expiry
gates. The [shared callback renderer](rust-oidc-browser-callback.md) uses that
view for a known protocol failure; successful responses consume the genuine
`AuthorizedOidcAuthorization`. Raw request parameters cannot construct a target
or grant. The parsed origin is CSP/display data; the registered redirect remains
literal. This projection does not change P2 state admission or mount the public
authorize/login entry page.

## SQLite LOCAL integration

The explicit [SQLite LOCAL grant APIs](rust-sqlite-oidc-local-grants.md) reuse this
policy and authorized codec with genuine prepared LOCAL login. Their completion
revalidates the current SQLite identity, profile and roles in the same transaction.
The public SQLite browser journey and Server backend dispatch remain separate.
