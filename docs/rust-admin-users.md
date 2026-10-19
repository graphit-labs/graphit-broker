---
references:
  - target: {type: task, id: tsk-3025, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-6055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4697, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: depends_on
---

# Native LOCAL user and service-credential administration

This page covers the mounted native PostgreSQL server and its LOCAL user, MFA and service-credential lifecycle. It does not establish completion of the wider Broker migration.

The enabled native administration block mounts these operations alongside the
[existing reads](rust-admin-read.md) and [RBAC mutations](rust-admin-rbac.md):

| Method and path below `/admin/api/v1` | Current SQL action | Success |
| --- | --- | --- |
| POST `/local-users` | `users.write` | 201, empty body |
| PUT `/local-users/{username}` | `users.write` | 204 |
| DELETE `/local-users/{username}` | `users.write` | 204 |
| POST `/local-users/{username}/mfa/reset` | `users.write` | 204 |
| GET `/local-users/{username}/credentials` | `users.read` | 200, redacted inventory |
| POST `/local-users/{username}/credentials` | `users.write` | 201, one secret presentation |
| DELETE `/local-users/{username}/credentials/{id}` | `users.write` | 204 |

A valid credential does not grant these actions, `session.read`, `roles.write` or
PROJECT access. Each operation observes its own current action in the same SQL
transaction as its mutation. Genuine configured Broker JWTs, opaque LOCAL/service
credentials, upstream bearer tokens and LOCAL/federated cookies share the mounted
[authentication ingress](rust-admin-session-http.md). A known nonempty cookie has
priority; invalid cookies never fall through to a valid Bearer header. Cookie writes
require exactly one matching current CSRF token. Bearer writes do not require CSRF.
No operation renews a cookie or calls UserInfo as a validity check.

## User input and lifecycle

POST and PUT accept one closed JSON object. Unknown and duplicate fields, invalid
JSON, null required strings and oversized bodies are rejected. Input fields are
`username`, `subject`, `kind`, `password`, `name`, `email`, `organization`,
`teams`, `roles`, `enabled` and `password_change_required`. Username uses the native
trimmed ASCII identity-segment rules and 128-byte limit. Subject is trimmed,
nonempty, at most 512 UTF-8 bytes and contains no control characters. Profile text
is trimmed and limited to 512 Unicode scalar values per field. Teams and roles are
trimmed, sorted and deduplicated. Role `user` is implicit; explicit roles must exist.
There is no independent corpus or aggregate quota.

Creation defaults an empty/omitted kind to `human`. Human creation requires a native
[password](rust-local-password.md); service creation rejects a nonempty password.
Omitted or null `enabled` means true. An administrative password always requires
replacement by its owner. Service identities never have a password verifier or a
password-change obligation. User roles can be supplied under `users.write`; this
does not grant permission to modify role definitions or assignments independently.

PUT fully replaces profile attributes, teams, explicit roles and enabled state.
Username may change; subject and kind are immutable. Empty password keeps the
current verifier. A human's password-change flag is the logical OR of the previous
flag, the requested flag and whether a new password was supplied. A successful
update increments the current LOCAL revision, including profile-only edits. Mutation
timestamps are captured after target locking/validation, so a refresh that wins the
user lock before the update is not mislabelled as issuance after the new revision.

A password write first authenticates, checks the current action/CSRF and validates
the target. It then releases SQL locks before running Argon2. The final transaction
reauthenticates the actual caller and checks the current target again before writing.
One server-owned `LocalPasswordEngine` is shared by administrative writes and enabled
LOCAL login. Its physical KDF concurrency comes from
`auth.local.rate_limit.max_concurrent` (sourced default 2); the worker retains its
permit until the blocking KDF exits, even if its request is cancelled. Shutdown
joins that engine once before closing SQL.

Administration can write a human password while `auth.local.login.enabled` is false.
This does not enable LOCAL authentication: the existing portal and federated choices
remain available, login-options reports `local:false`, and both LOCAL password POST
routes return 503 `administration_unavailable` without password/CAPTCHA work.

MFA reset applies to an existing human, including a disabled human. It removes both
TOTP material and recovery codes, increments the LOCAL revision and invalidates the
old LOCAL authentication state. It never creates replacement secrets or recovery
codes. The owner's genuine subsequent login performs required password replacement
and/or MFA enrollment according to the current login policy. Invalid codes retain
the pending challenge without producing a completed login; a reset recovery code
cannot complete a new enrollment. Service MFA reset fails.

User deletion removes the user, its LOCAL cookies/tokens and dependent LOCAL
factors. Recreating the same username/subject does not reactivate old persisted LOCAL tokens
or cookies; signed JWTs retain the separate expiry window described below. Updates, MFA reset and deletion reuse the active LOCAL invalidator used
by password change/enrollment. It revokes LOCAL access/refresh/service credentials,
removes bound LOCAL authorization requests, challenges and device codes, and preserves
valid federated grants with the same literal subject. Cookie cleanup explicitly
requires issuer `local`; the shared subject alone does not identify a LOCAL factor.

All mutations serialize through the existing administration guard before actor,
cookie and target rows. Credential inventories retain shared LOCAL row locks rather
than upgrading their target to a write lock, so reciprocal service reads can coexist.
Demotion, disabling or deletion preserves the existing last-admin rule, including
concurrent writers: another external admin assignment or enabled, canonical LOCAL
admin must remain. Disabled, absent or malformed LOCAL candidates do not qualify. An authorized self-edit
can return 204 after known COMMIT; the previous LOCAL cookie or opaque credential
is denied on the next request.

## Service credentials

Only an existing service identity has a credential inventory. Issuance additionally
requires it to be enabled. GET and revoke remain available for disabled services.
Issuance input is a closed object with optional `client_id`, `scopes` and `expires_in`
(integer seconds). Empty client ID defaults to username. Scopes are trimmed, sorted
and deduplicated. The emitter uses the configured `auth.audience`; consumers requiring
a different audience cannot use that token. `administration.local_bearer` remains an
explicit audience/scope policy when opaque administration access is enabled.

The native `auth.service_credential_max_ttl` setting preserves the existing 365-day
sourced default and accepts 1 hour through 5 years. It appears in the redacted effective
configuration. Omitted/zero `expires_in` selects the smaller of 90 days and that maximum;
an explicit value must be at least 1 hour and at most the configured maximum.
No additional TTL or implicit audience alias is introduced.

The emitter uses CSPRNG bytes for a `gb_sc_` token and separate public ID. SQL stores
only the existing domain-separated service-credential HMAC, closed LOCAL principal,
current revision, client/audience/scopes and timestamps. The 201 object contains
`id`, `token`, `token_type:"Bearer"`, `expires_at` and `scopes`. Raw output is built
within the configured response bound and returned only after known COMMIT. It is
never included in GET, logs or error responses. Secret inputs/intermediate owners
and undelivered response buffers are zeroized; this does not claim erasure of HTTP,
SQL driver or operating-system copies.

GET returns `{"credentials":[...]}` with public ID, client ID, scopes, created/expiry
and optional revocation timestamps, including expired/revoked entries. It streams
SQL rows into the bounded response writer without retaining a second row corpus.
Revoke affects only the actual current service/ID pair. Missing or already-revoked
credentials fail; they do not produce a false successful deletion.

## Failure and validity boundaries

Authentication and current permission failures retain the shared 401/403 contract;
invalid LOCAL integrity is 500 and unavailable/uncertain storage is 503. Domain failures
are finite 400 codes `user_create_failed`, `user_update_failed`, `user_delete_failed`,
`mfa_reset_failed`, `invalid_credential`, `credential_create_failed` or
`credential_revoke_failed`. A missing/nonservice credential target is 404
`service_identity_not_found`. Credential RNG failure is 500; inventory failure is 500
`credentials_read_failed`. All responses are no-store and carry the bounded request
reference without echoing protected inputs.

Known COMMIT precedes success. Cancellation/deadline retains transaction cleanup and
connection ownership; an uncertain COMMIT is not replayed and exposes no credential.
Operators can query redacted current state to resolve uncertainty. Original request
and factor deadlines are not extended by password work or SQL waits.

A previously signed JWT can still pass offline signature/issuer/audience/temporal
validation until its access-token expiry. This lifecycle does not install a blacklist
or change that TTL. Native `oidc.access_ttl` keeps its sourced 600-second default
and 60–3600-second range; an explicit deployment value determines the actual window
([token exchange configuration](rust-oidc-token-exchange.md)). Upstream tokens retain
their issuer-provided expiry. Administrative/current-LOCAL consumers additionally verify the
persisted current revision for cookies and opaque credentials. The native Broker
JWT carries no LOCAL revision: its administrative binding checks the current enabled
identity and matching pseudonym/username, plus the current SQL action. Profile-only
edits do not revoke that JWT; disabling/removing its identity or removing permission
can still deny the operation. Federated bearer tokens
follow their configured JWT validity window and independent current SQL permissions;
JWT validity never grants PROJECT authorization.

Source: `broker-control/src/admin_users.rs`, `service/admin_users.rs`,
`service/local_auth.rs` and `broker-presence/src/admin_users.rs`; server composition
uses the shared configured password engine and native auth TTL. Functional contracts
are `postgres_admin_user_lifecycle_contract` and
`broker_admin_user_lifecycle_http_contract`, using PostgreSQL TLS and the actual
native executable with genuine factors. They require no vendor CLI, account or plan.

The explicit [SQLite LOCAL user and credential adapter](rust-sqlite-admin-users.md) preserves the seven administrative operations with physical IMMEDIATE transactions and the shared password engine. It does not select SQLite globally in Server.
