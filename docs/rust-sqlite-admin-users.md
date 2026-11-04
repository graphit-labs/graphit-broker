---
references:
  - target: {type: task, id: tsk-3025, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-6055, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---
# SQLite LOCAL user and service-credential administration

Audience: administrators, native API integrators and maintainers. This page describes the explicit SQLite library and router. Library composition alone does not select SQLite in the executable Server.

The explicit router preserves the [native administrative contract](rust-admin-users.md). A hosting application supplies its shared SQLite store, verifier, password engine and existing AdminUsersHttpConfig. It must retain and drain these owners through its serving lifecycle. The PostgreSQL executable and its existing defaults have independent qualification.

## Operations and current authority

All paths below start with /admin/api/v1. A valid factor alone grants none of these operations.

| Method and path | Current action | Successful response |
|---|---|---|
| POST /local-users | users.write | 201, empty |
| PUT /local-users/{username} | users.write | 204, empty |
| DELETE /local-users/{username} | users.write | 204, empty |
| POST /local-users/{username}/mfa/reset | users.write | 204, empty |
| GET /local-users/{username}/credentials | users.read | 200, bounded inventory |
| POST /local-users/{username}/credentials | users.write | 201, one secret presentation |
| DELETE /local-users/{username}/credentials/{id} | users.write | 204, empty |

The configured signed Broker JWT, opaque LOCAL or service credential, upstream bearer and LOCAL or federated cookie pass through their genuine verifier/producer. Stored profile data cannot construct an authenticated result. Each operation observes its own current action; session.read is unnecessary. A known nonempty cookie has priority, with no Bearer retry after denial. Cookie mutations require exactly one matching current CSRF token. Inventory reads require no CSRF. Responses preserve no-store/no-cache, request IDs and redacted finite errors.

To create a service account, send a closed JSON object such as {"username":"build-agent","subject":"build-agent-subject","kind":"service"} to POST /local-users using users.write. A 201 empty response confirms creation. Supply client_id, scopes and expires_in to its credential POST, retain the returned token securely, and use the id for revocation. The credential GET never returns that token. A lost issuance response cannot recover the secret: inspect the authorized inventory, revoke the unwanted credential by id, and issue a replacement deliberately.

## User changes and recovery

The existing AdminUserInput parser rejects unknown/duplicate fields, invalid types and trailing JSON. Empty kind selects human, enabled omitted/null selects true. A human creation requires a native password of at least15 characters within the existing byte maximum and starts with mandatory replacement. Service accounts reject nonempty passwords and have no password-change obligation.

Username is trimmed, safe ASCII and at most128 bytes; subject is trimmed, nonempty, bounded to512UTF-8 bytes and has no control characters. Profile fields are trimmed and bounded to512 Unicode scalar values; teams/roles are normalized, sorted and deduplicated. The user role is implicit; explicit roles must exist.

PUT replaces profile, teams, roles and enabled state. Username may change; subject and kind remain immutable. Empty password preserves the existing verifier. Human password-change state is previous OR requested OR new password. Every update increments revision and invalidates prior LOCAL persisted authentication. An authorized self-edit returns its known-COMMIT result even when it invalidates the current opaque proof or cookie; the next request must authenticate again.

MFA reset accepts an existing human, including a disabled account. It removes TOTP and recovery material, increments revision and invalidates LOCAL challenges and grants. It does not issue replacement material. After the administrator enables the account, the owner signs in through the existing LOCAL journey and completes required password replacement and fresh MFA enrollment. Resetting a service account fails. Demotion, disabling and deletion preserve the last explicit administrator rule, including concurrent physical SQLite owners and disabled targets.

Delete removes only LOCAL cookies/tokens/assignments and the account's LOCAL factors. Update/reset/delete share the mature LOCAL invalidator. It preserves coherent federated OAuth requests and tokens even when their literal subject equals the LOCAL subject. Malformed persisted request codecs abort the whole administrative mutation; the failure is never interpreted as an absent request.

## SQL, password work and delivery

Mutations use a real IMMEDIATE transaction in the owning SQLite connection. Password writes first authenticate, observe the action/CSRF and validate the target in a committed preflight. They release SQL before calling the same LocalPasswordEngine used by login. A new IMMEDIATE transaction reobserves the actor, action, CSRF and target after hashing. Preflight grants no lease.

The producer retains genuine authentication through hashing, SQL, COMMIT acknowledgement and result delivery. The request's Original deadline, physical operation budget and factor expiry all remain effective. Factor expiry during hashing retains its authentication error category while Original remains valid. A secret or success is released only after known COMMIT acknowledgement and final temporal checks. Uncertain COMMIT keeps priority: do not infer rollback or automatically repeat a write. Cancellation releases the caller without abandoning the physical SQL/KDF owner.

## Service credentials and errors

Only service identities have an inventory. Issuance requires an enabled account; inventory and revocation remain available while disabled. Empty client_id uses username. Scopes are trimmed, sorted and deduplicated. Audience and maximum TTL are explicit existing configuration; maxTTL accepts whole seconds from1 hour through 5 years. Omitted/zero expires_in uses min(90 days, maxTTL); explicit values require1 hour throughmaxTTL. This library introduces no configuration default.

CSPRNG creates a gb_sc_ bearer and a distinct public id. SQL stores only the domain-separated HMAC, closed LOCAL principal/current revision and metadata. The one-time 201 body contains id, token, token_type:"Bearer", expires_at and scopes. Bounded inventory includes expired/revoked entries, omits revoked_at while active and never includes a bearer. Revocation of an absent or already revoked id fails. Fresh verification rejects a revoked, expired, disabled or stale-revision credential; claimed client/scopes do not create privileges.

The existing adapter maps invalid authentication to401, action/CSRF denial to403, domain failures to400, missing/non-service credential targets to404, malformed inventory/RNG failures to500, unavailable/uncertain outcomes to503 and Original expiry to504. SQL text, driver errors and secrets are excluded from responses. Correct invalid input/access before retrying; for503 or lost responses inspect current authorized state before deciding a new mutation.

## API and focused verification

SqliteControlStore::admin_users(&LocalPasswordEngine,&AdminUsersLimits) returns the borrowed SqliteAdminUsers view. execute accepts the existing AdminReadAuthentication, AdminUsersRequest, optional CSRF and Original, and returns the protected AdminUsersResult. The engine and configured owners must outlive the producer. sqlite_admin_users_router composes the same seven handlers as PostgreSQL behind a private backend selection.

Source owners: crates/broker-control/src/sqlite/flow/admin_users.rs and admin_users/data.rs; pure validation is shared with PostgreSQL in src/admin_users/validation.rs. The adapter is crates/broker-presence/src/admin_users.rs. Focused commands run unchanged from the repository root:

~~~text
cargo test --locked --offline -j4 -p broker-control --test sqlite_admin_users -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_admin_users_http -- --ignored --test-threads=1
~~~

The targets use private physical SQLite, genuine protocol producers, real Argon2/MFA and TCP HTTP. Compilation, product execution, previous failures, reused evidence and unexecuted conditions must remain distinct in qualification. See [SQLite persistence](rust-sqlite-control.md) for the wider backend boundary and [native administration](rust-admin-users.md) for the shared input and wire contract.

The retained runner selects both ignored targets in the SQLite LOCAL qualification phase. These use the real entropy source; artificial OS entropy failure injection and other-platform execution are outside these tests.
