---
type: document
title: SQLite public OIDC client registration
status: implemented
description: Public OAuth client registration through the private SQLite service and explicit HTTP router, with shared metadata admission and commit uncertainty.
references:
  - target: {type: task, id: tsk-a51f3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-d1a2, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4546, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# SQLite public OIDC client registration

Backend integrators can register public OAuth/OIDC clients through a borrowed service on the [private SQLite control store](rust-sqlite-control.md). Registration reuses the [shared metadata parser, response contract and PostgreSQL registration behavior](rust-oidc-registration.md).

The SQLite library producer is qualified under tsk-d1a2. The explicit HTTP registration consumer described below is qualified under tsk-a51f3. SQLite server configuration and global dispatch, discovery, authorization, token endpoints and other Presence integration remain under tsk-8069. Registration creates catalog metadata; it grants no user identity, PROJECT access or tokens.

## Borrow the service

API signatures:

~~~text
SqliteControlStore::oidc_registration_service<'a>(
    &'a self,
    policy: &'a OidcAuthorizationPolicy,
) -> SqliteOidcRegistrationService<'a>

SqliteOidcRegistrationService::enabled(&self) -> bool

SqliteOidcRegistrationService::register(
    &self,
    raw: &[u8],
    original: Instant,
) -> Result<RegisteredOidcClient, OidcRegistrationError>  // async
~~~

The view borrows its store and policy. Its Debug output is redacted; it provides no Clone, Default or serde representation.

The caller retains the genuine store and policy and passes its original deadline. One effective end is captured before parsing: the earlier of that deadline and the existing operation budget. Parsing, preparation, SQL execution and final delivery do not renew it. Disabled registration returns Disabled without SQL.

## Shared metadata admission

Registration::parse, columns and response remain the shared implementation. The SQLite service adds no parallel decoder or metadata schema.

The raw body is limited to 32768 bytes. Shared serde and the pinned metadata SDK reject duplicate known fields, invalid types and trailing JSON; unknown extensions are ignored without fetching their URLs.

Only public authentication method none, Authorization Code plus refresh grants, and response type code are supported. The SDK response contains no client secret, registration access token or management protocol.

An omitted or empty scope retains the existing DCR default:

~~~text
openid profile email offline_access
~~~

Device login has its own empty-scope contract; it does not change this DCR default.

Names are trimmed and limited to 256 Unicode characters and 1024 UTF-8 bytes, alongside the existing scalar limit. Redirects and scope use the existing parameter bounds; serialized columns retain the policy's JSON bounds.

Redirect literals are trimmed and deduplicated through the shared admission. HTTP requires original loopback authority; HTTPS requires nonloopback authority. A mixed catalog is classified as web. SDK URL validation does not authorize normalization that changes the admitted authority or literal callback identity.

## Prepare, insert and return

The service generates a CSPRNG identifier from 32 random bytes, encoded as canonical unpadded base64url: 43 characters, with no first-letter assumption. Collision with the configured static CLI identifier returns Random. There is no prefix workaround, retry or upsert.

Creation time uses real UTC microseconds. The SDK response and serialized columns are prepared before SQL mutation.

One private IMMEDIATE transaction inserts exactly one row into the existing six columns:

~~~text
client_id
client_name
redirect_uris_json
scopes_json
application_type
created_at
~~~

Existing primary-key and catalog constraints remain authoritative. The affected row count must be one. Existing clients and the static CLI registration are not overwritten.

A successful RegisteredOidcClient is returned only after the executor reports known COMMIT and the final deadline guard succeeds.

## Failures and uncertain outcomes

| Error | Meaning |
| --- | --- |
| Disabled | Registration policy is disabled; no SQL operation. |
| InvalidMetadata | Shared admission or concrete bounds rejected the request before insertion. |
| Random | Identifier generation failed or collided with the configured static CLI identifier. |
| Control | Existing finite SQLite executor failure, including deadline, cancellation, closure or uncertain outcome. |

If the final guard expires after known COMMIT, the service returns Control(OutcomeUncertain) without a registration response. The row may already be durable. This is not evidence of rollback.

Missing acknowledgement likewise permits uncertainty; it does not authorize replay. Fresh authorized observation and recovery belong to the backend caller. The service neither retries insertion nor adopts another writer's result.

The existing executor continues to own the worker, connection, cancellation and close lifecycle. Its physical commit/acknowledgement guarantees are reused. Errors do not expose SQL, paths, driver details, metadata bodies or credentials.

## Mount the explicit HTTP router

The broker-presence entrypoint is:

~~~text
sqlite_oidc_registration_router(
    store: Arc<SqliteControlStore>,
    policy: Arc<OidcAuthorizationPolicy>,
    config: OidcRegistrationHttpConfig,
) -> Router
~~~

The router uses the genuine SQLite producer and the existing DCR handler. The active PostgreSQL constructor remains oidc_registration_router with its genuine PostgreSQL store. Backend selection is private to this handler; neither constructor selects the server database backend. The native server configuration and global dispatch remain a separate integration.

When registration is enabled, POST /oauth/register returns 201 with the shared SDK public metadata after the producer confirms delivery. The request body is limited to 32768 bytes. One request deadline is captured before reading it and passed unchanged to the service; there is no new timeout around SQL registration and no retry.

| HTTP result | Condition | Cache behavior |
| --- | --- | --- |
| 201 | Registration response delivered by the committed producer | Cache-Control: no-store; Pragma: no-cache |
| 400 invalid_client_metadata | Malformed metadata or excessive body | no-store/no-cache |
| 504 temporarily_unavailable | Body or producer deadline | no-store/no-cache |
| 503 temporarily_unavailable | Closed producer or uncertain outcome | no-store/no-cache |
| 500 server_error | Random generation or another finite control failure | no-store/no-cache |
| 404 | Policy disabled; the existing empty router is mounted | Existing absent-route response, without invented handler headers |

The handler adds no new content-type, authentication or header admission policy. Public registration still issues no secret, management token or user authority. A disconnected peer or shutdown does not establish that SQL rolled back; uncertain effects retain the producer contract above. The caller owns the HTTP peer/server joins and SQL shutdown.

## Implementation and qualification

Implementation:

- crates/broker-control/src/sqlite/flow/oidc_registration.rs
- crates/broker-control/tests/sqlite_oidc_registration.rs

The target contains five SQLite tests covering admission and disabled behavior, response/catalog contents and reopen, independent owners, writer-lock/deadline behavior, and cancellation/closure recovery.

The final-gate composition is inspected alongside the unchanged tsk-6ebc physical COMMIT/ACK, cancellation and owner/close evidence. That reuse does not claim a newly executed temporal interleaving.

Run only the affected target and strict checks:

~~~text
cargo test --locked --offline -p broker-control --test sqlite_oidc_registration -- --test-threads=1
cargo clippy --locked --offline -p broker-control --lib --test sqlite_oidc_registration -- -D warnings
~~~

The HTTP consumer extends `crates/broker-presence/src/oauth_registration.rs`; its native integration target is `crates/broker-presence/tests/sqlite_oidc_registration_http.rs`. SQL producer cases and executor COMMIT/ACK behavior have separate tests.

~~~text
cargo test --locked --offline -p broker-presence --test sqlite_oidc_registration_http -- --test-threads=1
cargo clippy --locked --offline -p broker-presence --lib --test sqlite_oidc_registration_http -- -D warnings
~~~
