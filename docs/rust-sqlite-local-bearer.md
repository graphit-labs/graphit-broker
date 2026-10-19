---
title: SQLite LOCAL bearer authentication and PROJECT HTTP authorization
doc_type: reference
references:
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-cdd7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-7442, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-6ebc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7bd3, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# SQLite LOCAL bearer and PROJECT HTTP

Server integrators can compose raw LOCAL access/service credential authentication,
current [SQLite](rust-sqlite-control.md) identity and current whole PROJECT ACL
through the existing HTTP route. This is separate from the
[Broker JWT PROJECT producer](rust-sqlite-broker-project-authorization-http.md):
opaque LOCAL credentials require current SQL token/user state. The native server
still selects PostgreSQL; configuration and final dispatch remain under tsk-8069.
This vertical does not supply token issuance, administrative sessions or a complete
SQLite server.

## Raw credential verification

`SqliteControlStore::local_bearer_verifier(audience, json_bytes)` returns a borrowed
`SqliteLocalBearerVerifier`. Both arguments are explicit. Its asynchronous
`verify(raw, required_scopes, original)` returns the existing private
`VerifiedLocalBearer`, using the same
[opaque LOCAL contract](rust-local-bearer-verifier.md) and
[stored state codecs](rust-local-bearer-state.md) as PostgreSQL.

The exact prefixes `gb_at_` and `gb_sc_` select the access and service credential
HMAC domains. The entire raw string is hashed without trimming or a new suffix
grammar. Digest input limits still apply. Refresh credentials, JWT and unknown
prefixes have no alternative authentication path here. SQL stores only the
domain-separated digest lookup; neither the lookup nor the whole operation is
claimed constant time.

The configured audience is trimmed for comparison against the literal stored
value. An explicitly empty audience remains valid at this library boundary.
Required scopes are trimmed, empty requirements skipped and each remaining value
compared against the unmodified stored scopes. A stored `" padded "` does not
satisfy required `"padded"`; `"a,b"` remains one scope. Only the successful output
is trimmed, sorted and deduplicated.

One bounded SELECT joins the token with its current local user. Principal,
scopes and teams JSON are capped by byte length in SQL before the driver copies
them. Dynamic SQLite types are checked without converting blobs or numbers into
text. Scalar fields follow their schema/identity limits, including 512 Unicode
characters for profile values. Oversized applicable JSON returns
`State(ReadLimitExceeded)`; malformed JSON, types or stored values return
`State(MalformedStored)`. Invalid explicit caps return `State(InvalidLimits)`.
Corrupt rows are preserved.

The stored principal must bind issuer `local`, subject and revision to the token.
The current user must exist, be enabled and have that subject/revision. Access
requires a human; service credentials require a service identity. Current profile
and teams come from the user row, never historical token JSON. PHC, MFA,
password-change flags and roles are not selected. A token cannot use a stored
admin role to bypass a resource grant.

## Time and acknowledgement

The read result, including absence, is released only after known COMMIT.
Read-COMMIT uncertainty propagates as the existing finite `Control` error without
automatic replay. A single effective end, bounded by Original and the store
operation budget, covers the read and final gates. The executor
owns cancellation/COMMIT classification; there is no outer business timeout.

Any present revocation timestamp denies. Expiry must be strictly after current
UTC time. LOCAL access/service verification does not update `last_used_at` or
start a second transaction for accounting. Both successful verification and
denial preserve the persisted token/user state. The shared schema column and
separate OAuth lifecycle producers remain unchanged.

After SQL waits, the shared proof captures its UTC/monotonic expiry pair and checks
expiry again before delivery. Observing it does not renew its lifetime. Raw bearer
and digest are not retained in the proof, and Debug/errors remain redacted.
Cancellation, interrupted work and close retain the physical owner's existing
[executor lifecycle](rust-sqlite-control.md#cancellation-acknowledgement-and-shutdown).
Verify again for each consequential operation and consult that operation's ACL;
this observation is not a continuing authorization lease.

## PROJECT service and HTTP composition

`store.local_project_authorizer(audience, identity_json_bytes, grants_json_bytes)`
returns `SqliteLocalProjectAuthorizer`. Its asynchronous
`authorize(raw, required_scopes, module, action, project_id, original)` returns
the existing `AuthorizedLocalProjectAccess` proof. Canonical project and operation
validation precede authentication. Task, Memory, Knowledge and AST each support
independent read/write capabilities; Hub read uses `hub`, and Hub write is invalid.

After genuine credential verification, the service reads the
[current ACL snapshot](rust-sqlite-identity-acl.md), compiles the entire policy and
checks this current user and exact project/capability. Partial rules cannot be
combined to manufacture a grant. An unrelated malformed rule fails the whole
policy. Final credential expiry and Original checks precede either allow or
Forbidden. The result reports the observed ACL revision and grants no later lease.

`broker_presence::sqlite_project_authorization_router(Arc<SqliteControlStore>,
ProjectAuthorizationHttpConfig)` mounts the same POST
`/v1/project/access/authorize` with the existing strict JSON body:

```json
{"project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"task","action":"read"}
```

The caller supplies `Authorization: Bearer <raw LOCAL credential>`. The existing
HTTP config requires a nonempty audience, explicit JSON/body caps and a positive
request timeout; a configured scope entry cannot be empty. This preserves the
HTTP boundary's stricter audience policy. Listener and store shutdown remain
the caller's responsibility. PostgreSQL constructors and the Broker JWT branch
remain available through their explicit factories, without backend fallback.

Success is the existing JSON subject `{issuer:"local", subject:<raw subject>}`,
authorization revision, project ID, module and action. Unknown/duplicate fields,
invalid operation/project and unsupported method/content type preserve their
existing errors. Credential denial is 401, missing capability 403, malformed
authentication/ACL state 503 and deadline 504; store closure/uncertain outcomes
retain their finite existing mapper codes. Headers and response shape use the
shared handler. No raw credential, digest, driver error or profile is echoed.

## Focused qualification

From the Broker workspace:

```text
cargo test --locked --offline -j4 -p broker-control --test sqlite_local_bearer -- --test-threads=1
cargo test --locked --offline -j4 -p broker-presence --test sqlite_local_project_authorization_http -- --test-threads=1
cargo clippy --locked --offline -j4 -p broker-control -p broker-presence --lib --test sqlite_local_bearer --test sqlite_local_project_authorization_http -- -D warnings
```

Physical file tests cover genuine random raw credentials/HMAC, both identity
kinds, current attributes, wrong domain/pepper, audience/scopes, revision/disabled
state, bounded corrupt SQL, expiry while waiting on an actual writer, Original,
cancel/recovery and closed-store denial. TCP tests cover all nine PROJECT pairs,
current team/ACL changes, whole-policy failure, finite errors and body/config
limits. Successful access and service verification also compare complete
persisted token/user rows before and after the observation. The existing
6ebc physical ACK/cancellation proof and unchanged shared crypto/proof tests are
reused rather than replayed for this module. Only Linux execution is recorded.

Sources: [state projection](../crates/broker-control/src/sqlite/flow/local_bearer.rs),
[verifier](../crates/broker-control/src/sqlite/flow/local_bearer_verifier.rs),
[PROJECT service](../crates/broker-control/src/sqlite/flow/project_authorization.rs),
[HTTP consumer](../crates/broker-presence/src/project_authorization.rs),
[physical tests](../crates/broker-control/tests/sqlite_local_bearer.rs) and
[HTTP tests](../crates/broker-presence/tests/sqlite_local_project_authorization_http.rs).
