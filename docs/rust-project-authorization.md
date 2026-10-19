---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-aa85, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-5406, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5401, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-cdd7, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7604, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-70b2, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
---

# Local logical PROJECT authorization

An explicit [SQLite LOCAL PROJECT service and HTTP factory](rust-sqlite-local-bearer.md)
uses the same opaque credential and whole-policy contracts. The PostgreSQL
constructors below retain their signatures; final server database dispatch is separate.

The Broker PostgreSQL authorizer verifies a raw local access or service bearer
and reads current SQL grants for each logical operation on an exact project.
A successful observation requires the verified principal, requested capability
and project to match the **same rule**.

The logical capabilities are explicit operator grants:

| Module | Read | Write |
| --- | --- | --- |
| Task | task:read | task:write |
| Memory | memory:read | memory:write |
| Knowledge | knowledge:read | knowledge:write |
| AST | ast:read | ast:write |
| Hub | hub | Not admitted |

Read and write are independent. Granting task:write does not grant task:read.
A deliberate native pattern such as task:* can grant both; an operator can also
list both exact capabilities. Presence, S3 and administrator grants alone
do not grant these logical operations. A Hub grant authorizes only Hub read,
never Task, Memory, Knowledge or AST. There is no automatic grant or conversion.

Storage authorization remains a separate operation. S3 route, operations and
prefixes neither confer nor restrict an explicit logical PROJECT capability.
For example, an s3:read grant with a narrow prefix does not authorize Task.
A distinct task:read grant explicitly authorizes the logical operation; storage
still checks its own policy. This API does not mint storage credentials or
authorize physical prefixes.

## Operator example

Create a grant through an authorized grant-management operation with the
explicit task:read capability and the project's immutable ID. The relevant
policy fields are:

~~~json
{
  "access": "team",
  "principal": "platform",
  "capabilities": ["task:read"],
  "projects": ["01ARZ3NDEKTSV4RRFFQ69G5FAV"]
}
~~~

Those fields describe a policy rule, not an executable CRUD request or an
authentication proof. They must occur in the same stored rule. A separate
allowing principal, capability or project rule cannot contribute one of these
predicates. Grant mutation and HTTP management remain separate producers.

The whole policy is compiled before any allow, including unrelated rules.
Unknown access selectors, invalid native patterns, empty capability arrays
and noncanonical project selectors reject the document. A rule's empty project
array or literal * applies to any project only when its principal and explicit
capability already match. The operation still supplies one canonical nonzero ULID.

The [shared native pattern contract](rust-presence-authorization.md#native-rust-patterns)
uses pinned globset and the SDK's anchored byte regex, preserving case,
literal identifier bytes and backslashes. Both logical PROJECT and Presence use
one private ResourcePolicy engine. Access selectors retain their existing
global/anonymous/authenticated/user/team/organization/subject semantics.
Anonymous rules cannot match this authenticated local API.

## Server API

~~~rust
let authorizer = store.local_project_authorizer(
    explicit_audience,
    identity_json_bytes,
    grants_json_bytes,
)?;
let observed = authorizer.authorize(
    raw_bearer,
    required_scopes,
    broker_control::ProjectResourceModule::Task,
    broker_control::ProjectResourceAction::Read,
    project_id,
    original_deadline,
).await?;
~~~

ProjectResourceModule exposes Task, Memory, Knowledge, Ast and Hub; its as_str()
returns the lowercase module. ProjectResourceAction exposes Read and Write.
The module's capability(action) returns Some of the exact static string from
the table, or None for Hub Write. Both authorizers reject that unsupported pair
with InvalidOperation before authentication or SQL. Admitted observations retain
the validated capability and their capability() getter still returns a static string.
No caller-supplied capability string can replace that typed pair.

Audience, scopes and both NonZeroUsize JSON byte caps are supplied explicitly.
The [local verifier](rust-local-bearer-verifier.md) retains its audience and
requested-trim/raw-stored scope semantics. These scope checks authenticate the
credential; the current [grant snapshot](rust-resource-grants.md) separately
authorizes the exact logical capability. The builder does not invent configuration
defaults; invalid verification configuration fails at the owning verifier boundary.

AuthorizedLocalProjectAccess exposes principal(), project_id(), module(),
action(), capability() and policy_revision(). Its principal is the actual
VerifiedLocalBearer, including the literal local issuer, current raw subject and
SQL user attributes. It retains no raw bearer, digest or policy rules. Its
constructor is private, Debug is redacted and it has no Clone, Deserialize
or Default. The authorizer borrows its store and explicit audience.

The returned value records one operation's observation. It is not a Records
admission, a public authority factory or a lease for subsequent effects.
Consumers authenticate and consult current policy again per consequential request.

## Freshness and lifecycle

The same original monotonic deadline is bounded by the existing store operation
timeout and passed through verification, grant reading and compilation. There is
no second outer business timeout around the grant reader: that producer owns
read-COMMIT confirmation and its storage/Deadline classification. The
PostgreSQL metadata read has no persistent application effect and releases no
policy on failed confirmation.

Every call verifies current enabled state, identity revision, token audience,
scopes, revocation and expiry, then reads the coherent current whole SQL policy.
Before returning either an allowed observation or Forbidden, it checks observed
credential expiry and the original deadline again. Cancellation discards incomplete
reader connections through the existing guards. Expiry during a blocked ACL read
cannot deliver a successful observation.

Authentication and policy are separate observations; this API does not freeze
concurrent revocation during a later effect. A committed identity or policy change
is checked on the next call. There is no policy cache, replay or new budget.
LOCAL access/service verification and PROJECT authorization perform no token,
user, grant, revision or inventory writes.

| Error | Recovery |
| --- | --- |
| InvalidOperation | Choose a supported pair; Hub admits Read only |
| InvalidProject | Supply one exact canonical nonzero project ULID. |
| InvalidPolicy | Correct the stored whole policy through authorized management. |
| Forbidden | A verified caller has no matching logical capability and project. |
| Authentication(error) | Correct verifier configuration or obtain a valid current local bearer; finite malformed-state/cap errors remain causal. |
| Grants(error) | Correct malformed stored state or the explicit JSON cap; no partial policy activates. |
| Control(error) | Inspect the finite SQL, original deadline, closed store or clock cause; failed PostgreSQL read-COMMIT confirmation produces storage error or Deadline, no proof and no automatic replay. |

Messages and Debug contain finite codes, without credentials, identities,
pattern text, driver details or secret payloads. Nested Control errors retain
their concrete cause.

## Transport and identity boundaries

This producer authenticates opaque local access/service credentials. It does
not verify Web JWTs. The [local PROJECT HTTP route](rust-project-authorization-http.md)
exposes this producer with a strict operation body and current local subject.
Core/Auth Records and the Web JWT server verifier have separate delivery contracts.

The local principal's literal pair is local plus the raw SQL subject. A Broker
access JWT has its own verified issuer and stable JWT subject. A future JWT
decision must bind that verified token identity while evaluating the underlying
principal whose correspondence the server proved. An old Hub selector subject
cannot replace that binding. ID tokens, client IDs, request-body identities and
session cookie IDs alone are not backend access proofs.

## Qualification

Run from the Broker workspace:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test project_authorization postgres_local_project_authorization_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test postgres postgres_local_presence_authorization_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test postgres postgres_local_instance_registration_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test instance_inventory_read postgres_local_instance_inventory_read_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-control --test instance_list postgres_local_instance_list_contract -- --ignored --test-threads=1
cargo test --locked -j1 -p broker-presence --all-targets
cargo test --locked -j1 -p broker-presence --doc
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
~~~

The native fixture uses pinned PostgreSQL with TLS and an ordinary NOSUPERUSER
owner, real opaque access/service tokens and the production verifier and SQL
grant reader. It checks all eight pairs, independent actions, wrong project or
principal, same-rule isolation, explicit native patterns, fresh revisions,
grant removal, current identity and revocation, byte caps, whole-policy failures,
SELECT denial, observed ACL locks, expiry, cancellation, recovery and shutdown.
Its SQL oracle checks policy state remains unchanged by authorization. LOCAL
verification also preserves token state. Compile-fail examples prevent public
construction, cloning, deserialization, default construction and lifetime escape.

The initial library compilation failed on the private deadline error projection
(21.933 s); the first Clippy run failed on a duplicate error conversion
(5.681 s). Both were corrected and their logs retained. The final native
expiry case proves the token is still alive when the actual ACL lock is
observed, then crosses expiry before unlocking. Six protected source/manifest
files remain unchanged, and all 35 maintained local links resolve.

Those historical authorizer runs did not inject read-COMMIT disconnect.
Windows/macOS, Web JWT/HTTP/Records integration and storage remain separate
evidence boundaries.

Sources: crates/broker-control/src/project_authorization.rs,
src/service/project_authorization.rs, src/resource_policy.rs and
tests/project_authorization.rs. Existing Presence consumers retain their public
API and regression fixtures.

## Hub read for one project

POST the same endpoint with this body and an authenticated bearer:

```json
{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"hub","action":"read"}
```

One current SQL rule must match the verified principal, capability `hub` and
that project. Missing membership or capability returns 403 even while the JWT
is valid. Separate rules cannot contribute different parts of the allow.
Removing the grant affects the next call; the response remains the existing
`subject`, `authorization_revision`, `project_id`, `module`, `action` shape.
A SQL hub rule with projects [] or * retains its existing Any-project meaning;
a separate Global Hub admission cannot replace this PROJECT decision.
This is logical PROJECT access for Hub source records; global Hub metadata
and S3 storage operations retain their separate admission. It does not by itself
qualify the Code LiveSource consumer or a complete OAuth Web session.
