# SQL admission for Hub project storage in Rust

Audience: Broker maintainers and credential-issuer integrators. This page describes
the broker-control Rust library's current SQL admission boundary for project/module
Hub storage. It produces a private authenticated grant for the
[AWS issuer](rust-hub-storage-aws.md). The [credential HTTP route](rust-hub-storage-credentials-http.md)
retains its own qualification. The generic APIs also admit
[PROJECT corpora](rust-project-corpus-storage-admission.md); this page focuses on Hub.

The explicit [SQLite storage admission and HTTP composition](rust-sqlite-storage-admission.md)
uses current native JWT or verified opaque possession and the same protected grant,
route policy, credential service and issuers. Its separate receipt records the
SQLite SQL/TCP qualification and reused issuer evidence. This composition does not
issue human bearer credentials or select SQLite globally in Server.

## Configure and admit

Use an open PostgreSQL control store, its explicit operation budget and a
nonempty default route name from server configuration. Select one factory:

- Native: broker_storage_authorizer(verifier, grants_json_bytes, default_route).
  The actual BrokerAccessVerifier owns issuer, audience, optional resource,
  signature validation and the JWT's authenticated window.
- Opaque local: local_storage_authorizer(audience, identity_json_bytes,
  grants_json_bytes, default_route). The existing local verifier reads actual
  token and current user state; human access tokens and service credentials use
  their separate credential-digest domains.

Neither factory admits anonymous callers or switches authentication mode after
failure. Required scopes are explicit. An empty list introduces no new required
scope. Native missing scopes retain BrokerAccessError::InsufficientScope;
opaque scope failures retain LocalBearerVerificationError::Unauthenticated.

The original argument is the caller's absolute monotonic deadline. Authentication
bounds it by the store's operation budget. Keep the factory alive through both
phases and subsequent credential issuance:

~~~rust
let factory = store.broker_storage_authorizer(
    &verifier, grants_json_bytes, &configured_default_route,
)?;
let caller = factory.authenticate(&bearer, &required_scopes, original)?;
let scope = StorageScope::project(&canonical_project_id, StorageModule::Hub)?;
let grant = factory.authorize_authenticated(caller, &scope).await?;
grant.check()?;
~~~

This excerpt assumes already supplied configuration, bearer, store and verifier;
the complete compiling library example is in the
[grant API](../crates/broker-control/src/storage_admission.rs).
Opaque authenticate is async; its remaining flow is the same.
authorize(raw, required_scopes, scope, original) composes both phases when there
is no intervening request-body read.

authenticate returns AuthenticatedStorageCaller with private proof and clocks.
authorize_authenticated accepts only a caller from that same actual factory.
A caller from another store, verifier, mode, audience or even another factory
instance is rejected with InvalidConfiguration before reading grants. Safe
factory borrows prevent lifetime escape and address reuse while a caller exists.
The caller and grant have no public constructor, Clone, Default or Serde codec.
Their Debug implementations redact their contents.

## Scope, policy and output

StorageScope::project validates the existing canonical nonzero ULID constraint.
PROJECT `project_id()` is `Some` and `installation_id()` is `None`. The separate
[USER Memory SQL guide](rust-user-memory-storage-admission.md) describes its
installation DATA and actual authenticated literal owner; this Hub proof is
separate from USER qualification.
The scope, StorageOperation enum, timestamps and observer values are DATA.
They cannot construct a grant or substitute for an authenticated proof.
Server-owned roots are exactly:

~~~text
v1/projects/{canonical_project_id}/registry
v1/projects/{canonical_project_id}/artifacts
v1/projects/{canonical_project_id}/hub/metadata
v1/projects/{canonical_project_id}/hub/events
~~~

The [metadata/events extension](rust-project-hub-metadata-events-storage.md) preserves
registry/artifacts and appends the two exact native ProjectHub DATA roots.
A metadata-only prefix cannot reach events or the legacy roots; a broad Hub
prefix intersects metadata/events, while a broad project prefix intersects all
four roots and excludes corpora. PROJECT storage retains concrete S3 authority
without introducing the nonPROJECT Global Hub capability requirement.

The project is the Hub producer project. Artifact IDs, exact versions, digests,
URIs and provider bucket/base prefix are not admission inputs. Other module
roots, user memory and global Hub are separate storage domains.

Each authorization reads one current whole
[SQL resource-grant snapshot](rust-resource-grants.md), including its positive
revision. The entire policy must compile, even rules that do not match the caller.
It reuses the
[Hub principal matcher](rust-hub-access.md): access kinds are trimmed and
case-normalized; user, team, organization, raw subject and canonical issuer|subject
remain exact, case-sensitive principal data. Wildcards in identity attributes
have no principal-pattern meaning. global and authenticated can match an actual
caller; anonymous cannot. Projects use canonical ULIDs, * or an empty Any list.
Native identity comes from the verified JWT; opaque attributes come from current
local SQL state rather than the stored stale token principal or pseudonymous
OIDC subject.

A contributing rule must match principal and project. For each of Read, Write,
Publish and Delete, a mature capability glob must match s3 or s3:<operation>.
The rule's s3_operations is either empty (Any) or contains a matching mature glob.
A Hub selector, hub-only capability, logical PROJECT capability or transport
publish lease does not become storage authority.

An empty s3_prefixes grants that rule's allowed operations on the four Hub PROJECT roots.
Otherwise each template is trimmed at the outside and rendered using only
{project}, {username}, {organization} and {subject}. Each segment must be 1–128
ASCII bytes, start with an ASCII alphanumeric and contain only alphanumerics,
dot, underscore or hyphen. Empty segments, traversal, controls, wildcards and
unknown placeholders fail the whole policy. Missing or unsafe actual attributes
in a relevant template fail instead of receiving a replacement value.

A candidate intersects a root only at an exact segment boundary: an ancestor
contributes the root, a descendant contributes the candidate. Other projects,
artifacts2, siblings and unrelated modules contribute nothing. Prefixes are
deduplicated and sorted literally for each operation.

Only a rule contributing operation/prefix pairs selects a route. Its trimmed
s3_route overrides the explicit server default; different contributing routes
produce ConflictingRoutes. No contributing pairs produces Forbidden.
The resulting AuthorizedStorageGrant exposes scope(), route(), revision(),
prefixes(operation), canonical_subject(), request_deadline() and check().
The prefixes are relative to a later provider base prefix; the AWS issuer must
derive its policy from the actual grant, not from a caller-constructed metadata DTO.

## Freshness, lifetime and failures

The authentication window is captured before grant SQL. Native and opaque copy
their verifier's stored UTC and monotonic expiry. The opaque producer captures
the pair after SQL/usage, immediately before its final UTC observation; the
storage composer checks the proof and never reanchors it from later verified_at
metadata. A second UTC observation cannot renew that window.
Original, UTC expiry and monotonic expiry are checked before SQL and after
compilation/evaluation, including negative decisions, and before returning a grant.

check rechecks the retained clocks and proof. It does not reload grants or renew
authentication. A new authorization observes committed ACL changes.
Native signed JWTs retain their existing authenticated window after unrelated
local user/token changes; opaque verification observes current local disabled,
revoked, expired and user/token revision-consistent state. There is no promise of immediate revocation of an
already issued STS session.

| Error | Meaning and next action |
| --- | --- |
| Native(error), Local(error) | Preserve actual authentication/scope origin; correct the credential through its real authentication flow. |
| Grants(InvalidLimits) | Retained resource-reader error bridge; these factories reject an unrepresentable configured cap as InvalidConfiguration before admission. |
| Grants(ReadLimitExceeded) | Deliberately adjust the cap or authorized policy size; no truncated policy is usable. |
| Grants(MalformedStored) | Repair missing/invalid stored policy through an authorized writer. |
| Grants(Control(error)), Control(error) | Preserve storage/deadline/closed/OutcomeUncertain classification; restore availability or start a new authorized request after resolving the outcome. |
| InvalidConfiguration | Supply representable identity/grant JSON caps and a nonempty route; keep the actual authentication factory for both phases. |
| InvalidScope | Supply a canonical nonzero project ULID. |
| InvalidPolicy | Correct the whole policy or relevant unsafe identity expansion. |
| ConflictingRoutes | Resolve competing contributing route configuration. |
| Forbidden | No current operation/prefix authority matches this project. |
| Deadline | The retained request/policy deadline elapsed; observer calls cannot renew it. |

Display messages are finite and source() exposes no nested driver/policy text.
SQL owns transaction and COMMIT uncertainty classification. Admission wraps no
outer timer around the SQL reader and performs no automatic replay. Dropping an
owned authorization future discards its incomplete SQL transaction according to
the existing reader contract; it does not claim an external side effect rolled
back or an issued credential revoked.

## Source and verification

[Private proofs and public observers](../crates/broker-control/src/storage_admission.rs),
[policy](../crates/broker-control/src/storage_policy.rs),
[SQL factories](../crates/broker-control/src/service/storage_admission.rs) and
[real PostgreSQL test](../crates/broker-control/tests/storage_admission.rs)
cover the API, literal scope/operation/route boundaries and both modes.
Rustdoc compile-fail cases cover private authority, codecs, Clone/Default and
factory/verifier lifetimes; a positive example compiles the two-phase Native API.
The native test uses pinned PostgreSQL with TLS and an ordinary NOSUPERUSER
owner, actual Ed25519 JWTs and actual local credential digests. It exercises
current identity/ACL, whole-policy failures, byte caps, privilege failure,
lock-driven positive/negative expiry, original deadline, cancellation and pool
recovery, retained observations and a closed store.

From the Broker checkout with Docker available:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo clippy --locked -j1 -p broker-control -p broker-presence --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo test --locked -j1 -p broker-control --test storage_admission -- --ignored --exact hub_storage_admission_postgres_contract --test-threads=1
~~~

Executed results and platform limits belong to the delivery's qualification
record. This SQL test does not exercise STS, S3, HTTP, SDK publishing, a lost
COMMIT acknowledgment, or the migration's final integration suite.

Authentication windows copy the [actual verifier expiry pair](rust-authentication-expiry.md). Opaque finish metadata does not reanchor or renew the stored monotonic expiry.

The [Rust AWS issuer](rust-hub-storage-aws.md) consumes these actual grants to request temporary STS credentials; its integration qualification is tracked separately.


The [Hub credentials HTTP route](rust-hub-storage-credentials-http.md) composes actual authentication, fresh storage admission and AWS issuance; its actual TCP qualification is tracked separately.

The [global Hub SQL library](rust-global-hub-storage-admission.md) is a separate
nonPROJECT admission contract for Registry/Rules, requiring effective Hub plus
S3 authority. Its DATA constructor and empty project observer do not grant
permission or enable a Global HTTP body; these existing PROJECT/USER contracts
retain their roots and authority.
