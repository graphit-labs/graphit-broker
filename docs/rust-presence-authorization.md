---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-70b2}
    relation: implements
  - target: {type: task, id: tsk-cdd7}
    relation: uses
  - target: {type: task, id: tsk-7604}
    relation: uses
---

# Local presence authorization by project

The PostgreSQL server authorizer checks an exact raw local bearer and current
SQL grants for each operation on one project. Read and publish require the
current principal, explicit capability and project to match the **same rule**.
A capability in one rule cannot borrow a project scope from another. A valid
bearer, administrator role, Hub grant or registration owner supplies no implicit
presence permission.

This API composes the [local verifier](rust-local-bearer-verifier.md) and the
[coherent grant reader](rust-resource-grants.md). It delivers local opaque
authentication plus a presence decision for one project. HTTP registry,
inventory filtering, live WebSocket activity, Now, JWT and external OIDC
authentication remain separate producers and integration deliveries.
The [local inventory lister](rust-instance-list.md) composes this whole policy
for partial Read projection and visible-only pagination per page.

For signed Broker access JWTs, use the separate
[native Presence authorizer](rust-broker-presence-authorization.md). Its local
JWT authentication window and current SQL ACL are explicit in that contract.

## Server API

~~~rust
let authorizer = store.local_presence_authorizer(
    explicit_audience,
    identity_json_bytes,
    grants_json_bytes,
)?;
let observed = authorizer.authorize_project(
    raw_bearer,
    required_scopes,
    broker_control::PresenceCapability::Read,
    project_id,
    original_deadline,
).await?;
~~~

Both JSON caps are explicit NonZeroUsize values with the existing readers'
representability requirements. The server supplies its explicit audience and
required scopes. Scope checks retain the verifier's requested-trim/raw-stored
membership behavior; the capability is independently evaluated through ACL.
The authorizer supplies no audience, scope, TTL or quota default.

PresenceCapability selects Read (presence:read) or Publish (presence:publish).
The project must be an exact canonical nonzero ULID. Lowercase, zero, a version
name or the word global cannot stand in for a project.

AuthorizedLocalPresence exposes principal(), project_id(), capability() and
policy_revision(). Its principal is the verifier's current local user, including
literal local issuer and raw subject; pseudonymous token claims and request-body
owner data cannot replace it. Construction is private; the result has no public
factory, Deserialize, Default or Clone. It retains neither bearer, digest nor
policy rules. Debug output is redacted.

The result records an operation's observation. It does not freeze changes after
return or authorize another operation. Consumers verify the raw bearer and read
current ACL again for each consequential operation. Registration must authorize
all projects; a listing without a project filter must check each returned project
of each instance. Finding one allowed project never exposes the full inventory.
Those multi-project consumers are not implemented by this single-project API.

## Rule contract

The entire fetched presence policy is validated and compiled before any allow.
An invalid unrelated rule prevents partial activation of a document containing
another allowing rule. No-match returns Forbidden; an invalid document returns
InvalidPolicy. Neither yields anonymous success or an Any policy.

| Access selector | Current principal comparison |
| --- | --- |
| global | Matches a successfully verified local bearer. |
| authenticated | Matches a successfully verified local bearer. |
| anonymous | Never matches this API, which requires a verified local bearer. |
| user | Pattern against current username. |
| team | Pattern against any current team. |
| organization | Pattern against current organization. |
| subject | Pattern against raw subject or issuer followed by a pipe and raw subject. |

Access names are trimmed and ASCII-lowercased, then must be one of these known
selectors. The user/team/organization/subject pattern is trimmed and must be
nonempty. Other selectors ignore their principal payload. Actual principal
attributes are not trimmed or case-folded by the matcher; the verifier's documented
current-team normalization still applies.

Every rule requires a nonempty capability array, and every trimmed capability
pattern must be nonempty and compile successfully. presence:* explicitly covers
read and publish. An empty capability array does not grant anything; it makes
that stored policy invalid. CSV is a literal pattern, not a list separator.
Patterns granting Hub or S3 alone do not imply presence.

Project selectors are exact canonical nonzero ULIDs or the literal wildcard *.
They are not trimmed, parsed as CSV or treated as globs. An empty project array
means Any for a rule that already explicitly grants the matching capability;
an explicit * has the same project scope. This never creates authentication or
a capability by itself. Versions filter inventories and do not expand ACL.

S3 route, operations and prefixes remain data for their separate producer. The
presence evaluator does not interpret storage routing or mint S3 authority.

## Native Rust patterns

Principal and capability patterns use globset **0.4.20** with
case_insensitive(false), literal_separator(true), backslash_escape(true),
allow_unclosed_class(false) and empty_alternates(false). The public Glob::regex()
expression is compiled unchanged by regex::bytes::Regex **1.13.1** and matched
against the literal bytes of the identifier. SDK-generated anchors and options
are retained.

The SDK Candidate path API normalizes Windows backslashes into path separators.
Identity strings use the public byte-regex composition instead, preserving a
literal backslash independently of the host filesystem. No Go translator,
handwritten glob parser or legacy configuration importer is involved.

| Native pattern | Effect |
| --- | --- |
| * | Zero or more bytes within a slash-separated segment; cannot cross /. |
| ? | One byte excluding /; a two-byte UTF-8 literal such as é requires ?? or the exact literal. |
| [ab], [0-9] | Character class or range in the SDK's byte-regex syntax. |
| [!ab], [^ab] | Native negated class. |
| a\* or a\? | Literal metacharacter. |
| a\\b | A literal backslash between a and b; does not become a/b. |
| {a,b} | Native alternatives. |
| {a,{b,c}} | The pinned SDK accepts nested alternatives; verified for a, b and c. |
| ** | Matches everything, including slashes. |
| a/**/b | Matches a/b and intermediate slash-separated segments. |
| a/** | Matches entries under a, including nested entries; does not match a itself. |

A pattern * is not given a special universal identity meaning that would bypass
literal separators. Administrators choosing ** explicitly choose the wider native
scope. Literal UTF-8 names match their exact bytes; the matcher does not promise
Unicode scalar semantics for ? or reproduce Go matching quirks. Unclosed classes,
invalid ranges, unmatched braces and trailing escapes fail with InvalidPolicy.
Other syntax follows the pinned SDK rather than a separate application grammar.

Primary SDK references: [globset syntax](https://docs.rs/globset/latest/globset/),
[GlobBuilder options](https://docs.rs/globset/0.4.20/globset/struct.GlobBuilder.html),
[public byte-regex contract](https://docs.rs/globset/latest/globset/struct.Glob.html),
[regex byte API](https://docs.rs/regex/latest/regex/bytes/struct.Regex.html).
The qualification records actual pinned behavior where older prose differs.

## Freshness, errors and recovery

The authorizer bounds the caller's original monotonic deadline with the existing
store operation timeout, then verifies the raw bearer, reads one coherent grant
snapshot, compiles the whole policy and evaluates the same-rule predicate. It
checks credential expiry and the original deadline again before returning either
a successful observation or Forbidden. A credential expiring during ACL work
cannot leave an authenticated result.

Authentication and ACL are separate current SQL observations; the API does not
claim one transaction freezes both, or that concurrent revocation cannot occur
after their reads. Changes committed between operations take effect on the next
call. There is no process policy cache, automatic SQL replay or reservation
framework. Compiling patterns is synchronous SDK work, with deadline checks
between patterns/rules and after compilation; it is not an interruptible native
worker.

LOCAL access/service verification and presence authorization write no token
usage metadata, users, grants, ACL revision or installation inventory.
Reader transaction guards discard incomplete connections on error/cancellation;
a confirmed read COMMIT precedes its snapshot return.

| Error | Recovery |
| --- | --- |
| InvalidProject | Supply an exact canonical nonzero project ULID. |
| InvalidPolicy | Correct the policy through an authorized management operation; no partial document becomes usable. |
| Forbidden | A valid principal has no matching same-rule presence capability and project. |
| Authentication(error) | Existing uniform invalid-credential denial or finite state/limit diagnostic; obtain a valid local bearer/configuration. |
| Grants(error) | Existing malformed-state or explicit JSON-cap diagnostic; correct the policy/configuration. |
| Control(error) | Original deadline, closed store, SQL failure or clock; failed PostgreSQL read-COMMIT confirmation returns storage error or Deadline without a proof or automatic replay. |

Errors carry finite codes, with static messages and no credential, pattern,
principal, driver text or secret payload. HTTP status/error mapping belongs to
the transport producer.

## Qualification

Run from the Broker workspace:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test postgres postgres_local_presence_authorization_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
git diff --check
~~~

Unit fixtures cover selectors, native byte-pattern behavior, same-rule scope,
cross-grant denial and whole-document validation. Compile-fail rustdocs prevent
public construction, wire deserialization and cloning of an observed result.

The native fixture uses pinned PostgreSQL, TLS, an ordinary NOSUPERUSER owner
and real raw access/service credentials with the production Rust digest and SQL
verifier. It checks current identity and grant changes, explicit deny paths,
invalid unrelated rules, byte caps, corruption, privileges, causal table-lock
deadline/cancellation, pool recovery and expiry after initial authentication.
Its blocked-expiry case waits for the actual ACL query before releasing the lock
after expiry. User/grant SQL snapshots and token usage metadata remain unchanged.

Linux qualification passed under tsk-70b2: 50 fast tests, 18 final rustdocs,
formatting, strict Clippy and one native PostgreSQL test (54.928 s). The final
native fixture uses the canonical value columns for grants. Bounded Tracker
recheck reports no residual fault; 23 maintained relative links resolve.
Initial failures are retained separately: an incorrect nested-alternative
expectation, a fixture token discriminant comparison and the first native run
with incorrect column names (93.058 s). The corrected native run qualifies the
implementation; earlier fast tests did not execute that ignored fixture.
All old lockfile package blocks remain exact except the authorized broker-control
dependency additions; six SDK dependency packages were added.
Those historical presence runs did not inject read-only COMMIT disconnect.
The underlying PostgreSQL readers now use storage errors or Deadline for
missing confirmation, with no persistent application effect or proof released.
Windows/macOS and broad final product integration remain separate evidence.
This library alone does not deliver the HTTP registry, live presence or Now.

Sources: crates/broker-control/src/presence_authorization.rs,
src/resource_policy.rs, src/service/presence_authorization.rs and tests/postgres.rs
in broker-control. The private ResourcePolicy matcher is shared with
[logical PROJECT authorization](rust-project-authorization.md); its extraction
and current affected regression qualification are recorded under tsk-5401.

Authenticated ALL-project registration and empty-inventory ownership are provided
by [local instance registration](rust-instance-registration.md). This operation
composes current raw local Auth, fresh Publish grants and the SQL inventory writer.

Use the [authenticated own-inventory reader](rust-instance-inventory-read.md)
for current local Auth, literal ownership and complete Read permission.

The [local Now wire contract](rust-now-local-wire.md) defines the minimal
four-section allowlist for the separate Runtime composition.
