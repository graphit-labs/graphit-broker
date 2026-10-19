---
title: Rust Broker JWT Presence authorization
description: Authorize one Presence read or publish with a signed Broker identity and current SQL grants.
references:
  - target: {type: task, id: tsk-1137, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-bf2f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-c091, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7604, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Authorize Presence with a Broker JWT

The Rust server combines [native Broker JWT authentication](rust-broker-access-jwt.md)
with a fresh [SQL grant snapshot](rust-resource-grants.md) to authorize one
Presence read or publish for one project. Use this API for signed Broker access
tokens. The [opaque local Presence API](rust-presence-authorization.md) retains
its distinct authentication path; callers select the configured factory rather
than detecting a token's format or retrying another verifier.

This library producer does not implement WebSocket delivery, online activity,
registration ownership or a Now endpoint. Those consumers must compose their
own real registration and logical PROJECT checks. Presence permission alone
never authorizes reading Task, Memory, Knowledge or Ast records.

## Configure and call the server API

Use the configuration owner's actual trusted `BrokerAccessVerifier`, the actual
`PostgresControlStore`, and an explicit nonzero grant payload byte limit. The
verifier owns the trusted issuer, API audience, optional exact resource audience,
key snapshot and token limit described in its linked contract. The authorizer
borrows both owners and supplies no audience, scope, TTL or quota defaults.

~~~rust
use broker_control::{
    BrokerAccessVerifier, BrokerPresenceAuthorizationError,
    PostgresBrokerPresenceAuthorizer, PostgresControlStore,
};
use std::num::NonZeroUsize;

fn configured<'a>(
    store: &'a PostgresControlStore,
    verifier: &'a BrokerAccessVerifier,
    grants_json_bytes: NonZeroUsize,
) -> Result<PostgresBrokerPresenceAuthorizer<'a>, BrokerPresenceAuthorizationError> {
    store.broker_presence_authorizer(verifier, grants_json_bytes)
}
~~~

Call `authorize_project(raw_bearer, required_scopes, capability, project_id,
original_deadline).await`. `PresenceCapability::Read` requires `presence:read`;
`PresenceCapability::Publish` requires `presence:publish`. Read and Publish are
independent. The project input must be an exact canonical nonzero ULID;
whitespace, lowercase, zero, `*` and `global` are invalid request identifiers.

The original deadline is an absolute `std::time::Instant`. The operation uses
the earlier of that deadline and the store's operation budget, without renewal.
The grant reader's existing byte-limit representability rules also apply.
The caller explicitly supplies required token scopes. A signed purpose scope
passes authentication's purpose check but supplies no Presence capability.

A successful `AuthorizedBrokerPresence` exposes `principal()`, `project_id()`,
`capability()` and the observed `policy_revision()`. The legitimate principal
borrows the actual trusted verifier and provides its canonical signed issuer,
subject, signed attributes and expiry checks. The result has private fields and
construction, no `Clone`, `Default`, `Serialize` or `Deserialize`, and redacted
`Debug`. It retains neither the raw bearer nor SQL policy rules.

This result records one operation's observation. Retaining it creates no
permission lease. Authenticate and read current grants again for each later
effect; checking the retained principal only checks authentication time and its
original deadline, not a later ACL revision.

## Match the current whole policy

The server authenticates locally, reads the current coherent grant snapshot,
compiles the entire policy, and evaluates principal, capability and project in
the **same rule**. It rechecks JWT expiry and deadline before returning either
an allow or `Forbidden`. An unrelated malformed rule fails the whole operation;
an empty valid policy denies it. A capability in one rule cannot borrow another
rule's project or principal.

[The shared PROJECT matcher](rust-broker-project-authorization.md#signed-attributes-and-current-whole-policy)
also defines the signed identity view used here. Subject patterns match the
signed raw subject or signed issuer followed by `|` and that subject; they do
not remap an upstream subject or an opaque local identity. User, team and
organization patterns use signed `preferred_username`, `groups` and
`organization`. Absent attributes remain absent; they are never replaced with
empty wildcard candidates. Existing case-sensitive anchored byte glob semantics
are preserved. Global and authenticated selectors require successful JWT
authentication; anonymous selectors never match this API.

For example, an operator can provision a resource rule with these logical fields:

~~~json
{
  "access_kind": "subject",
  "principal": "https://broker.example.test|broker-subject",
  "capabilities": ["presence:read"],
  "projects": ["01D39ZY06FGSCTVN4T2V9PKHFZ"]
}
~~~

These are rule fields, not a new HTTP mutation endpoint. `presence:*` explicitly
covers both capabilities. A valid rule may use an empty project array or `["*"]`
to express Any project; this expands neither authentication nor capabilities.
Administrator roles, JWT scopes, Hub, S3, logical PROJECT capabilities and
registration ownership supply no implicit Presence permission. S3 routes,
operations and prefixes remain data for their separate storage consumer.

## JWT window and current ACL

As with [native PROJECT authorization](rust-broker-project-authorization.md),
a valid signed JWT authenticates locally until its signed expiry and original
deadline. User disablement, changed SQL identity attributes, token revocation
or deleted SQL client metadata do not force an identity lookup on this path.
Signed identity claims stay the observed claims until expiry. There is no
UserInfo call, opaque-token lookup, introspection fallback or token-ledger gate.

SQL grants are different: each invocation reads the committed policy anew.
A committed capability removal affects the next invocation; an uncommitted
change is not permission state. The revision identifies that read observation,
not a lease or global atomic snapshot across consumers. No SQL re-read at return
claims to linearize later revocation.

## Errors and recovery

| Error | Meaning and next action |
| --- | --- |
| `InvalidProject` | Use an exact canonical nonzero project ULID. |
| `Authentication(InvalidToken/Expired/InsufficientScope)` | Use a valid native access JWT for the configured issuer, audience and explicit purpose; obtain a new token when expired. |
| `Authentication(InvalidConfiguration)` | Correct the explicit authentication configuration; do not switch verifiers. |
| `Forbidden` | Authentication succeeded but no complete current rule allowed the requested capability/project. Have an authorized operator inspect the rule. |
| `InvalidPolicy` | Correct the whole malformed grant policy before activation. |
| `Grants(ReadLimitExceeded/MalformedStored)` | Resolve the configured grant cap or persisted grant state; do not publish a partial policy. |
| `Control(Deadline/Closed/Storage/Configuration)` | Respect the original deadline or repair the actual store/configuration. Do not report an allow. |
| `Control(OutcomeUncertain)` | The grant reader could not establish its transaction outcome; preserve uncertainty and use a new operation after the store is usable. |

Authentication's `Deadline` maps to `Control(Deadline)`. Errors preserve the
existing grant reader's timeout and COMMIT classification. The authorizer adds
no outer SQL timer, automatic retry, repair, import or fallback. Dropping a
pending operation relies on that reader's existing connection guard; no
instantaneous PostgreSQL cancellation or rollback promise is made by this API.

## Verification and source

`crates/broker-control/tests/broker_presence_authorization.rs` uses real
PostgreSQL TLS with a NOSUPERUSER owner, actual Ed25519 signatures and current
SQL grants. It covers independent capabilities, same-rule isolation, principal
selectors, Any, no implicit grants, committed and uncommitted ACL changes,
identity SQL changes with a still-valid JWT, permission failures and policy caps.
Causal ACL locks exercise expiry for both allowing and denying policies,
deadlines, abort recovery and store close/reopen. Public proof/factory doctests
exercise private construction, forbidden traits and borrowed lifetimes.

~~~text
cargo test --locked -j1 -p broker-control --test broker_presence_authorization -- --ignored --exact postgres_broker_presence_authorization_contract
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
cargo fmt --all --check
~~~

The native test requires the existing fixture's Docker/PostgreSQL tooling.
Qualification evidence in Task distinguishes executed Linux suites from
unexecuted platforms and later WS/Now integration.

Implementation: `src/broker_presence_authorization.rs` owns the private proof
and finite errors; `src/service/broker_presence_authorization.rs` composes the
actual verifier, grant reader and existing private policy. Neither changes the
opaque Presence or logical PROJECT authorizer.


The [Now channel authorization contract](rust-now-channel-authorization.md)
uses the actual verified principal, fresh whole SQL grants and registry, and
consumes the shared pure DATA mask. Channel observations remain separate from
Hub/WS/Runtime qualification.
