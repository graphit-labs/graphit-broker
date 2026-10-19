---
references:
  - target: {type: task, id: tsk-8632, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5870, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-70b2, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Rust authenticated instance registration

Audience: Broker server integrators and maintainers. This PostgreSQL operation
registers or replaces an installation's complete inventory using a raw local
bearer, current identity and fresh resource grants. The HTTP route, list API,
live presence, Now, JWT and external identity providers are separate deliveries.

Use [instance inventory](rust-broker-instances.md) for data validation and SQL
ownership, [local bearer verification](rust-local-bearer-verifier.md) for
authentication, and [presence authorization](rust-presence-authorization.md) for
the native grant pattern language.

## Call contract

~~~rust
async fn register(
    store: &broker_control::PostgresControlStore,
    raw_bearer: &str,
    inventory: &broker_control::InstanceInventory,
    deadline: std::time::Instant,
) -> Result<broker_control::RegistrationResult, broker_control::InstanceRegistrationError> {
    let registrar = store.local_instance_registrar(
        "explicit-audience",
        std::num::NonZeroUsize::new(4096).unwrap(),
        std::num::NonZeroUsize::new(16384).unwrap(),
    )?;
    registrar.register(
        raw_bearer, &["presence:publish".into()], inventory, deadline,
    ).await
}
~~~

The audience and byte limits above are an integration example, not product
defaults. Required scopes are supplied explicitly. The registrar borrows its
store and accepts no owner, verified-principal metadata or digest as authority.
Inventory construction validates the installation ID, canonical nonzero ULIDs,
unique projects and meaningful unique versions before this call.

Authenticate the raw bearer on each operation and read fresh grants. Compile
the entire presence policy before evaluating it; any malformed rule rejects
activation. Every listed project must match the current principal and explicit
Publish capability in the same rule. Different projects may match different
rules, but capability and project predicates cannot be borrowed across rules.
Version strings are inventory data, not authorization predicates. Hub or
administrator state provides no implicit Publish permission.

For an empty inventory, require a matching explicit Publish rule with an empty
project selector or an explicit '*' entry. A specific-project Publish rule,
even combined with another rule granting Read for any project, cannot authorize
an empty first registration or clearing an existing installation. No synthetic
global project is used.

The owner is the current verified local issuer and raw subject. A first empty
registration is allowed with the above permission. The SQL writer arbitrates
first ownership and locks an existing row; another authenticated owner receives
OwnerConflict even with Any-project Publish permission. Ownership is immutable.

## Effects and errors

The existing writer atomically replaces all inventory children. Clearing retains
the parent and creation timestamp. Equal canonical inventories return Unchanged
with stable timestamps; changes return Created or Updated with server-generated
microsecond timestamps. Return a RegistrationResult only after confirmed COMMIT.

InstanceRegistrationError has two finite variants:
Authorization(PresenceAuthorizationError) and Registry(InstanceRegistryError).
Authentication failures, Forbidden, InvalidPolicy, bounded JSON read errors,
database failures, Closed and Deadline remain typed and redacted. Registry owner
conflicts and malformed stored state remain distinct. OutcomeUncertain is
preserved as Registry(Control(OutcomeUncertain)); do not retry automatically or
interpret that error as proof that the write had no effect. A later integration
must reconcile stored state before deciding what to do.

One bounded original deadline flows through authentication, ACL and SQL.
The authorization phase has a timeout; token expiry and the deadline are checked
again immediately before entering the writer. The writer owns cancellation,
transaction cleanup and COMMIT uncertainty classification, so the compositor
does not wrap the whole write in an outer timeout.

Identity and grant reads are separate current observations; they do not freeze
concurrent revocation or policy edits until COMMIT. Best-effort token last-used
telemetry may update during authentication even if authorization or a later
stage fails. No new user or grant writes occur. Authentication/ACL denial before
the writer leaves installation tables unchanged.

## Qualification

Commands use the project's existing Rust toolchain and native PostgreSQL fixture:

~~~text
cargo test --locked -j1 -p broker-control --all-targets
cargo test --locked -j1 -p broker-control --doc
cargo test --locked -j1 -p broker-control --test postgres postgres_local_instance_registration_contract -- --ignored --test-threads=1
cargo fmt --all --check
cargo clippy --locked -j1 -p broker-control --all-targets --all-features -- -D warnings
~~~

The native test uses the pinned PostgreSQL image over TLS with an ordinary
NOSUPERUSER application role and actual raw Access/Service credentials. It checks
all-project denial, current attributes and revocation, canonical replacement,
empty first registration/clear/no-op, immutable foreign ownership, malformed
policy, permission/read-limit failures, expiry during a causally observed ACL
read, the original writer deadline, actual task cancellation, pool recovery and
reopen. The unchanged SQL writer's constraint rollback and actual COMMIT
disconnect qualification remain recorded in the linked inventory contract.

Linux qualification passed: 52 fast tests (13.277 s), 19 rustdocs (0.313 s),
the focused native test (42.873 s), fmt (0.204 s) and strict Clippy (13.089 s).
The bounded static impact review found no fault; 22 affected local document
links resolve. Existing source deltas are limited to the listed exports, private
Any predicate/unit, native test import/append and three navigation links. No
manifest or lockfile changed in this leaf. Logs are retained in
.build/rust-postgres-instance-registration-2026-10-11/. Windows/macOS,
full HTTP product integration and injected read-only COMMIT disconnect have not
been executed for this leaf. Its completion does not deliver all of N6/N7/N9.

Sources: broker-control src/instance_registration.rs,
src/service/instance_registration.rs, private PresencePolicy::allows_any_project,
and tests/postgres.rs::postgres_local_instance_registration_contract.

The strict Rust [instance registration HTTP route](rust-instance-registration-http.md)
uses the authenticated business registrar through the shared control store.

The independently selected [Native Broker registrar](rust-broker-instance-registration.md)
uses verified signed issuer/subject identity and current whole SQL grants.
