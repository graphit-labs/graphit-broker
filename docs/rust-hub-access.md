---
references:
  - target: {type: task, id: tsk-4f6e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-7616, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---
# Hub access resolution in Rust

`broker-control` resolves the projects a Hub reader can discover using current
PostgreSQL grants. This page covers the SQL producer and its identity boundary.
HTTP routing and issuing storage credentials are separate consumers.

The explicit [SQLite SQL and HTTP composition](rust-sqlite-hub-access.md)
uses the same Hub policy, protected result and metadata reader with its physical
SQLite owner. Its separate receipt records qualification progress. The PostgreSQL
configuration and transaction details on this page remain specific to that backend;
global Server SQLite selection remains under tsk-8069.

## Configure and resolve

Open a `PostgresControlStore` with its explicit TLS, pool and credential-digester
configuration. Choose one ingress factory; the server does not detect token
formats or switch verifiers after authentication fails:

- `broker_hub_access_resolver(&BrokerAccessVerifier, grants_json_bytes)` verifies
  a native signed access JWT using the configured issuer, API audience, JWKs and
  explicit optional resource. `Some(resource)` requires its exact audience
  binding; `None` still checks the API audience and all other token requirements.
- `local_hub_access_resolver(audience, identity_json_bytes, grants_json_bytes)`
  verifies an opaque access or service credential against current local SQL
  state. Audience comparison follows the existing verifier's explicit trimmed
  audience argument; this factory adds no default or new audience validation.

The byte caps use `NonZeroUsize`. Both factories return `Result`. Call
`.resolve(raw: Option<&str>, original: Instant)` with the caller's original
deadline. `None` explicitly selects anonymous; `Some("")` and invalid credentials
fail authentication. Interpreting HTTP headers belongs to the transport.
Required token scopes are the fixed empty set. Scopes, roles and PROJECT grants
do not grant Hub access.

Every call authenticates, reads a fresh grant snapshot with a known SQL COMMIT,
validates the entire Hub policy, enumerates selectors, then rechecks identity
expiry and the bounded deadline. There is no outer timeout around the SQL
reader's COMMIT classification. The deadline is the earlier of the caller's
original deadline and the store's operation budget.

## Response and permissions

`HubAccessResolution` has getters `authorization_revision() -> &str`,
`subject() -> &str`, `selectors() -> &[HubProjectSelector]`, and `Serialize`:

```json
{"v":1,"authorization_revision":"42","subject":"anonymous|anonymous","selectors":[{"id":"01D39ZY06FGSCTVN4T2V9PKHFZ"},{"all":true}]}
```

Authenticated subjects are `issuer|subject` from the actual verified identity.
Opaque identities use their current local principal, not token-snapshot names or
OIDC pseudonyms. Missing matches succeed with `selectors: []`. Each selector is
an exact canonical ULID `id` or `all: true`; no name-prefix selector is emitted.
The revision is the decimal string observed from `resource_acl_state`.

The result retains a private real identity and bounded deadline. Native results
borrow their verifier; opaque results own their verified local identity. Before
emitting a retained result, call its mutable `check()` immediately. It rechecks
expiry/deadline even for an empty list; it does not renew expiry, reload grants,
or turn this response into a lease. Debug output redacts the result and factories.
Serialization includes only the four response fields, never proof/configuration.
Storage operations require their own current authorization and credentials.

## Hub policy

The whole policy must be valid, including rules that do not match the caller:

| Access kind | Match |
|---|---|
| `global` | All callers. |
| `anonymous` | Only the explicit anonymous variant. |
| `authenticated` | Only an actual verified identity. |
| `user`, `team`, `organization` | Exact attribute equality against trimmed grant principal. |
| `subject` | Exact raw subject or canonical `issuer|subject`. |

Access kinds are trimmed and lowercased. Attributes remain case-sensitive literal
data: `*`, `?` and brackets in a principal do not expand as patterns. An absent
optional JWT attribute does not match an empty principal. An authenticated user
named `anonymous` remains authenticated. The existing PROJECT glob matcher is
unchanged.

Capabilities are a nonempty list of valid mature glob patterns. Only rules with
a pattern matching `hub` (including `*`) contribute selectors; a valid pattern
that does not match contributes none. Invalid patterns or access kinds fail the
entire resolution. Projects are
trimmed and must be canonical ULIDs or `*`; an empty project list or `*` emits
`all`. Rules and projects retain PostgreSQL `COLLATE "C"` snapshot order, then
selectors are deduplicated by their first complete value. IDs remain present
alongside `all`; the resolver does not sort or collapse them after enumeration.
Committed grant changes and removals affect the next call.

## Errors and verification

`HubAccessError` distinguishes `Authentication(BrokerAccessError)`,
`LocalAuthentication(LocalBearerVerificationError)`,
`Grants(ResourceGrantReadError)`, `Control(ControlError)` and `InvalidPolicy`.
Nested `Deadline`, `Closed`, `Storage` and `OutcomeUncertain` remain causal
errors, never empty/all selectors. An uncertain COMMIT is not a successful
observation or an automatic retry signal. Display messages are static and redacted.
Restore a valid policy or SQL availability before a new authorized read; an
invalid credential must be corrected through its actual authentication flow.

Source: [response types](../crates/broker-control/src/hub_access.rs),
[SQL composition](../crates/broker-control/src/service/hub_access.rs),
[policy](../crates/broker-control/src/resource_policy.rs). The focused
[native test](../crates/broker-control/tests/hub_access.rs) uses PostgreSQL TLS,
an ordinary `NOSUPERUSER` owner, signed Ed25519 JWTs, actual opaque credential
digests/current local state, ACL changes, whole-policy errors, SQL privilege
failure, real lock/expiry/deadline, abort and pool recovery. It does not simulate
lost COMMIT acknowledgments as proof of network behavior.

From the Broker checkout, with Docker available, run
`cargo test --locked -j1 -p broker-control --test hub_access -- --ignored --test-threads=1`.
Affected ordinary tests use `cargo test --locked -j1 -p broker-control --lib --test hub_access`;
documentation tests use `cargo test --locked -j1 -p broker-control --doc`.
Qualification evidence and execution platforms are recorded with the delivery;
this SQL API alone does not establish a deployed HTTP or STS integration.

The [Hub project storage admission](rust-hub-storage-admission.md) derives separate
operation/prefix authority from actual authentication and fresh SQL grants.
Discovery selectors remain DATA and cannot substitute for its private grant.
