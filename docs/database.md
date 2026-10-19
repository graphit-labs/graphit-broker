---
references:
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# Database backends

The native Rust server selects PostgreSQL or private SQLite with `database.backend`. Its [runbook](rust-broker-server.md) defines complete mappings and lifecycle/SQL budgets. [MySQL Control](rust-mysql-control.md) remains a qualified library API and gate, with separate [sessions](rust-mysql-sessions.md), [identity](rust-mysql-identity.md) and [roles](rust-mysql-roles.md); the server does not select it.

The broker has one SQL database selected by the deployment. It stores local users and Argon2id PHC
verifiers, resource grants and revision, system roles and assignments, OIDC login state,
administration sessions, Broker OIDC authorization/token state, and service credentials. It never stores
`config.yml`, the expanded configuration, the authentication pepper, raw passwords, or raw token
and code values. It stores domain-separated HMACs for those random credentials and their
subject/client/audience/scope/expiry/revocation metadata, but no other deployment secrets. Local
sessions store the user's revision so identity/password/state
changes force reauthentication. Individual embeddings are persisted by SHA-256 of the input
and a provider/model/revision compatibility fingerprint; the input text is not stored. Rerank
response caches and issued STS credentials remain in memory.

Local TOTP secrets are stored only as AES-256-GCM ciphertext. Recovery codes and local login
challenges are stored only as domain-separated HMAC values; challenge records are short-lived and
carry the user revision, purpose, binding, and stage. No plaintext TOTP secret, recovery code,
password, session token, authorization grant, or service credential is persisted.

OIDC login rows contain separate HMAC-SHA-256 values for the state and the browser-binding secret;
the raw values are never stored. Both HMACs use `auth.pepper` with distinct
cryptographic domains, and a callback consumes a row only when both values match.

OIDC authorization requests store a domain-separated HMAC of the request ID, serialized protocol
state, and later a one-time code HMAC; raw request IDs and codes are not persisted. Authorization
codes and device codes are short-lived and one-time. The raw signed access JWT is never persisted;
SQL keeps its non-secret `jti` and lifecycle metadata. Refresh tokens are stored only by
domain-separated HMAC and remain bound to the owning local identity revision. Refresh-token rows
retain their family identifier so reuse can revoke every related token. Service credential rows retain a non-secret ID, expiry,
revocation, and last-use timestamps for administration without exposing the secret again.

## PostgreSQL

Use the [complete example](../config.example.yaml) with explicit host, port, database, dedicated login, password, trusted CA and pool/flow budgets. Startup requires verified TLS and the exact schema. Grant only required schema/database privileges; server qualification uses a NOSUPERUSER login. Keep credentials outside version control. SQL errors are not automatically replayed; preserve OutcomeUncertain and recovery rules.

## SQLite

Use the [private SQLite mapping](rust-broker-server.md#select-private-sqlite) or [health-only example](../examples/health-only.yaml). Startup/operation/shutdown budgets and file path are required. Connection URIs and in-memory paths are rejected. The owner creates missing private parents/files and checks existing parents, database and sidecars without repairing permissions. Preserve format `rust-broker-v1` epoch2 and use a filesystem with correct locking; do not share one file among independent replicas.

## Schema and recovery

An incompatible database fails startup; there is no migration/import/reset path. Stop writers and retain protected backups before an explicit deployment replacement. Restore with matching build and deployment secrets, then verify administration and required consumer flows. See [operations](operations.md). Embedding rows have no automatic TTL; revision changes isolate incompatible vectors rather than deleting rows. Bounded rerank caches are in memory and do not persist across restart.
