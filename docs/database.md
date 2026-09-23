# Database backends

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
the raw values are never stored. Both HMACs use `authentication.token_pepper` with distinct
cryptographic domains, and a callback consumes a row only when both values match.

OIDC authorization requests store a domain-separated HMAC of the request ID, serialized protocol
state, and later a one-time code HMAC; raw request IDs and codes are not persisted. Authorization
codes and device codes are short-lived and one-time. The raw signed access JWT is never persisted;
SQL keeps its non-secret `jti` and lifecycle metadata. Refresh tokens are stored only by
domain-separated HMAC and remain bound to the owning local identity revision. Refresh-token rows
retain their family identifier so reuse can revoke every related token. Service credential rows retain a non-secret ID, expiry,
revocation, and last-use timestamps for administration without exposing the secret again.

## Common configuration

```yaml
database:
  driver: sqlite
  dsn: "${BROKER_DATABASE_DSN:-~/.graphit/broker/broker.db}"
  # connect_timeout: 15s  # optional; initial connection only
  max_open_conns: 1
  max_idle_conns: 1
  conn_max_lifetime: 3m
```

Environment values are used only through explicit YAML references. The example config chooses
`BROKER_DATABASE_DSN`, but the executable gives that name no special meaning. Another config can
choose a different variable, a literal DSN, or no environment reference. `${NAME:-fallback}` uses
the fallback when the selected variable is empty; `${NAME:?message}` makes it required.
Driver values are `sqlite`, `postgres`, and `mysql`. The database selection and DSN are
deployment-owned and cannot be changed through the UI.

`connect_timeout` is optional. It accepts a positive duration such as `5s` or `1m` and defaults
to `15s`; it bounds the initial connection attempt during startup. Schema initialization has its
own 15-second limit. After startup, Go's `database/sql` pool replaces unusable connections as
needed. There is no broker setting for a reconnection interval or retry count, and failed SQL
operations are not automatically replayed.

The example's YAML-owned fallback stores `broker.db` under `.graphit/broker` in the current user's
home directory. A leading `~/` in a configured SQLite path is resolved with native path rules on
Linux, macOS, and Windows. An omitted or empty `dsn` is invalid; there is no code-owned database
path or database environment variable.

The broker creates its current schema at startup and requires an exact schema-version match.
This development version has no database migration or compatibility path; recreate the database
after a schema change. The embedding table has a unique composite primary-key index on
`(compatibility_hash, input_hash)`, so lookups do not scan the growing table. Embeddings have
no automatic expiration; include the table in backup/storage planning and change the embedding
revision whenever the vector space changes.

## SQLite

```yaml
database:
  driver: sqlite
  dsn: "${BROKER_DATABASE_DSN:-~/.graphit/broker/broker.db}"
  max_open_conns: 1
  max_idle_conns: 1
  conn_max_lifetime: 3m
```

SQLite is the Docker default and is appropriate for one broker process. Compose persists the
default file under `/home/graphit/.graphit/broker` in the `broker-global` volume. The broker creates
the parent directory with mode `0700` when absent, preserves operator-managed permissions on an
existing writable directory, creates the database with mode `0600`, enables foreign keys, WAL, and
a bounded busy timeout, and deliberately limits the pool to one connection. Do not share one SQLite
file between replicas or place it on a filesystem that does not correctly implement locking.

## PostgreSQL

```yaml
database:
  driver: postgres
  dsn: postgres://graphit:REPLACE@postgres.example:5432/graphit?sslmode=require
  max_open_conns: 20
  max_idle_conns: 10
  conn_max_lifetime: 3m
```

Create an empty database and a dedicated login that can create and modify tables and data in the
selected schema. Require TLS outside a private, equivalently protected service network. Keep the
DSN in a secret manager or injected environment value, not in version control. Multiple broker
replicas can share PostgreSQL; grant changes use a compare-and-swap revision inside one
transaction, so concurrent stale writes return `409`.

## MySQL

```yaml
database:
  driver: mysql
  dsn: graphit:REPLACE@tcp(mysql.example:3306)/graphit?parseTime=true&tls=true
  max_open_conns: 20
  max_idle_conns: 10
  conn_max_lifetime: 3m
```

Use an empty InnoDB database and a dedicated account with schema/data privileges. Configure a
registered TLS mode appropriate to the deployment and keep `parseTime=true`. Several broker
replicas may share the same MySQL database; the same transactional revision fence applies.

## Backup and restore

Back up the database together with the deployment definition, while backing up injected secrets
through the secret manager's own mechanism. The database contains authorization state,
administrative identities, and live session records, but not configuration/provider/S3 secrets.
Encrypt backups and restrict access.

Restore into the same broker build/schema version, then start one broker and verify `/readyz`,
discovery, an administrative read, and representative denied/allowed consumer requests before
adding replicas. SQLite backups must use an online backup mechanism or a stopped, consistent copy
that includes WAL state.
