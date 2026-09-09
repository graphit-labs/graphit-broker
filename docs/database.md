# Database backends

The broker has one SQL database selected by the deployment. It stores local users and Argon2id PHC
verifiers, resource grants and revision, system roles and assignments, OIDC login state,
administration sessions, local OAuth grants/tokens, and service credentials. It never stores
`config.yml`, the expanded configuration, the authentication pepper, raw passwords, or raw token
and code values. It stores domain-separated HMACs for those random credentials and their
subject/client/audience/scope/expiry/revocation metadata, but no other deployment secrets. Local
sessions store the user's revision so identity/password/state
changes force reauthentication. In-memory AI result caches and generated pre-signed URLs are not
persisted.

Local TOTP secrets are stored only as AES-256-GCM ciphertext. Recovery codes and local login
challenges are stored only as domain-separated HMAC values; challenge records are short-lived and
carry the user revision, purpose, binding, and stage. No plaintext TOTP secret, recovery code,
password, session token, OAuth grant, or service credential is persisted.

OIDC login rows contain separate HMAC-SHA-256 values for the state and the browser-binding secret;
the raw values are never stored. Both HMACs use `authentication.token_pepper` with distinct
cryptographic domains, and a callback consumes a row only when both values match.

Authorization codes and device codes are short-lived and one-time. Access and refresh tokens are
bound to the owning local identity revision. Refresh-token rows retain their family identifier so
reuse can revoke every related token. Service credential rows retain a non-secret ID, expiry,
revocation, and last-use timestamps for administration without exposing the secret again.

## Common configuration

```yaml
database:
  driver: sqlite
  dsn: /var/lib/graphit-broker/broker.db
  max_open_conns: 1
  max_idle_conns: 1
  conn_max_lifetime: 3m
```

`BROKER_DATABASE_DRIVER` and `BROKER_DATABASE_DSN` override the corresponding YAML fields.
Driver values are `sqlite`, `postgres`, and `mysql`. The database selection and DSN are
deployment-owned and cannot be changed through the UI.

The broker creates its current schema at startup and checks an exact schema version. It does not
run migrations. In this development phase an incompatible database must be discarded and
recreated; there is no automatic import or compatibility mode.

## SQLite

```yaml
database:
  driver: sqlite
  dsn: /var/lib/graphit-broker/broker.db
  max_open_conns: 1
  max_idle_conns: 1
  conn_max_lifetime: 3m
```

SQLite is the Docker default and is appropriate for one broker process. Mount
`/var/lib/graphit-broker` as a persistent volume. The broker creates the parent directory
with mode `0700`, the database with mode `0600`, enables foreign keys, WAL, and a bounded busy
timeout, and deliberately limits the pool to one connection. Do not share one SQLite file between
replicas or place it on a filesystem that does not correctly implement locking.

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
