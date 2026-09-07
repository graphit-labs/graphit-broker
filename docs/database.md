# Database backends

The broker has one authoritative SQL database selected by the deployment. Every durable feature
uses it: broker configuration, resource grants and revision, administration roles and assignments,
OIDC login state, and sessions. In-memory AI result caches and generated pre-signed URLs are not
persisted.

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

Back up the database together with the deployment definition and injected secrets. The database
contains sensitive provider secrets, direct S3 signing credentials, administrative identities,
and live session records. Encrypt backups and restrict access.

Restore into the same broker build/schema version, then start one broker and verify `/readyz`,
discovery, an administrative read, and representative denied/allowed consumer requests before
adding replicas. SQLite backups must use an online backup mechanism or a stopped, consistent copy
that includes WAL state.
