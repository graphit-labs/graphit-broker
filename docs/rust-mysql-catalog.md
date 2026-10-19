---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5ca4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-3e19, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9a45, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# Typed SQL schema and declared MySQL reference

Audience: Broker storage integrators and maintainers. This producer is
**qualified on Linux**, under `tsk-5ca4`. Historical qualification artifacts retain
their earlier versions. This page describes the current implementation, observed
native behavior and limits of its qualification.

## Single declaration and API

`broker-store::schema` owns 25 immutable `TableDefinition` declarations in foreign-key
creation order. The three DDL renderers and the expected MySQL projection derive
from those same definitions. There is no general SQL parser, old-format importer,
retained SQL body or independently maintained column/catalog model. The format
remains `rust-broker-v1`, epoch 2; seeds and UTC timestamp representations are unchanged.

The fixed MySQL options and character width are declared once in a private,
immutable profile owned by `TableDefinition`. The renderer and table/column
projections read that same profile. The DDL row-format token derives its uppercase
spelling from the native representation; this does not normalize arbitrary SQL.

| API | Result and boundary |
| --- | --- |
| `Table::definition()` | `&'static TableDefinition`, private fields and readonly getters |
| `Table::name()` | Fixed static table name |
| `Table::create_statement(Dialect)` | Owned `String`, generated on demand |
| `schema_statements(Dialect)` | `ExactSizeIterator<Item = String>` in FK order |
| `Table::mysql_shape()` | Owned immutable expected `MysqlTableShape` using borrowed static names |

Column types are `SmallInt`, `BigInt`, `Varchar(width)`, `Text` and `LargeText`.
Embedding JSON and instance project versions use `LargeText`: MySQL renders `LONGTEXT`; SQLite/PostgreSQL
render `TEXT`. External callers cannot construct declarations, mutate their
fields or pass arbitrary identifiers to a renderer. Readonly schema data grants
no authority and validates no captured database state.

```rust
use broker_store::schema::{Dialect, Table};
let ddl: String = Table::AdminSessions.create_statement(Dialect::Postgres);
let definition = Table::AdminSessions.definition();
assert_eq!(definition.columns()[0].name(), "token_hash");
let expected = Table::AdminSessions.mysql_shape();
assert!(!expected.columns()[0].nullable());
```

Declaration nullability and physical nullability differ. Fifteen inline primary
keys omit explicit `NOT NULL`; the new instance key declares it explicitly. Ordinary SQLite rowid tables permit null in the former
keys. MySQL/PostgreSQL imply non-null primary keys. Composite primary-key columns
keep their explicit non-null declarations. The SQLite fixture must verify both
`PRAGMA` metadata and actual INSERT behavior, rather than projecting MySQL rules
onto SQLite. [SQLite primary-key rules](https://www.sqlite.org/lang_createtable.html),
[PostgreSQL constraints](https://www.postgresql.org/docs/17/ddl-constraints.html).

## Expected MySQL structure

The projection describes **declared structure of the 25 tables**. It includes
column ordinals, full types and signed integer widths, nullability, native default
values, character capacities/settings, absent generated/EXTRA fields, complete
primary/unique/FK-support indexes, FK targets/actions, CHECK expressions/enforcement,
and the explicit table options. Every MySQL table declares InnoDB, DYNAMIC,
utf8mb4 and utf8mb4_bin. Different database defaults are permitted; the fixture
uses latin1/latin1_bin defaults to exercise that separation.

Native index/constraint names are grouping and join keys only. Comparison retains
semantic multisets and exact cardinality, including duplicate or extra structures.
FK-support indexes derive from prefix coverage of primary and unique indexes;
`role_assignments.role` and `local_auth_challenges.subject` need additional support.
Expected indexes are visible ascending BTREE indexes over full columns, without
expressions or prefixes. Foreign-key DELETE is CASCADE; InnoDB omitted NO ACTION
and RESTRICT UPDATE are the explicitly recognized equivalent actions.
[MySQL foreign-key rules](https://dev.mysql.com/doc/refman/8.4/en/create-table-foreign-keys.html).

Native `COLUMN_DEFAULT=NULL` does not distinguish an absent default from an
explicit NULL default. The `local_tokens.resource` empty-string default remains
distinct. VARCHAR character capacity is the declared width and octet capacity is
four times that width for utf8mb4. For native metadata, TEXT character/octet
capacities are both 65535 and LONGTEXT capacities are both 4294967295:
MySQL's text calculation uses charset `mbminlen=1`, not `mbmaxlen=4`.
The pinned MySQL 8.4.11 Broker fixture observed these capacities under utf8mb4_bin,
including tables created in a database with different default character settings.
The expectations also derive from pinned official code.
[Native character-length calculation](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/sql/item_func.cc#L9180),
[utf8mb4 charset](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/strings/ctype-utf8.cc#L7623).

`MysqlCheckShape::native_clause()` is a strict reference for MySQL 8.4.11 DDL
created with `sql_quote_show_create=ON`: ``(`id` = 1)``, ``(`epoch` > 0)`` and ``(`position` > 0)``.
The fixture asserts the setting in the actual creation session before DDL.
The catalog reads persisted expression text; this is not a session-independent
expression normalizer or a policy/default for an application connection.
[Persisted CHECK text](https://github.com/mysql/mysql-server/blob/mysql-8.4.11/sql/dd/dd_table.cc#L1686),
[session quoting option](https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_sql_quote_show_create).

The projection does not prove complete database-object inventory, temporary-table
visibility, absence of views/triggers/routines/events, metadata privileges or
complete capture. Undeclared storage options such as inherited encryption gain
no invented defaults or renderer overrides. General native capture, finite external
payload limits, visibility, session policy and normalization belong to the required
M2B refinement before a MySQL service. There is no public RawMysqlCatalog,
CatalogLimits or validate-catalog API. No application pool, SQLx MySQL dependency,
TLS, startup lock, recovery, identity, authorization or HTTP behavior is delivered here.

The current schema adds [normalized instance registration](rust-broker-instances.md).
The version is not indexed or bounded by a VARCHAR width. The child FK cascades
from instance identity; its `(instance_id, project_id, position)` primary key
also supplies the MySQL FK-support prefix. Application validation and writes
remain separate producers. Epoch-1 databases are rejected, without automatic
upgrade or conversion.

## Native schema verification

The existing SQL-server target uses the pinned MySQL 8.4.11 and PostgreSQL 17.11
images. Test-only CLI transport uses NULL-tagged hexadecimal UTF-8 fields and native
metadata projections, without a SQL/JSON parser. Real MySQL comparisons cover all
declared relations and valid native mutants for type, width, unsigned integer,
nullability, defaults, ordinals, extra/missing/generated/invisible columns,
character settings, primary/unique/extra/prefix/descending/invisible indexes,
FK targets/actions/absence, weakened/unenforced/extra/missing CHECKs, engine and
row format. An engine-rejected DDL mutation is a failed fixture, not a successful
comparator proof. Every mutant starts and ends at an exactly compared fresh
reference in the owned fixture; its database drops never run in production.
Owned containers must be removed and their absence observed.

Current commands from the Broker workspace:

```text
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked -p broker-store --all-targets -- --test-threads=1
cargo test --locked -p broker-store --doc
cargo test --locked -p xtask --lib
cargo test --locked -p xtask --all-targets
cargo test --locked -p broker-store --test sql_servers -- --ignored --test-threads=1
cargo audit --file Cargo.lock --json
```

Pre-commit checks whitespace and formatting. Pre-push runs workspace Clippy, DOC and workspace all-target tests, followed by native SQL and packaging/container phases. The workspace test command covers the ordinary Store schema contract without a duplicated subset invocation.

See [SQL format/seeds/time](rust-sql-schema.md), [PostgreSQL persistence](rust-postgres-control.md)
and [database operations](database.md) for their respective contracts.

The [MySQL control implementation](rust-mysql-control.md) consumes this immutable projection for native startup and OIDC-flow persistence. Producer tests alone do not establish service integration.
