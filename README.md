<p align="center">
  <img src="docs/assets/logo.svg" width="72" height="72" alt="Graphit Broker">
</p>

<h1 align="center">Graphit Broker</h1>

<p align="center"><strong>The identity, authorization, AI, and storage gateway for Graphit.</strong></p>

<p align="center">
  <a href="https://github.com/graphit-labs/graphit-broker/releases/latest"><img src="https://img.shields.io/github/v/release/graphit-labs/graphit-broker?style=flat-square&color=b9fb63&labelColor=101311" alt="Latest release"></a>
  <a href="https://github.com/graphit-labs/graphit-broker/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/graphit-labs/graphit-broker/release.yml?style=flat-square&labelColor=101311" alt="Build status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/graphit-labs/graphit-broker?style=flat-square&labelColor=101311" alt="MIT license"></a>
  <a href="https://github.com/sponsors/lainosantos"><img src="https://img.shields.io/badge/Sponsor-Graphit-db61a2?style=flat-square&logo=github-sponsors&labelColor=101311" alt="Sponsor Graphit"></a>
</p>

<p align="center">
  <a href="#quick-start-with-docker">Quick start</a> ·
  <a href="docs/binary.md">Install</a> ·
  <a href="docs/configuration.md">Configure</a> ·
  <a href="docs/api.md">HTTP API</a> ·
  <a href="docs/security.md">Security</a> ·
  <a href="#documentation">Documentation</a> ·
  <a href="https://github.com/graphit-labs/graphit-code">Graphit Code</a>
</p>

Graphit Broker is the server-side identity, authorization, AI, and storage gateway for
Graphit. It validates end-user OIDC tokens, short-lived local access tokens, or revocable service
credentials,
evaluates deny-by-default resource grants from SQL, and exposes:

- `POST /v1/hub/access/resolve` — the authoritative Hub project grants for the verified caller;
- `POST /v1/s3/credentials` — renewable temporary S3 credentials restricted to one authorized project, user-memory, or Hub-metadata scope;
- `POST /v1/embeddings` — an OpenAI-shaped contract backed by local inference or a broker-owned
  OpenAI-compatible, Cohere, Voyage, or Google adapter;
- `POST /v1/rerank` — the versioned Graphit contract backed by local inference, native
  Cohere/Voyage/Jina adapters, or embedding-simulated OpenAI and Google Gemini adapters;
- `/admin/` — the OIDC/local-password UI for Projects, Project access, Local users, Admin roles,
  and read-only Configuration, including role assignments and service credentials.

Only the broker knows AI API keys, upstream models, and the permanent S3 credentials used to call
STS. After authenticating Graphit, it selects the route from current grants for the requested scope and returns that route's
bucket, region, endpoint, root prefix, and short-lived STS credentials. Graphit renews them before
expiry and accesses S3 directly; anonymous callers never receive storage credentials.

A deployment without an object store can instead give a route the `filesystem` driver: the broker
keeps Hub objects on a mounted volume and serves them itself over an S3-compatible, Signature
Version 4 endpoint that the AWS SDK and the query engine's `httpfs` extension read unchanged,
still returning per-project credentials from the same endpoint. See
[configuration](docs/configuration.md#the-filesystem-driver).

For HTTP MCP, Graphit validates the end user's OIDC bearer and preserves it for every broker call.
The default direct-relay mode uses one shared MCP/broker audience. If the IdP supports RFC 8693,
Graphit may instead exchange the MCP token for a short-lived broker-audience token. The broker
validates the final token independently in both modes; exchange failure never downgrades to relay
or anonymous access.

The current native Rust artifact serves [PostgreSQL or private SQLite](docs/rust-broker-server.md).
Its [embeddings composition](docs/rust-broker-server.md#native-embeddings) combines current SQL capability admission, four mature HTTP provider families or verified GGUF inference, durable cache and service discovery.
Its [build, container and CI](docs/deployment.md) qualify the composed native paths;
Full platform release parity and remaining consumer integration remain migration
work. The capability catalog also records those remaining product contracts.

## The governance workspace

In **Project access**, choose who gets access, which projects it covers and what people can do.
The initial choices grant signed-in people read access to all projects when a default storage route
is configured. Without project storage, choose **Find projects** for discovery access. Advanced
storage settings stay available for specialized rules. Administration roles remain a separate decision.

See the [administration guide](docs/administration.md#the-governance-workspace) for identity and
policy workflows, or explore [Code and Broker together](https://graphit-labs.github.io/graphit-code/#workspace-demo).

The native OIDC server exposes [explicit UserInfo profile retrieval](docs/rust-oidc-userinfo.md) [Bearer-authorized token introspection](docs/rust-oidc-introspection.md) and [ID-hint end-session](docs/rust-oidc-end-session.md); JWT consumers continue local verification until expiry.

The native [Device flow](docs/rust-device-authorization.md) composes LOCAL browser sign-in, explicit consent and atomic JWT redemption with empty effective scope. Nonempty scope requests are rejected; API/PROJECT permissions are separate. Device discovery requires OIDC and LOCAL. Focused HTTP/browser contracts are qualified locally on Linux; client integration remains a separate delivery.

## Persistence and authorization

`config.yaml`, after environment expansion, is the sole configuration authority. Changes are
applied by deployment/restart and the administration API exposes only a redacted read-only view.
SQL stores local identities and Argon2id verifiers, normalized resource grants, grant revision,
system roles and assignments, login flows, sessions, and HMAC-protected local tokens—but never raw
passwords/tokens, the configuration document, pepper, or resolved deployment secrets. SQLite is
the default single-node deployment; PostgreSQL and MySQL use the same domain model.

Resource grants are created through the UI or administration API. A new database has no grants and
therefore denies every consumer operation.

There is deliberately no migration, compatibility loader, dual read/write, or fallback path in
this development version. Recreate the database when the schema version changes.

Local identities live in SQL. For the native server, configure `auth.pepper`, explicit LOCAL
password/MFA policy and administrative cookie sessions, then run
`graphit-broker --config config.yaml --bootstrap-admin-stdin` with the temporary password supplied
only through a non-terminal stdin stream. The command creates the fixed first username and subject
`admin` atomically with its database `admin` role and refuses creation when any local user already
exists. Passwords need at least 15 Unicode characters and at most 4096 UTF-8 bytes. The user must
replace the temporary password at first login; TOTP enrollment follows when the configured
`auth.local.mfa.required` is true. No listener, storage volume, session or token is created by bootstrap.
See [first local administrator](docs/administration.md#first-local-administrator) for the stdin
format and prerequisites, and [native LOCAL login](docs/rust-admin-local-login.md) for bounded
password admission, rate limits and optional adaptive CAPTCHA.

Passwords are accepted only at browser/device login and are never reusable API Bearers. Desktop
CLI login uses the Broker as a standard OpenID Provider with Authorization Code, PKCE, nonce and
EdDSA ID-token verification; headless login uses Device Authorization, and
automation uses passwordless service identities with independently expiring/revocable credentials.

RBAC applies throughout the broker. Every authenticated OIDC or local principal receives the
built-in `user` role by default; `admin` and custom roles add system actions. Resource grants remain
the independent, deny-by-default authorization layer for project capabilities:

- roles control system/UI actions; optional verified OIDC claim roles override SQL assignments;
- resource grants control which verified consumer may use `hub`, `s3`, `embeddings`, and
  `rerank`, for which exact projects and S3 operations/routes/prefixes.

## Quick start with Docker

Build the productive native Rust executable and Linux container:

```text
cargo run --locked -p xtask -- build --debug
make docker-build
```

Provision the [native SQL YAML, Ed25519 key and PostgreSQL CA when selected](docs/rust-broker-server.md)
and follow [container deployment](docs/deployment.md) for UID10001, volumes,
health/readiness, hooks and shutdown. This server uses real configured SQL.
The earlier Go health-only configuration is not accepted by the native artifact.
Other API/CLI/backend integration and platform release gaps remain migration obligations; this does
not establish full parity.

CI validates the maintained Rust/SQL/HTTP/container gate. The tag workflow consumes
its native Linux artifact and requires native macOS/Windows package jobs with complete
runtime dependencies and installed configuration/SQLite checks. Those native jobs and
hosted publication still require execution. See [binary scope](docs/binary.md).

## Documentation

- [Configuration reference](docs/configuration.md)
- [Local GGUF model catalog and examples](docs/models.md)
- [Native binary build and qualification](docs/binary.md)
- [Database backends](docs/database.md)
- [OIDC integration](docs/oidc.md)
- [Resource authorization](docs/authorization.md)
- [Administration UI and API](docs/administration.md)
- [Consumer HTTP API](docs/api.md)
- [Deployment](docs/deployment.md)
- [Security model](docs/security.md)
- [Rust server credential digest contract](docs/rust-credentials.md)
- [Rust PostgreSQL control persistence](docs/rust-postgres-control.md)
- [Rust SQLite flow persistence, qualified locally on Linux](docs/rust-sqlite-control.md)
- [Rust PostgreSQL local identity and current SQL roles](docs/rust-postgres-identity.md)
- [PostgreSQL role definitions](docs/rust-postgres-roles.md)
- [MySQL role definitions](docs/rust-mysql-roles.md)
- [Operations and troubleshooting](docs/operations.md)

## Development

```bash
cargo fetch --locked
make fmt
make test
make vet
make lint
make build
```

Git hooks are declared in the root `githooks` object of `.graphit/project.json`.
Run `graphit git sync` after changing the configured events. Graphit registers
its dispatcher through Git's native `hook.<name>.event/command/enabled`
configuration; it does not use `core.hooksPath`. Commands are read when the hook
runs, so editing an existing event's commands needs no reinstall.

Pre-commit checks workflow syntax and keeps the staged-path checks for formatting,
shell files and the admin UI. Pre-push runs formatting, strict Clippy and the xtask
unit tests. During development, run the suites affected by each change and reuse
valid results for unchanged code.

The Broker builds from its own checkout. Cargo fetches the shared Graphit Code
crates at the exact revision recorded in `Cargo.lock`. Use `make check` to run
formatting, strict Clippy, documentation tests and ordinary workspace tests.
The device authorization suite starts the native Broker on loopback with a
temporary SQLite database. The `Native CI` workflow runs these Rust checks on
Linux, macOS and Windows and checks the administration UI syntax.

Use `make qualify` or `cargo run --locked --offline -p xtask -- qualify` for
the explicit SQL, HTTP, STS, storage and native container contracts. These
checks need Docker, the [pinned S3 tools](docs/rust-hub-storage-fixture.md#build-and-prerequisites)
and the release build tools described in [Deployment](docs/deployment.md).
The `Native qualification` workflow provisions those prerequisites, validates
the workflows and installers, builds the CUDA-enabled Linux package, and checks
relocated installations on macOS and Windows. Stable tag releases require
this workflow.

For Windows source builds, enable [Git long-path support](https://gitforwindows.org/git-cannot-create-a-file-or-directory-with-a-long-path.html)
with `git config --global core.longpaths true` before `cargo fetch --locked`.
Upstream Cargo dependencies contain deeply nested paths; the Windows CI runner
applies this configuration too. Installed release packages do not need this build
setup.

[Administrative session persistence in Rust](docs/rust-admin-sessions.md) provides PostgreSQL create/read/revoke contracts qualified on Linux; administrative HTTP login and current policy remain separate.

The [typed SQL schema and declared MySQL reference](docs/rust-mysql-catalog.md)
is qualified on Linux under `tsk-5ca4`, including real engines and hook counterproofs. It
validates the schema producer. The separate MySQL control implementation
is described below.

The [Rust MySQL control implementation](docs/rust-mysql-control.md) provides native control persistence. Server backend selection is described separately in the [native server guide](docs/rust-broker-server.md).

The [MySQL administrative session source](docs/rust-mysql-sessions.md) adds creation, consistent reading and revocation using the existing control store.

The [Rust MySQL local identity and SQL role read](docs/rust-mysql-identity.md) revalidates an already authenticated local caller and reads current SQL roles. Credential authentication, upstream policy and resource grants remain separate.

The [PostgreSQL local identity and SQL role read](docs/rust-postgres-identity.md) uses the existing control pool and shared identity data types. Authentication, identity mutations and resource grants remain separate.

The [PostgreSQL role definition replacement](docs/rust-postgres-roles.md) preserves fixed built-ins, serializes writers of one role, and makes committed permissions visible to the next current RBAC read. Administrative HTTP authority remains separate.
