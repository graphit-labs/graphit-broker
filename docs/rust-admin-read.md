---
title: Read native administrative data
description: Current SQL authorization, bounded projections and effective redacted deployment data in the native Broker.
doc_type: reference
tags: [rust, administration, authorization, postgresql]
references:
  - target: {type: task, id: tsk-0dff, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-3daa, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-b7fc, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-38d8, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: derived_from
  - target: {type: task, id: tsk-9548, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---

# Read native administrative data

The native PostgreSQL server mounts the following GET/HEAD routes when
`administration.enabled` is true. They use the same configured authentication
owners as [session read](rust-admin-session-http.md): signed LOCAL access JWT,
[opaque LOCAL/service bearer](rust-admin-local-bearer-session.md),
[upstream bearer](rust-admin-upstream-session.md), and genuine
[LOCAL or federated cookies](rust-admin-federated-cookie.md). Cookie transport and
each bearer transport still require their own configuration.

| Route | Current SQL action | Result |
|---|---|---|
| `/admin/api/v1/projects` | `projects.read` | Hub project catalog and Graphit CLI commands |
| `/admin/api/v1/roles` | `roles.read` | Definitions and the nine supported system actions |
| `/admin/api/v1/role-assignments` | `roles.read` | Literal subject/role assignments |
| `/admin/api/v1/local-users` | `users.read` | Human/service identity metadata |
| `/admin/api/v1/principals` | `grants.read` | Principal hints for policy editors |
| `/admin/api/v1/grants` | `grants.read` | Current policy document and ETag |
| `/admin/api/v1/config` | `configuration.read` | Redacted effective deployment YAML |

Wildcard permission also permits these actions. Each route checks its own action;
it does not require an additional `session.read` check. A prior session response,
principal hint, role list or discovery catalog does not authorize a later request.
The [administrative UI](administration.md), browser login composition, service
credential inventory and administrative writes have their own native deliveries.
The full [release API catalog](api.md) does not imply those routes are mounted.

## Shared document codecs

The PostgreSQL reader and the SQLite readers use the same bounded document
codecs in `crates/broker-control/src/admin_read/projection.rs`. These functions accept
bounded snapshot or row DATA and return an encoded document; they do not authenticate
or authorize a caller. PostgreSQL and SQLite retain separate physical transactions
and observe the selected genuine authentication factor for each action.

The SQLite reader observes its requested action and projects the response in one IMMEDIATE transaction, retains the genuine authentication proof/window, and requires a known COMMIT before success. It does not use a completed `session.read` result as permission. The [SQLite read vertical](rust-sqlite-admin-read.md) covers LOCAL, Broker JWT, F1 and federated-cookie channels. Global Server composition remains separate.

## Configure the read bounds

Use the complete native [administration example](rust-admin-session-http.md).
In addition to the existing actor identity/profile bounds and request timeout,
administration requires positive, representable `grants_json_bytes` and
`response_json_bytes`. The examples use 65536 for both as operator choices, not
defaults. The first bounds the SQL grant document; the second bounds complete
read responses and aggregate SQL list projections. A list that exceeds the bound
fails as a whole; it is not truncated. These bounds do not impose a new per-user,
per-role or per-project quota, and do not bound PostgreSQL's internal aggregation
memory. `rows` and `roles` continue to bound the authenticated actor's role join.

The optional `administration.cli` block accepts `provider_name` and `profile_name`.
After trimming, an empty provider name uses the existing `organization-broker`
name; an empty profile name uses that provider name. Commands use the validated
native `server.public_url`, with POSIX shell quoting for literal arguments. The
server only returns text; it does not execute those commands. There is no broker
URL placeholder or alternate CLI syntax.

## Read the catalog and policy

Projects return:

```json
{"projects":[],"all_projects":false,"authorization_revision":1,"provider_command":"..."}
```

The revision is a positive JSON number. Complete eligible Hub rules must match
both the caller's literal principal and a capability pattern matching `hub`.
Project IDs and their literal capability strings are unique and sorted. An empty
project list or `*` in an eligible rule sets `all_projects`; it does not enumerate
a registry or create a synthetic `*` project. Catalog metadata does not grant
storage access.

LOCAL callers use the current SQL profile and raw LOCAL subject after genuine
authentication and binding, including when a signed JWT contains an older profile
or a pseudonymous OIDC subject. Federated callers use the issuer's verified mapped
identity. Cookie reads use current issuer trust, selector policy and role
definitions without JWKS or UserInfo requests. Upstream bearer verification keeps
the common verifier's legitimate JWKS cache/rotation behavior within the request's
original deadline.

Grants return `{v:1,revision,updated_at,rules}` with `updated_at` in UTC RFC3339 and
an ETag containing the same quoted decimal revision. The wire field is `access`;
optional principal, project and S3 selector fields are omitted when empty. This
read exposes structurally valid stored DATA; it does not compile that document
into the authority permitting `grants.read`. Grant mutation and `If-Match` CAS
belong to the separate write protocol.

## Read identities and roles

Roles return `{roles:[{name,permissions}],actions:[...]}`. Wildcard `*` is a
permission, not a tenth system action. Assignments return
`{assignments:[{subject,role,created_at}],bootstrap_only}`. The flag is true only
when the complete assignment list is empty, including non-admin assignments.

Assignment subjects are literal SQL DATA of at most 512 Unicode characters,
the natural `VARCHAR(512)` width. The reader does not impose the raw LOCAL
subject byte cap, require an issuer separator, trim a persisted binding, or
resolve it through username/email. The raw LOCAL identity subject keeps its
separate 512-byte domain.

Users return `{users:[...]}` ordered by username. Records include kind, raw
subject, enabled/password-change/MFA flags, positive revision, UTC RFC3339 creation
and update times, and effective role names including the implicit `user` role.
Nonempty profile fields are included. Neither SQL projections nor responses
select password PHCs, MFA secrets or recovery codes. `mfa_enabled` reports the
presence of the persisted factor; it does not authenticate that factor.

Principal hints begin with `anonymous` and `authenticated`, then list all LOCAL
users, including disabled users, by username. LOCAL hint IDs are raw subjects;
LOCAL role lookup uses canonical `local|subject` bindings. Hints are DATA for
the editor and cannot manufacture an authenticated LOCAL principal. Empty lists
are JSON arrays, and corrupt stored fields fail closed.

## Inspect deployment configuration

Config returns `{source:"deployment",restart_required:true,yaml:"..."}`. The YAML
is a closed, typed projection captured while validated builders resolve the
effective configuration. It includes applied native defaults and public paths,
without reading signing-key bytes or querying discovered AWS credentials.
Nonempty database passwords, pepper, CAPTCHA secret and static storage key pairs
are replaced with `[configured-secret]`. Original config/secret wrappers and
runtime owners do not implement serialization for this view.

Inactive capabilities do not appear as active configuration. Browser-client
configuration that the native compositor does not yet support is not fabricated.
The view is read-only, contains redacted values and is not an importable deployment
file. Apply actual configuration changes through the deployment and restart the
process. Rendering and the actual enclosing JSON byte bound are validated before
opening SQL, storage volumes or listeners.

## Completion, errors and recovery

Each request retains its genuine factor, physical owners and original UTC/monotonic
expiry gates through SQL, known COMMIT and response preparation. Action and data
queries share the operation's SQL transaction. READ COMMITTED provides a fresh
snapshot per statement; it does not promise a single simultaneous snapshot across
all statements or a permission lease. Native cookie reads preserve user-before-
session locking and confirmed expiry cleanup.

Responses are `no-store`/`no-cache`, preserve the native request ID contract, do not
set or renew a cookie, and require no CSRF token for GET/HEAD. HEAD authenticates
and authorizes the same read before returning headers without a body.

Invalid or expired authentication returns 401 `admin_unauthorized`; current action
denial returns 403 `admin_forbidden`. Authorization SQL corruption/failure returns
500 `authorization_failed`. Projection failures use the corresponding
`*_read_failed` code (or `configuration_encode_failed`); project projection/policy
failure is 503 and other projection failures are 500. Deadline is 504
`administration_unavailable`; closed/uncertain SQL outcomes are 503 with that code.
Messages are finite and never include SQL, driver diagnostics or credential data.

An unconfirmed COMMIT acknowledgment never yields a protected success or an
automatic replay. Start a separate request to observe current state after recovery.
Authentication/deadline gates also apply to negative results; an actual uncertain
COMMIT retains its distinct outcome.

The implementation lives in `crates/broker-control/src/admin_read.rs`, its private
SQL service, `crates/broker-presence/src/admin_read.rs`, and the native server's
typed configuration projection/composition. The owned PostgreSQL contract is in
`crates/broker-control/tests/postgres_admin_read.rs`; qualification remains scoped
to the actual contracts recorded for the delivery.

## Executable verification

The owned SQL and actual binary contracts run unchanged on each supported host:

```text
cargo test --locked --offline -j4 -p broker-control --test postgres_admin_read -- --ignored --test-threads=1
cargo test --locked --offline -j4 -p broker-server --test admin_read -- --ignored --test-threads=1
```

They use owned TLS PostgreSQL with a NOSUPERUSER role and real configured
credentials. The federated cookie test performs the genuine HTTPS/PKCE browser
code exchange through the programmatic H1 producer, then consumes the cookie over
Native HTTP; it does not claim a native browser callback route. Response bounds
are charged while accumulating the catalog, before project/capability expansion.

The explicit `xtask` qualification plan runs both aggregate read suites before later
PROJECT, Presence and audit integration. Pre-commit runs whitespace and formatting checks; workspace Clippy and ordinary tests run in `make check`. The saved runner is:

```text
cargo run --locked --quiet -p xtask -- hook pre-commit
cargo run --locked --quiet -p xtask -- qualify
```

Running a hook does not authorize a push. Platform-specific execution and failures
are reported in the delivery evidence; passing one host is not cross-platform proof.
