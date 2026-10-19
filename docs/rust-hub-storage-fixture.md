---
title: Native Hub storage process fixture
doc_type: reference
references:
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-2f3e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e8dd, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-81ba, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-5651, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-1dd5, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-7aaf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-ccd4, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-ed33, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-6488, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-0257, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-d75f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-b788, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
---

# Native Hub storage process fixture

`broker-presence/examples/hub_storage_fixture.rs` is an executable process for
consumer tests that need real Native or Web OAuth authentication, Hub Resolve, SQL storage
admission and temporary AWS STSv3 credentials usable against owned MinIO.
Consumers use its JSONL process protocol and the public HTTP endpoints.
The PostgreSQL and MinIO test supports remain internal to Broker.

It composes the existing [Hub credential HTTP service](rust-hub-storage-credentials-http.md)
and [AWS storage issuer](rust-hub-storage-aws.md). It creates a PostgreSQL TLS
database with a NOSUPERUSER runtime owner, a separate MinIO IAM caller, real SQL
grants, and an Ed25519 Native access token signed and verified by the existing
Broker SDK. It follows the warm Native verification/profile recipe of the
[Native Inventory fixture](rust-native-inventory-fixture.md). The explicit
`start_web` profile additionally composes the productive
[LOCAL browser authorization](rust-oidc-browser-authorization.md), registration,
token/refresh and [canonical discovery](rust-oidc-discovery.md) producers.
The Native-only `start` profile keeps its existing warm verification contract.
Both profiles use the short explicit route base `t` and bucket
`hub` inside the process-owned MinIO instance and private volume. These compact
fixture identifiers keep the existing scoped permissions, including the restricted
catalog Delete roots, within the real STS 2048-byte ceiling. Consumers use the
actual prefix and bucket returned by Ready and STS. Canonical keys, SQL grants,
identities and issued-credential shapes are preserved. Each grant still contains
the actual project in its `v1/projects/{project}/...` key; only the redundant
private fixture namespace is shortened. Earlier bases `tenant/{project_id}` and
`t/{project_id}` are historical fixture identifiers.

## Build and prerequisites

Restore the upstream MinIO and mc dependencies qualified by `tsk-6488` under
`.build/rust-hub-sts-fixture-refinement/bin/{minio,mc}`. MinIO is pinned to
`github.com/minio/minio@v0.0.0-20251015172955-9e49d5e7a648`, with module checksum
`h1:6TdolSCLSs2nwm8i0PpWDqf9iX2Ty9WQK8wmr7dCnUM=`; mc is pinned to commit
`cf909e1063a9`. These are external upstream validation dependencies. Record
the resolved version and newly observed binary hashes after reconstruction;
the historical MinIO binary hash does not establish reproducibility.
Docker must provide the PostgreSQL image pinned by the existing SQL support.

The Code consumer requires libclang and the workspace native build tools.
From the Code checkout, use `cargo xtask cargo build/test ...`: xtask prepares
Ladybug directly from the locked official `lbug` Cargo sources and passes the
same engine/headers to the binding and C++ adapter. No downloaded Graphit SDK,
OpenBLAS pkg-config prefix or manual Ladybug environment is required. The Broker
fixture itself does not depend on the AST engine and uses normal Cargo below.

```text
cargo build --locked --offline -p broker-presence --example hub_storage_fixture
cargo test --locked --offline -p broker-presence --example hub_storage_fixture
cargo test --locked --offline -p broker-presence --example hub_storage_fixture -- --ignored --exact tests::hub_storage_fixture_native_sts_contract --test-threads=1
```

The last command requires the normal example binary from the first command in
the same target/profile. A consumer spawns that binary directly with private
stdin/stdout pipes. With the default Cargo target its path is
`target/debug/examples/hub_storage_fixture` (with the platform executable
suffix). `CARGO_TARGET_DIR` changes the target root.

The process contract allows 300 seconds for Start/Ready, including external
PostgreSQL and MinIO setup. Its external Shutdown/Ack and EOF/child-join
guards also allow 300 seconds for owned PostgreSQL/Docker and MinIO cleanup.
The internal Now/HTTP/SQL operation budgets and token/heartbeat lifetimes
stay unchanged. `GRAPHIT_BROKER_FIXTURE_DIAGNOSTICS=1` enables static
startup phase labels on stderr. It never logs the private Ready payload or
credentials. On a failed observation the test closes stdin and waits for owned
cleanup before terminating and reaping the child as a contingency.
Diagnostics also mark the Now, HTTP, SQL, PostgreSQL and MinIO shutdown phases.
They can report an allowlisted relative panic location and finite
connection timeout or `io::ErrorKind` categories. They preserve the existing
PostgreSQL behavior and omit panic payloads, DSNs and raw SQL/TLS errors.

For a change confined to the Inventory or Now composition, run the exact causal
contract below. It uses the same process helper, real Native Inventory
publication/read, actual Now WebSockets, Hub Resolve and STSv3 issuance/denial. The full recurring
contract above retains the signed S3 conditional/multipart checks.

```text
cargo test --locked --offline -p broker-presence --example hub_storage_fixture -- --ignored --exact tests::hub_storage_fixture_native_inventory_contract --test-threads=1
```

## App Web consumer tests

The Code module `crates/graphit-app/src/browser_auth/tests/remote_native_web.rs`
contains four bounded ignored cases under `browser_auth::tests::remote_native_web`:

- `real_broker_web_reads_installed_remote_ast_without_project_authority`:
  exact installed releases, schema/sample/Cypher/neighborhood/Source and current
  provider denial through a genuine browser session.
- `real_broker_web_rejects_corrupt_root_and_source_manifest_with_healthy_sibling`:
  full descriptor SHA, physical Lance manifest SHA, healthy sibling and unchanged
  installed catalogue.
- `real_broker_web_checks_origin_cancels_one_job_and_joins_owned_shutdown`:
  current origin, subscriber cancellation, independent sibling and retained-owner
  shutdown using the existing test-only NativeGate.
- `real_broker_web_reads_ast_published_pins_and_knowledge_corpus_with_cpu_and_degraded_search`:
  direct real AST PublishedPins and a single Knowledge corpus containing documentary
  rows and compatible nullable vectors, Source entity/selectors, AST FTS/semantic/vector/hybrid,
  Knowledge contexts/heads/page/search and
  same-pin degraded search after stopping the actual model child.

The first three require `GRAPHIT_BROKER_HUB_STORAGE_FIXTURE_BIN` naming the normal
Broker executable built above, PostgreSQL/Docker and the pinned MinIO/mc binaries.
They need no downloaded model or active Native profile for the Web reader. The
CPU case requires an explicitly provisioned GGUF model bundle and the native model-server executable; prior runtime-library fixture evidence does not qualify the GGUF consumer.
Its producer and consumer have separate installations, authorities and model
owners. Two release identities preserve the captured SDK pins; this case does
not claim that their physical dataset versions differ. It performs no package
export/import or fabricated manifest reconstruction.

Payload setup uses the fixture's Native bearer only to obtain actual STSv3 keys
for the publisher. The Web reader performs DCR, LOCAL authorization, PKCE callback
and protected HTTP requests through the current provider/lease, STSv3 and S3.
Ready, browser URLs, codes, tokens and cookies remain private. No access override,
extra verification key or fabricated callback qualifies these cases. Setup is
inside failure guards; host, Source/graph, Task/foreground/model where present,
and Broker cleanup are attempted independently while retaining the first failure.

The fixture explicitly configures the Broker HTTP loopback key. Its Browser
TaskServer also attaches the existing native storage transport before clones,
with a redirect-free, no-proxy client and loopback enabled only for that already
configured fixture. Native/Broker product defaults are unchanged. Portable
vector identity is resolved by the Model producer; operational ConfigId/RPC
bindings remain separate. The CPU assertion inputs, two installations, schemas
and expected HTTP200 responses were preserved.

## Private JSONL protocol

Write and flush one JSON object per line. The first command must be:

```json
{"command":"start","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","second_project_id":"01D39ZY06FGSCTVN4T2V9PKHG0"}
```

`project_id` is required and canonical. `second_project_id` may be omitted;
if present it must be a distinct canonical ID. In Native-only `start`, it
receives only Native Inventory read/publish grants, with no Hub Resolve, STSv3
or S3 grant. The explicit Web setup adds the confined publisher capability
described below. Explicit
null, wrong types, duplicate or unknown fields, invalid IDs and Shutdown before
Start are errors before external setup.

Native Ready contains the following fields. The access bearer and all subsequent
HTTP-issued STS credentials stay in the consumer's private process channel and
memory; do not copy them to logs, Task records or validation artifacts.

| Field | Meaning |
| --- | --- |
| `event` | `ready` |
| `endpoint`, `issuer` | Actual loopback Broker origin |
| `api_audience`, `resource` | Actual Native JWT verification audience/resource |
| `client_id`, `subject`, `scope`, `redirect_uri_path` | Existing Native warm profile recipe |
| `expires_at` | Actual signed Native token expiry, epoch seconds |
| `access_bearer` | Actual signed Native access token, private |
| `project_id`, optional `second_project_id` | Validated requested IDs |
| `bucket`, `region`, `storage_endpoint` | Actual owned MinIO topology |
| `prefix` | Explicit fixture route base: `t` in both profiles |

The isolated fixture fixes audience `broker-api`, client `native-client`,
subject `native-subject`, scope `openid fixture`, redirect path
`/auth/callback`, and access lifetime 600 seconds using the existing Native
recipe. Region is `us-east-1`; the route/session use explicit fixture values
and a 900-second STS request. These values are not product defaults. The bearer
is checked by the real verifier immediately before Ready is emitted.

In the Native-only `start` profile, the `/.well-known/graphit-broker`,
`/.well-known/openid-configuration` and `/jwks` routes expose the existing
warm verification shape and actual public key. Their metadata does not qualify
functional authorization/token endpoints; that profile provides no login or
refresh implementation.

## Explicit Web OAuth profile

Use `start_web` as the first command with canonical project IDs and four
required integer lifetime fields: `authorization_ttl_seconds`,
`local_challenge_ttl_seconds`, `access_ttl_seconds` and
`refresh_ttl_seconds`. There are no omitted-field defaults. The existing
policies validate authorization lifetime (30–600 seconds), LOCAL challenge
lifetime (120–1800 seconds), access lifetime (60–3600 seconds), and refresh
lifetime (at least access lifetime, at most 90 days) before external setup.
The optional second project retains the Native Inventory permissions specified
above and provisions a second independent Web identity scoped only to that project.
In this Web profile, the Native setup publisher additionally receives S3
read/write for the second project registry/artifacts and write/delete only
under its artifacts/staging prefix. This supports actual publication into both
requested projects. The Native publisher also gets write on the literal canonical metadata root
`v1/projects/{second_project_id}/hub/metadata/project.json`, needed by the real
catalog seed before its artifact manifests. This uses the productive prefix
model (the root and its descendants); write retains its existing Get/Put,
multipart and prefix-conditioned listing semantics. It grants no parent
metadata directory, sibling key, DELETE, second-project Hub Resolve, other
project, global ACL prefix or permission to either Web subject. Unknown/duplicate fields, null, invalid IDs and policy-invalid
lifetimes are errors before effects.

Ready retains the Native publisher fields above and adds one private `web`
object with `subject`, `username`, `password` and `scope`. The process generates
a new random password and password/MFA pepper, hashes the password through the
productive LOCAL engine, and provisions an enabled human SQL identity. The
subject is the canonical pseudonym derived from that identity by the store's
credential digester. It is distinct from the Native subject. With an explicit
`second_project_id`, Ready also contains `web_second` with the same four fields.
It has a separate random password, enabled LOCAL human row and canonical
subject. It uses the same productive DCR, LOCAL login and PKCE routes; consumers
perform a real login for each identity. Without a second project, `web_second`
is omitted. The existing `web` object retains its shape and primary identity.
Keep the complete
Ready payload, password, codes, tokens and issued STS keys only in private
pipes and memory; never put them in documentation, logs or receipts.

The isolated LOCAL profile explicitly disables required MFA and CAPTCHA, uses
one password worker with saturation multiplier two, five failures per
60-second window, a 300-second lockout and capacity 4096. The LOCAL challenge
lifetime comes from the required command field. It composes no upstream
provider in this LOCAL journey; productive Server MFA/recovery/upstream
behavior and their existing qualifications remain unchanged. These are
fixture choices, not product defaults.

The Web profile compiles the canonical Server discovery producer directly;
it does not copy discovery JSON or export a fixture-only production API.
It serves the advertised `/oauth/authorize`, `/oauth/login`,
`/oauth/register`, `/oauth/token`, `/oauth/userinfo`, `/oauth/introspect`, `/oauth/revoke`,
`/oauth/end-session` and `/v1/oidc/keys` routes through existing
producers. Issuer, API audience and accepted resource are the actual Ready
literals. Register the Web redirect URI dynamically, use S256 PKCE and retain
state/nonce in the real consumer. Obtain access/ID/opaque refresh tokens through
LOCAL login and the authorization-code exchange, and rotate refresh through
`/oauth/token`. An access override or extra verification key is not Web OAuth.
There is no fabricated `user_subject` JWT claim or per-request UserInfo lookup.

The token gate for Inventory, Now and STSv3 in this explicit profile requires
`openid`; Native-only `start` continues to require `fixture`. SQL grants remain
the separate authorization decision. By default, the Web LOCAL subject receives its own
`hub` Resolve and `s3` **read-only** grants for the first producer's registry
and artifacts. It gets no Native inventory/publish/domain grants, S3 write or
delete, or second producer access. The Native publisher bearer retains its existing shape; only the explicit
second-project setup capability above extends its S3 admission in this Web profile. Hub authority grants no application PROJECT
permission automatically. The same real verifier, SQL admission and STSv3
issuer validate Web bearer requests; the same Broker key signs actual OAuth
tokens and supplies the advertised JWKS.

The second Web identity receives distinct `hub` and read-only `s3` grants
for only `second_project_id`, with registry/artifact prefixes and the same
real SQL admission and STSv3 producer. Neither Web identity inherits the
other's project or the Native publisher's grants. The second receives no
Now, Native, PROJECT, write or delete grant. The first identity's optional
`now_read` grants retain their existing explicit behavior. Grant IDs and
passwords are independent; the fixture adds no fabricated Web bearer.

This two-user producer extension supports the separately owned Code
`tsk-d75f` HTTP Hub isolation proof. Building the example verifies composition;
actual A/B login and API/read isolation require that consumer qualification.

The focused causal command is:

```text
cargo test --locked --offline -p broker-presence --example hub_storage_fixture -- --ignored --exact tests::hub_storage_fixture_web_oidc_contract --test-threads=1
```

Build the normal example first in the same target/profile. This contract drives
the process over private JSONL and actual HTTP: canonical discovery, DCR, LOCAL
login, PKCE/code/state/nonce, EdDSA verification against advertised JWKS, literal
issuer/audiences, refresh rotation/replay denial, Hub Resolve and STSv3. A Native
publisher writes real MinIO bytes; the refreshed Web caller reads those bytes
and is denied write/delete, Presence publication/subscription and the wrong
producer. The Presence negative uses protected PUT and WSv1 subscribe: own-GET
returns NotFound for a missing inventory before its capability decision, so it
is not a valid missing-grant oracle. Native
inventory/Now and their live shutdown checks still run in this Web composition.
The command/protocol tests also reject missing and invalid lifetime fields
before effects. Fixture qualification alone does not prove the App's
AuthenticatedWebCaller, installed AST/Knowledge/graph HTTP consumers, two
immutable artifact versions or the full `tsk-5651` delivery; those remain the
consumer's integration obligations.

### Optional primary Web Hub storage writer

Add `"hub_storage_write":true` to a valid `start_web` command when the real
consumer needs to publish to its own Hub storage. The optional closed boolean
defaults to false. It accepts no ACL, operation or prefix list from the consumer.
Ready keeps the same `web`, `web_second` and storage shapes. Null, other types,
duplicate fields and this field on Native-only `start` are rejected before setup.

Only the primary Web subject receives the extra S3 operations on its primary
project: write on registry, artifacts and the literal canonical metadata root
`v1/projects/{project_id}/hub/metadata/project.json`, plus delete only on
`v1/projects/{project_id}/artifacts/staging`. Write uses the existing Get/Put,
multipart/abort and prefix-conditioned listing semantics. This supports real
metadata creation/update, conditional catalog updates, payload creation and
cleanup of the publisher's staging object. Final artifacts, metadata, other catalog roots, metadata parent/sibling, the
global namespace and other projects gain no Delete operation. The restricted
fixture catalog grant below is separate from these publication grants. No
additional Now capability is granted.

The second Web identity remains read-only and isolated even when this flag is true. The flag adds S3 storage authority only; productive PROJECT Hub/write remains unsupported. Code/Auth retain their independent admission for each mutation. This fixture does not turn Hub/read into PROJECT write or accept arbitrary role/ACL input. With false or omission, both read-only Web journeys and their existing denials remain unchanged. Web publication and denial require separate consumer tests.

## Web composition validation

The first Web run failed after its OAuth/STSv3/S3 observations because the
test incorrectly expected 403 from own-GET before creating an inventory.
The source-defined result is NotFound for a missing row. The corrected test
uses protected PUT and WSv1 subscription for capability denial, without
changing the production authorization logic. That failed attempt remains
historical evidence rather than a passing result. No full integration suite,
Windows/macOS result or installed App Web consumer is implied by these checks.

## Actual admission and storage operations

The same Broker origin also serves real Native
`PUT /v1/instances/{id}/inventory` and own
`GET /v1/instances/{id}/inventory` through the existing
`broker_instance_inventory_router`. The authenticated subject has
`presence:publish` and `presence:read` for the requested project and optional
second project. The consumer publishes its complete monitored projects and
versions through HTTP; the fixture seeds no inventory and filters no projects.
With no second project, cross-project publication is denied. With a second
project, inventory containing both projects is admitted. Native-only `start`
keeps Hub and storage authority restricted to the first project; `start_web`
also admits the confined second-project S3 publication described above. An unrelated project is
denied and the existing inventory is preserved. These handlers use the same
store/verifier, required scope `fixture`, 65536-byte grant/body/inventory bounds
and 10-second request timeout as explicit fixture configuration.

The same origin serves **GET `/v1/realtime`** through the productive
`broker_realtime_router`. It shares the exact Store and Native verifier with
Inventory, Hub and STSv3. Consumers first publish their complete inventory,
then send the existing WSv1 `publish` command for a registered
`(instance_id, project_id, version)` tuple, or `subscribe` for a project.
The fixture retains one `RealtimeServerRuntime` with an explicit 30-second
heartbeat and broadcast capacity 32. Required scope is `fixture`; grants,
inventory, command and outbound bounds are 65536 bytes, with a 10-second
operation budget. These are isolated fixture parameters, not product defaults.

Presence read/publish grants admit the first and optional second project.
They do not grant Task, Memory or Knowledge reads: the productive Now mask
continues to hide those sections without their respective capabilities.
The causal contract opens actual authenticated publisher/subscriber sockets
for both projects, checks snapshots and forbidden domain sections, rejects
an ungranted third project and checks that a missing bearer receives 401.
Immediately before Shutdown, each publisher and subscriber must answer a
WebSocket control Ping with its exact Pong payload. This uses the existing
WebSocket transport, with no new Now command or acknowledgment. It leaves
those confirmed live sockets open until Shutdown to verify owned cleanup.
The update check separately republishes a new generated timestamp and waits
within one 10-second budget for that exact instance/version and timestamp in
the typed snapshot DTO. Earlier queued snapshots do not satisfy the check;
absence of the instance is distinct from an invalid or missing header.
The fixture validates the generated DTO after selecting its timestamp. Its
Task and Session leases end at `2000000`, so updates use `1000001`; setting
`generated_at` to `2000000` makes those leases non-future and is invalid.
A separate real `feature` channel checks that this original bad payload is
rejected with `invalid_data` and close 1008, withdrawing its slot. The server
validator stays strict; the valid A/B updates must retain their channels.

Use the Native bearer for:

- `POST /v1/hub/access/resolve` to resolve the actual SQL Hub grant;
- `POST /v1/s3/credentials` with
  `{"scope":"project","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","module":"hub"}`
  for real STSv3 keys, using the project from Start.

The credential response is the existing HTTP wire: string
`authorization_revision` containing a positive decimal, RFC3339 string
`expires_at`, string endpoint (empty for the AWS default), exactly one
`prefixes` entry, issued keys/bucket/region and exact scope/project/module.
It is distinct from Ready's Native token expiry.

SQL grants give the exact authenticated Native subject `hub` Resolve and
`s3` read/write over `v1/projects/{project}/registry` and
`v1/projects/{project}/artifacts`. Existing write/delete staging authority remains
confined to `v1/projects/{project}/artifacts/staging`. The restricted fixture
catalog grant below is a separate Delete grant; final artifacts and all other
catalog roots gain no Delete operation. Native-only `start` denies the second producer at Broker
admission before S3. In `start_web`, the explicit second project gets separate
S3 registry/artifact and staging grants for the Native setup subject, plus
write on the canonical metadata key root above. It adds no global ACL prefix.
Web grants stay confined per subject/project and default to read-only; the
explicit primary storage-write opt-in above is the only exception.

Below `prefix`, the consumer keeps its canonical
`v1/projects/{producer}/artifacts/…` and `registry/…` layout. Staging is
`v1/projects/{producer}/artifacts/staging/{native-upload-random}`, within the
existing admitted project root. The fixture adds no scope root or policy
bypass. Its project-bearing base prefix is explicit route configuration; the
production issuer does not derive that base automatically.

The unchanged AWS policy from `tsk-6488` supports GET/HEAD/ranges, conditional
PUT Create and catalog Update with etag/version, multipart upload/copy/abort,
and deletion of granted staging. It already permits prefix-conditioned
`ListBucket` for non-Delete operations. The publisher journey does not invoke
LIST; this fixture does not claim a new DENY-ListBucket policy.

The real contract tests use the actual process and SDK, including wrong-producer
denial, conditional conflicts, multipart copy Create, final-delete denial and
owned-staging deletion. These transport payloads do not qualify Graphit artifact
formats; native AST/Knowledge publication and readers are the consumer's tests.

## Optional Standalone storage setup

A Native consumer that also needs the maintained Standalone ACL documents can
explicitly request this setup-only capability:

```json
{"command":"start","project_id":"01D39ZY06FGSCTVN4T2V9PKHFZ","standalone":true}
```

Start without this flag, or with false, preserves the existing Native profile.
Null, strings, numbers and duplicate/unknown command fields are rejected. The
Web command does not accept `standalone`; it uses the explicit catalog opt-in
below instead.

Only that opted-in process receives private Ready field `standalone_storage`
with bucket, region, endpoint, prefix, access_key_id, secret_access_key,
session_token and expires_at. Its prefix is `standalone/{project_id}`; the consumer
appends its existing `v1/global.json`, anonymous/authenticated/user/team ACL docs
and `v1/projects/...` paths. The MinIO child accesskey has a null session_token
and a real Unix-second expires_at, exactly 1800 seconds after setup. The owned
upstream mc configures that same UTC expiry. The pinned MinIO requires at least
15 minutes remaining when it receives the creation request; an absolute
900-second expiry loses transport time and is rejected. This fixture explicitly
uses 30 minutes and the API-admitted 20/40-character accesskey/secret lengths;
the secret is zeroized on drop.
Do not print or persist this private payload, including in test receipts.

The accesskey is a restricted child of the fixture's existing MinIO caller.
Its policy allows GetObject (including HEAD) and PutObject only beneath the
dedicated prefix. It grants neither bucket LIST nor DELETE, another Standalone
prefix or Hub objects. Root credentials remain internal to the owned fixture.
For catalog all/name-prefix discovery, additionally pass `"standalone_catalog":true`
on the same Native Start command. There it defaults to false and is rejected
without `standalone:true`. In `start_web`, `standalone_catalog:true` directly
enables this same restricted Standalone capability with listing, using the
existing factory and Ready shape; omit it or use false to keep it absent.
For example, add `"standalone_catalog":true` to a valid `start_web` command
with its four required lifetimes. Null, non-booleans and duplicate fields are
rejected before external setup. Only this mode adds ListBucket on the owned bucket,
conditioned on `s3:prefix` matching the dedicated prefix or its descendants.
Get/Put remain confined and DELETE remains denied; the original setup still
denies LIST and retains its existing scope contract. The actual CLI catalog
journey exercises this explicit listing mode, with qualification tracked by 81ba.

Web setup consumers must use this private `standalone_storage` capability and
its prefix for Standalone global/user/team/project ACL documents. Hub STSv3
credentials remain confined to their project scopes and cannot seed those ACLs.

### Separate catalog seed publisher

With the existing `standalone_catalog:true` opt-in, private Ready also includes
`standalone_publisher_storage`. It has the same bucket, region, endpoint,
prefix, credential/session/expiry shape as `standalone_storage`, with an
independently generated service-account key pair and the same existing finite
1800-second lifetime. Without catalog opt-in this extra field is absent.
The existing reader account and its Get/Put/catalog-list policy stay unchanged;
it still cannot delete objects. Native Hub/STSv3 and production grants are unchanged.

Use the separate publisher account only for fixture artifact seeds. In addition
to its own Standalone namespace's existing Get/Put and catalog listing, it can
delete keys matching `<base>/v1/projects/*/artifacts/staging/native-upload-*`.
The SDK supplies the artifact producer's ProjectId inside this layout; it can
differ from the setup/consumer project. The wildcard stays beneath the actual
owned `standalone/{setup_project}` base, with no other namespace/bucket grant.
Immutable artifacts, registries, metadata, ACL documents and other staging
basenames retain delete denial. No consumer can submit an ACL, role or prefix
list to the closed command protocol.

The separate credential is necessary because artifact publication cleans its
owned staging object before the final conditional registry write. S3 bulk
DeleteObjects can return HTTP200 with an AccessDenied result for an individual
key; the SDK treats that item as a failure. Check per-object results rather
than accepting the HTTP status as publication success. Keep both credential
objects and complete Ready only in private pipes/memory; never log either.

Build the normal example, then run only the focused account/process contract:

```text
cargo build --locked --offline -p broker-presence --example hub_storage_fixture
cargo test --locked --offline -p broker-presence --example hub_storage_fixture -- --ignored --exact tests::hub_storage_fixture_standalone_publisher_contract --test-threads=1
```

This contract uses real catalog Ready/MinIO credentials for upload, immutable copy, per-object bulk staging cleanup and a conditional registry write. It also checks reader bulk-delete denial, publisher delete denial for existing final, registry/metadata/ACL/foreign-staging objects and another namespace, preserved reader Get/List, and confirmed owned Shutdown/Ack/exit0. This is a fixture account contract; actual SDK and Web/Standalone publication require separate consumer tests.

This setup does not change production Broker STSv3 grants, authenticate a caller
or grant PROJECT permission; the original signed Native identity remains the
one used by the real consumer. The fixture owns the credential's MinIO lifetime
and joins that child before acknowledging shutdown.

The exact affected process contract checks genuine Get/Head/Put of ACL and
project documents, denial against an existing independently readable Hub object,
denial of another prefix, LIST and DELETE, plus confirmed shutdown. It avoids
replaying the unchanged Native/Web/OIDC and multipart suites:

```text
cargo test --locked --offline -p broker-presence --example hub_storage_fixture -- --ignored --exact tests::hub_storage_fixture_standalone_scope_contract --test-threads=1
```

## Confirmed shutdown

```json
{"command":"shutdown"}
```

Shutdown first stops LOCAL password admission when the Web profile owns it,
then closes and joins the Now supervisor, WebSocket connections and Hub
maintenance and HTTP. It joins the LOCAL engine before the SQL store/connections, the owned PostgreSQL
container and MinIO child before emitting
`{"event":"ack","command":"shutdown","ok":true}` and exiting zero.
`Minio::shutdown` returns the actual kill/wait result; Drop remains best-effort
cleanup. EOF also closes owned resources and exits zero without an Ack.
Errors produce a finite sanitized stderr message and nonzero exit, never a
success Ack before confirmed cleanup.

## PROJECT metadata integration

The process fixture mounts the productive `GET /v1/hub/catalog/projects` reader
against the same server-owned AWS route/provider as STSv3. The publisher's actual
PROJECT grant includes `hub/metadata`, in addition to registry/artifacts; it does
not introduce a universal grant. App consumer tests publish the canonical v1
PROJECT document through FILE or Native Source entrypoints, without manually
seeding it, and observe the real local name via this HTTP catalog. The metadata
key is `v1/projects/{id}/hub/metadata/project.json`; older key aliases are absent.
This extends the fixture only for affected metadata/catalog journeys and does
not require repeating CPU/NN or model-account qualification.

The publication grant includes the canonical PROJECT Hub metadata prefix. Its STS policy omits actions and listing entries already granted by a literal ancestor path; extra staging DELETE remains restricted to staging. Sibling prefixes remain independent, and the concrete 2048-byte STS policy ceiling is unchanged.

### Restricted catalog unpublish fixture

The real CLI/MCP and Web HTTP unpublish journeys use kind `skill` and the
concrete ids `fixture/web-file-reader` and `fixture/web-publication`. The producer
is the primary project from Start/Ready. The fixture adds a separate S3 Delete
grant with the two canonical SDK prefixes
`v1/projects/{project}/registry/skill/Zml4dHVyZS93ZWItZmlsZS1yZWFkZXI.json` and
`v1/projects/{project}/registry/skill/Zml4dHVyZS93ZWItcHVibGljYXRpb24.json`.
Each basename is base64url without padding of the complete UTF-8 artifact id,
matching SDK `remote_storage::registry_key`; the slash-separated id is not the
catalog basename. `{project}`
is resolved through the existing grant model for that primary project. No free
producer, path, prefix, operation, ACL or additional flag is accepted.

Native-only `start` grants it to the existing authenticated Native subject.
`start_web` grants it to both that Native subject and the real primary Web
writer only with `hub_storage_write:true`. It uses the same issuer and subjects
as their existing grants. With false or omission, no catalog Delete is added
in Web mode. The second Web identity and second producer gain no catalog Delete.
Read permissions, staging grants, final artifacts and metadata remain unchanged.

This uses the existing root-and-descendants prefix semantics: the root `.json`
key and descendants below that literal root are admitted. It is not an exact-key
policy. Other catalog keys, siblings, parents and other projects are outside this
additional grant. Productive NativeHubWrite or WebHubWrite admission, real SDK
publication/reseed and conditional If-Match deletion remain the consumer
requirements; deleting the reference does not delete its payloads or local caches.

For this fixture change, check the affected normal example build, formatting, whitespace and guide links. Real unpublish HTTP/CLI/MCP consumers and filesystem conditional-delete behavior have separate tests.

### Catalog policy size correction

The fixture uses the compact names above, replacing the empty initial random bucket and its private parent-policy bucket resources before Ready. The parent keeps the same actions and ARN shapes inside the same owned MinIO; no grant is removed or broadened and the STS limit/TTL/timeouts are unchanged. The second concrete item uses base `t` to keep both items within the same policy ceiling. Full-id encoded roots authorize the canonical SDK objects; shortened slash-id roots do not.

### STS response observation and sequential rearming

The private `hold_sts`, `await_sts` and `release_sts` commands retain the next
successful POST `/v1/s3/credentials` response for a controlled consumer race.
Each `hold_sts` creates fresh one-shot observation, release and completion
channels. A second hold is rejected while an arm or its retained response is
still active. Once the middleware retention finishes or its future is cancelled, the same
fixture can arm again; `release_sts` also cancels an arm with no retained response.
This completion marks the middleware retention, not network delivery. Shutdown
releases any retained response. The observation still has its existing
30-second timeout. A failed STS response is not reported as a successful hold.

The fast focused command is:

```text
cargo test --locked --offline -p broker-presence --example hub_storage_fixture fixture_refinement_ -- --test-threads=1
```

It checks canonical full-id keys, three sequential observations, overlapping
hold rejection, release before completion, cancellation and reuse. The real
Web HTTP consumer retains its three journeys within the same owned fixture;
these focused checks do not replace its STS and unpublish qualifications.
