---
title: Run the Rust Broker server
doc_type: operations
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-8069, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-0a57, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: supports
  - target: {type: task, id: tsk-64c6, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-f63f, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b289, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-e4cf, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-81df, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-f903, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-217b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b436, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5554, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-18f1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-b72e, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-f7f9, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Run the Rust Broker server

For operators and server integrators working on the Rust migration. Build the
`broker-server` package to produce the native `graphit-broker` executable:

```text
cargo build --locked -p broker-server --bin graphit-broker
graphit-broker --config config.yaml --check-config
graphit-broker --config config.yaml
graphit-broker --healthcheck http://127.0.0.1:8080/readyz
graphit-broker --version
```

Run the built executable from `target/debug` or install that binary in your PATH.
This storage server mounts `/healthz`, `/readyz`, `/v1/oidc/keys`,
`/v1/s3/credentials`, and the configured filesystem S3 buckets. Enabling the
native `oidc` section additionally mounts [authorization-code exchange](rust-oidc-token-exchange.md)
at `POST /oauth/token`, using genuine native LOCAL/P2b or [federated OAuth codes](rust-oidc-federated-grants.md), and
[native refresh rotation](rust-oidc-refresh.md) from its committed initial grants.
It mounts [explicit revocation](rust-oidc-revocation.md) at `POST /oauth/revoke` with the same
request/body/CORS settings; this does not add a JWT authentication lookup.
The [shared upstream callback](rust-oidc-browser-callback.md) is composed once for
configured browser clients, including OAuth with Administration disabled. It
uses the corresponding existing request timeout from arrival and an independent
flow cookie. The [public browser transport](rust-oidc-browser-authorization.md)
mounts GET/POST `/oauth/authorize` and `/oauth/login`, composing LOCAL stages,
request-owned recovery and upstream selection without an administrative cookie.
HEAD returns405 before effects; disabling OIDC leaves these routes404.
With `oidc.dynamic_registration: true`, [public dynamic registration](rust-oidc-registration.md)
also mounts `POST /oauth/register`; false leaves that route absent. Enabled OIDC publishes
[both discovery documents](rust-oidc-discovery.md), describing the configured public issuer
and productive endpoints. Remaining unmapped operations are not advertised. Enabled [native embeddings](#native-embeddings) publish their own service metadata. Enabling the explicit
[administration section](rust-admin-session-http.md) additionally serves
GET/HEAD `/admin/api/v1/session` and the seven [administrative reads](rust-admin-read.md), with native LOCAL JWT authentication and current
SQL authorization. The explicit [Cookie transport](rust-admin-cookie-session.md) adds a genuine LOCAL issuer, current cookie session read and confirmed CSRF/logout. The optional [native LOCAL login](rust-admin-local-login.md) mounts GET/HEAD `/admin/api/v1/login-options` and POST `/admin/auth/local` and `/admin/auth/local/continue`. Its enabled `auth.local.login` uses the [shared LOCAL runtime](rust-local-login-runtime.md), eligible with active Admin cookie transport or the native OIDC server. Only administrative LOCAL login requires its cookie; the runtime shares one password/MFA owner and drains KDF workers before SQL. The [native upstream browser adapter](rust-admin-upstream-login.md) serves the existing HTML and accepts `auth.oidc[].browser_clients`, with genuine begin/callback to H2 cookie issuance. [Native RBAC writes](rust-admin-rbac.md) and [resource-grant writes](rust-admin-grants.md) are mounted for PostgreSQL. [LOCAL user, MFA and service-credential writes](rust-admin-users.md) are mounted for PostgreSQL and the HTTP lifecycle. They share the configured password engine even with LOCAL login disabled, without enabling LOCAL authentication. Remaining OP endpoints, other backends and UI editors are outside this PostgreSQL administration qualification. The native [federated cookie consumer](rust-admin-federated-cookie.md) already uses the common issuer and current SQL authorization for session and administrative data reads.
Its explicit optional `administration.local_bearer` block also admits
[LOCAL opaque human access and service credentials](rust-admin-local-bearer-session.md)
with a separate configured audience, identity JSON cap and required scopes,
using the same current SQL session permission and preserving JWT trust.
Known nonempty cookies retain precedence without Bearer fallback.
With the explicit [project_access section](rust-project-access-http.md), the same
server also mounts POST `/v1/project/access/authorize` for locally verified
Broker access JWTs and current SQL PROJECT grants, with independent Read/Write
operations. JWT claims alone do not grant PROJECT access.
With the explicit [presence section](rust-presence-server.md), it also mounts
inventory and real HTTP1 WebSocket upgrades. Select `broker_jwt` for Native JWT
PUT/own GET/HEAD and realtime, or `local_opaque` for SQL access/service credentials
and the existing partial inventory LIST as well. Both modes use the same configured
SQL store and one owned realtime runtime; the server never guesses the mode.
Presence and PROJECT section Read grants remain independent.
Explicit PostgreSQL and private SQLite selection are implemented in this executable. First-administrator onboarding uses the explicit stdin command below. MySQL selection, model-setup and update commands remain outside this executable. Coordinated integration and release qualification remain separate migration work. The [native container and CI](deployment.md) now consume
this same executable; hosted publication and other platforms require their own evidence.

The native OIDC server exposes [explicit UserInfo profile retrieval](rust-oidc-userinfo.md) [Bearer-authorized token introspection](rust-oidc-introspection.md) and [ID-hint end-session](rust-oidc-end-session.md); JWT consumers continue local verification until expiry.

## Supply configuration and key files

Use the clean Rust YAML schema below. The earlier Go release schema is not
accepted or imported. Unknown fields, duplicate keys, extra YAML documents,
invalid durations and unsupported backends/drivers fail configuration. The
config file and expanded text each have a 4 MiB bound. Owned config text,
private-key bytes, pepper, password and static credential fields use zeroizing
storage; diagnostics report finite error categories and omit source values.

`--config` takes precedence over `GRAPHIT_BROKER_CONFIG`. Otherwise the native
home directory supplies `.graphit/broker/config.yaml`; `GRAPHIT_GLOBAL_DIR`
relocates that root. Key, CA and volume paths are relative to the YAML's parent;
absolute paths and `~/` are supported. Paths must be nonempty. Environment
expressions `${NAME}`, `${NAME:-fallback}` and `${NAME:?message}` expand before
typed YAML decoding. Unset/empty values use the documented fallback or cause
failure. The required-expression message is not echoed, because it may contain
sensitive text. Expanded YAML is never written into SQL.

Provide an Ed25519 PKCS8 **DER** file at `auth.pkcs8_file`, with operator-supplied
issuer, audience and key ID. The actual issuer SDK validates the bytes and
produces the public JWK used by the verifier. There is no generated product key,
pepper-derived signing key, Go fallback or per-request JWK network lookup. The
private signer is discarded after deriving configured verification trust when
OIDC exchange is absent/disabled. Enabled [code exchange](rust-oidc-token-exchange.md)
retains that same owner to sign access and ID tokens; there is no second key or
per-request key-file read. Its default access and ID lifetime is 10 minutes; storage credentials have their independent
one-hour default. Verification honors the actual JWT expiry and current SQL
authorization rather than inventing a lifetime clamp.

`--check-config` reads and validates the real configured key and CA files,
typed database settings and active route constructors. It creates no SQL
schema, pool, volume or listening socket, and performs no network request.
It cannot prove that SQL storage is reachable/writable, volumes are writable/unowned,
the listener can bind or AWS will allow AssumeRole; normal startup checks those
dependencies as they are used.

The following explicit budgets are illustrative operator choices, **not hidden
server defaults**. Replace addresses, paths, issuer/audience and bounds with your
deployment's values. Supply secrets through your secret-management environment
or configuration file. Existing SQL grants and local tokens must be provisioned
by their owning identity/authorization services, using the same configured pepper.

```yaml
server:
  address: 127.0.0.1:8080
  public_url: https://broker.example.test
database:
  backend: postgres
  host: postgres.example.test
  port: 5432
  database: graphit
  username: graphit_owner
  password: "${BROKER_DATABASE_PASSWORD:?required}"
  ca_file: postgres-ca.pem
  text_bytes: 256
  ca_bytes: 8192
  pool:
    max_connections: 2
    min_connections: 0
    statement_cache_capacity: 0
    connect_timeout: 8s
    acquire_timeout: 5s
    operation_timeout: 8s
    startup_timeout: 15s
    shutdown_timeout: 2s
    max_lifetime: 60s
    idle_timeout: 30s
    statement_timeout: 10s
    lock_timeout: 10s
    idle_transaction_timeout: 15s
  flows:
    provider_bytes: 128
    request_bytes: 128
    continuation_bytes: 512
auth:
  issuer: https://broker.example.test
  audience: storage-api
  kid: configured-key
  resource: https://broker.example.test/v1
  pkcs8_file: signing.pk8
  key_bytes: 8192
  pepper: "${BROKER_PEPPER:?required}"
  digest:
    pepper_bytes: 256
    token_bytes: 8192
    binding_bytes: 256
    subject_bytes: 256
    recovery_bytes: 256
storage:
  enabled: true
  required_scopes: []
  request_timeout: 10s
  sts_timeout: 5s
  identity_json_bytes: 8192
  grants_json_bytes: 65536
  head_bytes: 16384
  token_bytes: 8192
  metadata_bytes: 65536
  routes:
    native-fs:
      driver: filesystem
      bucket: native-storage
      base_prefix: graphit
      directory: volumes/native-storage
```

For `database.backend: postgres`, endpoint,
credentials, CA file, pool, flow and digest budgets are mandatory. CA parsing
uses rustls; connection verification uses the actual PostgreSQL store's pinned
WebPKI roots **plus** the supplied CA, hostname verification and VerifyFull TLS.
The supplied CA is additive, not an exclusive trust store. Plaintext and hostname
bypass are unavailable. The store rejects ambient PostgreSQL connection variables
at startup and bypasses pgpass; see [PostgreSQL persistence](rust-postgres-control.md).

## Defaults and route validation

The server defaults are `0.0.0.0:8080`, read/body inactivity 15s, write/body
inactivity 60s, socket read inactivity 120s, shutdown 15s and JSON credential body
4 MiB. Override `server.read_timeout`, `write_timeout`, `idle_timeout`,
`shutdown_timeout` and `body_bytes` explicitly. Durations are positive strings;
an explicit zero is invalid. HTTP1 header-read timeout is 5s. Hyper, Tokio IO
timeouts and tower-http body timeouts implement these operations; successful
frames/operations reset their inactivity timers and trailers remain frames.
The gateway separately enforces each filesystem request's configured Original.
There is no outer handler timeout that abandons a mutator future.

`server.public_url` is mandatory: an HTTPS origin without userinfo, path, query
or fragment, or HTTP on loopback/localhost. The listener itself serves HTTP1;
terminate public TLS at the deployment's reverse proxy. The public URL supplies
an omitted filesystem endpoint. Configure the proxy's upload limits/timeouts
for the actual object size. The credential JSON limit is not a filesystem upload
limit; filesystem objects default to 5 GiB per route.

Routes are a deterministic map with unique names. A single route becomes
`storage.default_route`; multiple routes require an explicit configured default.
The actual SQL grant can select another configured route. Missing routes or
provider errors do not cause retry/fallback to another driver.

For a filesystem route, `bucket`, `base_prefix` and `directory` are mandatory.
Region defaults to `us-east-1`, `session_duration` to `1h`, endpoint to public
URL and `max_object_bytes` to 5368709120. Bucket names must be distinct and cannot
collide with reserved API roots. Token bytes must fit the configured head bound.
AWS role, STS endpoint, key pair, session name, `conditional_delete` and loopback-transport fields are
invalid on filesystem routes.

For S3 routes, `conditional_delete` is a boolean with a safe default of false.
Set it to true only when the backend atomically enforces `If-Match` on DELETE;
the server does not infer support from AWS/MinIO names or endpoints and does not
probe it. The redacted administrative configuration includes the effective boolean.
The required STSv3 response field carries this capability, which does not grant
permission. Filesystem always emits true from its native implementation and
rejects this S3 configuration option, including when storage is disabled.
The required `copy_if_not_exists` wire strategy is fixed by the issuer: `multipart`
for S3 or `if_none_match` for Filesystem. It selects an existing SDK copy operation,
adds no configuration option and is independent of the DELETE capability.
See the [wire contract](rust-hub-storage-credentials-http.md#conditional-delete-capability).

For AWS, an omitted `driver` means `s3`. Supply `bucket`, `base_prefix` and
`role_arn`; region defaults to `us-east-1`, session name to `graphit-broker`, and
duration to `1h`. Optional `endpoint`/`sts_endpoint` configure SDK endpoints;
HTTPS is required unless `allow_loopback_http: true` explicitly enables HTTP
on loopback for local services. Provide both `access_key_id` and
`secret_access_key`, or neither to select the mature AWS credential chain.
Filesystem directory/object-size fields are invalid. See [AWS issuance](rust-hub-storage-aws.md)
for actual bounds and policy construction. No credential chain is fetched while
checking config. Enabled routes are validated before startup effects.

With `storage.enabled: false`, the strict schema and incompatible-field checks
still apply, but inactive issuer/volume topology is not opened. The credentials
endpoint returns 404 before authentication or body decoding, and filesystem
bucket routes are absent.

## Create the first LOCAL administrator

Merge the explicit [LOCAL password/MFA configuration](rust-admin-local-login.md) and enabled
[administrative cookie configuration](rust-admin-cookie-session.md) before bootstrapping. Their
configured limits and `auth.pepper` are reused; the command does not silently enable features.
It works with the selected PostgreSQL or private SQLite backend:

~~~text
cat /run/secrets/broker-first-admin-password | graphit-broker --config config.yaml --bootstrap-admin-stdin
~~~

This explicit mode accepts only non-terminal stdin through EOF. Supply 15 or more Unicode
characters within 4096 UTF-8 bytes; exactly one final LF or CRLF is removed, with spaces preserved.
Invalid input fails before password workers or SQL. The native executable has no interactive
`--bootstrap-admin` mode. The temporary password never belongs in argv, an environment variable,
output or a qualification receipt.

The configured startup Original begins after input capture and bounds password preparation,
hashing, SQL startup and the atomic first-user transaction. The command serializes with current
administrative writers, requires an empty local-user table, and creates only the ordinary enabled
human `admin` plus `local|admin`'s `admin` assignment. It leaves
`password_change_required=true`. No listener, volume, MFA enrollment, session, token or resource
grant is created. Password workers and SQL drain physically before return, under the existing
shutdown budget; a committed write is never changed to a pre-commit timeout by a later clock read.
The PostgreSQL pool retains its close future until acquired connections return, even if the
shutdown Original is already expired or expires during the drain.

Start the server and use `/admin/` to change the temporary password. MFA enrollment follows the
explicit `auth.local.mfa.required` policy, including `false`. See
[first administrator and recovery](administration.md#first-local-administrator) for precise framing,
configuration prerequisites, concurrent/repeated attempts and uncertain outcomes.

## Select private SQLite

Replace the complete database mapping in the example above with this explicit
native mapping:

~~~yaml
database:
  backend: sqlite
  path: private/broker.db
  startup_timeout: 10s
  operation_timeout: 4s
  shutdown_timeout: 3s
  flows:
    provider_bytes: 128
    request_bytes: 1024
    continuation_bytes: 4096
~~~

These durations are operator choices, not defaults. All three are mandatory,
positive and representable by the monotonic clock. SQLite has no host, password,
CA or pool fields; cross-backend fields are rejected. Expansion uses the same
explicit YAML expressions as the PostgreSQL example. Relative paths resolve
against the configuration file's directory; a configured ~/ prefix resolves
against the current user's home. Empty paths, connection URIs and in-memory
forms are rejected before resolution. Check-config opens no SQL, volume or
listener.

The [SQLite owner](rust-sqlite-control.md) creates private directories/files and
checks existing parent, database and sidecars without repairing permissions.
On Windows an existing database directory must grant private access to the
current user and inherit that same access for files created by SQLite.
Use a local filesystem with correct locking and one deployment-owned database.
Its exact format is rust-broker-v1 epoch 2; an incompatible database fails startup
without import, reset or schema conversion. Stop all owners and preserve backups
and deployment credentials before any explicit replacement of disposable data.

The same enabled Administration, LOCAL, upstream, OP, PROJECT, Hub, storage,
inventory/Now and embeddings sections select their real SQLite factories.
Administrative configuration reads expose only backend, resolved path, the three
budgets and flows for SQLite. No PostgreSQL secret, CA or dummy pool is added.
Selecting the backend does not provision users or grant authority. Use the explicit
[first-administrator command](#create-the-first-local-administrator) with operational LOCAL and
administrative cookie configuration when the local-user table is empty.

A single startup Original covers started owners and readiness requires a live
listener within that Original. Partial failures close started owners. Signal
shutdown closes admission and joins HTTP/FS/Now and the password engine before
SQL, retaining physical SQLite close after deadline expiry and preserving the
deadline error. Volumes remain owned until those joins finish.

Run the focused SQLite Server process target with:

    cargo test --locked --offline -p broker-server --test sqlite_server
    cargo test --locked --offline -p broker-server --test sqlite_server -- --ignored --test-threads=1

The ignored target is selected by the existing SQLite pre-push phase. A Linux
run does not qualify Windows/macOS signals, filesystem policy or runtime.

## Requests, startup and shutdown

`POST /v1/s3/credentials` accepts one sensitive Authorization Bearer header.
`gb_at_` and `gb_sc_` envelopes go directly to the current local SQL factory;
all other envelopes go directly to the configured JWT verifier and SQL grant
factory. Failed authentication never tries another authority. Both paths use
one captured Original, authenticate before decoding the strict JSON body, and
produce the existing [credential wire response](rust-hub-storage-credentials-http.md)
with `Cache-Control: no-store`. Public `/v1/oidc/keys` contains only verification
JWKs, without private `d` material. Enabled OIDC discovery points to this same key owner.

Startup opens the selected SQL backend, initializes its native schema, opens each owned
filesystem volume once, constructs exact gateways and routes, then binds the
listener and reports ready. A partial-volume or bind failure closes initialized
resources and releases volume owners; this does not roll back created directories
or a successful schema transaction. Fix the reported dependency and restart.

On SIGINT/SIGTERM, the binary clears readiness, drops the listening socket,
closes filesystem admission/cancels its tracked work and asks Hyper to close
owned HTTP connections. One shutdown Original governs these bounded operations.
On deadline, it closes and joins its own HTTP tasks and still joins retained
filesystem IO using the existing tracker, preserving the original timeout as an
error. Only then does it close the SQL pool and release volumes. Native IO may
take longer than the deadline to finish; there is no kernel-interruption or
filesystem rollback guarantee. HTTP1 upgrades are enabled;
enabled Presence also owns upgraded WebSocket connections and maintenance. Its
explicit shutdown closes admission and joins that runtime before closing SQL. If
the Original expires, the already started shutdown future is retained and drained;
the deadline is not renewed and the timeout remains an error. The runtime Drop
fallback cancels/aborts work and does not establish a completed join.

`/healthz` returns `{"status":"ok"}`. `/readyz` returns
`{"status":"ready"}` after bind; during shutdown, an already owned connection
can observe 503 `{"status":"not_ready"}`. The CLI healthcheck makes one actual
HTTP(S) GET with a five-second timeout, follows no redirects and exits nonzero
on network/non-success status.

For an independently managed local Linux process, the [user-service deployment
procedure](deployment.md#local-linux-user-service) uses this same foreground
entrypoint and signal handling. Prepare the stable executable and validate the
unit/configuration first; coordinate the old process's shutdown/join before
starting its replacement with the existing database, keys and configuration.
Unit verification and `--check-config` do not establish service startup, login or
reboot behavior. The readiness healthcheck belongs after the coordinated start.

## Verification

```text
cargo test --locked --offline -p broker-server --all-targets
cargo test --locked --offline -p broker-server --test startup -- --ignored --exact broker_storage_server_startup_contract --test-threads=1
```

Ordinary tests validate the strict loader/defaults and actual CLI without opening
dependencies. The focal ignored fixture supplies Docker PostgreSQL TLS with a
NOSUPERUSER owner, actual PKCS8/config files and the actual executable. It checks
JWT/access/service ingress on one URL, mature FS SDK IO above the JSON cap,
denials, configuration/bind/volume/TLS failures, signal shutdown during native
temp IO with both normal and expired shutdown Originals, socket closure, temp cleanup, volume reownership and restart. The
existing filesystem S3 protocol suites retain their independent qualification.
The [Presence composition guide](rust-presence-server.md) supplies the focused
native binary HTTP/WS test command and both authentication examples. That test
also exercises SQL authorization/masks, registry and credential changes, opaque
LIST, live WebSocket signal shutdown/restart and existing PROJECT/Admin routes.
Linux process/signal execution does not establish Windows/macOS qualification.
Server source lives in `crates/broker-server/src/{config,runtime,main}.rs`; the
composed handler in `crates/broker-presence/src/storage_credentials.rs` consumes
existing authorities and [storage service](rust-storage-credentials-service.md).

The common `auth.oidc` set can admit [federated administrative resource JWTs](rust-admin-upstream-session.md) through the mounted session endpoint, with explicit issuer/audience/access-profile/claim/cache/TLS limits and current SQL system permissions. Configured `browser_clients` additionally enable the [native administrative browser journey](rust-admin-upstream-login.md) with active cookie transport. Alternatively, enabled native OIDC accepts the same
browser-client configuration for [federated OAuth grants](rust-oidc-federated-grants.md)
without requiring administration. The token runtime reuses this verifier; browser
[Public authorize/login](rust-oidc-browser-authorization.md) and the shared OAuth
callback are implemented; [discovery](rust-oidc-discovery.md) advertises those productive routes.

## Native embeddings

Local GGUF staging uses the privately captured installation `<global>/tmp`, selected by `GRAPHIT_GLOBAL_DIR` or the native home `.graphit` directory even when `--config` points elsewhere. This infrastructure path is separate from bundle paths, administrative views, model identity and request inputs. Only an enabled local GGUF service prepares it. See [local model residency and staging](models.md#local-gguf-models).

Enable `services.embeddings` in the native Rust configuration to compose `POST /v1/embeddings` with current SQL capability authorization, a captured HTTP or GGUF provider, and durable SQL cache. The request accepts only `input` and `input_type`; unknown `model` and `route` fields are rejected. Each request, including a cache hit, independently authorizes the literal `embeddings` capability. Project selectors do not restrict this capability. Invalid credentials cannot become anonymous.

The following bounds are explicit example choices. Required byte/transport bounds have no implicit defaults. Omitted or zero `max_batch` means 256, omitted or zero `max_input_bytes` means 1 MiB, and omitted `request_timeout` means 45 seconds. This one timeout bounds the whole request and is further shortened by genuine authentication expiry. `upstream.timeout`, RAM-cache settings and client-selected model/route fields are outside this strict schema.

```yaml
services:
  embeddings:
    enabled: true
    revision: embedding-space-v1
    dimensions: 1536
    max_batch: 256
    max_input_bytes: 1048576
    request_timeout: 45s
    required_scopes: []
    request_body_bytes: 2097152
    response_body_bytes: 16777216
    identity_json_bytes: 65536
    grants_json_bytes: 1048576
    vector_json_bytes: 65536
    metadata_bytes: 8192
    upstream:
      protocol: openai-embeddings-v1
      model: text-embedding-3-small
      model_revision: deployment-2026-10-20
      recipe: openai-document-query-v1
      url: https://api.openai.com/v1/embeddings
      api_key: "${OPENAI_API_KEY:?required}"
      send_dimensions: false
      transport:
        request_body_bytes: 4194304
        response_body_bytes: 16777216
        url_bytes: 8192
        header_bytes: 32768
        header_count: 128
        max_in_flight: 16
        max_idle_per_host: 16
        idle_timeout: 60s
        max_certificates: 32
        max_certificate_bytes: 1048576
        allow_loopback_http: false
```

HTTP protocols include the existing OpenAI, Cohere, Voyage and Google aliases. An HTTP provider needs a nonempty service `revision`, model and positive dimensions. `upstream.model_revision` and `upstream.recipe` are required, exact declarations of the deployed model revision and query/document recipe; replace the example deployment values with real values. They are neither synthesized hashes nor provider attestations. Changing either separates cached vectors. For local GGUF, these two overrides are rejected: the manifest supplies model revision and the declared model/execution identity supplies the recipe identity. The key is optional; a configured key uses `Authorization: Bearer` by default, or `x-goog-api-key` without a scheme for Google. `api_key_header` and `api_key_scheme` may override those values; framing headers and malformed values fail configuration. `transport.ca_file` captures optional PEM roots. Redirects, ambient proxies and automatic retries are disabled by the mature bounded client. The administrative configuration projection replaces the key with `[configured-secret]`.

For local EmbeddingGemma2, retain the service-level bounds and replace only `upstream` with a provisioned GGUF bundle:

```yaml
    upstream:
      protocol: gguf-embeddinggemma2
      model: embeddinggemma2
      directory: models/embeddinggemma2
      manifest_file: models/embeddinggemma2/model.json
      max_artifact_bytes: 600000000
      device: cpu
      device_id: 0
      threads: 2
      queue_capacity: 8
      manifest_limits:
        max_manifest_bytes: 1048576
        max_artifacts: 32
        max_role_bytes: 128
        max_relative_path_bytes: 4096
        max_id_bytes: 128
        max_revision_bytes: 256
        max_dimension: 768
        max_tokens: 8192
```

Bundle and manifest paths resolve against the configuration file. The shared typed `ModelManifest` decoder validates task and recipe at configuration time; the first valid uncached request verifies contained artifact paths/digests and loads the native worker. Model ID must match the manifest; omitted/zero dimensions derive from the recipe and positive dimensions assert equality. HTTP settings and model revision/recipe overrides are rejected. Service revision includes the verified manifest/execution identity.

CPU is the default; explicit CUDA or Metal must register successfully. Metal requires macOS and device ID zero. Auto reports the actual accelerator or CPU fallback. Threads default to half the available logical CPUs, rounded up. The queue bounds pending requests. The administrative view reports actual device registration, not proof of GPU placement on untested platforms.

Query/document prefixes belong to the mature provider or manifest. SDK input budgets include the maximum per-item prefix with checked arithmetic while the public limit continues to count literal UTF-8 input. Cache entries store hashes and validated vectors, never input text or credentials; `max_entries` is the request batch bound, with no SQL TTL or corpus quota. Complete cache hits omit unobserved usage. Valid siblings from a complete provider response may be persisted even when the HTTP request fails as a whole.

Enabled discovery publishes `services.embeddings` with the public protocol `graphit-embeddings-v1`, path, model, declared model revision, effective recipe, service revision/dimensions and input limits. With OIDC disabled, the Graphit document publishes this service without inventing OpenID endpoints. Disabled embeddings return `404 capability_disabled`, initialize no provider/cache, and publish no service. Shutdown stops inference admission before HTTP drain and retains the provider until cancelled native requests have joined, before SQL closes.

The maintained checks cover HTTP/SQL behavior and real local GGUF consumers with explicit provisioned bundles, including authorization, cache persistence, first-use integrity rejection and worker shutdown. Linux CPU execution does not establish GPU or Windows/macOS execution. See the [embedding service contract](rust-embeddings.md) for component-level behavior and bounds.

## Native rerank

The native `services.rerank` composition supports PostgreSQL/SQLite Broker executables and the Code rerank SDK consumer. Local rerank uses the typed GGUF manifest and provisioned BAAI/bge-reranker-v2-m3 F16 bundle through the shared paired rank classifier. It remains opt-in. There is no automatic download or cosine fallback. CPU qualification does not establish GPU or other-platform support. See the [HTTP contract](api.md#rerank) and [current SQL admission](authorization.md#native-rerank-sql-admission).

This native fragment selects an already deployed Graphit service. Replace its
endpoint and revision with actual deployment values. Requests cannot select a model.

```yaml
services:
  rerank:
    enabled: true
    revision: rerank-route-v1
    max_documents: 1000
    max_document_bytes: 1048576
    max_batch: 200
    request_timeout: 45s
    required_scopes: []
    request_body_bytes: 2097152
    response_body_bytes: 1048576
    identity_json_bytes: 8192
    grants_json_bytes: 1048576
    cache:
      ttl: 5m
      max_entries: 1000
    upstream:
      protocol: graphit-rerank-v1
      model: deployed-reranker
      model_revision: deployment-2026-10-20
      recipe: deployed-native-rerank-v1
      service_revision: upstream-rerank-route-v3
      max_documents: 200
      url: https://rerank.example.invalid/v1/rerank
      transport:
        request_body_bytes: 2097152
        response_body_bytes: 1048576
        url_bytes: 8192
        header_bytes: 16384
        header_count: 64
        max_in_flight: 8
        max_idle_per_host: 4
        idle_timeout: 30s
        max_certificates: 8
        max_certificate_bytes: 1048576
```

`max_batch` and HTTP/SQL bounds are explicit. Omitted `max_documents`,
`max_document_bytes` and `request_timeout` retain defaults 1000, 1 MiB and 45s.
Omitted cache settings retain five minutes and 1000 entries; zero TTL or
zero entries disables response caching. Cache never supplies authority.

Native remote protocols are `cohere`/`cohere-v2`, `jina`/`jina-v1`,
`voyage`/`voyage-v1` and `graphit-rerank-v1`. Provider protocols require a
configured model. Graphit upstream configuration declares its deployed `model`,
`model_revision` and `recipe` for provenance; its wire still omits model selection.
Graphit upstream additionally requires its own `upstream.service_revision` and
positive `upstream.max_documents`, pinned from that deployed service's discovery
descriptor. These are not the outer Broker's `revision` or `max_documents`.
The typed SDK splits upstream batches by the declared upstream maximum and rejects
responses whose model, model revision, recipe or service revision differs from the
pinned descriptor. Deployment configuration supplies the endpoint and metadata;
startup does not invent a revision or perform another discovery request. The
upstream-only fields are rejected for other protocols.
All remote protocols require those exact declarations. For local GGUF rerank, the manifest
and declared execution identity supply the values; overrides are rejected. Discovery
and the response `graphit` object publish the same identity alongside the distinct
service `revision`, and these fields separate the response cache. Cosine adapters accept
`openai`, `openai-compatible`, `openai-embeddings-v1`, `cohere-embed-v2`,
`voyage-embeddings-v1`, `google`/`google-embed-content-v1beta` and
`gemini`/`gemini-embed-content-v1beta`, with explicit `dimensions`.
`send_dimensions` is an optional embedding-provider setting. Native scoring
rejects embedding dimension settings.

Optional `api_key`, `api_key_header` and `api_key_scheme` use the established
bounded transport and header validation. Admin configuration redacts the key.
Framing/routing headers cannot be used as key headers. Insecure HTTP needs
explicit loopback permission; custom CA inputs use bounded certificate parsing.

For `protocol: gguf-bge-reranker-v2-m3`, supply model `bge-reranker-v2-m3`, a provisioned `directory`, `manifest_file`, `max_artifact_bytes` and the manifest bounds shown above. The manifest runtime is `gguf-bge-reranker-v2-m3`; its BGE recipe declares embedded XLM-R query/document pairs, rank pooling, F16 weights, a single output and raw-logit or sigmoid scores. No external runtime library is configured. CPU/CUDA/Metal/auto, thread and queue settings follow the embedding worker contract independently. Local configuration rejects HTTP settings and revision/recipe overrides. [Local models](models.md) describes provisioning and lifecycle.

Discovery advertises enabled rerank protocol/path/revision/`max_documents`.
Disabled rerank does not open its provider/model or appear in discovery;
POST returns `404 capability_disabled`. Both AI services share one document. Local weights load only on a valid uncached request. `upstream.idle_timeout_seconds` is positive, defaults to 300 seconds, and measures time since completed native inference. Idle cleanup joins the worker before releasing model/context/staging, and the next use reloads with the same identity. Cache hits do not reset residency.
The local reranker reads, verifies, stages and loads its weights on the first valid
uncached request, using that request's original context. Before that, discovery and
configuration checks use bounded manifest declarations only. An unavailable asset
or requested device fails first use. Normal shutdown, partial-startup cleanup and
administrator bootstrap stop admission, wait for initialization/inference and join
an existing worker; an unused reranker is not loaded for shutdown.

After inference, genuine SQL identity/grants are read again before response/cache
publication. Both the initial authentication cutoff and fresh admission remain
checked. Revocation during computation denies publication. Local CPU retains
its existing per-batch context and physical cancellation/join, without a new
per-CPU callback.
