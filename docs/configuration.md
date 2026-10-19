---
references:
  - target: {type: task, id: tsk-ea46, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-170b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-4645, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
---

# Configuration reference

The native Rust executable accepts the strict schema in the [server runbook](rust-broker-server.md#supply-configuration-and-key-files). Unknown fields, duplicate keys, multiple YAML documents, invalid durations and incompatible options fail before readiness. The file and expanded document each have a 4 MiB bound. Configuration is deployment-owned and is never imported from an earlier schema or stored in SQL.

Start with [config.example.yaml](../config.example.yaml) for explicit PostgreSQL and filesystem storage, or [health-only.yaml](../examples/health-only.yaml) for private SQLite with services disabled. These examples make operator choices; they do not establish defaults. Supply signing key, CA and required secrets before running the executable.

```text
graphit-broker --config config.yaml --check-config
```

Check-config validates keys and configuration without opening SQL, volumes or a listener. Local models validate bounded manifests; weights are read and loaded only on the first valid uncached request. Configuration changes require restart. The administrative configuration endpoint is a redacted read-only view, not an import format.

Environment expressions `${NAME}`, `${NAME:-fallback}` and `${NAME:?message}` expand before typed decoding. Names in examples are YAML choices, not implicit secret sources. Paths resolve against the configuration file's parent; absolute paths and a leading `~/` follow the native path rules. An explicit `--config` takes precedence over `GRAPHIT_BROKER_CONFIG`; otherwise the native home supplies `.graphit/broker/config.yaml`, relocated by `GRAPHIT_GLOBAL_DIR`.

## Database

Select `database.backend: postgres` or `sqlite` explicitly. PostgreSQL uses separate host/port/database/username/password/CA fields and explicit pool, SQL and lifecycle budgets. SQLite uses a private file path, explicit startup/operation/shutdown budgets and flow limits. Connection URIs, in-memory SQLite paths, cross-backend fields and incompatible schemas are rejected. See [database backends](database.md) and the [complete mappings](rust-broker-server.md#select-private-sqlite). MySQL Control libraries remain separately qualified; the server does not select MySQL.

## Server

Configure bind address and public URL separately. Native OIDC requires `auth.issuer == server.public_url` byte for byte, including case, trailing slash and explicit port. HTTPS is required for public issuers, with the documented loopback HTTP exception for development. Use a TLS reverse proxy in production. [OIDC discovery](rust-oidc-discovery.md) publishes the accepted configuration without injecting a resource. Configure `oidc.accepted_resources` explicitly when a consumer derives its resource from the endpoint. Empty is valid; empty, padded and duplicate items are rejected.

The runbook describes HTTP/body and shutdown settings. `/healthz` reports liveness; `/readyz` becomes ready after startup and is cleared during shutdown. The native `--healthcheck URL` command rejects credentials/fragments, follows no redirects and has a bounded HTTP timeout.

## Authentication

The `auth` mapping supplies issuer, audience, key ID, explicit Ed25519 PKCS8 file, key byte cap, pepper and digest limits. The signing key is independent of the pepper. Keep both in deployment secret management. SQL stores credential proofs and lifecycle state, not raw configuration or passwords.

Enable the closed `auth.local` policies for [LOCAL password/MFA login](rust-admin-local-login.md). The shared password engine provides bounded KDF work, rate admission, CAPTCHA and MFA; its owner drains before SQL. The [first-administrator command](rust-broker-server.md#create-the-first-local-administrator) reads protected non-terminal stdin and creates the first LOCAL administrator atomically; it does not serve HTTP or mint a login session.

Configure upstream issuers under `auth.oidc` for [federated bearer](rust-admin-upstream-session.md) and [browser authentication](rust-admin-upstream-login.md). Claims selectors and explicit browser clients use mature verification and current SQL policy. An upstream username never maps to a LOCAL account. Native `oidc` enables the Broker OpenID Provider, [authorization](rust-oidc-browser-authorization.md), [code exchange](rust-oidc-token-exchange.md), [refresh rotation](rust-oidc-refresh.md), [discovery](rust-oidc-discovery.md) and the remaining documented endpoints.

## Administration

The optional `administration` section requires explicit identity/profile/role/row/grants/response limits and request budget. Its [session read](rust-admin-session-http.md), [reads](rust-admin-read.md), [RBAC writes](rust-admin-rbac.md), [grant writes](rust-admin-grants.md) and [LOCAL user/service-credential writes](rust-admin-users.md) use current SQL authorization. [Cookies and CSRF/logout](rust-admin-cookie-session.md) require their explicit transport policy. [LOCAL opaque/service bearer](rust-admin-local-bearer-session.md) has its own audience, identity cap and scopes; a known nonempty cookie retains precedence. The configuration view redacts secrets.

Configure [PROJECT authorization](rust-project-access-http.md) and [Presence/Now](rust-presence-server.md) in their independent sections. Presence requires an explicit authentication selector, bounds, budgets and grants; selecting a database does not select an authentication mode or grant authority.

## Local GGUF upstreams

Use the typed manifest and explicit provisioned GGUF bundle described in [local models](models.md). EmbeddingGemma2 and BGE reranker v2-m3 F16 use the shared native workers. Model ID and manifest must match. No runtime-library selection, automatic download or model substitution occurs. Invalid declarations fail before readiness. Both models check their artifacts and requested devices on first use. Local `upstream.idle_timeout_seconds` is positive and defaults to 300 seconds; the owner unloads after completed inference becomes idle, with no change to identity and no interruption of in-flight work. Disabled services do not open a model.

## Embeddings

Use the [native embeddings schema](rust-broker-server.md#native-embeddings) for HTTP/GGUF protocol, dimensions, batch/input/body/identity/grants/transport bounds and one request budget. The SQL cache stores vectors under compatible input/effective-model identities. Current capability authorization is checked even on a full hit; embedding authority is separate from rerank.

## Rerank

Use the [native rerank schema](rust-broker-server.md#native-rerank) for native Cohere/Jina/Voyage/Graphit scoring, supported embedding-based cosine adapters or local GGUF. Select providers/models explicitly; Graphit upstream omits caller model selection and pins its own `service_revision`, `model`, `model_revision`, `recipe` and positive `max_documents` in the upstream configuration. Upstream service revision and document maximum are independent of the outer Broker's values. Cosine requires dimensions; native scoring rejects embedding dimension settings. Enabled metadata appears in combined discovery. Requests, responses and private in-memory caches remain bounded, with original authentication expiry and genuine SQL reauthorization before publication. See the [HTTP contract](api.md#rerank).

## Storage credentials

The native `storage` mapping selects routes, required scopes and request/STS/identity/grants/head/token/metadata limits. Current SQL grants remain required for issuance. See [storage configuration](rust-broker-server.md) and [authorization](authorization.md).

### The `s3` driver

An external route configures bucket, prefix, region, role and optional endpoint/credential source. The mature AWS SDK issues restricted STS credentials under the original budget. Keep source credentials in secret management. Issued credentials retain their bounded policy until expiry or platform revocation. A failing route never silently changes authority.

### The `filesystem` driver

A filesystem route selects bucket, safe prefix and deployment-owned volume directory. Relative directories resolve against the YAML parent. The server serves the [native S3 gateway](rust-filesystem-s3-gateway.md) with real SigV4, object/range/list/multipart and conditional publication behavior. Keep volumes persistent and private; the runbook defines object/session limits and lifecycle. SQL authorization, issued credentials and volume remain separate. A filesystem route does not start a MinIO fallback.
