---
title: Enable PROJECT authorization in the native Broker
doc_type: operations
references:
  - target: {type: task, id: tsk-5406, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5554, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-5df1, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Enable PROJECT authorization in the native Broker

For operators configuring the Rust `graphit-broker` executable. Add the following
section to the [native server configuration](rust-broker-server.md). These caps
and timeout are illustrative operator choices, not defaults:

```yaml
project_access:
  enabled: true
  required_scopes: []
  grants_json_bytes: 65536
  body_bytes: 4096
  request_timeout: 3s
```

All four settings after `enabled` are required when enabled. Scopes must be
nonblank and contain no ASCII space; an explicit empty list adds no scope
requirement. Byte caps must be positive and representable by the actual readers.
The timeout must be positive and fit a monotonic deadline. Unknown fields,
duplicate keys, missing settings and invalid values fail `--check-config`
before opening a pool, volume or socket. Omit the section or set
`project_access: {enabled: false}` to leave the route unmounted (404).

Run `graphit-broker --config config.yaml --check-config`, then start the server.
It mounts the existing JWT factory at `POST /v1/project/access/authorize`, using
the same PostgreSQL store and verifier as its other Broker JWT routes. The
configured `auth.issuer`, `auth.audience`, optional `auth.resource`, key and token
cap define trust. No request-derived trust, opaque authenticator fallback,
new token lifetime or implicit PROJECT grant is introduced.

Use the [HTTP contract](rust-broker-project-authorization-http.md) for exact input,
response and error details. A request names a canonical nonzero project ULID,
one of `task`, `memory`, `knowledge`, `ast` with `read` or `write`,
or `hub` with `read` only:

```json
{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"memory","action":"read"}
```

Authenticate with a signed Broker **access** token. The response contains the
verified literal issuer/sub, current authorization revision and authorized
operation. Neither username/raw LOCAL subject nor the API audience identifies
the project. A current SQL grant must match the signed principal, exact module
capability and project in the same rule. Each of the original eight Read/Write
pairs is independent: granting `memory:read` does not grant `memory:write`.
Hub read uses the existing literal `hub` capability and matching project.
Hub write returns 400; Knowledge and S3 grants do not substitute for Hub.

An authentic JWT without a matching grant returns 403. Removing a SQL grant
affects the next request while that JWT remains locally valid; restoring a grant
restores the permitted operation. Scopes and roles alone never authorize PROJECT.
Each success describes one decision, without a permission cache TTL or lease.
Invalid access tokens, ID tokens and untrusted issuers/keys/audiences return 401.
Missing required scopes return 403 `insufficient_scope`. Invalid request bodies
and unsupported methods retain the existing factory's finite errors and bounds.

The public `GET /v1/oidc/keys` endpoint exposes the configured public signing
key. Another service can obtain that JWKS and construct its verifier with its
explicit trusted issuer/audience/resource; request headers cannot select trust.
Key refresh/rotation policy belongs to that service's configuration owner.
The Broker route verifies locally, without a per-request JWKS or UserInfo call.

Qualification lives in `crates/broker-server/tests/project_access.rs`: actual
native binary, genuine LOCAL/P2b → HTTP P3 exchange, TLS PostgreSQL ordinary
owner, eight capabilities, read-only denial, live-JWT grant changes and a
distinct TCP consumer using the producer's public JWKS. Run:

```text
cargo test --locked -p broker-server --test project_access -- --ignored --exact broker_project_access_http_contract --test-threads=1
```

This activates PROJECT in the server. Inventory/realtime composition, Auth/Core
consumer integration, other OP/Admin journeys and full migration acceptance
remain their respective deliveries.

## Hub read for one project

POST the same endpoint with this body and an authenticated bearer:

```json
{"project_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV","module":"hub","action":"read"}
```

One current SQL rule must match the verified principal, capability `hub` and
that project. Missing membership or capability returns 403 even while the JWT
is valid. Separate rules cannot contribute different parts of the allow.
Removing the grant affects the next call; the response remains the existing
`subject`, `authorization_revision`, `project_id`, `module`, `action` shape.
A SQL hub rule with projects [] or * retains its existing Any-project meaning;
a separate Global Hub admission cannot replace this PROJECT decision.
This is logical PROJECT access for Hub source records; global Hub metadata
and S3 storage operations retain their separate admission. It does not by itself
qualify the Code LiveSource consumer or a complete OAuth Web session.
