---
title: Enable inventory and realtime in the native Broker
doc_type: operations
references:
  - target: {type: task, id: tsk-1e9b, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: relates_to
  - target: {type: task, id: tsk-b436, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: implements
  - target: {type: task, id: tsk-adca, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
  - target: {type: task, id: tsk-e381, scope: project, scope_id: 01KSH1CRFFG8Z74B5ZS78WW808}
    relation: uses
---
# Enable inventory and realtime in the native Broker

For operators starting the Rust `graphit-broker` executable. Add this section to
the [native configuration](rust-broker-server.md). Every setting shown is required
when enabled; these values are illustrative operator choices, not defaults:

```yaml
presence:
  enabled: true
  authentication:
    type: broker_jwt
  heartbeat_timeout: 30s
  broadcast_capacity: 32
  publish:
    required_scopes: []
    grants_json_bytes: 65536
    body_bytes: 65536
    request_timeout: 3s
  read:
    required_scopes: []
    grants_json_bytes: 65536
    inventory_json_bytes: 65536
    request_timeout: 3s
  realtime:
    required_scopes: []
    grants_json_bytes: 65536
    inventory_json_bytes: 65536
    command_bytes: 65536
    outbound_bytes: 65536
    operation_timeout: 3s
```

Select exactly one authentication mode. `broker_jwt` uses the existing explicit
`auth.issuer`, `auth.audience`, optional resource, configured key and token cap.
It serves [Native PUT/own GET](rust-broker-instance-inventory-http.md) at
`/v1/instances/{id}/inventory` and [WSv1](rust-realtime-ws.md) at `/v1/realtime`.
HEAD follows own GET. It does not add a Native LIST endpoint.

To use current opaque LOCAL access or service credentials, replace only the
`authentication` map above with this explicit map; retain the publish/read/realtime
and heartbeat/broadcast settings. Audience, identity cap and independent LIST
settings are required for this mode:

```yaml
  authentication:
    type: local_opaque
    audience: opaque-presence
    identity_json_bytes: 8192
    list:
      required_scopes: []
      grants_json_bytes: 65536
      inventory_json_bytes: 65536
      query_bytes: 4096
      request_timeout: 3s
```

This mode uses the qualified [opaque registry/own-read composition](rust-instance-inventory-read-http.md),
including [partial authorized LIST](rust-instance-inventory-list-http.md) at
`GET /v1/instances`, and the explicit opaque WS factory. There is no credential
format probing, fallback authenticator, subject conversion or inferred audience.
A token for the other mode fails authentication. Inventory owners retain the
literal identity of their original mode; selecting another mode does not convert
or import that registration.

Scopes and SQL grants are separate. An explicit empty scope list adds no scope
requirement; it never grants Presence or PROJECT permission. Publish requires
Presence Publish for **all** registered projects; own GET requires Presence Read
for all projects and the matching literal owner. Empty inventory requires an
explicit Any grant. Opaque LIST preserves its partial authorized view.

Byte caps must be positive and fit their actual SDK/SQL readers. Budgets must be
positive and representable. Heartbeat also must fit the wall clock; broadcast
capacity must fit Tokio's supported range. Unknown fields, duplicate keys,
missing/mixed authentication settings and invalid caps/timing fail
`--check-config` before pool, volume, socket or realtime task creation.
Omit `presence`, or use `presence: {enabled: false}`, to leave these routes
unmounted (404) and create no realtime owner.

Validate with `graphit-broker --config config.yaml --check-config`, then run the
server. Its existing HTTP/1 listener supports actual WebSocket upgrades. Send
one Bearer header, then the first full `publish` or `subscribe` Text command
immediately; welcome follows admitted input. Use the [WS contract](rust-realtime-ws.md)
for exact commands, heartbeat/full-view/mask/error and recovery rules.

JWT identity remains local until signed expiry. Opaque identity reads current
SQL state. Grants, registry binding and PROJECT section masks are rechecked by
the existing producers. Changing a grant affects the next operation; a quiet
socket does not promise immediate revocation notification. Publication removes
its live snapshot when disconnected/expired, while its SQL registration remains.
No old DATA cache, extra token lifetime or framework quota is introduced.

SIGINT/SIGTERM closes admission and joins the owned socket supervisor and Hub
maintenance before SQL closes. HTTP connections receive graceful shutdown under
the same server shutdown deadline. If that deadline expires, cleanup drains the
started joins and retains the shutdown error. Drop closes/aborts as an emergency
fallback; it does not itself confirm joins. HTTP graceful shutdown alone does
not own upgraded WebSockets.

The composition tests use the actual native binary, TLS PostgreSQL ordinary
owner, genuine P3 JWT, current opaque access/service SQL bindings and mature
WebSocket clients. Snapshot fixture DATA tests server transport and policy; it
does not prove real Core corpus production. The two-process Runtime/CLI/MCP
integration remains its own required delivery.

```text
cargo test --locked -p broker-server --test presence -- --ignored --test-threads=1
```

Explicit SQLite library composition now supports both the [Native JWT inventory/Now routers](rust-sqlite-presence.md) and the [LOCAL opaque inventory/Now routers](rust-sqlite-local-presence-now.md). The latter preserves current bearer verification, own GET, partial LIST, section masks and full-publication heartbeat semantics. Executable backend selection and its readiness/shutdown proof remain the Server integration under tsk-8069; this library result does not activate a different database through the configuration above.
