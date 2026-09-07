# Administration UI and access policy

## Open the console

Enable `administration`, mount a writable state directory, then browse to
`https://broker.example.com/admin/`. Paste an administration token configured under
`administration.api_keys`; the UI keeps it only in the browser tab's `sessionStorage`. Consumer
OIDC tokens and broker API keys do not open the console, and an admin token does not authorize
consumer endpoints.

The static page and API are served by the broker itself. No Node.js service, database or CDN is
required. Put `/admin/` behind the same HTTPS boundary as the API and, when possible, add a VPN,
identity-aware proxy or source-IP control as defense in depth.

## Access levels

Every rule is an allow grant; there are no implicit grants and no deny override. An empty policy
denies everything.

| `access` | `principal` | Matches |
|---|---|---|
| `global` | omitted | Every request, authenticated or anonymous |
| `anonymous` | omitted | Only requests with no `Authorization` header |
| `authenticated` | omitted | Any successfully validated OIDC/API-key principal |
| `user` | username | Exact normalized verified username |
| `team` | team | One exact verified team membership |
| `organization` | organization | Exact verified organization |
| `subject` | subject | Exact `sub` or canonical `issuer|sub` |

`global` is intentionally broader than `anonymous`: global also grants authenticated clients.
Use `anonymous` when a public catalog should be visible only through the unauthenticated path.
For user/team/organization/subject, `principal` is required; it must be empty for the three broad
levels.

Capabilities are `embeddings`, `rerank`, `s3`, or an S3 operation capability such as `s3:read`.
S3 rules can further constrain project globs, logical operations (`read`, `write`, `publish`,
`delete`), one optional named storage route, and safe logical-key prefix templates. Empty route
selects `services.s3.default_route`; multiple matching routes fail closed. GET/HEAD/list accept a read, write or publish grant; PUT
accepts write or publish; DELETE accepts delete or publish.
Saving rejects unknown route names. Any access level, including `global` and `anonymous`, may
select a configured route; authentication and ACL evaluation happen before signing.

## Editing and concurrency

The UI first reads `GET /admin/api/v1/access`, receiving an `ETag` policy revision. Save sends the
whole validated rule set to `PUT /admin/api/v1/access` with `If-Match`. If another administrator
saved first, the broker returns `409`; reload, reconcile and save again. Writes use a temporary
file, `fsync`, atomic rename, mode `0600`, and a mode `0700` parent directory.

The YAML rules seed a new state file. Once the state file exists it is authoritative. Back it up
and restore it as one JSON file. The file contains only ACL policy; administrator and consumer
secrets remain in configuration/environment.

## API examples

```bash
curl -H "Authorization: Bearer $BROKER_ADMIN_TOKEN" \
  https://broker.example.com/admin/api/v1/access

curl -X PUT -H "Authorization: Bearer $BROKER_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -H 'If-Match: "3"' \
  https://broker.example.com/admin/api/v1/access \
  --data-binary @policy.json
```

`GET /admin/api/v1/principals` lists the anonymous/authenticated categories and configured API-key
principals without exposing their keys. OIDC users are not provisioned in a broker database: they
are evaluated from verified token claims, so user/team/organization rules can be created before
or after the first login.
