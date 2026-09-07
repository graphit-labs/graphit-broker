# OIDC integration guide

Most installations register two OIDC applications:

1. a public/native client used by Graphit users to obtain consumer access/refresh tokens;
2. a confidential web client used by the broker administration UI to obtain administrator ID
   tokens and establish a server-side session.

They can share one issuer, but have different redirect URIs, audiences, credentials and trust
boundaries. Assigning the same human to both does not merge the permissions.

## What the identity provider must issue

The Graphit CLI uses Authorization Code + PKCE and obtains an access token and refresh token. The
same access token is sent as a bearer credential to every broker capability. It must therefore:

1. be a signed JWT discoverable from the configured issuer;
2. contain the broker audience in `aud`;
3. contain every configured scope in `scope` or `scp`;
4. carry the configured username and, if ACLs use them, organization/team claims;
5. have a lifetime long enough for a request, while refresh-token policy permits recurring use.

The broker downloads discovery/JWKS metadata from each issuer, verifies signature, exact issuer,
audience and expiration, then maps claims to a normalized principal. It never trusts username,
organization or team data supplied in the request body.

## IdP application registration

Create a public/native OIDC client for the Graphit CLI:

- grant: Authorization Code;
- PKCE: required, method S256;
- client secret: normally none for a native client; if your IdP requires one, Graphit stores it in
  the named provider topology, so limit access to the global Graphit directory;
- redirect URI: the loopback URI configured by `graphit provider add --redirect-uri`;
- scopes: at least `openid`, plus `offline_access` when required for refresh tokens and your broker
  scope such as `graphit.use`;
- API/resource audience: `graphit-broker` (or your chosen value).

The IdP API/resource registration must use that same audience and authorize the native client to
request it. Add claim mapping/mappers for username, organization and teams. Prefer immutable org
and team IDs over display names.

## Broker configuration

```yaml
authentication:
  oidc:
    - issuer: https://id.example.com/realms/acme
      audiences: [graphit-broker]
      required_scopes: [openid, graphit.use]
      username_claim: preferred_username
      organization_claim: organization.id
      teams_claim: groups
```

Multiple entries can coexist, including different issuers and claim shapes. An incoming token is
accepted only by the verifier for its exact `iss`. If Graphit's MCP endpoint and broker both consume
the same token, configure the same audience for both. For IdPs that cannot mint one token usable by
both resources, use a dedicated common API audience or introduce token exchange at your gateway;
the current Graphit profile intentionally keeps a single refreshable access-token session.

## Administration OIDC application

Create a second web application for the broker control plane:

- grant: Authorization Code;
- redirect: exactly `https://broker.example.com/admin/auth/callback`;
- client authentication: a client secret (recommended); store it only in deployment secrets and
  the protected SQLite control-plane database;
- PKCE: allow S256—the broker always sends it in addition to confidential-client authentication;
- scopes: `openid profile email`, or a smaller set containing `openid`;
- ID token: include immutable `sub`, the administration client ID in `aud`, and normal expiry.

```yaml
administration:
  enabled: true
  database_path: /var/lib/graphit-auth-broker/broker.db
  superadmin_subject: ${BROKER_SUPERADMIN_SUBJECT:?required}
  session_ttl: 8h
  oidc:
    issuer: https://id.example.com/realms/acme
    client_id: graphit-broker-admin
    client_secret: ${BROKER_ADMIN_OIDC_CLIENT_SECRET:?required}
    redirect_url: https://broker.example.com/admin/auth/callback
    scopes: [openid, profile, email]
```

Set `BROKER_SUPERADMIN_SUBJECT` to the exact `sub` of the first owner, start with an empty persistent
database, browse to `/admin/`, and sign in. Before any role assignment exists only that subject is
accepted. Use **Roles & users** to assign the built-in `admin` role to additional exact subjects.
The superadmin remains an out-of-band deployment override and is never removed by database edits.

For providers such as Keycloak, create a confidential client, enable Standard Flow, register the
exact valid redirect URI, and map any desired name/email claims into the ID token. For Auth0 or
Okta, create a regular web application and configure the same callback. Provider-specific labels
differ, but the protocol requirements above are the contract.

## Graphit provider and login

```bash
graphit provider add company \
  --type oidc \
  --issuer https://id.example.com/realms/acme \
  --client-id graphit-cli \
  --redirect-uri http://127.0.0.1:8765/callback \
  --scopes openid,offline_access,graphit.use \
  --broker-endpoint https://broker.example.com \
  --broker-audience graphit-broker \
  --embedding-mode broker \
  --rerank-mode broker

graphit login --provider company --profile alice-acme
```

For a headless flow, obtain tokens using an approved IdP mechanism and pass all values explicitly:

```bash
graphit --non-interactive login --provider company --profile ci-acme \
  --access-token "$ACCESS_TOKEN" \
  --refresh-token "$REFRESH_TOKEN" \
  --id-token "$ID_TOKEN" \
  --token-expires-at 2026-09-07T18:00:00Z
```

`--non-interactive` is a contract: every missing value that would otherwise prompt is an error.
Login activates the profile immediately. Subsequent broker calls resolve the active profile and
refresh OIDC tokens before expiry.

## Claim examples

Flat claims:

```json
{
  "iss": "https://id.example.com/realms/acme",
  "sub": "00u123",
  "aud": ["graphit-broker"],
  "scope": "openid graphit.use",
  "preferred_username": "alice",
  "org_id": "acme",
  "groups": ["platform", "developers"]
}
```

Use `organization_claim: org_id`. Nested claims work as well:

```json
{"organization":{"id":"acme"},"authorization":{"teams":["platform"]}}
```

Use `organization_claim: organization.id` and `teams_claim: authorization.teams`.

## Validation checklist

- Open the issuer's `/.well-known/openid-configuration` from the broker network.
- Decode a development token locally and compare `iss` byte-for-byte.
- Confirm `aud`, scopes and configured claim paths.
- Call discovery, then an authenticated capability with a token from the intended client.
- Repeat with wrong audience, expired token, missing scope and unauthorized team; expect 401 for
  authentication failures and 403 for ACL failures.
- Verify refresh by using a short access-token lifetime in a non-production tenant.
- Open `/admin/auth/login`, confirm the redirect uses the administration client, then verify the
  callback establishes an HttpOnly cookie and `/admin/api/v1/session` reports the exact subject.
- Try an unassigned administration subject and expect 403; assign then revoke `admin` and confirm
  access changes immediately.
- Rotate the administration client secret through the full configuration UI/API and confirm the
  next login uses the replacement while existing sessions expire at their configured lifetime.
