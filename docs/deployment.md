# Deployment and object-storage guide

## Container

The Dockerfile builds a static Go binary and runs it from `scratch` as UID/GID 65532. Mount the
configuration read-only and inject secrets using your orchestrator's secret mechanism.

```bash
docker build -t registry.example.com/graphit-auth-broker:1.0.0 .
docker run -d --name graphit-auth-broker --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env-file /etc/graphit-auth-broker/broker.env \
  -v /etc/graphit-auth-broker/config.yaml:/etc/graphit-auth-broker/config.yaml:ro \
  -v graphit-broker-state:/var/lib/graphit-auth-broker \
  -p 127.0.0.1:8080:8080 registry.example.com/graphit-auth-broker:1.0.0
```

Place an HTTPS reverse proxy/load balancer in front, preserve `X-Request-ID`, and use `/healthz`
for liveness and `/readyz` for readiness. The built-in Docker healthcheck targets port 8080.

The container runs as UID/GID `65532`. The `/var/lib/graphit-auth-broker` mount must be writable by
that identity; the image seeds its state directory as `0700` and the process creates `broker.db` as
`0600`. The supplied Compose file uses a named volume (Docker copies the correctly owned/mode-set
directory into a new volume), which is preferable to an incorrectly owned bind mount. It also
runs the root filesystem read-only and keeps only the SQLite volume and a small `/tmp` tmpfs writable.

`config.yaml` seeds a database only when no configuration row exists. A normal restart reads the
authoritative configuration from SQLite. `administration.database_path`, the enabled state and
`BROKER_SUPERADMIN_SUBJECT` remain deployment-owned; changing other environment-expanded values in
the seed file does not overwrite an existing database. Rotate mutable secrets through `/admin/` or
the administration API. To deliberately start fresh, stop the broker and mount a new empty volume;
never delete a production database as a configuration-update mechanism.

At minimum inject these administration values through the orchestrator's secret/config facility:

```text
BROKER_SUPERADMIN_SUBJECT=<exact immutable OIDC sub>
BROKER_ADMIN_OIDC_ISSUER=https://identity.example.com
BROKER_ADMIN_OIDC_CLIENT_ID=graphit-broker-admin
BROKER_ADMIN_OIDC_CLIENT_SECRET=<confidential client secret>
BROKER_ADMIN_OIDC_REDIRECT_URL=https://broker.example.com/admin/auth/callback
```

## Direct S3 route credentials

Each named route has one access-key pair stored only in the broker's secret-managed configuration.
The principal behind that key must have only the object-store permissions needed by the route's
bucket and `base_prefix`. The broker ACL narrows which logical operations it will sign, while the
object-store policy remains an independent upper bound.

Example IAM policy for a route whose bucket is `graphit-artifacts` and base prefix is `graphit`:

```json
{
  "Version":"2012-10-17",
  "Statement":[
    {"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket"],
     "Resource":"arn:aws:s3:::graphit-artifacts",
     "Condition":{"StringLike":{"s3:prefix":["graphit","graphit/*"]}}},
    {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload"],
     "Resource":"arn:aws:s3:::graphit-artifacts/graphit/*"}
  ]
}
```

Reduce actions further for read-only routes. Use separate routes and keys for different tenants or
security boundaries. Inject `access_key_id` and `secret_access_key` from Docker/Kubernetes secrets,
Vault, or the deployment platform's equivalent. Never commit them or return them to Graphit.

## S3-compatible systems

Set each route's `endpoint` to its object-store URL and provide an access key and secret accepted by
that service's S3-compatible SigV4 API. The service must support the signed operations Graphit uses:
GET, HEAD, PUT, DELETE and ListObjectsV2. Validate region/path-style behavior in a staging route.

## Rollout order

1. Add a new broker route revision while the old deployment remains available.
2. Deploy and verify discovery, authentication and negative ACL cases.
3. Update the named Graphit provider only when the endpoint/audience changes; normal discovery
   learns route revisions.
4. Reindex Graphit vectors before serving queries after any embedding revision/width change.
5. Roll back the broker only to a deployment whose discovery revision matches its actual model.

For an administration/control-plane rollout, first back up SQLite, then save the desired YAML in the
UI. Validation constructs every OIDC verifier, AI service, ACL and S3 signer before the revision is
committed. A rejected configuration leaves both the active runtime and stored revision unchanged.
With one broker process, consumer requests observe either the old or new complete runtime.
The listen address and Go HTTP server deadlines are constructed before serving and therefore apply
from the next restart; authentication, ACL, AI, S3, discovery and body-limit changes are live.

SQLite is intentionally a single-node control plane. Do not run several writable broker replicas
against one database file over NFS or an object-backed volume. Use one writable instance and put
availability at the container/VM restart layer. In-memory AI caches are per process and are not part
of persistence.

Storage topology or credential changes need no Graphit provider update or login. Add the new route, update ACL rules
to select it, verify positive and negative presign cases, then remove the old route only after its
short-lived URLs have expired. Matching rules must never select two routes for the same request.
