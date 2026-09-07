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

Storage topology or credential changes need no Graphit provider update or login. Add the new route, update ACL rules
to select it, verify positive and negative presign cases, then remove the old route only after its
short-lived URLs have expired. Matching rules must never select two routes for the same request.
