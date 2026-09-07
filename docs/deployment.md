# Deployment and AWS guide

## Container

The Dockerfile builds a static Go binary and runs it from `scratch` as UID/GID 65532. Mount the
configuration read-only and inject secrets using your orchestrator's secret mechanism.

```bash
docker build -t registry.example.com/graphit-auth-broker:1.0.0 .
docker run -d --name graphit-auth-broker --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env-file /etc/graphit-auth-broker/broker.env \
  -v /etc/graphit-auth-broker/config.yaml:/etc/graphit-auth-broker/config.yaml:ro \
  -p 127.0.0.1:8080:8080 registry.example.com/graphit-auth-broker:1.0.0
```

Place an HTTPS reverse proxy/load balancer in front, preserve `X-Request-ID`, and use `/healthz`
for liveness and `/readyz` for readiness. The built-in Docker healthcheck targets port 8080.

## AWS `assume_role`

The broker needs an AWS credential chain identity allowed to call `sts:AssumeRole` on
`services.s3.role_arn`. In Kubernetes/ECS, prefer workload identity/task roles over static keys.
The target role needs S3 permissions broad enough for all prefixes the broker may grant; the inline
session policy narrows each issued session.

Trust-policy sketch (replace account and principal):

```json
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":{"AWS":"arn:aws:iam::123456789012:role/graphit-broker-runtime"},
    "Action":"sts:AssumeRole"
  }]
}
```

## AWS `web_identity`

Register the external OIDC issuer in IAM, configure the target role trust policy for the intended
audience/subjects, and set `mode: web_identity`. The broker calls `AssumeRoleWithWebIdentity` with
the same token it already validated and with its own tighter inline policy. API-key principals
cannot use this mode because their bearer value is not an OIDC web-identity token.

## S3-compatible systems

Set `services.s3.endpoint` to the object-store URL returned to clients and `sts_endpoint` to its
STS-compatible endpoint. The system must implement the AWS STS calls and session-policy semantics
used here. If it does not enforce inline policies, do not claim equivalent ACL isolation; use
separate credentials/tenants or an adapter that does.

## Rollout order

1. Add a new broker route revision while the old deployment remains available.
2. Deploy and verify discovery, authentication and negative ACL cases.
3. Update the named Graphit provider only when the endpoint/audience changes; normal discovery
   learns route revisions.
4. Reindex Graphit vectors before serving queries after any embedding revision/width change.
5. Roll back the broker only to a deployment whose discovery revision matches its actual model.
