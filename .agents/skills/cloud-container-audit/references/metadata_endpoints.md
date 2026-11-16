# Cloud Metadata Endpoints (for use through a confirmed SSRF only)

Proof of impact = reaching the metadata service and reading a **non-secret** field. Reading credential or token paths needs explicit written approval for that check; never use any credential returned. See ssrf-audit for SSRF delivery and bypasses.

| Provider | Base URL | Required header | Safe proof field | Never read without approval |
|---|---|---|---|---|
| AWS EC2 IMDSv1 | `http://169.254.169.254/latest/meta-data/` | none | `instance-id`, `placement/region`, `ami-id` | `iam/security-credentials/<role>`, `user-data` (may hold secrets) |
| AWS EC2 IMDSv2 | `PUT http://169.254.169.254/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then `X-aws-ec2-metadata-token: <token>` | token | same as v1 | same |
| AWS ECS task | `http://169.254.170.2/v2/metadata` (task metadata), credentials at `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | none | task ARN, cluster | credentials URI |
| AWS Lambda | environment only (`AWS_LAMBDA_RUNTIME_API` at `127.0.0.1:9001`) | none | runtime API reachable | `/2018-06-01/runtime/invocation/next` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` | `compute/location`, `compute/vmId` | `metadata/identity/oauth2/token?resource=...` |
| Azure App Service | `$IDENTITY_ENDPOINT` (for example `http://127.0.0.1:41xxx/msi/token`) | `X-IDENTITY-HEADER` | reachability | token |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` (also `169.254.169.254`) | `Metadata-Flavor: Google` | `project/project-id`, `instance/zone` | `instance/service-accounts/default/token`, `attributes/kube-env` |
| GCP legacy | `http://metadata.google.internal/computeMetadata/v1beta1/` | none (if not disabled) | same | same |
| Oracle Cloud | `http://169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` | `region`, `availabilityDomain` | `identity/` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | none | `instance-id`, `region-id` | `ram/security-credentials/` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | none | `id`, `region` | `user-data` |
| OpenStack | `http://169.254.169.254/openstack/latest/meta_data.json` | none | `uuid` | `user_data` |
| Kubernetes | `https://kubernetes.default.svc/version` (from a pod), service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` | bearer token | `/version` | token file (file read via LFI or SSRF `file://`) |

## Notes for reports

- IMDSv1 reachable via SSRF on AWS is high to critical because role credentials are one request away; state that you stopped at a non-secret field.
- IMDSv2 blocks simple GET SSRF (needs PUT and a custom header); report the SSRF and note IMDSv2 mitigated metadata access.
- Azure and GCP require custom headers; a GET-only SSRF without header control usually cannot reach them (report what you could and could not reach).
- Alternate encodings for 169.254.169.254 (decimal `2852039166`, hex `0xA9FEA9FE`, IPv6 `[::ffff:a9fe:a9fe]`, DNS names resolving to it) belong to ssrf-audit bypass rows.
