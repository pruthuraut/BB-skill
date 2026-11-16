# Cloud and Container Security Checklist

Class key: `passive` = DNS, JS, docs, versions. `bounded` = read-only status/version requests, anonymous listing requests, one anonymous connection attempt. `authorized-only` = metadata credentials, using found keys, resource listing beyond version, exec/run, writes, IAM enumeration, escape attempts.

## Core checks (15)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CC-001 | AWS S3 | Bucket allows public list, public read, or public write (bucket policy/ACL) | bounded | cloud_exposure_check.py `--buckets`: anonymous `GET https://<b>.s3.amazonaws.com/` → `ListBucketResult` = public list; write is authorized-only (read policy instead) |
| CC-002 | AWS metadata | 169.254.169.254 reachable via SSRF; IMDSv1 (no token) vs IMDSv2 (PUT token required) | bounded | Through a confirmed SSRF: `/latest/meta-data/` root or `instance-id` only; credentials path is authorized-only |
| CC-003 | Azure metadata | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true` reachable via SSRF | bounded | Same rule: compute/location fields only; `identity/oauth2/token` is authorized-only |
| CC-004 | GCP metadata | `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google` (or legacy v1beta1 without header) via SSRF | bounded | Project ID or zone only; `service-accounts/default/token` is authorized-only |
| CC-005 | Docker | Docker Engine API exposed on 2375 (HTTP) or 2376 (TLS without client cert) | bounded | cloud_exposure_check.py `GET /version` and `/_ping`; never `/containers/create` or `/exec` |
| CC-006 | Kubernetes | Kubernetes API on 6443/8443/443 allows anonymous access beyond `/version` | bounded | `GET /version` (often public), `GET /api` and `/apis` status; 200 on `/api/v1/namespaces` is a finding (status only, do not save body) |
| CC-007 | Containers | Container escape exposure: vulnerable runc (CVE-2019-5736, CVE-2024-21626), containerd, Docker, kernel (Dirty Pipe CVE-2022-0847); privileged containers, mounted docker.sock, hostPath `/`, CAP_SYS_ADMIN | passive | Version evidence and manifests/config in scope; never attempt escape |
| CC-008 | Storage | Azure Blob container anonymous list/read; GCS bucket `allUsers`/`allAuthenticatedUsers` | bounded | cloud_exposure_check.py `--azure acct/container`, `--buckets` (GCS checked too) |
| CC-009 | IAM | IAM misconfiguration and privilege escalation (over-broad roles, `iam:PassRole`, `*:*`, wildcard trust policies, public resource policies, long-lived keys) | authorized-only | Only with approval or provided read-only credentials; see `iam_privesc.md` |
| CC-010 | Serverless | Function exposure: Lambda function URLs (`AuthType NONE`), API Gateway without authorizer, Google Cloud Functions/Run allowing `allUsers`, Azure Functions `authLevel anonymous` or keys in clients | bounded | `--functions` anonymous GET status; key leaks via jsrecon |
| CC-011 | Databases | Cloud database publicly reachable without auth (RDS/Aurora public, Cloud SQL public IP, Cosmos DB keys, Elasticsearch/OpenSearch domains, MongoDB Atlas 0.0.0.0/0, Redis, Firebase RTDB) | bounded | Port reachability and one anonymous metadata call (for example Elasticsearch `GET /`); never query data |
| CC-012 | Queues | Queue/topic exposure: SQS queue policy `Principal: *`, SNS topics open, Pub/Sub `allUsers`, Service Bus/Event Hub SAS keys leaked, RabbitMQ/Kafka public | bounded | Policy review when available; leaked connection strings via jsrecon; never send or receive messages |
| CC-013 | etcd | etcd on 2379 without client auth | bounded | cloud_exposure_check.py `GET /version` and `/health`; never read keys (`/v2/keys`, v3 range) |
| CC-014 | K8s dashboard | Kubernetes dashboard exposed without auth or with skip-login / over-privileged service account | bounded | `GET /`, `/api/v1/login/status`, `/api/v1/csrftoken/login` status; do not use skip-login |
| CC-015 | CDN | CDN misconfiguration enabling cache manipulation: caching authenticated content, unkeyed headers, origin directly reachable (WAF bypass), open purge, S3 origin without OAC | bounded | See cache-poisoning-audit; origin bypass via Host header to origin IP (CLD-CF-001) |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CC-V-001 | Kubelet | Kubelet API 10250 anonymous auth (`/pods`, `/runningpods`) or read-only 10255 | bounded | Status code only; never `/run`, `/exec`, `/attach`, `/logs` |
| CC-V-002 | Docker registry | Registry v2 anonymous catalog/pull (`/v2/_catalog`) | bounded | Status and repository count only |
| CC-V-003 | Kubernetes RBAC | `system:anonymous` or `system:unauthenticated` bound to roles | authorized-only | Config review in scope |
| CC-V-004 | Helm | Tiller (Helm v2) on 44134 | bounded | Port reachability only |
| CC-V-005 | cAdvisor / metrics | cAdvisor 4194/8080, Prometheus node exporter 9100, kube-state-metrics exposed | bounded | `GET /metrics` status; note sensitive labels |
| CC-V-006 | Consul / Nomad / Vault | HashiCorp APIs without ACLs (8500, 4646, 8200) | bounded | `GET /v1/status/leader`, `/v1/sys/health` |
| CC-V-007 | ECS / Fargate | Task metadata `169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` via SSRF | authorized-only | Report reachability only |
| CC-V-008 | Cognito | Unauthenticated identity pool returns credentials | authorized-only | See cloud-supplychain CLD-COG-001 |
| CC-V-009 | Keys | Cloud keys in JS, mobile apps, repos (AKIA/ASIA, `AIza`, Azure SAS/connection strings, GCP service-account JSON) | passive | jsrecon, trufflehog; report redacted |
| CC-V-010 | Takeover | Dangling cloud resources (deleted bucket, released Elastic IP, Azure app name) | passive | subdomain-takeover |
| CC-V-011 | Object ACL | Public objects inside private buckets; presigned URLs long-lived | bounded | file-download-audit FD-007 |
| CC-V-012 | Snapshots | Public EBS/RDS snapshots or AMIs owned by the target account | authorized-only | Report only with approval to query by account ID |
| CC-V-013 | K8s ingress | Ingress controllers exposing internal services or default backends; NGINX Ingress CVE-2025-1974 (IngressNightmare) admission webhook reachable | passive | Version and reachability of admission port 8443 from outside |
| CC-V-014 | Serverless env | Function errors leak environment variables or keys | bounded | Malformed input to own-accessible function; see cloud-supplychain CLD-LAM-002 |
| CC-V-015 | Container images | Public images contain secrets (`docker history`, layers) | passive | Pull public image of the target and scan with trufflehog |

## Port and endpoint table

| Service | Port | Safe request | Exposure signal |
|---|---|---|---|
| Docker API | 2375 / 2376 | `GET /version`, `GET /_ping` | JSON with `ApiVersion`; `OK` |
| Kubernetes API | 6443, 8443, 443 | `GET /version`, `GET /api` | `/api` 200 anonymously (403 is normal) |
| Kubelet | 10250 (TLS) / 10255 | `GET /pods` status | 200 = anonymous kubelet |
| etcd | 2379 / 2380 | `GET /version`, `GET /health` | `etcdserver` version JSON |
| K8s dashboard | 443, 8443, 30000-32767 | `GET /` and `/api/v1/login/status` | Dashboard HTML, `tokenPresent` JSON |
| Docker registry | 5000, 443 | `GET /v2/`, `/v2/_catalog` | 200 with `repositories` |
| Consul | 8500 | `GET /v1/status/leader` | leader address |
| Vault | 8200 | `GET /v1/sys/health` | JSON (health is public by design; note version) |
| Elasticsearch | 9200 | `GET /` | cluster name and version without auth |
| Redis | 6379 | `PING` via redis-cli (one) | `PONG` without auth |
| MongoDB | 27017 | `mongosh --eval "db.runCommand({ping:1})"` (one) | ok without auth |

## Cross-references

| CC row | Related rows |
|---|---|
| CC-001, CC-008 | cloud-supplychain CLD-S3-*, CLD-AZ-*, CLD-GCS-001 |
| CC-002 to CC-004 | ssrf-audit metadata rows, CLD-EC2-001/002, CLD-GCP-001 |
| CC-005, CC-006, CC-013, CC-014, CC-V-001, CC-V-002 | tech-stack-audit TS-DO-028 to TS-DO-033 |
| CC-010 | CLD-LAM-001, CLD-APIGW-001 |
| CC-015 | cache-poisoning-audit, CLD-CF-001 |
| CC-V-010 | subdomain-takeover |
