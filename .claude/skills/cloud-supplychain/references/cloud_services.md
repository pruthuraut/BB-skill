# Cloud Services, PaaS, Hosting, and Storage (extension)

Class key: `passive` = DNS, JS, and headers. `bounded` = anonymous read-only list or GET. `authorized-only` = any write, key use, or account action.

## Object storage and buckets

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CLD-S3-001 | AWS S3 | Public list permission | bounded | `aws s3 ls s3://<bucket> --no-sign-request` |
| CLD-S3-002 | AWS S3 | Public read of objects | bounded | `curl -sI https://<bucket>.s3.amazonaws.com/<known-key>` |
| CLD-S3-003 | AWS S3 | Public write | authorized-only | Never test writes; read bucket policy with approval |
| CLD-S3-004 | AWS S3 | Object ACL misconfiguration | authorized-only | Approved read of ACL |
| CLD-S3-005 | AWS S3 | Bucket name permutations discovered in JS and DNS | passive | Grep JS for bucket URLs; `dig CNAME` |
| CLD-AZ-001 | Azure Blob | Anonymous container list | bounded | `curl -s "https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list"` |
| CLD-AZ-002 | Azure Blob | Public access level | bounded | Container properties HEAD request |
| CLD-AZ-003 | Azure | App Service auth endpoints (.auth/me, login callback) | bounded | `curl -sI https://<app>.azurewebsites.net/.auth/me` |
| CLD-AZ-004 | Azure | Function app keys in client JS | passive | Grep JS for defaultHostKey and function keys |
| CLD-AZ-005 | Azure DevOps | PAT tokens in config or JS | passive | Grep for DevOps PAT patterns |
| CLD-GCS-001 | Google Cloud Storage | Public bucket listing | bounded | `curl -s https://storage.googleapis.com/<bucket>` |
| CLD-DO-001 | DigitalOcean Spaces | Public listing in ams3, sfo3, default regions | bounded | GET listing per region |
| CLD-BUNNY-001 | Bunny storage | Public listing | bounded | See saas file SAAS-007 |
| CLD-MINIO-001 | MinIO | Public bucket policy and default minioadmin credentials | authorized-only | Anonymous GET of bucket; credential test only if approved |
| CLD-FB-001 | Firebase RTDB | `.read: true` rules | bounded | `curl -s "https://<project>.firebaseio.com/.json?shallow=true"` |
| CLD-FB-002 | Firestore | Documents readable with API key only | bounded | Anonymous REST list on a known collection |
| CLD-FB-003 | Firebase Auth | Email enumeration via signInWithPassword error | bounded | One request with own test address |
| CLD-FB-004 | Firebase | API key in client code (expected; rules are the control) | passive | Grep for apiKey; report only if rules are open |
| CLD-HOSTEDBUCKET-001 | Generic | Bucket name in JS, HTML, or CNAME that returns NoSuchBucket | passive | Grep and dig; report dangling bucket (see takeover) |

## Serverless and API gateways

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CLD-LAM-001 | AWS Lambda | Function URL exposure (`*.lambda-url.<region>.on.aws`) | bounded | GET status with no auth |
| CLD-LAM-002 | AWS Lambda | Environment variable leakage through error output | bounded | Malformed own-request, grep error body for env names (redact values) |
| CLD-LAM-003 | AWS Lambda | Execution role over-privilege | authorized-only | Requires approved IAM review |
| CLD-APIGW-001 | AWS API Gateway | Endpoints without authorizer | bounded | Anonymous GET and OPTIONS on documented routes |
| CLD-APIGW-002 | AWS API Gateway | API key in client JS | passive | Grep for x-api-key values |
| CLD-APIGW-003 | AWS API Gateway | Lambda proxy SSRF through url parameter | bounded | See ssrf-audit; OOB host only |
| CLD-COG-001 | AWS Cognito | Unauthenticated identity pool credentials and over-permissive role | bounded | `aws cognito-identity get-id --identity-pool-id <id> --no-sign-request` (ID only, no credential use) |
| CLD-COG-002 | AWS Cognito | Self-signup enumeration and abuse | bounded | One signup attempt with own address, check response wording |
| CLD-CF-001 | AWS CloudFront | Origin bypass to S3 or ALB | bounded | Host header check, see techfingerprint CDN-010 |
| CLD-CF-002 | AWS CloudFront | Signed URL bypass | authorized-only | Review policy only |
| CLD-ALB-001 | AWS ALB | Direct ALB access bypassing WAF | bounded | Host header against ALB name |
| CLD-EC2-001 | EC2 metadata | IMDSv1 reachable through SSRF | bounded | See ssrf-audit SSRF-IMDS checks |
| CLD-EC2-002 | EC2 metadata | IMDSv2 token required (PUT with TTL header) | bounded | Only from an approved host you control |
| CLD-EC2-003 | EC2 | Security group and user-data review | authorized-only | Requires approved account access |
| CLD-GCP-001 | GCP metadata | metadata.google.internal reachable through SSRF with Metadata-Flavor header | bounded | See ssrf-audit |
| CLD-GCP-002 | Google Apigee | Proxy endpoints and debug traces exposed | bounded | Anonymous GET on proxy base path |

## PaaS and hosting

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CLD-PAAS-001 | Heroku | .env and Procfile exposed through web root | passive | GET status |
| CLD-PAAS-002 | Heroku | Release and metadata via headers | passive | Headers |
| CLD-PAAS-003 | Glitch | .env and .data exposed; public remix cloning | passive | GET /.env and /.data status |
| CLD-PAAS-004 | Netlify / Vercel / Render / Railway / Replit | Env values and deploy keys in build output | passive | Grep bundles and build manifests |
| CLD-PAAS-005 | Pythonanywhere | Username in subdomain | passive | Note only |
| CLD-PAAS-006 | Cloudways / Pantheon / Platform.sh / WP Engine / SiteGround / Kinsta / Liquid Web | Environment URLs (dev, test, live) exposed | passive | Header and DNS review |
| CLD-VPS-001 | Hetzner / Vultr / OVHcloud / Tencent Cloud / Hostinger / Hostgator / Infomaniak / IONOS | Cloud API tokens, control panel exposure, server IPs in DNS | passive | Panel status on known ports; token leaks as secret findings |
| CLD-VPS-002 | Hetzner Cloud | API token in repos or JS | passive | Grep for token patterns |
| CLD-K8S-001 | Cloud Kubernetes | Dashboard and API exposure | passive | See tech-stack-audit devops-containers.md TS-DO-030 to 033 |
| CLD-DOCK-001 | Docker host | Port 2375 or 2376 exposed | passive | See tech-stack-audit TS-DO-029 |
| CLD-CDN-001 | Vercel / Netlify / Cloudflare Pages | Preview deployments indexed | bounded | Own project preview URL check; review sitemap for preview hosts |
