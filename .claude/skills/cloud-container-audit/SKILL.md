---
name: cloud-container-audit
description: Audit authorized cloud and container attack surface across 15 checks — AWS S3 public access, AWS/Azure/GCP instance metadata reachable via SSRF (169.254.169.254, IMDSv1 vs IMDSv2, Metadata:true, Metadata-Flavor), exposed Docker API on 2375/2376, exposed Kubernetes API on 6443/8443, container escape exposure (version-gated CVEs, privileged pods, mounted sockets), Azure Blob and GCS public access, cloud IAM misconfiguration and privilege-escalation paths, exposed cloud functions (Lambda URLs, Cloud Functions, Azure Functions), public cloud databases, exposed queues (SQS, Pub/Sub, Service Bus), etcd on 2379, Kubernetes dashboard without auth, and CDN misconfiguration enabling cache manipulation — plus variants (kubelet 10250/10255, Docker registry, Kubernetes anonymous RBAC, Helm/Tiller, cAdvisor, Consul/Nomad, Firebase, Cognito identity pools, leaked keys). Includes a scope-gated read-only exposure checker and an IAM privilege-escalation reference for keys found in scope. Triggers on "cloud", "AWS", "Azure", "GCP", "S3 bucket", "metadata endpoint", "169.254.169.254", "IMDS", "Docker API", "2375", "Kubernetes", "kubelet", "etcd", "k8s dashboard", "container escape", "IAM", "Lambda", "Cloud Functions", "SQS", "Pub/Sub", "Service Bus", "CloudFront", or when recon finds cloud hosts, buckets, or container ports.
---

# Cloud and Container Security (15 checks + variants)

Check what the target exposes in its cloud accounts and container platforms: storage, metadata services reachable through SSRF, orchestration APIs, serverless endpoints, data services, queues, and CDNs. Every active check is a read-only status or version request; nothing is created, written, executed, or claimed.

- Checklist: `references/cloud_container_checklist.md` (CC-001 to CC-015, CC-V-*, port and endpoint table).
- Metadata reference: `references/metadata_endpoints.md` (AWS, Azure, GCP, Oracle, Alibaba, DigitalOcean, Kubernetes, ECS; required headers; what a safe proof looks like).
- IAM reference: `references/iam_privesc.md` (how to assess a key found in scope without misusing it; common privilege-escalation permissions).
- Tracker: `references/cloud_container_tracker.md`.
- Checker: `scripts/cloud_exposure_check.py` (Docker API, Kubernetes API, kubelet, etcd, Kubernetes dashboard, Docker registry on given hosts; S3, GCS, and Azure Blob anonymous listing for given bucket names; anonymous status of given function URLs).
- Related: `cloud-supplychain` (CLD-* bucket, Firebase, Lambda, Cognito rows), `ssrf-audit` (metadata via SSRF), `tech-stack-audit` (`devops-containers.md` TS-DO-*), `network-portscan`, `subdomain-takeover` (dangling cloud resources), `cache-poisoning-audit` (CDN), `jsrecon` (keys in JS).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. Cloud resources must be in scope explicitly: add bucket hostnames, function hostnames, and IP ranges to `scope.txt` before active checks. Account ownership must be the target's (do not test buckets that merely look related).
2. Inventory: from recon (DNS CNAMEs to `s3`, `blob.core.windows.net`, `storage.googleapis.com`, `cloudfront.net`, `azurewebsites.net`, `lambda-url`, `run.app`, `cloudfunctions.net`), JS bundles, and network-portscan (2375, 2376, 2379, 2380, 5000, 6443, 8001, 8080, 8443, 10250, 10255, 30000+).
3. Run the checker:

   ```bash
   python3 .agents/skills/cloud-container-audit/scripts/cloud_exposure_check.py --target example.com \
     --hosts hosts.txt --buckets buckets.txt --azure acct/container --functions fn_urls.txt \
     --out artifacts/example.com/cloud_exposure.json
   ```

4. Metadata (CC-002 to CC-004): only through an SSRF you already confirmed in ssrf-audit. Proof is reaching the metadata root or a non-secret field (instance ID, region). Never read credential paths (`iam/security-credentials/<role>`, `identity/oauth2/token`, `service-accounts/default/token`) without explicit written approval, and never use credentials.
5. Container escape (CC-007): version checks (runc, containerd, Docker, kernel) and exposure facts (privileged pod, Docker socket mounted, hostPath `/`), never exploit.
6. IAM (CC-009): if a key is found in scope, follow `references/iam_privesc.md` (identify the key owner with a read-only identity call only with approval; report and recommend rotation).
7. Databases and queues (CC-011, CC-012): check reachability and whether auth is required (one connection or one anonymous API call returning metadata); never read or write data.
8. Save findings to `artifacts/<target>/cloud_container.json` and the tracker to `artifacts/<target>/cloud_container_tracker.md`.

## Classes

- `passive`: DNS, CNAMEs, JS, public docs, CT logs, version strings.
- `bounded`: read-only GET/HEAD to status or version endpoints, anonymous bucket listing requests, one anonymous connection attempt to data services.
- `authorized-only`: reading metadata credentials, using any found key, listing cluster resources beyond `/version`, exec/attach/run on Docker or Kubernetes, writes to buckets or queues, IAM enumeration with a found key, and any escape attempt.

## Rules

- Never create containers, pods, jobs, or functions; never call `exec`, `attach`, `run`, or `logs` endpoints.
- Never download bucket contents beyond a listing proof; record object count and a few names (redact).
- Never use leaked keys. Report the location, key type and prefix (redacted), and recommend rotation.
- Stop and report at the first proof of exposure.

## Mitigation guidance for reports

- S3 Block Public Access at account level; Azure Blob `allowBlobPublicAccess=false`; GCS uniform bucket-level access and public access prevention.
- IMDSv2 required (hop limit 1), Azure/GCP metadata only from trusted workloads; block 169.254.169.254 egress from apps that fetch URLs.
- Never expose Docker (2375/2376) or Kubernetes control plane, kubelet, or etcd to the internet; require mTLS and RBAC, disable anonymous auth.
- Least-privilege IAM, no long-lived keys, rotation, SCPs/guardrails, alerts on credential use from new locations.
- Functions behind auth (IAM auth, API Gateway authorizers, Azure function keys not in clients).
- Databases and queues private (VPC/private endpoints, no public IPs), auth required, resource policies scoped.
- CDN: cache only static content by allowlist, honor `Cache-Control: private`, restrict origin access (OAC/OAI), and lock purge APIs.

## Sources

AWS, Azure, and GCP security best-practice documentation; CIS Benchmarks for AWS, Azure, GCP, Docker, and Kubernetes; OWASP Kubernetes Top 10 and Docker Security Cheat Sheet; HackTricks Cloud; Rhino Security Labs AWS privilege escalation research; MITRE ATT&CK for Cloud and Containers.
