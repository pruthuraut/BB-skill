# Server-Side Request Forgery (SSRF) Vulnerability Audit Checklist

This checklist guides the methodical assessment of applications against Server-Side Request Forgery (SSRF) risks, cloud metadata exposure, and internal service pivoting based on TBHM Module 15 and repository notes (`9thADV-SSRF1.txt`, `SSRF-Basic.txt`).

**Progress:** `[ 0 / 25 Complete ]`

---

## Audit Matrix

| # | Check Description | Subagent | Focus / Verification Criteria | Status |
|---|-------------------|----------|-------------------------------|--------|
| **01** | Identify user-supplied URL inputs in parameters | Subagent 01 | Audit query/body params: `url=`, `dest=`, `file=`, `uri=`, `source=`, `fetch=` | `[ ]` |
| **02** | Identify webhook and callback registration endpoints | Subagent 01 | Audit integrations accepting custom notification endpoints | `[ ]` |
| **03** | Identify document, image, and PDF conversion services | Subagent 01 | Audit HTML-to-PDF, screenshot capture, and image import routines | `[ ]` |
| **04** | Identify import/export from external cloud storage | Subagent 01 | Audit file transfer routines pulling from remote S3/GCP URLs | `[ ]` |
| **05** | Identify URL preview and social sharing card generators | Subagent 01 | Audit OpenGraph / Twitter card crawler routines fetching remote metadata | `[ ]` |
| **06** | Audit AWS EC2 Metadata service (IMDS) security | Subagent 02 | Verify IMDSv2 token enforcement (`X-aws-ec2-metadata-token`) vs IMDSv1 | `[ ]` |
| **07** | Audit Google Cloud Platform (GCP) metadata headers | Subagent 02 | Verify enforcement of `Metadata-Flavor: Google` header requirement | `[ ]` |
| **08** | Audit Azure Instance Metadata Service (IMDS) security | Subagent 02 | Verify enforcement of `Metadata: true` header requirement on `169.254.169.254` | `[ ]` |
| **09** | Audit Kubernetes etcd and kubelet API exposure | Subagent 02 | Check network reachability to `127.0.0.1:2379` and `:10250` from workloads | `[ ]` |
| **10** | Audit Docker daemon API socket exposure | Subagent 02 | Check reachability to local docker socket or `127.0.0.1:2375` | `[ ]` |
| **11** | Audit internal RFC 1918 network segmentation | Subagent 02 | Verify egress firewall rules blocking requests to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | `[ ]` |
| **12** | Audit loopback interface reachability | Subagent 02 | Verify egress blocks to `127.0.0.0/8` and `::1` | `[ ]` |
| **13** | Audit non-HTTP URI scheme restriction | Subagent 03 | Ensure fetcher restricts schemes strictly to `http` and `https` (`file://`, `gopher://` disabled) | `[ ]` |
| **14** | Audit URL parser differentials | Subagent 03 | Evaluate URL parser alignment between validator and HTTP client library | `[ ]` |
| **15** | Audit alternative IP address encoding validation | Subagent 03 | Verify validator handles decimal (`2130706433`), hex (`0x7f000001`), and octal IPs | `[ ]` |
| **16** | Audit enclosed / rare alphanumeric IP encodings | Subagent 03 | Verify handling of IPv6 mapped IPv4 (`[::ffff:127.0.0.1]`) and mixed representations | `[ ]` |
| **17** | Audit HTTP redirect following behavior | Subagent 03 | Verify HTTP client does not automatically follow 301/302 redirects to internal IPs | `[ ]` |
| **18** | Audit DNS Rebinding attack resilience | Subagent 04 | Verify destination IP is re-evaluated immediately prior to socket connection | `[ ]` |
| **19** | Audit DNS Resolution Pinning | Subagent 04 | Verify application pins resolved IP for both validation and connection | `[ ]` |
| **20** | Audit Strict Hostname Allowlisting | Subagent 04 | Verify destination hostnames are matched against strict allowlists | `[ ]` |
| **21** | Audit Out-of-Band (Blind) SSRF interactions | Subagent 01 | Verify asynchronous processing pipelines (email generators, loggers) for egress queries | `[ ]` |
| **22** | Audit Network-level Egress Filtering | Subagent 04 | Verify firewall egress rules restrict outbound traffic from application tiers | `[ ]` |
| **23** | Audit Forward Proxy / DMZ Isolator architecture | Subagent 04 | Ensure outbound requests route through dedicated egress proxies with inspectable rules | `[ ]` |
| **24** | Audit Content-Type and Body size restrictions on fetch | Subagent 04 | Ensure fetchers enforce maximum byte limits and expected MIME types | `[ ]` |
| **25** | Audit Internal service authentication requirements | Subagent 04 | Verify all internal services (Redis, Elasticsearch, DBs) require mutual TLS and auth | `[ ]` |
