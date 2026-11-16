# SSRF Extension (extension)

Use an OOB callback host you control for the first test of each sink. Internal-address probes use a single request per target and only addresses inside the approved scope.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSRF-X-001 | Generic | Fetch parameter reaches OOB host | bounded | `?url=https://<oob-host>/x` and check callback |
| SSRF-X-002 | Generic | Internal service reachable (127.0.0.1 and private ranges) | bounded | Compare response for 127.0.0.1:<port> vs closed port; timing delta, no payloads |
| SSRF-X-003 | Generic | DNS rebinding bypasses hostname allowlist | bounded | Your rebinding domain, approved; one request |
| SSRF-X-004 | Generic | Allowlist check on hostname only (`evil.com#target.com`) | bounded | Parser differential variants |
| SSRF-X-005 | IMDS | AWS IMDSv1 reachable through SSRF | bounded | GET `http://169.254.169.254/latest/meta-data/` (listing only, no credential path) |
| SSRF-X-006 | IMDS | IMDSv2 token required | bounded | Token request from the SSRF vector should fail for IMDSv2 |
| SSRF-X-007 | IMDS | GCP metadata with Metadata-Flavor header | bounded | `http://metadata.google.internal/computeMetadata/v1/` listing only |
| SSRF-X-008 | IMDS | Azure IMDS | bounded | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with Metadata: true |
| SSRF-X-009 | Port scan | Internal port fingerprint by timing | bounded | Limited port list, one request each |
| SSRF-X-010 | Image proxy | Image URL fetch from internal host | bounded | OOB host first |
| SSRF-X-011 | Webhooks | Webhook URL accepts internal hosts | bounded | Own webhook receiver config, internal IP check on own tenant |
| SSRF-X-012 | Renderers | PDF or HTML renderer fetches attacker URL | bounded | OOB host in HTML marker |
| SSRF-X-013 | Imports | CSV or XLSX WEBSERVICE or IMPORTXML fetch | bounded | OOB host in own file |
| SSRF-X-014 | Egress | Outbound allowed to arbitrary hosts | bounded | Callback from server to OOB host on common ports |
| SSRF-X-015 | Schemes | file://, gopher://, dict:// accepted | bounded | file:///etc/hostname only; no gopher payloads |
| SSRF-X-016 | Redirect | 30x redirect followed to internal host | bounded | Own redirector to internal address |
| SSRF-X-017 | Blind | Blind SSRF confirmed only by OOB DNS or HTTP hit | bounded | OOB host only |
