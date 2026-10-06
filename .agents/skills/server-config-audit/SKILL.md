---
name: server-config-audit
description: Audit authorized Apache, Nginx, IIS, Tomcat, Jetty, WildFly, WebLogic, WebSphere, JBoss, GlassFish, and HTTP/2 deployments for default content, exposed modules and consoles, unsafe headers, routing weaknesses, and protocol misconfiguration. Uses passive or bounded verification by default; credential attempts, state changes, denial-of-service, flood, and smuggling tests require separate authorization or an isolated lab.
---

# Server Configuration Deep Audit

Evaluate server configuration without converting a misconfiguration review into an availability test. Inherit hosts and ports from `techfingerprint`, `network-portscan`, or `artifacts/live_subdomains.txt`, then run only checks applicable to the detected server/protocol stack.

## Execution classes

- **P — Passive:** existing headers, TLS/ALPN, DNS, version evidence, or one ordinary GET/HEAD/OPTIONS request.
- **B — Bounded active:** at most three low-impact requests per variation to an idempotent endpoint, with conservative timeouts and no concurrency burst.
- **C — Credential-gated:** one login attempt only when the asset owner explicitly authorizes it, identifies a disposable test account, supplies its credential pair, confirms lockout/MFA/session side effects are acceptable, and approves the test window. Never automatically try well-known defaults such as `tomcat/tomcat`, `weblogic/weblogic`, `admin/admin`, or `admin/adminadmin`. Never store the supplied secret.
- **M — Mutation-gated:** requires explicit authorization, a disposable canary resource, a documented cleanup plan, and confirmation that no production data is affected. WebDAV write validation belongs here.
- **L — Lab/configuration only:** inspect versions, configuration, mitigations, and vendor advisories in production. Execute malformed-frame sequences, floods, compression exhaustion, rapid resets, cache injection, request smuggling, or resource-starvation payloads only in an isolated replica or owner-operated staging environment.

Authorization for ordinary reconnaissance does not authorize C, M, or L execution. If the required environment or permission is absent, mark the row `CONFIG_REVIEW`, `LAB_REQUIRED`, or `BLOCKED`; do not improvise a live test.

## Workflow

1. **Inherit and profile targets.** Correlate hostname, address, port, scheme, server header, TLS certificate, ALPN protocol, reverse proxy/CDN, and backend fingerprint. Avoid attributing an edge response to an origin server without evidence.
2. **Collect a baseline.** Save status, headers, redirect chain, title, content length, body hash, TLS/ALPN, and HTTP version for `/` plus a random nonexistent path. This separates default pages and custom error templates from real exposures.
3. **Run applicable server checks.** Follow [references/checklist_102.md](references/checklist_102.md). Preserve exact request/response evidence and identify whether the result came from the edge, proxy, or application server.
4. **Evaluate security headers contextually.** HSTS applies only over HTTPS; CSP and frame protections depend on the content served; CORS requires origin-specific behavior and credential analysis. Missing headers are not automatically vulnerabilities.
5. **Handle administrative surfaces safely.** Verify reachability and authentication boundaries. Do not enumerate users, brute-force, change configuration, deploy applications, or invoke administrative actions.
6. **Assess HTTP/2 in two stages.** Production testing is limited to negotiation, advertised settings, a small number of standards-conformance requests, and passive configuration/version evidence. All availability, flood, compression, stream-exhaustion, cache-poisoning, and proxy-desynchronization cases remain lab-only.
7. **Report evidence, not tool output.** A scanner match, server banner, or generic error is a lead. Confirm behavior manually within the row's execution class and record false positives.

## Coverage and status rules

Create one checklist row for every `(target, check_id)` pair. All 102 IDs must appear for every target, including checks that are not applicable. Report both distinct-check coverage (`102/102`) and target coverage (`completed rows / target_count × 102`). Aggregation is allowed only when the targets, evidence, and result are identical and the row explicitly lists every covered target.

- `PASS` — the check is applicable, was safely executed to its permitted class, and affirmative negative evidence was saved.
- `FINDING` — reproducible security impact was demonstrated within the permitted class and request/response evidence was saved.
- `INFO` — an exposure or configuration was confirmed without demonstrated material impact.
- `NOT_APPLICABLE` — the required server, module, protocol, or route is absent, supported by fingerprint evidence.
- `CONFIG_REVIEW` — runtime behavior cannot establish the result, but relevant version/configuration/advisory evidence was reviewed.
- `LAB_REQUIRED` — proving the stated condition requires L execution and no authorized isolated lab was supplied.
- `BLOCKED` — an otherwise applicable safe check could not run because of scope, authentication, authorization, tooling, or runtime error.

Scanner silence, banner absence, or an unexecuted C/M/L portion can never produce `PASS`. For mixed-class rows, record `performed_class` and `untested_class`. A passive observation cannot pass a claim such as writable, overflow, manipulation, injection, exhaustion, or denial of service when its gated portion was not executed; use `INFO`, `CONFIG_REVIEW`, `LAB_REQUIRED`, or `BLOCKED` as appropriate.

Reachability of a default page, console, docs/examples application, a missing response header, or an advertised HTTP/2 numeric setting is normally `INFO`. Promote it to `FINDING` only when intended policy or concrete sensitive/actionable impact is established. A version-only CVE match remains `CONFIG_REVIEW` until the affected build and relevant configuration are established.

## Evidence hygiene

Timestamp evidence and record tool versions. Redact cookies, authorization values, CSRF tokens, test credentials, personal data, client addresses from status pages, and unnecessary filesystem paths. Store only the minimum response body needed; prefer a hash plus a short redacted excerpt. CORS credential checks must use a synthetic test session, and Origin/Host variations must remain within allowlisted domains—never use real-user cookies or third-party callback domains.

## Stop conditions

Stop active testing immediately on elevated latency, connection errors above baseline, 5xx spikes, rate limiting, instability, or scope ambiguity. Never continue a protocol stress test to “prove” denial of service. Do not test shared CDN/proxy infrastructure unless it is explicitly included.

## Required artifacts

- `artifacts/server_config/target_inventory.tsv`
- `artifacts/server_config/baselines.jsonl`
- `artifacts/server_config/checklist_102.tsv`
- `artifacts/server_config/http_evidence/`
- `artifacts/server_config/http2_settings.jsonl`
- `artifacts/server_config/credential_checks.tsv`
- `artifacts/server_config/server_configuration_report.md`

The checklist TSV must include `check_id`, `status`, `execution_class`, `performed_class`, `untested_class`, `target`, `applicability_evidence`, `evidence_paths`, `finding_id`, and `notes`. Cross-reference a single finding when multiple rows expose the same root cause.
