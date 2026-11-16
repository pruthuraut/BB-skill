---
name: ssrf-audit
description: Audit authorized applications for Server-Side Request Forgery across 55 checks plus a white-box appendix — URL parameters, import-from-URL, webhooks, image proxies, header/Referer and routing-based (Host header) SSRF, OAuth/OIDC/SAML fetchers, PDF/HTML renderers, SVG xlink/font-face, XXE/XInclude/XSLT, headless screenshot tools, spreadsheet WEBSERVICE/OOXML, FFmpeg/ImageMagick media; filter bypass via decimal/octal/hex/short/mixed IPs, IPv6 and mapped IPv4, Unicode/enclosed alphanumerics, wildcard DNS, DNS rebinding, 30x and open-redirect chains, URL-parser differentials (@, #, backslash, multi-host), suffix truncation, scheme switching, CRLF request splitting; cloud and container metadata (AWS/GCP/Azure/Oracle/Alibaba/DigitalOcean, ECS, Lambda, Kubernetes, Docker, Consul) with IMDSv2/header assessment; file://, gopher/dict/ldap scheme support, bounded port fingerprinting, internal admin panels, UNC/WebDAV, blind SSRF, and known SSRF-prone products. Built on PortSwigger SSRF/blind SSRF/URL-validation-bypass/routing-based labs, OWASP WSTG-INPV-19 and the SSRF Prevention cheat sheet, Orange Tsai's parser research, PayloadsAllTheThings, HackTricks and community tips.
---

# Server-Side Request Forgery (SSRF)

Find every place where the server makes a network request whose destination you influence. First prove that the server fetches from your own host. Then prove internal reach with the least sensitive response available. Stop before credentials, secrets or state changes unless the program explicitly allows them.

Primary methodology sources:

- PortSwigger Web Security Academy:
  - *SSRF*, *Blind SSRF*, the *URL validation bypass cheat sheet*, *Routing-based SSRF* (Host header), *XXE*
  - labs: basic SSRF against the local server and against back-end systems, blacklist and whitelist filters, filter bypass via open redirection, blind SSRF with out-of-band detection and with Shellshock, routing-based SSRF, SSRF via flawed request parsing, SSRF via OpenID dynamic client registration, XXE to SSRF
- OWASP: WSTG v4.2 **WSTG-INPV-19** Testing for SSRF; *Server Side Request Forgery Prevention* cheat sheet
- Research and talks:
  - Orange Tsai, *A New Era of SSRF*
  - James Kettle, *Cracking the Lens*
  - Agarri, *Server-side browsing considered harmful*
  - neex/1u.ms and rbndr.us (DNS rebinding)
  - Wallarm, *Blind SSRF exploitation*
  - Appsecco (PDF on EC2)
  - Christophe Tafani-Dereeper (AWS metadata)
- Payload references: PayloadsAllTheThings *SSRF*, HackTricks *SSRF* and *URL Format Bypass*, cujanovic/SSRF-Testing, jdonsec/AllThingsSSRF, 0xn3va SSRF and SVG cheat sheets, the "SSRF Bible"
- Supplied with this skill: the community tips and HackerOne reports, plus [references/realworld_ssrf_reproduction_guide.md](references/realworld_ssrf_reproduction_guide.md)
- CWE-918

## Execution classes and safety boundary

Pass the scope gate before any request. Every check states the classes it may use:

| Class | Allowed actions | Requirement |
|---|---|---|
| **O** out-of-band | The target fetches **your own** host (collaborator, interactsh, `ssrf_listener.py`), with labelled variants | Default for in-scope targets |
| **R** internal reach (benign) | Loopback/internal web pages and titles. Non-secret metadata: `instance-id`, `ami-id`, `hostname`, `project-id`, IAM **role name**. `/etc/hostname` or the first line of `/etc/passwd`. Version endpoints (`/version`, `/metrics`, `/health`). Bounded port differential on **one** host (≤ 30 common ports) | Default once O or a differential shows a server-side fetch |
| **S** sensitive read | IAM/ECS/managed-identity credentials, GCP/Azure tokens, `user-data`, recursive metadata dumps, k8s secrets or service-account tokens, `/proc/self/environ`, keys, configs, `actuator/env` secrets | Explicit program permission (`BB_SSRF_ALLOW_SENSITIVE=1`). If secrets appear unexpectedly: stop, do not use or test them, redact, report for rotation |
| **W** internal protocol / state change | gopher/dict/ldap to internal services (Redis, memcached, SMTP, FastCGI, MySQL, RMI), Docker/kubelet write APIs, admin actions, header-injection attacks (Shellshock) to internal hosts | Explicit permission (`BB_SSRF_ALLOW_PROTOCOL=1`), usually **report-only**. Never write crons, keys, webshells or config |
| **N** network scanning | More than one internal host, subnets, more than 30 ports | Explicit permission (`BB_SSRF_ALLOW_SCAN=1`), low rate |

Hard rules:
- **No NTLM capture.** No Responder, hash capture, cracking or SMB relay. A UNC or WebDAV connection to your own host is enough evidence.
- **No DoS.** No SSRF→DoS (heavy downloads, fan-out, slowloris through the fetcher).
- **Your own infrastructure only.** Use your own collaborator, VPS, redirector and DNS. canarytokens.org is fine without a VPS. Never use third-party webhooks or collector URLs copied from notes (for example, the Discord webhook in the supplied PHP logger belongs to someone else).
- **Mind third-party DNS services.** Wildcard and rebinding services (nip.io, sslip.io, 1u.ms, rbndr.us, localtest.me) are third-party infrastructure. For sensitive programs, prefer an A record on your own domain.
- **Rate.** ≤ 2 req/s. Webhooks and imports often retry, so do not queue thousands of deliveries.

## Inputs

1. `artifacts/discovered_parameters.json`, `artifacts/discovered_endpoints.txt`, URL archives, HARs. Grep with [references/ssrf_param_names.txt](references/ssrf_param_names.txt) (SR-31).
2. `artifacts/technology_profile.json`: cloud provider (AWS/GCP/Azure/…), container platform, proxies and service mesh (Linkerd/Envoy), products with known SSRF endpoints (Jira, Confluence, GitLab, WordPress, Next.js, Grafana).
3. Features: link previews, screenshot and PDF tools, avatars and image proxies, import and export, webhooks, integrations ("test connection"), OAuth/OIDC client registration, document and media converters, admin backup and restore.
4. Your infrastructure: a collaborator domain, `ssrf_listener.py` on a VPS (redirector, TOCTOU, timing), optionally a domain whose A records you control.

## Workflow

1. **Inventory** (SR-31): `artifacts/ssrf/surface_map.md` lists each fetcher with its input location, whether the response is reflected, async or retried behaviour, and the observed User-Agent.
2. **Confirm the fetch** (O): `ssrf_probe.py --mode oob`. Labelled variants show which URL forms and schemes the fetcher accepts. DNS-only is INFO; HTTP is SSRF.
3. **Model the filter** (SR-35): run `ssrf_probe.py --mode internal`. It groups identical block pages and flags differentials and signatures.
4. **Bypass if needed**: `ssrf_payloads.py` generates IP formats, IPv6, Unicode, DNS, rebinding, parser, scheme and redirect forms. `ssrf_listener.py` provides redirects (`/r?b64=`), TOCTOU (`/toctou`) and timing (`/slow`).
5. **Prove impact** (R): use metadata `instance-id` and role name, internal page titles, bounded ports on one host, version endpoints, benign files. Document the S/W escalation path instead of performing it.
6. **Renderers and parsers**: `ssrf_files.py` builds SVG, HTML/PDF, XXE, XInclude, XSLT, CSV/WEBSERVICE and HLS files with per-vector labels.
7. **Report** with the exact request, hit logs (source IP and User-Agent), the internal response (redacted), the gated escalation path, cleanup of webhooks and imports created, and `[ N / 55 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **SR-A** Entry Points & Discovery | URL params, imports, webhooks, image proxies, blind OOB, inventory, header/Referer, routing-based (Host), OAuth/OIDC/SAML fetchers | 01, 02, 03, 05, 18, 31, 32, 33, 51 |
| **SR-B** Document & Media Renderers | PDF generators and exports, SVG refs and font-face, XXE, headless screenshot/unfurl, spreadsheet/OOXML, FFmpeg/ImageMagick, XInclude/XSLT | 04, 06, 19, 28, 29, 47, 48, 49, 50 |
| **SR-C** Filter Bypass: IP Formats & DNS | URL encoding, IPv6, decimal, octal, mapped, hex/short/Unicode, partial encodings, IDNA, wildcard DNS | 11, 12, 13, 14, 15, 16, 36, 37, 38 |
| **SR-D** Filter Bypass: Parsers, Redirects & Rebinding | rebinding (TOCTOU and pinned), 30x redirects, method override, fragments, parser differentials, `@` userinfo, suffix truncation, scheme switching, open-redirect chains, filter modelling, CRLF splitting, HTTP/0.9/SNI | 09, 10, 17, 20, 21, 22, 26, 27, 30, 34, 35, 45, 46 |
| **SR-E** Cloud & Container Metadata | 169.254.169.254, AWS/GCP/Azure, Kubernetes, ECS/Lambda/Docker/Consul, other clouds, IMDSv2/header assessment | 08, 24, 25, 42, 43, 44 |
| **SR-F** Internal Network, Protocols & Impact | internal IPs, `file://`, non-HTTP schemes, bounded port fingerprinting, internal admin/APIs, product-specific endpoints and mesh headers, UNC/WebDAV, blind amplification, command/template injection via fetch | 07, 23, 39, 40, 41, 52, 53, 54, 55 |

White-box appendix WB-1…WB-8 (resolve-then-pin, allowlist, redirect policy, scheme restriction, egress isolation, metadata hardening, response handling, internal service auth) is assessed as `CONFIG_REVIEW` when code or infrastructure access exists.

## Status values

- `PASS`: the fetcher was tested with the relevant bypass families, and internal destinations are rejected consistently. Evidence saved.
- `FINDING`: server-side fetch to internal or arbitrary destinations proven at the stated class.
- `INFO`: DNS-only interaction, external-only SSRF with no internal reach, or a differential that could not be confirmed.
- `GATED`: escalation (S/W/N) not attempted for lack of permission. Expected impact described.
- `NOT_APPLICABLE`: the feature, cloud or product is absent. Evidence cited.
- `BLOCKED`: WAF, rate limit, scope or tooling prevented testing.
- `CONFIG_REVIEW`: white-box control assessed from code or configuration.

## Severity guidance

| Condition | Typical severity |
|---|---|
| Cloud credentials reachable (IMDSv1 role present, ECS/GCP/Azure token path reachable), RCE path via internal service (Docker API, Redis via gopher, actuator), k8s API/kubelet reachable | Critical |
| Full-read SSRF to internal network or loopback services, `file://` read, internal admin panels | High–Critical |
| Blind SSRF with a proven internal oracle (port/host differential, internal image), routing-based SSRF to internal hosts | Medium–High |
| Blind external-only SSRF (fetches arbitrary internet URLs, no internal reach), DNS-only interaction | Low / Informational (program-dependent) |
| Metadata reachable but header/method requirement (IMDSv2, GCP/Azure headers) blocks access | Informational (defence working; note it) |

## Helper scripts

```bash
S=.agents/skills/ssrf-audit/scripts

# Offline: payload families (TSV family/class/note/payload)
python3 -I $S/ssrf_payloads.py --target 127.0.0.1 --families ip,ipv6,unicode,dns
python3 -I $S/ssrf_payloads.py --target 169.254.169.254/latest/meta-data/instance-id --families redirect,rebind \
  --redirector https://YOU/r --rebind-from YOUR.PUBLIC.IP
python3 -I $S/ssrf_payloads.py --target 127.0.0.1:8080/admin --families parser --allowed-host cdn.allowed.example
python3 -I $S/ssrf_payloads.py --families metadata,scheme --collab "$COLLAB" --cloud aws,gcp,azure

# Scope-gated probe (FUZZ in --url / --data / --json / one --header)
python3 -I $S/ssrf_probe.py --target example.com --url 'https://app.example.com/fetch?url=FUZZ' --mode oob --collab "$COLLAB"
python3 -I $S/ssrf_probe.py --target example.com --url 'https://app.example.com/api/hooks' --json '{"url":"FUZZ"}' \
  --mode internal --cloud aws --candidates artifacts/ssrf/my_candidates.txt
python3 -I $S/ssrf_probe.py --target example.com --url 'https://app.example.com/fetch?url=FUZZ' --mode ports --host 127.0.0.1

# Your infrastructure: OOB logger + redirector (/r?to= or ?b64=) + TOCTOU (/toctou) + timing (/slow)
python3 -I $S/ssrf_listener.py --port 8000 --bind 0.0.0.0 --allow-redirect-host 127.0.0.1,169.254.169.254

# Offline: SVG / HTML-PDF / XXE / XInclude / XSLT / CSV-WEBSERVICE / HLS / OOXML probes with per-vector labels
python3 -I $S/ssrf_files.py --out artifacts/ssrf/files --collab "$COLLAB" [--internal-proof]
```

Probe markers: `!!` means a signature matched (metadata keys, service banners, `/etc/passwd`, win.ini, Kubernetes/Docker/Consul JSON). `~` means a status, size or time differential. Identical block pages are collapsed into one line. Credential-like responses are redacted and stop the run.

Related tools: Burp Collaborator, Collaborator Everywhere, Taborator, Param Miner (headers), interactsh-client, SSRFmap and Gopherus (W class only, report-only), Orange Tsai's Tiny URL Fuzzer, `nuclei` SSRF/OOB templates for triage, ffuf with `references/ssrf_param_names.txt`.

## Required artifacts

- `artifacts/ssrf/surface_map.md`
- `artifacts/ssrf/probe*.tsv` (every request) and `artifacts/ssrf/listener_hits.jsonl` (your host)
- `artifacts/ssrf/evidence/SR-XX_<short>.txt`: request, hit log (source IP, User-Agent), internal response with secrets redacted
- `artifacts/ssrf/cleanup.md`: webhooks, imports and integrations created, and their removal
- `artifacts/ssrf/ssrf_checklist_55.tsv` with columns `check_id  status  class_performed  class_untested  severity  finding_id  evidence_path  notes`
- `artifacts/ssrf_report.md`: findings, escalation paths (gated), defence observations (IMDSv2, header requirements, egress), `[ N / 55 ]`

## Related skills

- `linkparamdiscovery` / `contentdiscovery` / `jsrecon`: URL-taking parameters and internal hostnames. `techfingerprint`: cloud, proxy, products.
- `xss` XS-30 and `path-traversal`: headless renderers and `file://`/UNC reads (classes shared). `oauth-sso`: DCR/`request_uri`/`jwks_uri` (SR-51).
- `server-config-audit`: routing and Host-header proxies, actuator, mod_proxy (SR-33/52). `cloud-supplychain`: what leaked cloud roles could reach (report-only).
- `network-portscan`: external port inventory. Internal scanning via SSRF stays bounded here (class N).
- `access-control`: method-override and gateway-versus-backend differences (SR-20).

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, OOB payloads, webhook or import creation, internal reach tests, port differentials, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- Internal addresses reached **through** the target are covered only as far as the program allows SSRF testing. Classes S, W and N need explicit permission in addition to the scope gate. Record that permission in the report.
- If the gate fails, stop the active steps and report the failure. Passive, offline and read-only analysis of artifacts already collected may continue.
- `ssrf_probe.py` runs the same gate and refuses to start otherwise. `ssrf_listener.py` runs on your own infrastructure and sends nothing to targets.

## Extended checklist (added)

- File: `references/ssrf_extended.md` (SSRF sinks, IMDS variants, and egress checks).
- Class policy: `passive` and `bounded` rows run in scope with the limits stated in the row. `authorized-only` rows need explicit approval for that check.
- Start automatically when `scripts/route_target.py` matches a parameter or technology listed in that file.
