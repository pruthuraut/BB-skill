# Jason Haddix TBHM Lecture Methodology & Attack Surface Pipeline Playbook

This reference playbook provides a systematic synthesis of the Jason Haddix Bug Hunter's Methodology (TBHM) lecture series (Lectures 1 through 8 and Advanced Notes), outlining the end-to-end attack surface discovery and verification pipeline.

---

## 1. Lecture 1 & 1stADV: Scoping, Sorting & Tooling Infrastructure

### Scoping & Classification Hierarchy
When approaching an enterprise bug bounty program, divide targets into tiered categories:
1. **Tier 1 (Main Web Apps):** Primary customer-facing web and mobile properties (highest security controls, high bounty payout).
2. **Tier 2 (SaaS & Microservices):** Subsidiary endpoints, API gateways, partner integrations (medium controls).
3. **Tier 3 (Acquisitions & Legacy Infrastructure):** Unmaintained servers, dev/staging environments, forgotten Jenkins/Jira portals (lowest controls, highest vulnerability density).

### Essential Tooling Setup
- **Reconnaissance Engine:** Go runtime (`go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
- **HTTP Verification:** `httpx` (`github.com/projectdiscovery/httpx/cmd/httpx@latest`)
- **DNS Resolution:** `shuffledns` or `puredns` with validated public resolvers.
- **Content Crawling:** `katana` and `gau` (GetAllUrls).

---

## 2. Lecture 3: Google Dorking Catalog for Hidden Attack Surfaces

Execute targeted search queries across search engines to uncover exposed administrative assets:

| Purpose | Google Dork Query |
| :--- | :--- |
| **Admin & Login Panels** | `site:target.com inurl:login OR inurl:admin OR inurl:dashboard OR inurl:portal` |
| **Staging & Dev Environments** | `site:target.com inurl:dev OR inurl:staging OR inurl:qa OR inurl:test OR inurl:uat` |
| **Exposed Documents & Spreadsheets** | `site:target.com ext:pdf OR ext:docx OR ext:xlsx OR ext:csv OR ext:txt` |
| **Configuration & Secrets** | `site:target.com ext:xml OR ext:json OR ext:env OR ext:yaml OR ext:yml OR ext:conf` |
| **Database & Backup Archives** | `site:target.com ext:sql OR ext:db OR ext:bak OR ext:zip OR ext:tar.gz` |
| **API Documentation** | `site:target.com inurl:swagger OR inurl:api-docs OR inurl:openapi OR inurl:graphiql` |

---

## 3. Lecture 4: JavaScript Mining & Link Discovery Pipeline

### Methodology
1. **Gather Live Hosts:**
   ```bash
   subfinder -d target.com -silent | httpx -silent -mc 200,301,302 > live_hosts.txt
   ```
2. **Scrape & Aggregate All URLs (`gau`, `waybackurls`, `katana`):**
   ```bash
   cat live_hosts.txt | gau --subs > all_history_urls.txt
   katana -list live_hosts.txt -silent -jc -d 3 >> all_history_urls.txt
   sort -u all_history_urls.txt -o all_history_urls.txt
   ```
3. **Deterministic Extension Sorting & Separation (from AUTOMATION2.0 & Lecture 4):**
   - **JavaScript Files:** `grep -E "\.js(\?.*)?$" all_history_urls.txt | sort -u > js_files.txt`
   - **JSON Endpoints:** `grep -E "\.json(\?.*)?$" all_history_urls.txt | sort -u > json_endpoints.txt`
   - **XML / SOAP Feeds:** `grep -E "\.xml(\?.*)?$" all_history_urls.txt | sort -u > xml_endpoints.txt`
   - **Parameterized URLs:** `grep "=" all_history_urls.txt | sort -u > params_urls.txt`
4. **Dedicated Local Bundle Storage (`artifacts/js_bundles/`):**
   - Probe live `.js` files using `httpx -l js_files.txt -mc 200 -silent > live_js_files.txt`
   - Download the raw `.js` files into `artifacts/js_bundles/` for offline static analysis, LinkFinder, AST routing recovery, and `.js.map` sourcemap unpacking.

---

## 4. Lecture 5: Active DNS Brute-Forcing & Wildcard Filtering

### The Wildcard Problem
Many organizations configure wildcard DNS records (`*.target.com IN A 1.2.3.4`). Standard brute-force tools will report millions of false positive subdomains because every arbitrary hostname resolves to the wildcard IP.

### Deterministic Wildcard Handling Procedure
1. **Probe Known Non-Existent Subdomains:**
   - Query 5 random, high-entropy subdomains:
     ```bash
     dig a-random-string-983419.target.com +short
     ```
2. **Record Wildcard Signatures:**
   - If IP addresses are returned, note the response IPs (e.g. `104.18.2.1`, `104.18.3.1`).
3. **Filter Active Brute-Force Runs:**
   - Configure DNS resolution tools (e.g. `shuffledns -m target.com -r resolvers.txt -filter-wildcard`) to discard responses that match the recorded wildcard IP signature.

---

## 5. Lecture 7: Professional Reporting & Triage Communication

When submitting verified vulnerability findings to Bugcrowd, HackerOne, or private VDPs, follow the gold standard format:
1. **Clear Title:** `[Vulnerability Type] on [Target Domain/Endpoint] leads to [Specific High-Impact Result]`.
2. **Severity Assessment:** Map directly to CVSS v3.1 vector.
3. **Executive Summary:** 2–3 sentences explaining what was found and the real-world business risk.
4. **Step-by-Step Reproduction Instructions:** Numbered, reproducible steps with exact cURL commands or Burp HTTP requests.
5. **Remediation Recommendation:** Precise configuration or code-level patch guidance.
