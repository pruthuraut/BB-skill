# Subagent 01: Core Web Profilers, Headers, Cookies & Meta Tags

## Role & Mission
Responsible for baseline automated technology profiling across passive response headers, session cookies, HTML meta tags, and CLI fingerprinting engines (WhatWeb, Webanalyze, Wappalyzer, BuiltWith).

## Assigned Checklist Tasks (8 Checks)
- **Check 01:** Wappalyzer browser extension & headless DOM stack analysis
- **Check 02:** WhatWeb CLI technology fingerprinting at scale
- **Check 03:** Webanalyze (Go-based Wappalyzer) high-speed batch profiling
- **Check 04:** HTTP response headers analysis for server version disclosure
- **Check 05:** `X-Powered-By` backend runtime identification
- **Check 06:** Cookie structure analysis for framework identification
- **Check 07:** Framework-specific HTML meta and generator tag auditing
- **Check 16:** BuiltWith API for historical technology profiling

---

## Standardized Execution Playbook

### Step 1: Automated CLI Profilers (Checks 01, 02, 03, 16)
```bash
# 1. WhatWeb deep scan (aggression level 3)
whatweb -a 3 -v --color=never https://<target> > artifacts/whatweb_report.txt

# 2. Webanalyze (Go-based Wappalyzer rules)
webanalyze -host https://<target> -crawl 2 -silent -output json > artifacts/webanalyze.json

# 3. HTTPx multi-technology and header banner extraction
httpx -u https://<target> \
  -title -server -tech-detect -status-code -content-type -websocket -cname \
  -json -o artifacts/httpx_tech.json

# 4. BuiltWith API Profiling (Check 16)
if [ -n "$BUILTWITH_KEY" ]; then
  curl -s "https://api.builtwith.com/v20/api.json?KEY=$BUILTWITH_KEY&LOOKUP=<target>" > artifacts/builtwith_profile.json
fi
```

### Step 2: HTTP Response Header Deep-Dive (Checks 04, 05)
Extract raw headers to uncover server versions, proxy chains, and backend execution layers:

```bash
curl -sIL -A "Mozilla/5.0" https://<target> > artifacts/raw_headers.txt

# Audit Server and X-Powered-By
grep -Ei "^(Server|X-Powered-By|X-AspNet-Version|X-AspNetMvc-Version|X-Generator|X-Runtime|X-Version):" artifacts/raw_headers.txt
```

### Step 3: Session Cookie Heuristics Matrix (Check 06)
Examine `Set-Cookie` directives in response headers to detect the underlying framework:

| Cookie Name | Framework / Language / Platform |
|---|---|
| `PHPSESSID` | PHP (Native session) |
| `JSESSIONID` | Java Servlet / Spring / Tomcat / JBoss |
| `ASP.NET_SessionId` | Microsoft ASP.NET |
| `__RequestVerificationToken` | ASP.NET Anti-Forgery |
| `connect.sid` | Node.js Express Session |
| `_session_id`, `_app_session` | Ruby on Rails |
| `csrftoken`, `sessionid` | Python Django |
| `session` (Base64/HMAC like `.eJ...`) | Python Flask |
| `laravel_session`, `XSRF-TOKEN` | PHP Laravel |
| `CAKEPHP` | PHP CakePHP |
| `ci_session` | PHP CodeIgniter |
| `drupal_` | Drupal CMS |
| `wp-settings-`, `wordpress_` | WordPress CMS |

```bash
# Automated Cookie Audit
grep -i "Set-Cookie:" artifacts/raw_headers.txt | tr ';' '\n' | grep -Ei "(PHPSESSID|JSESSIONID|ASP\.NET|connect\.sid|_session_id|laravel_session|sessionid)"
```

### Step 4: HTML Meta & Generator Tag Auditing (Check 07)
```bash
curl -sL https://<target> | \
  grep -iE "<meta[^>]+(generator|application-name|framework)[^>]+>" > artifacts/meta_generators.txt
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_01_core_tech.md`
