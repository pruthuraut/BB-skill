---
name: xss
description: Audit authorized applications for cross-site scripting across 60 checks — reflected (URL params, headers, error pages, paths, numeric/cookie/locale fields), stored (UGC, uploads, SVG/XML, Markdown/WYSIWYG, emails, PDF renderers, cache poisoning), blind (own callback host), DOM-based (sources/sinks, postMessage, DOM clobbering, prototype pollution), framework injection (AngularJS sandbox escape, Vue, React dangerouslySetInnerHTML), mXSS/sanitizer bypass, context breakouts (attributes, hidden inputs, JS strings, template literals), event-handler/javascript:/data:/srcdoc/base/form/meta/object/embed/MathML/SVG-animate/autofocus vectors, entity/Unicode/UTF-7/UTF-16 and WAF bypasses, CSP analysis and dangling markup, XSSI/JSONP leakage, content-type confusion, self-XSS chaining and safe impact demonstration. Built on PortSwigger XSS labs, cheat sheet and research, OWASP WSTG INPV-01/02 and client-side testing, the OWASP XSS prevention and filter-evasion cheat sheets, PayloadsAllTheThings, HackTricks and community payload collections.
---

# Cross-Site Scripting (XSS)

Find every place where input you control ends up in a page, script, style, URL or DOM sink without encoding that fits its context. Prove execution with `alert(document.domain)` in your own browser and accounts, and show realistic impact between your own test accounts. Never use real users' sessions or data.

Primary methodology sources:

- PortSwigger Web Security Academy:
  - Topics: *Cross-site scripting* (reflected, stored, DOM-based, contexts, CSP, dangling markup), the *XSS cheat sheet*, *DOM-based vulnerabilities* (web messages, DOM clobbering), *Prototype pollution*, *Web cache poisoning*
  - Research by Gareth Heyes on AngularJS sandbox escapes, parentheses-less XSS and Vue gadgets
  - DOM Invader
- OWASP:
  - WSTG v4.2 **WSTG-INPV-01** Reflected and **WSTG-INPV-02** Stored XSS
  - WSTG **4.11 Client-side Testing**: DOM XSS, JavaScript execution, HTML injection, client-side URL redirect, CSS injection, web messaging, cross-site script inclusion
  - Cheat sheets: *Cross Site Scripting Prevention*, *DOM based XSS Prevention*, *XSS Filter Evasion*
- Community payload collections:
  - PayloadsAllTheThings *XSS Injection*, HackTricks XSS / XSSI
  - brutelogic (KNOXSS, limited-input XSS), s0md3v AwesomeXSS, terjanq Tiny-XSS-Payloads, RenwaX23 XSS-Payloads, payloadbox
  - Securitum/Bentkowski mXSS research, ardern.io blind XSS
  - Bugcrowd's "Ultimate guide to finding and escalating XSS"
  - The community tips supplied with this skill: [references/community_payloads.md](references/community_payloads.md)
- CWE-79, CWE-80, CWE-83, CWE-87, CWE-116

## Execution classes and safety boundary

Pass the scope gate before any request. Every check states the classes it may use:

| Class | Allowed actions | Requirement |
|---|---|---|
| **R** reflect-proof | Inert alphanumeric canaries and special-character probes; context mapping; reading JS/CSP offline | Default for in-scope targets |
| **E** execute | `alert(document.domain)` / `print()` in **your own** browser session; reflected and DOM payloads delivered only to yourself | Default once R shows a fitting context |
| **S** stored | Persisting a payload in content other users can load | Prefer content only your accounts can see. If it must be public, use an interaction-required, harmless payload, record where it is, and delete it right after confirming. Some programs forbid public stored payloads, so check |
| **B** blind | Payloads that call back to **your own** host from staff, back-office or third-party views | Program must allow blind XSS. `probe.js` collects URL, referrer, title and user agent only. No cookies, storage, DOM dumps, screenshots or keystrokes. Report the hit and stop. Never browse or act inside the admin context |
| **I** impact demo | Reading a CSRF token, performing an action, reading data across accounts | Only between your own test accounts (A's payload, B as victim). Never against real users or staff sessions |

Hard rules:
- No worms or self-propagating payloads, no phishing content shown to real users, no defacement, no redirects of real traffic.
- No third-party collector URLs, numeric-IP callbacks or `xss.ht`/`js.rip`/`xss.report` IDs copied from public notes. Use your own host.
- Do not search for other researchers' collector domains to discover programs.
- Cache-poisoning checks use a unique cache buster, so only your own cache key is ever poisoned.
- Rate ≤ 2 req/s. Scanners (dalfox, XSStrike, KNOXSS) only on scope-checked targets, with delays, and only if the program allows automated scanning.

## Inputs

1. `artifacts/discovered_parameters.json`, `artifacts/discovered_endpoints.txt`, HARs (`artifacts/flows/*.har`). Candidate parameters, plus hidden ones via Arjun/x8 and `wordlists/params.txt`. Favour `q`, `search`, `s`, `query`, `keyword`, `name`, `message`, `comment`, `title`, `redirect`, `url`, `next`, `return`, `callback`, `lang`, `color`, `theme`, `page`, `id`, `error`, `msg`.
2. `artifacts/js/` (from `jsrecon`): downloaded and de-minified bundles for DOM analysis. `artifacts/technology_profile.json` gives framework and library versions, CSP and WAF.
3. Two self-owned accounts (A attacker, B victim), a role ladder if one exists, and your own blind-XSS host.
4. Rendering features: comments/posts/reviews, profile fields, uploads (images, SVG, documents), Markdown/WYSIWYG editors, HTML emails and notifications, PDF/report exports, admin/support views, chat, search, error pages.

## Workflow

1. **Map reflections.** Use `xss_reflect.py` on every parameter, header and body field, with `--follow-url` for stored and second-order reflections. Record each context and the characters that survive in `artifacts/xss/reflection_map.md`.
2. **Map the DOM.** Run `dom_sinks.py` over JS bundles, then confirm the source→sink flows with DOM Invader (canary, sinks, `postMessage`, prototype pollution, DOM clobbering).
3. **Check defences.** `csp_analyze.py` covers CSP, nosniff, Trusted Types and HttpOnly (XS-46). This decides which vectors matter.
4. **Choose payloads per context.** Use `xss_payloads.py --context X --allowed CHARS`. Escalate to bypass families only when needed (XS-F), and only if the program allows it.
5. **Stored and blind.** Use files from `xss_files.py` (SVG/XML/HTML/Markdown/PDF/filenames). Blind payloads are labelled per field, served from your own `bxss_listener.py`.
6. **Cross-origin leakage.** Run `xssi_check.py` on JS/JSONP endpoints (XS-51).
7. **Confirm and assess impact** (XS-60). Use a real browser and A→B accounts, and note HttpOnly, CSP, the role of the viewer and interaction required. Clean up stored payloads.
8. **Report** with the exact request, rendered context, browser/version, screenshots, cleanup, and progress `[ N / 60 ]`.

## Subagent split

| Subagent | Focus | Checks |
|---|---|---|
| **XS-A** Reflection Surfaces | URL params, all occurrences, headers, upload filenames, error pages, context mapping, attribute/hidden-input tricks, JS-string breakouts, path reflection, split/length-limited, unexpected fields, device/locale variants | 01, 04, 05, 06, 18, 41, 42, 43, 53, 54, 55, 56 |
| **XS-B** Stored, Blind & Rendering Pipelines | UGC, SVG uploads, Markdown/WYSIWYG, SSTI→XSS, HTML emails, blind callbacks, self-XSS chains, PDF renderers, cache poisoning | 02, 07, 08, 09, 27, 28, 29, 30, 57 |
| **XS-C** DOM, Frameworks & Cross-Origin | DOM sources/sinks, JSON→HTML, AngularJS, Vue, React/Angular/Svelte escape hatches, mXSS, template literals, postMessage, DOM clobbering, prototype pollution, XSSI/JSONP, vulnerable libraries | 03, 17, 23, 24, 25, 26, 33, 48, 49, 50, 51, 59 |
| **XS-D** Element & Event Vectors | event handlers, SVG/XML namespaces, iframe srcdoc, MathML, object, embed, SVG animate/set, autofocus | 10, 13, 19, 32, 35, 36, 39, 40 |
| **XS-E** URL, Navigation & Scriptless | javascript:, data:, base tag, form action, meta refresh, href, style attribute, CSS @import, redirect→XSS, dangling markup | 11, 12, 20, 21, 22, 34, 37, 38, 47, 58 |
| **XS-F** Bypass, CSP & Impact | entity/Unicode/legacy IE/charset encodings, filter logic, WAF classes, CSP analysis, content-type confusion, impact escalation | 14, 15, 16, 31, 44, 45, 46, 52, 60 |

## Status values

- `PASS`: every reflection and sink tested is encoded or sanitised for its context. Evidence saved.
- `FINDING`: execution confirmed in a current browser (state which one), at the stated class.
- `INFO`: HTML injection without script, a reflection blocked only by CSP, missing defence headers, or self-XSS with no chain found.
- `GATED`: stored, blind or impact class not run for lack of permission. Expected impact described.
- `NOT_APPLICABLE`: the feature, framework or browser is absent (e.g. IE-only vectors). Evidence cited.
- `BLOCKED`: WAF, rate limit, scope or tooling prevented testing.

## Severity guidance

| Condition | Typical severity |
|---|---|
| Stored or blind XSS executing in admin/staff views; stored XSS on high-traffic pages; XSS leading to account takeover (token readable, or a CSRF-protected action performed) | High–Critical |
| Reflected or DOM XSS without user interaction beyond visiting a link, on the main application origin | Medium–High |
| XSS needing significant interaction (hover, keypress, accesskey), on a sandbox domain, or blocked from impact by CSP/HttpOnly | Low–Medium |
| XSSI / JSONP leaking personal data or tokens | Medium–High |
| HTML injection, scriptless form/meta/base injection without XSS | Low–Medium |
| Self-XSS without a chain; legacy-browser-only (IE, UTF-7) vectors | Informational / Low |

## Helper scripts

```bash
S=.agents/skills/xss/scripts

# Scope-gated reflection & context analyser (inert canaries only; ranks payloads that fit)
python3 -I $S/xss_reflect.py --target example.com --url 'https://app.example.com/search?q=x&lang=en' --all-params
python3 -I $S/xss_reflect.py --target example.com --url 'https://app.example.com/api/profile' --data 'bio=FUZZ' \
  --follow-url 'https://app.example.com/u/me'
python3 -I $S/xss_reflect.py --target example.com --url 'https://app.example.com/' --header 'Referer: FUZZ'

# Offline: context-aware payloads (TSV), filtered by characters that survive
python3 -I $S/xss_payloads.py --context attr-dq --allowed '"= ()/' --families autofocus,events,noparen
python3 -I $S/xss_payloads.py --context url-attr
python3 -I $S/xss_payloads.py --context html --families waf,mxss,csti,scriptless --scriptless-host YOUR.HOST

# Offline: DOM sources/sinks, postMessage without origin checks, clobbering/prototype-pollution hints
python3 -I $S/dom_sinks.py artifacts/js/ --min-score 2

# Offline: CSP / header analysis
python3 -I $S/csp_analyze.py --har artifacts/flows/all.har

# Scope-gated: XSSI / JSONP (with and without YOUR session; PoC page for your own session)
python3 -I $S/xssi_check.py --target example.com --urls artifacts/xss/js_endpoints.txt --auth-header 'Cookie: session=YOURS'

# Offline: upload/render test files + blind payloads and minimal probe for your own host
python3 -I $S/xss_files.py --out artifacts/xss/files --callback https://bx.YOUR-DOMAIN
python3 -I $S/bxss_listener.py --dir artifacts/xss/files --port 8000 --bind 127.0.0.1   # put your TLS proxy in front
```

Related tools: Burp Suite (Repeater, Intruder with the PortSwigger cheat-sheet tag/event lists, DOM Invader, Reflector), dalfox (`--skip-bav --delay 500`), XSStrike, KNOXSS, `gau`/`waybackurls` + `gf xss` + `kxss`/`Gxss` for candidate triage, ParamSpider, Retire.js, Google CSP Evaluator, self-hosted XSS Hunter or interactsh.

## Required artifacts

- `artifacts/xss/reflection_map.md` and `artifacts/xss/reflect*.tsv` / `.json`
- `artifacts/xss/dom_sinks.tsv`, `artifacts/xss/xssi/xssi.tsv`
- `artifacts/xss/evidence/XS-XX_<short>.{txt,png}`: request, rendered context, browser and version, screenshot
- `artifacts/xss/stored_payloads.md`: where every stored or blind payload was placed, its label, and when it was removed
- `artifacts/xss/blind_hits.jsonl` (from your listener)
- `artifacts/xss/xss_checklist_60.tsv` with columns `check_id  status  class_performed  class_untested  severity  finding_id  evidence_path  notes`
- `artifacts/xss_report.md`: findings, impact (A→B), CSP/HttpOnly context, cleanup, `[ N / 60 ]`

## Related skills

- `linkparamdiscovery` / `contentdiscovery`: parameters, endpoints, hidden inputs. `jsrecon`: bundles and source maps for XS-C.
- `techfingerprint`: framework and library versions, WAF. `server-config-audit`: headers, error pages.
- `session-management`: HttpOnly/SameSite and token storage, which feed XS-60. `authbypass` AB-39/AB-40: stored and blind XSS via registration fields and public forms.
- `sqli`: shared triage string. `ssrf-audit` / `path-traversal`: PDF renderer file and URL access (XS-30).
- `api-security`: JSON/GraphQL fields rendered later. `idor`: reflected IDs.
- CSRF is its own category. Here it appears only as XSS impact (token theft, XS-60) and as a self-XSS chain (XS-29).

## Authorization Gate (applies to every run)

Before any active step (HTTP requests, uploads, stored or blind payloads, scanner runs, or verification of a finding), the target must pass the shared scope gate:

```bash
scripts/scope_check.sh TARGET_DOMAIN
```

- The target must have its own `scope.txt` under `~/Documents/bugbounty/TARGET_DOMAIN/` with `authorized-by:`, `date:`, and in-scope lines. Nothing is assumed authorized, and a target named in a prompt is not authorization.
- Classes S, B and I need the program to allow them in addition to the scope gate. Record that permission in the report.
- If the gate fails, stop the active steps and report the failure. Passive, offline and read-only analysis of artifacts already collected (JS bundles, HARs, CSP headers) may continue.
- Runners that take `--target` run the same gate and refuse to start otherwise. `bxss_listener.py` runs on your own infrastructure and sends nothing to targets.
