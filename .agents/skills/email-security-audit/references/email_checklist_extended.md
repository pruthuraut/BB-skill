# Email Security Testing Checklist (EM, 25 checks)

Extends `spf_dkim_dmarc.md` (MAIL-001 to MAIL-014). Class key: `passive` = DNS queries and public data. `bounded` = own-address form submissions, a single SMTP session to an in-scope mail server (banner, EHLO, STARTTLS, VRFY of `postmaster` and one random name). `authorized-only` = sending to third parties, relay tests with external recipients, volume tests.

Tool: `scripts/email_dns_audit.py` covers EM-001 to EM-012, EM-021, EM-023, EM-024 (DNS) and EM-017/EM-018 (SMTP, opt-in `--smtp`, scope-gated).

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| EM-001 | SPF | SPF record exists and is valid (`v=spf1`, single record, valid mechanisms) | passive | email_dns_audit.py; multiple SPF records = permerror |
| EM-002 | SPF | SPF qualifier on `all`: `-all` (fail) vs `~all` (softfail) vs `?all`/`+all`/missing (permissive) | passive | email_dns_audit.py; `~all` is acceptable only with DMARC enforcement |
| EM-003 | SPF | SPF DNS lookup limit (`include`, `a`, `mx`, `ptr`, `exists`, `redirect` ≤ 10, void lookups ≤ 2) | passive | email_dns_audit.py recursive count; >10 = permerror (SPF fails open for many receivers) |
| EM-004 | DKIM | DKIM record exists for active selectors | passive | email_dns_audit.py selector sweep; also read `DKIM-Signature: s=` from own received mail |
| EM-005 | DKIM | DKIM key length ≥ 2048 bits (1024 is weak, 512 breakable); `t=y` testing flag; revoked empty `p=` | passive | email_dns_audit.py key size |
| EM-006 | DKIM | DKIM selector enumeration (multiple selectors, old/vendor selectors with weak keys still published) | passive | email_dns_audit.py with built-in list or `--selectors` |
| EM-007 | DMARC | DMARC record exists; policy `p=reject` / `quarantine` / `none`; subdomain policy `sp=` | passive | email_dns_audit.py |
| EM-008 | DMARC | `rua` aggregate reporting destination (present, external domains authorized via `<domain>._report._dmarc.<external>`) | passive | email_dns_audit.py external-destination authorization check |
| EM-009 | DMARC | `ruf` forensic reporting destination (present, external, privacy implications) | passive | email_dns_audit.py |
| EM-010 | DMARC | `pct` enforcement percentage (< 100 lets a share of spoofed mail through) | passive | email_dns_audit.py |
| EM-011 | Spoofing | Spoofing via missing DMARC or `p=none` (combined with SPF/DKIM state) | passive | email_dns_audit.py verdict; report from DNS evidence, do not send spoofed mail |
| EM-012 | Spoofing | Spoofing via relaxed alignment (`adkim=r` / `aspf=r` with permissive subdomains or third-party senders in SPF) | passive | email_dns_audit.py alignment + include review |
| EM-013 | Forms | Email header injection in contact/feedback/invite forms (`%0d%0aBcc:`, `\nCc:` in name/subject/email fields) | bounded | Own address, benign marker; inspect delivered headers (MAIL-010, open-redirect-and-header-injection EMAIL-HDR rows) |
| EM-014 | Forms | CRLF injection in email header fields (Subject, From name, Reply-To) | bounded | Own address; `%0d%0aX-Test: em014` in each field |
| EM-015 | MIME | MIME injection in content (inject boundary `--boundary`, `Content-Type: text/html`, attachments) | bounded | Own address; check whether injected parts render |
| EM-016 | Webmail | Email content XSS in webmail clients (HTML/SVG in user-controlled email content rendered by target webmail, `mailto:`/`data:` links) | bounded | Own mailbox in the target's webmail only; xss rules; MAIL-014 version checks |
| EM-017 | SMTP | Open SMTP relay on target mail servers | authorized-only | Passive: banner and auth requirements only (`--smtp`); relay test only with written approval to an address you own |
| EM-018 | SMTP | SMTP user enumeration via VRFY / EXPN (and RCPT TO differences) | bounded | email_dns_audit.py `--smtp`: VRFY `postmaster` vs a random name, EXPN support; no wordlists |
| EM-019 | DSN | Delivery Status Notification leakage (bounce messages reveal internal hostnames, IPs, software, routing, internal addresses) | bounded | Send one message from your own address to a non-existent address at the target only if the program allows; inspect the bounce |
| EM-020 | Abuse | Email bomb via mass subscription (newsletter/signup/invite forms without CAPTCHA or confirmation used to flood a victim) | bounded | Own address, 2–3 submissions to show missing double opt-in/rate limit; resource-exhaustion rules |
| EM-021 | CAA | CAA DNS record (which CAs may issue; `iodef` contact) | passive | email_dns_audit.py |
| EM-022 | Tracking | Link rewriting and tracking pixels leak data (tokens in tracked links, reset links passed through third-party redirectors, pixels with user IDs/emails) | bounded | Own received mail: inspect link hosts, query params, pixel URLs; data-exposure-audit DE-018/DE-020 |
| EM-023 | BIMI | BIMI record (`default._bimi`, `v=BIMI1`, `l=` SVG, `a=` VMC) — requires DMARC enforcement | passive | email_dns_audit.py |
| EM-024 | Subdomain MX | Subdomain mail misconfiguration (subdomains without SPF/null MX and weak `sp=`, MX pointing to dangling or third-party hosts, mail hosts on decommissioned services) | passive | email_dns_audit.py `--subdomains`; subdomain-takeover for dangling MX |
| EM-025 | Auto-reply | Auto-reply information disclosure (out-of-office/ticket auto-replies reveal names, phone numbers, internal ticket IDs, systems, other addresses) | bounded | One message from your own address to a published contact address (if allowed); inspect the reply |

## Common DKIM selectors (built into email_dns_audit.py)

`default`, `dkim`, `mail`, `email`, `selector1`, `selector2` (Microsoft 365), `google` (Google Workspace), `k1`, `k2`, `k3` (Mailchimp/Mandrill), `s1`, `s2` (SendGrid), `smtpapi`, `mxvault`, `mandrill`, `mailjet`, `pm` (Postmark), `zendesk1`, `zendesk2`, `amazonses`, `ses`, `sig1`, `everlytickey1`, `everlytickey2`, `dkim1024`, `20161025`, `20210112`, `20230601`, `fm1`, `fm2`, `fm3` (Fastmail), `protonmail`, `protonmail2`, `protonmail3`, `mx`, `smtp`, `key1`, `key2`, `hs1`, `hs2` (HubSpot), `cm` (Campaign Monitor), `mailgun`, `krs` (Mailgun).

## Spoofability verdict (email_dns_audit.py)

| SPF | DMARC | Verdict |
|---|---|---|
| Any | missing | Spoofable (no policy) |
| Any | `p=none` | Spoofable (monitoring only) |
| Any | `p=quarantine`/`reject` with `pct<100` | Partially spoofable |
| `+all`/`?all`/permerror | enforced | Spoofing blocked by DMARC only if DKIM/SPF alignment fails as expected; review |
| `-all`/`~all` | `p=reject`, `pct=100` | Not spoofable via direct domain |
| Subdomains | `sp=none` or missing `sp` with `p=none` | Subdomains spoofable |

## Cross-references

| EM rows | Related |
|---|---|
| EM-001 to EM-003 | MAIL-001, MAIL-002 |
| EM-004 to EM-006 | MAIL-005 |
| EM-007 to EM-012 | MAIL-003, MAIL-004, MAIL-009 |
| EM-013, EM-014 | MAIL-010, open-redirect-and-header-injection |
| EM-016 | MAIL-014, xss |
| EM-017 | MAIL-012, MAIL-013 |
| EM-020 | resource-exhaustion |
| EM-022 | data-exposure-audit |
| EM-024 | MAIL-006, subdomain-takeover |
