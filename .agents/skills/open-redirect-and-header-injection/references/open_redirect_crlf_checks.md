# Open Redirect and CRLF Injection Checklist (extension)

Class key: `passive` = source and config review. `bounded` = redirect and marker probes to your own host, capped at 40 requests. `authorized-only` = anything that writes headers at scale or affects other users.

## Open redirect

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| ORX-001 | Parameters | Redirect parameter (`?url=`, `?redirect=`) accepts an external host | bounded | `redirect_crlf_probe.py --param redirect --oob-host` |
| ORX-002 | Protocol-relative | `//evil` redirects off-site | bounded | Probe variant `//<oob>` |
| ORX-003 | Encoding | URL-encoded host passes the filter | bounded | Probe with percent-encoded host |
| ORX-004 | Encoding | Double-encoded host passes the filter | bounded | Probe with double-encoded host |
| ORX-005 | Fragment | `#` fragment hides the host from validation | bounded | Probe `https://<oob>#<own-host>` |
| ORX-006 | Userinfo | `@` symbol tricks the host check | bounded | Probe `https://<own>@<oob>` |
| ORX-007 | Backslash | Backslash accepted in place of slash | bounded | Probe `https:\\<oob>` |
| ORX-008 | Subdomain | Attacker-controlled subdomain of the target accepted | bounded | Probe `https://<own>.<oob>` |
| ORX-009 | Data URI | `data:` URI accepted in a redirect | bounded | Probe; inspect Location |
| ORX-010 | JavaScript URI | `javascript:` URI accepted in a redirect | bounded | Probe; inspect Location (no execution in production) |
| ORX-011 | Host header | Redirect built from the Host header | bounded | Own request with Host: <oob>; inspect Location |
| ORX-012 | Forwarded host | Redirect built from X-Forwarded-Host | bounded | Own request with the header; inspect Location |
| ORX-013 | OAuth | redirect_uri open or prefix-matched (see oauth-sso) | bounded | Own client; see oauth-sso checks |
| ORX-014 | SAML | RelayState used as a redirect target | bounded | Own test flow; inspect RelayState handling |
| ORX-015 | Post-login | `next` or `continue` after login redirects off-site | bounded | Own login with the parameter set to the OOB host |

## CRLF injection

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| ORX-016 | URL parameters | CRLF in a parameter reflected into headers | bounded | `redirect_crlf_probe.py --crlf-param` |
| ORX-017 | Headers | CRLF in a request header reflected into a response header | bounded | Own request header with CRLF marker |
| ORX-018 | Email headers | CRLF in contact-form fields adds headers | bounded | Own address, marker only (see email-security-audit) |
| ORX-019 | Response splitting | CRLF creates a second response | bounded | Marker probe; inspect raw response |
| ORX-020 | Header injection to XSS | Injected header carries script to a browser | authorized-only | Report only; no script payloads |
| ORX-021 | Cookie injection | CRLF adds Set-Cookie | bounded | Marker cookie name on own session |
| ORX-022 | Cache poisoning | CRLF response cached for other users | authorized-only | Cache-buster path only; approval |
| ORX-023 | Log injection | CRLF in logged fields forges log lines | passive | Review logging code and log samples |
| ORX-024 | Redirect URLs | CRLF in the Location value | bounded | Probe with marker |
| ORX-025 | Filenames | CRLF in filename parameters reaches headers | bounded | Own filename with marker |
