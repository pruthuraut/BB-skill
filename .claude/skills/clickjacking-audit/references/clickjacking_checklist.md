# Clickjacking Checklist

Class key: `passive` = headers, meta tags, and scripts read only. `bounded` = GET with your own session; PoCs opened in your own victim profile acting on your own account. `authorized-only` = real users, or chains needing another vulnerability on the target origin.

A **finding** is a sensitive action completed on your own victim account through a framed page in a current browser.

## Core checks (10)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CJ-001 | Framing | Target page can be embedded in a cross-origin iframe | bounded | clickjack_check.py, then open the generated PoC from localhost in your victim profile; page renders |
| CJ-002 | X-Frame-Options | XFO missing, or value not `DENY` / `SAMEORIGIN` (invalid, `ALLOW-FROM`, typo, multiple values) | passive | Read the header; `ALLOW-FROM` is ignored by modern browsers, so treat as missing unless CSP covers it |
| CJ-003 | CSP | CSP `frame-ancestors` missing, `*`, broad (`https:`, `*.example.com` with weak subdomains), only in meta tag, or only in Report-Only | passive | Parse CSP and CSP-Report-Only; meta-tag frame-ancestors is ignored by browsers |
| CJ-004 | Same origin | `SAMEORIGIN` / `'self'` bypass by framing from a same-origin page that the attacker can influence (user HTML, uploaded HTML/SVG, XSS, open iframe gadget, preview pages) | authorized-only | Identify same-origin content you can control on your own account; report the chain |
| CJ-005 | Drag and drop | Drag-and-drop clickjacking for data exfiltration (victim drags a token or text out of the framed page, or drops attacker content into a framed field) | bounded | Own victim: PoC with draggable decoy; record browser support (many browsers restrict cross-origin drag) |
| CJ-006 | Cursor | Cursorjacking: hidden real cursor and fake cursor offset so the click lands elsewhere | bounded | Own victim: cursor-offset PoC; confirm click lands on the framed button |
| CJ-007 | Multi-step | Multi-step clickjacking (action needs 2+ clicks, for example "Delete" then "Confirm") | bounded | Own victim: PoC moves the decoy between clicks |
| CJ-008 | Sensitive actions | Clickjacking on sensitive buttons: delete account, disable 2FA, role change, add user, authorize app, payment approve, privacy change, API key | bounded | Own victim: complete the action, then restore |
| CJ-009 | Authentication | Clickjacking on auth pages: login (login CSRF via framed form), SSO, OAuth authorize/consent, MFA enroll, password reset confirm, account linking | bounded | Own accounts: frame the consent page and approve an own test client |
| CJ-010 | Overlay | Transparent iframe over decoy content (opacity 0 to 0.0001, z-index, pointer alignment) | bounded | PoC with opacity slider; confirm the click reaches the framed page |

## Variants and bypasses

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CJ-V-001 | Coverage | Header present on main page but missing on some routes, methods, query variants, or error pages (404, 500) | passive | Run the checker on a route list including error pages |
| CJ-V-002 | Coverage | Alternate hosts (mobile, legacy, staging, regional, API-rendered HTML) without the header | passive | Same page on each host |
| CJ-V-003 | Headers | Duplicate or conflicting XFO headers (`DENY, SAMEORIGIN`, two headers) | passive | Browsers may ignore invalid combined values; record exact raw headers |
| CJ-V-004 | Headers | XFO set via `<meta http-equiv>` (ignored by browsers) | passive | Checker flags meta XFO |
| CJ-V-005 | CSP | frame-ancestors only in `Content-Security-Policy-Report-Only` | passive | Checker flags report-only |
| CJ-V-006 | CSP | frame-ancestors allows a host you can place content on (third party, user subdomain, `http:` scheme) | bounded | List allowed sources; check hosting possibilities |
| CJ-V-007 | Proxy/CDN | Header added by app but stripped by CDN or proxy for some paths, or only on 200 responses | passive | Compare cached vs uncached, compressed vs not |
| CJ-V-008 | Frame-busting | JavaScript frame-buster (`if (top != self) top.location = self.location`) bypassed by `sandbox="allow-forms allow-scripts"` without `allow-top-navigation` | bounded | Sandbox PoC; note forms may still submit |
| CJ-V-009 | Frame-busting | Frame-buster bypassed by `onbeforeunload` cancel, double framing, or a `204` navigation trick in older browsers | bounded | Record browser and version |
| CJ-V-010 | Frame-busting | CSS `display:none` anti-framing defeated when JS is disabled in the sandbox (`sandbox` without `allow-scripts` but page still usable) | bounded | Sandbox without scripts; check if the action works |
| CJ-V-011 | Double-clickjacking | Popup and double-click swap: decoy asks for a double-click, the first click switches the opener to the target page, the second click lands on its button; bypasses XFO and CSP because no frame is used | bounded | Own victim, own OAuth client or settings page; record browser |
| CJ-V-012 | Prefill | Form fields prefilled from URL parameters, so a framed page needs only a click (email change, share target, payment amount) | bounded | Own victim: frame URL with parameters; submit |
| CJ-V-013 | Keystrokes | Keystroke hijacking: decoy asks the victim to type; focus moves into the framed input | bounded | Own victim; harmless text only |
| CJ-V-014 | Likejacking | Social buttons (follow, like, share, subscribe) frameable | authorized-only | Own accounts only; never on public feeds with real users |
| CJ-V-015 | File | Filejacking or upload dialog triggered in frame | bounded | Own victim, harmless file |
| CJ-V-016 | Cookies | Session cookie `SameSite=None` (framed page loads logged in) vs Lax/Strict (loads logged out) | passive | Record cookie attributes; impact depends on this |
| CJ-V-017 | Cookies | Third-party cookie blocking or partitioning in current browsers prevents logged-in frames | passive | Test in Chrome, Firefox, and Safari; record which loads logged in |
| CJ-V-018 | Auth | Token-in-URL auth (magic links, embedded SSO) makes the framed page authenticated even without cookies | bounded | Own victim links only |
| CJ-V-019 | OAuth | OAuth consent page frameable: one click grants an attacker client access | bounded | Own client, own accounts; revoke after; see oauth-sso |
| CJ-V-020 | Browser ext | Pages rendered inside extensions, Electron, or WebViews with no frame protection | bounded | Own app install |
| CJ-V-021 | Mobile | Mobile web or in-app WebView pages frameable (tapjacking) | bounded | Own device |
| CJ-V-022 | Same origin | Nested framing: attacker frames a same-origin page that frames the sensitive page (SAMEORIGIN checks only the parent in some older browsers) | authorized-only | Report with browser version |
| CJ-V-023 | Chain | Clickjacking + self-XSS (victim pastes or clicks to trigger self-XSS in frame) | authorized-only | Own account only |
| CJ-V-024 | Chain | Clickjacking + CSRF-protected form (token is in the framed page, so the click is valid) | bounded | See csrf-audit XSRF-B-035 |
| CJ-V-025 | Detection | Page is frameable but has `pointer-events` or visibility checks (IntersectionObserver v2) | bounded | Note whether the action is disabled when obscured |

## Severity guide

| Situation | Typical severity |
|---|---|
| One-click account takeover path (email change prefilled, OAuth consent, link account) | High |
| One or two clicks: delete account, disable 2FA, add admin, transfer, change privacy | Medium to high |
| Multi-step with typing or unpredictable values | Low to medium |
| Social actions (like, follow) | Low |
| Frameable page with no sensitive action, or frame loads logged out in all current browsers | Informational |

## Cross-references

| CJ row | Related rows |
|---|---|
| CJ-001, CJ-002, CJ-003 | csrf-and-headers-audit CLICK-001, CLICK-002, CSP-001 |
| CJ-V-024 | csrf-audit XSRF-B-035 |
| CJ-009, CJ-V-019 | oauth-sso consent rows |
| CJ-V-016 | session-management cookie rows |
| CJ-004, CJ-V-023 | xss |
