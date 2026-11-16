---
name: postmessage-audit
description: Audit authorized web applications for window.postMessage security across 10 core checks — handlers without origin checks, weak origin validation (indexOf, includes, startsWith, endsWith, unanchored regex, null), sensitive data posted to window.parent or opener, wildcard targetOrigin, data injection from external windows, XSS through message content (innerHTML, eval, location, jQuery, document.write), missing event.source validation, cross-subdomain trust, iframe communication channels (OAuth/SSO popups, payment and chat widgets, SDK bridges), and browser-extension messaging — plus variant rows (MessageChannel ports, BroadcastChannel, JSON.parse prototype pollution, origin "null" from sandboxed frames, race on load, redirect-based token leaks). Includes a passive JS scanner and PoC templates. Triggers on "postMessage", "message event", "addEventListener('message')", "event.origin", "targetOrigin", "window.opener", "iframe communication", "cross-window messaging", "extension messaging", or when jsrecon finds message listeners.
---

# postMessage Security (10 core checks + variants)

`postMessage` lets windows on different origins talk. Two directions can break:

- **Receiving:** a `message` listener that does not verify `event.origin` (and often `event.source`) accepts data from any window the attacker can open or frame, and may pass it to a dangerous sink or a privileged action.
- **Sending:** `postMessage(secret, "*")` or posting to a window the attacker controls (opener, parent, frame that was navigated) leaks tokens or PII.

- Checklist: `references/postmessage_checklist.md` (PMX-001 to PMX-010 core, PMX-V-* variants, weak origin-check patterns, sinks).
- PoC templates: `references/postmessage_poc_templates.md` (frame and popup senders, listener sniffer, wildcard-leak catcher, null-origin sender, extension test).
- Tracker: `references/postmessage_tracker.md`.
- Scanner: `scripts/pm_scan.py` (offline: scans saved JS/HTML for listeners, origin checks and their weaknesses, sinks reached from `event.data`, and `postMessage` calls with `*` or dynamic target origins).
- Related: `client-side-js-security` (PM-001 to PM-004), `jsrecon` (collect JS), `xss` (DOM XSS sinks), `oauth-sso` (popup token flows), `clickjacking-audit` (framing restrictions affect delivery).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Collect JS: use jsrecon output or save the page and bundles to a folder. Run `python3 .agents/skills/postmessage-audit/scripts/pm_scan.py <folder> --out artifacts/<target>/postmessage_scan.json`.
3. Dynamic review: in DevTools, `getEventListeners(window).message` per page; Burp DOM Invader with postMessage interception; set a breakpoint on each handler and send test messages.
4. For each listener, record: origin check (none, weak, exact), source check, expected data shape, and what it does with the data (sink, navigation, storage, API call, state change).
5. For each sender, record: target window (parent, opener, frame), targetOrigin (exact, `*`, dynamic from URL), and data (tokens, PII, auth codes).
6. Build the PoC on your own origin (`localhost` or own domain): frame the target (if framing allowed) or open it as a popup, then send or catch messages. Use harmless markers (`alert(document.domain)`-style proof only on your own session).
7. Confirm impact on your own account: XSS on the target origin, state change, or your own token received by the attacker page.
8. Save findings to `artifacts/<target>/postmessage.json` and PoCs to `artifacts/<target>/postmessage_pocs/`.

## Classes

- `passive`: reading JS, scanner output, and listener inventory.
- `bounded`: PoC pages on your own origin sending markers to, or receiving messages from, the target in your own browser session.
- `authorized-only`: delivering PoCs to real users, extension testing on others' machines, and chains needing another vulnerability (subdomain XSS or takeover).

## Rules

- Payloads prove execution with a harmless marker; no data exfiltration beyond your own session.
- When a sender leaks data, show only your own token or PII, then rotate it.

## Mitigation guidance for reports

- Check `event.origin` with an exact comparison against an allowlist (`allowed.has(event.origin)`), never substring, prefix, suffix, or unanchored regex; reject `"null"`.
- Check `event.source` is the expected window (for example `iframe.contentWindow`).
- Validate the data schema; never pass message data to HTML, script, or URL sinks; use `textContent` and URL allowlists.
- Always pass an exact `targetOrigin` when sending; never `*` for sensitive data.
- Prefer `MessageChannel` with ports handed to a verified frame.
- Extensions: validate `sender.id`/`sender.origin`, use `externally_connectable` allowlists, and never relay page messages to privileged APIs.

## Sources

MDN `Window.postMessage` security notes, PortSwigger Web Security Academy DOM-based vulnerabilities (web messages labs), OWASP WSTG-CLNT-11, CWE-345 and CWE-346, Burp DOM Invader documentation, and public HackerOne postMessage reports.
