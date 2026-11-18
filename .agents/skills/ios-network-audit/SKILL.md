---
name: ios-network-audit
description: "Audit iOS app network security: ATS exceptions (NSAllowsArbitraryLoads, local networking, exception domains), cleartext and ws:// URLs, certificate pinning (AFNetworking, Alamofire, TrustKit), custom trust evaluation, URLCredentialStorage, cookies, background sessions and token handling, using static rules, `sslscan`/`testssl.sh` on in-scope hosts, Frida network tracing and Burp."
---

# iOS Network Communication

Audit iOS app network security: ATS exceptions (NSAllowsArbitraryLoads, local networking, exception domains), cleartext and ws:// URLs, certificate pinning (AFNetworking, Alamofire, TrustKit), custom trust evaluation, URLCredentialStorage, cookies, background sessions and token handling, using static rules, `sslscan`/`testssl.sh` on in-scope hosts, Frida network tracing and Burp.

This skill is generated from the iOS checklist source (`.agents/skills/ios-app-audit/references/source/`). Edit the source and rerun `scripts/build_ios_checklists.py`, not this file.

## Scope and safety

1. Confirm scope before any device, network or backend action. Device work needs a test device and test accounts you own.
2. `passive` rows read the IPA only. `bounded` rows read from the test device, its backup, or in-scope hosts. `authorized-only` rows need written approval for each check.
3. `not-tested` rows are OS or platform behaviour. They are recorded, not tested.
4. Save evidence to `artifacts/<bundle>/`. Redact secrets in every artifact.

## Procedure

1. Run the static pass once for the bundle: `python3 -I .agents/skills/ios-app-audit/scripts/ios_static.py --ipa APP.ipa --out artifacts/<bundle>/ios-static.json`.
2. Start tracking: `python3 -I .agents/skills/ios-app-audit/scripts/ios_checklist.py init --bundle <bundle>`, then `ingest` each report.
3. Work this skill's checklist: `references/checklist.md`. The Tool column names the script or hook for each row.
4. For each `authorized-only` row, get approval for that check first, then run it on the test device.
5. Confirm every failed row by hand, then `ios_checklist.py set IOS-xxxx failed --note ...`.

## Notes

`ios_static.py` reports ATS keys and exceptions, cleartext http:// and ws:// URLs, and pinning libraries. Run `sslscan` or `testssl.sh` only against API hosts listed in scope. Use Burp with the test device proxy; if pinning blocks it, `frida/ssl_pinning_bypass.js` needs approval. `frida/network_trace.js` logs request URLs, header names and sensitive query parameters (values redacted).

## Coverage

- passive: 4
- bounded: 17
- authorized-only: 4
- total: 25
- sections: Network Communication (10); iOS Network Deep Testing (15)

Checklist rows: `references/checklist.md` (IDs `IOS-0066` to `IOS-0150`).
