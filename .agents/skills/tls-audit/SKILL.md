---
name: tls-audit
description: Audit authorized hosts for TLS/SSL configuration across 20 checks — protocol versions (reject SSLv2/SSLv3/TLS 1.0/1.1, require TLS 1.2+), weak ciphers (RC4, DES, 3DES, NULL, EXPORT, anon), POODLE, BEAST, CRIME/BREACH and TLS compression, Heartbleed, HSTS presence and max-age, certificate validity/chain/expiry, wildcard certificate scope, mixed content, cookies over HTTP, revocation (CRL/OCSP stapling), certificate pinning in apps, forward secrecy, Sweet32, Certificate Transparency, downgrade protection (TLS_FALLBACK_SCSV), insecure renegotiation and RFC 5746 secure renegotiation — plus extra rows (ROBOT, FREAK, Logjam, DROWN, Ticketbleed, CCS injection, Lucky13, key size, SAN mismatch, HTTP→HTTPS redirect). Includes testssl.sh/sslyze/nmap commands per check, a testssl JSON mapper to the checklist IDs, and a quick Python checker. Triggers on "TLS", "SSL", "testssl", "sslyze", "cipher suites", "POODLE", "BEAST", "CRIME", "BREACH", "Heartbleed", "Sweet32", "HSTS", "certificate", "OCSP", "forward secrecy", "renegotiation", "mixed content", or when a host serves HTTPS.
---

# TLS/SSL Configuration Audit (20 checks + extras)

Assess the transport layer of every in-scope HTTPS (and other TLS) service. Most checks are handshake-level and read-only; tools only negotiate and observe. Many programs rate pure TLS configuration findings (old protocols, weak ciphers, missing HSTS) as informational or out of scope; read the program policy and report with realistic impact.

- Checklist: `references/tls_checklist.md` (TLSX-001 to TLSX-020 core, TLSX-E-* extras, commands per row, severity notes).
- Tracker: `references/tls_tracker.md`.
- `scripts/tls_quick.py`: scope-gated Python checker (protocol acceptance, weak cipher acceptance where the local OpenSSL allows, negotiated cipher and forward secrecy, compression, certificate validity/chain/expiry/SAN/wildcard/key size, OCSP stapling hint, HSTS, HTTP→HTTPS redirect, cookie flags, mixed content on the landing page).
- `scripts/tls_map_testssl.py`: offline mapper from `testssl.sh --jsonfile` output to TLSX IDs with severities.
- Related: `server-config-audit` (TLS-001 to TLS-006, web server config), `csrf-and-headers-audit` (HDR-SEC-001 HSTS), `session-management` (Secure cookies), `subdomain-takeover` and `subdomainenum` (CT logs), `crypto-audit` (pinning bypass, app crypto).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. List TLS services (443, 8443, mail STARTTLS 25/587/993/995, LDAPS 636, custom) from network-portscan.
2. Full scan per service with testssl.sh (installed by setup.sh):

   ```bash
   testssl.sh --jsonfile artifacts/<target>/testssl_<host>.json --severity LOW --quiet https://<host>
   # STARTTLS example: testssl.sh -t smtp <host>:587
   python3 .agents/skills/tls-audit/scripts/tls_map_testssl.py artifacts/<target>/testssl_<host>.json
   ```

   Cross-check with `sslyze <host>` and `nmap --script ssl-enum-ciphers,ssl-cert -p 443 <host>`.
3. Quick check and web-layer items (HSTS, cookies, redirect, mixed content):

   ```bash
   python3 .agents/skills/tls-audit/scripts/tls_quick.py --target example.com --host www.example.com --out artifacts/example.com/tls_quick.json
   ```

4. Certificates and CT: inspect chain, expiry, SAN, wildcard reach (which hosts share it), key size; search crt.sh for issued certificates (also feeds subdomain discovery).
5. Mixed content and cookies: crawl authenticated pages for `http://` subresources; check every `Set-Cookie` for `Secure`.
6. Mobile apps (TLSX-013): check whether the app pins certificates and how it behaves with an intercepting proxy; pinning bypass belongs to crypto-audit CRY-011 and only on your own device.
7. Save results to `artifacts/<target>/tls.json` and the tracker to `artifacts/<target>/tls_tracker.md`.

## Classes

- `passive`: certificate, CT log, header, and cookie review.
- `bounded`: handshake scans with testssl.sh, sslyze, nmap scripts, and tls_quick.py at normal rates (one scan per service).
- `authorized-only`: anything beyond detection (for example extracting memory with Heartbleed beyond the single safe check, renegotiation floods, padding-oracle exploitation), and man-in-the-middle tests on networks you do not own.

## Rules

- Detection only. testssl.sh's Heartbleed and CCS tests are designed to be non-invasive; do not run exploit tools.
- Do not run renegotiation DoS or high-rate handshake loops.
- Report the exact protocol, cipher, and evidence line from the tool; note client compatibility impact in recommendations.

## Mitigation guidance for reports

- TLS 1.2 and 1.3 only; AEAD ciphers with ECDHE (TLS 1.2: ECDHE+AESGCM/CHACHA20); disable RC4, 3DES, CBC-SHA1 where possible, NULL, EXPORT, anon.
- Disable TLS compression; mitigate BREACH by not reflecting secrets in compressed responses (or per-request token masking).
- Enable TLS_FALLBACK_SCSV, secure renegotiation (RFC 5746), and disable client-initiated renegotiation.
- Patch OpenSSL (Heartbleed, CCS) and TLS stacks (ROBOT).
- HSTS `max-age=31536000; includeSubDomains` (preload when ready); redirect HTTP to HTTPS; `Secure` on all cookies.
- Valid chain, at least RSA 2048 or ECDSA P-256, short-lived certs with automated renewal, OCSP stapling, CT logging, limited wildcard scope.

## Sources

Mozilla Server Side TLS guidelines, OWASP Transport Layer Security Cheat Sheet and WSTG-CRYP-01, NIST SP 800-52r2, RFC 7457 (known TLS attacks), RFC 5746, RFC 7507 (TLS_FALLBACK_SCSV), RFC 6797 (HSTS), RFC 9162/6962 (CT), and testssl.sh, sslyze, and nmap documentation.
