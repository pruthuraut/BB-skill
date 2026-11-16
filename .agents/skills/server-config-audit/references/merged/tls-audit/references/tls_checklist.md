# TLS/SSL Checklist

Class key: `passive` = certificate, CT, header, and cookie review. `bounded` = one handshake scan per service with standard tools. `authorized-only` = exploitation, floods, or interception.

`H` = host. testssl.sh flags: `-p` protocols, `-E` ciphers per protocol, `-e` all ciphers, `-f` forward secrecy, `-S` server defaults (certificate), `-h` headers, `-U` all vulnerabilities, `-H` Heartbleed, `-I` CCS, `-T` Ticketbleed, `-BB` ROBOT, `-R` renegotiation, `-C` CRIME, `-B` BREACH, `-O` POODLE, `-Z` TLS_FALLBACK_SCSV, `-W` Sweet32, `-A` BEAST, `-L` Lucky13, `-F` FREAK, `-J` Logjam, `-D` DROWN, `-4` RC4.

## Core checks (20)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TLSX-001 | Protocols | TLS versions: SSLv2/SSLv3/TLS 1.0/TLS 1.1 rejected; TLS 1.2 (and 1.3) supported | bounded | `testssl.sh -p H`; `nmap --script ssl-enum-ciphers -p 443 H`; tls_quick.py |
| TLSX-002 | Ciphers | Weak cipher suites: RC4, DES, 3DES, IDEA, NULL, EXPORT, anon (aNULL), MD5 | bounded | `testssl.sh -E -4 H`; `sslyze H` |
| TLSX-003 | POODLE | POODLE (SSLv3 CBC fallback); also TLS POODLE on broken CBC padding checks | bounded | `testssl.sh -O H` |
| TLSX-004 | BEAST | BEAST: CBC ciphers offered with TLS 1.0 / SSLv3 | bounded | `testssl.sh -A H` (mostly client-side mitigated; report as low with TLS 1.0) |
| TLSX-005 | CRIME/BREACH | TLS-level compression (CRIME) and HTTP compression of responses reflecting secrets (BREACH) | bounded | `testssl.sh -C -B H`; BREACH needs a secret plus attacker-reflected input in a gzip response |
| TLSX-006 | Heartbleed | OpenSSL Heartbleed (CVE-2014-0160) | bounded | `testssl.sh -H H` or `nmap --script ssl-heartbleed -p 443 H` (detection only) |
| TLSX-007 | HSTS | HSTS present on HTTPS responses, `max-age` at least 31536000, `includeSubDomains`, preload status; not sent over HTTP | passive | `testssl.sh -h H`; `curl -sI https://H`; tls_quick.py |
| TLSX-008 | Certificate | Validity, chain completeness, trust, hostname match, expiry (and days left), signature algorithm (no SHA-1/MD5) | passive | `testssl.sh -S H`; `sslyze --certinfo H`; `openssl s_client -connect H:443 -servername H -showcerts` |
| TLSX-009 | Certificate | Wildcard certificate scope: which hosts share it, low-trust hosts (staging, third-party) holding the same key | passive | SAN list; crt.sh search for the wildcard; compare certificate fingerprints across hosts |
| TLSX-010 | Mixed content | HTTPS pages loading HTTP scripts, styles, iframes, images, forms posting to HTTP | bounded | tls_quick.py landing page; crawl authenticated pages; browser console |
| TLSX-011 | Cookies | Cookies without `Secure`, or set over HTTP; session cookies sent on HTTP requests | passive | tls_quick.py `Set-Cookie` review; `curl -sI http://H` |
| TLSX-012 | Revocation | CRL distribution point and OCSP URL in the certificate; OCSP stapling enabled; Must-Staple consistency | passive | `testssl.sh -S H` (OCSP stapling line); `openssl s_client -status` |
| TLSX-013 | Pinning | Mobile/desktop app certificate or public-key pinning implemented (traffic fails through an intercepting proxy with a user-installed CA) | bounded | Own device: proxy app traffic; record pinned or not (bypass is crypto-audit CRY-011) |
| TLSX-014 | Forward secrecy | ECDHE/DHE suites preferred; no static RSA key exchange; DH group at least 2048 bits | bounded | `testssl.sh -f H` |
| TLSX-015 | Sweet32 | 64-bit block ciphers (3DES, IDEA, Blowfish) offered (CVE-2016-2183) | bounded | `testssl.sh -W H` |
| TLSX-016 | CT | Certificate includes SCTs (embedded, TLS extension, or OCSP); certificate appears in CT logs | passive | `testssl.sh -S H` (Certificate Transparency line); crt.sh |
| TLSX-017 | Downgrade | Downgrade protection: TLS_FALLBACK_SCSV supported; TLS 1.3 downgrade sentinel; no version intolerance | bounded | `testssl.sh -Z H` |
| TLSX-018 | Renegotiation | Insecure renegotiation (CVE-2009-3555 prefix injection) and client-initiated renegotiation (DoS) | bounded | `testssl.sh -R H` (single check, no loop) |
| TLSX-019 | Renegotiation | Secure renegotiation RFC 5746 (renegotiation_info) supported | bounded | `testssl.sh -R H` "Secure Renegotiation" line |
| TLSX-020 | Compression | TLS compression enabled (CRIME variant, also SPDY/HTTP2 header compression issues on old stacks) | bounded | `testssl.sh -C H`; tls_quick.py compression field |

## Extras

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TLSX-E-001 | ROBOT | RSA PKCS#1 v1.5 oracle (ROBOT) | bounded | `testssl.sh -BB H` |
| TLSX-E-002 | FREAK | EXPORT RSA accepted (FREAK) | bounded | `testssl.sh -F H` |
| TLSX-E-003 | Logjam | EXPORT DH or weak DH groups (Logjam) | bounded | `testssl.sh -J H` |
| TLSX-E-004 | DROWN | SSLv2 on this or any host sharing the RSA key (DROWN) | bounded | `testssl.sh -D H`; check shared keys via certificate fingerprint |
| TLSX-E-005 | Ticketbleed | F5 Ticketbleed (CVE-2016-9244) | bounded | `testssl.sh -T H` |
| TLSX-E-006 | CCS | OpenSSL CCS injection (CVE-2014-0224) | bounded | `testssl.sh -I H` |
| TLSX-E-007 | Lucky13 | CBC timing (Lucky13) | bounded | `testssl.sh -L H` (informational on modern stacks) |
| TLSX-E-008 | Key | Key size: RSA below 2048 or ECC below 256 bits | passive | Certificate details |
| TLSX-E-009 | Redirect | HTTP does not redirect to HTTPS, or redirects to a different host over HTTP first | passive | tls_quick.py; `curl -sI http://H` |
| TLSX-E-010 | Services | Non-web TLS services (SMTP STARTTLS, IMAPS, LDAPS, RDP, databases) with old protocols or self-signed certs | bounded | `testssl.sh -t smtp H:587`, `-t imap`, `-t ldap` |
| TLSX-E-011 | Session | Session resumption across server blocks or virtual hosts (cross-host session ticket reuse) | bounded | See server-config-audit WS-SRV-011 |
| TLSX-E-012 | Cipher order | Server does not enforce its cipher preference | bounded | `testssl.sh -P H` |

## Severity notes

| Situation | Typical rating |
|---|---|
| Heartbleed, CCS, ROBOT, DROWN, SSLv2/SSLv3 enabled, expired or untrusted cert on main site | High (often accepted by programs) |
| Session cookie without Secure and HTTP reachable, mixed active content (scripts) | Medium |
| TLS 1.0/1.1 enabled, 3DES/Sweet32, missing HSTS, no forward secrecy | Low or informational (check policy) |
| BEAST, Lucky13, no OCSP stapling, no CT, client renegotiation | Informational |

## Cross-references

| TLSX row | Related rows |
|---|---|
| TLSX-001 | server-config-audit TLS-001 |
| TLSX-002 | TLS-002 |
| TLSX-006 | TLS-003 |
| TLSX-008 | TLS-004 |
| TLSX-007 | TLS-005, csrf-and-headers-audit HDR-SEC-001 |
| TLSX-017, 018 | TLS-006 |
| TLSX-011 | session-management cookie rows, csrf-and-headers-audit COOKIE-PFX-002 |
| TLSX-013 | crypto-audit CRY-011 |
| TLSX-016 | subdomainenum CT sources |
