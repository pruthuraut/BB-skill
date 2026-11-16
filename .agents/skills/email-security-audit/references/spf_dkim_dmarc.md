# Email Security: SPF, DKIM, DMARC, MX, Mail Header Injection

Class key: `passive` (DNS lookups only), `bounded` (own-address test messages where the program allows). No mail is sent to third parties.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| MAIL-001 | DNS | SPF record missing | passive | `dig TXT <domain>` and look for `v=spf1` |
| MAIL-002 | DNS | SPF permissive (`+all`, `?all`, very large include chains over 10 lookups) | passive | Parse SPF and count DNS lookups |
| MAIL-003 | DNS | DMARC missing | passive | `dig TXT _dmarc.<domain>` |
| MAIL-004 | DNS | DMARC policy p=none on a live domain | passive | Parse p= tag and rua presence |
| MAIL-005 | DNS | DKIM selectors missing or weak keys (<2048 bits) | passive | `dig TXT <selector>._domainkey.<domain>` for common selectors |
| MAIL-006 | DNS | Null MX missing and mail domains without MX | passive | `dig MX` and check parked-domain records |
| MAIL-007 | DNS | MTA-STS and TLS-RPT missing | passive | `dig TXT _mta-sts.<domain>`, `_smtp._tls.<domain>` |
| MAIL-008 | DNS | DNSSEC not configured | passive | `dig +dnssec <domain>` for RRSIG |
| MAIL-009 | Spoofing | Domain spoofing feasible with p=none and no enforcement | passive | Derived from MAIL-002 to MAIL-004; report only |
| MAIL-010 | Forms | Email header injection in contact or registration forms (`%0d%0aBcc:`) | bounded | Own address and benign subject marker (see open-redirect-and-header-injection EMAIL-HDR-001) |
| MAIL-011 | Forms | Reset email sent to arbitrary address set in request (email parameter override) | bounded | Own two addresses; check where the reset actually goes |
| MAIL-012 | Mail server | Open relay | authorized-only | Never test open relay against third-party recipients; passive banner only |
| MAIL-013 | Mail server | Legacy auth and STARTTLS not enforced | passive | Banner and EHLO output only |
| MAIL-014 | Webmail | Roundcube stored XSS CVE-2023-43770; RainLoop and Zimbra exposure | passive | Version check (see tech-stack-audit) |
