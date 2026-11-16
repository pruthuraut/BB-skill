# DNS Security Checklist

Class key: `passive` = configuration and records. `bounded` = a few read-only queries to the zone's own nameservers. `authorized-only` = spoofing, poisoning, amplification, rate tests, tunneling generation.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| DNS-001 | Zone transfer | AXFR allowed from nameservers (AXFR-001) | bounded | `dig @ns zone AXFR` only with approval; `dnsrecon -t axfr` |
| DNS-002 | DNSSEC | Zone signed and validated (DNSKEY, RRSIG, DS) | bounded | `dig +dnssec zone DNSKEY`; check DS at parent |
| DNS-003 | DNSSEC | Broken chain or expired signatures | bounded | `dig +dnssec +cd` vs default; check the validation result |
| DNS-004 | DoH | DNS over HTTPS endpoint configured and reachable (`/dns-query`) | bounded | HTTPS GET to `/dns-query` on the nameserver host |
| DNS-005 | DoT | DNS over TLS on TCP 853 with a valid certificate | bounded | `openssl s_client -connect ns:853` |
| DNS-006 | Cache poisoning | Source-port and TXID randomization; DNSSEC on resolvers | passive | Review resolver configuration and logs |
| DNS-007 | Local spoofing | Unauthenticated responses accepted on the local network | authorized-only | Lab only; never spoof live responses |
| DNS-008 | Rebinding | Hostname resolves to private IP for an attacker-controlled name | bounded | Own rebinding domain pointing to an in-scope test name; one query |
| DNS-009 | CNAME flattening | Apex CNAME flattening exposes provider or internal targets | passive | `dig CNAME` and `dig A` at apex; review the target |
| DNS-010 | TXT | Internal hostnames, keys, or verification tokens in TXT records | passive | `dig TXT zone +short`; redact values in reports |
| DNS-011 | SRV | Internal service enumeration through common SRV names | bounded | Query the common SRV list (`dns_probe.py` SRV-001) |
| DNS-012 | PTR | Reverse lookups reveal internal naming for in-scope IPs | bounded | `dig -x <ip>` for in-scope addresses only |
| DNS-013 | NAPTR | Service information disclosed in NAPTR records | passive | `dig NAPTR zone +short` |
| DNS-014 | Wildcard | Wildcard record hides subdomain takeover or masks real errors | bounded | Random label query; compare with takeover checks |
| DNS-015 | DNAME | DNAME aliasing exposes unintended zones | passive | `dig DNAME` on the zone and its children |
| DNS-016 | Tunneling | DNS tunneling detection and query-length limits | passive | Review resolver and SIEM logs for long or high-entropy labels |
| DNS-017 | Amplification | Open recursion or ANY responses usable for amplification | authorized-only | Detect recursion only (nmap dns-recursion); never run amplification |
| DNS-018 | Open resolver | Recursion enabled for untrusted clients | bounded | `nmap -sU -p53 --script dns-recursion` on the zone's own nameserver |
| DNS-019 | Cookies | DNS cookie support (RFC 7873) | bounded | `dig +cookie` against the nameserver |
| DNS-020 | Rate limiting | Response rate limiting configured (RRL) | authorized-only | Review config; any rate test needs approval and a lab |
| DNS-021 | Minimization | Query name minimization (RFC 7816) | bounded | `dig +trace` and review the query names sent to upstream servers |
| DNS-022 | Reporting | Evidence and fixes: DNSSEC, AXFR restriction, recursion off for public servers, DoT/DoH policy | passive | Recommendation list |
