---
name: dns-security-audit
description: "Audit authorized DNS infrastructure and zones for security issues across 20 checks: zone transfer (AXFR), DNSSEC validation, DNS over HTTPS and DNS over TLS configuration, cache poisoning and local spoofing exposure, DNS rebinding, CNAME flattening, TXT, SRV, PTR, NAPTR and DNAME information disclosure, wildcard records, tunneling detection, amplification and open-resolver exposure, DNS cookies, response rate limiting, and query name minimization. Uses Kali tools (dig, dnsrecon, nmap NSE, openssl) and a scope-gated read-only probe. Triggers on \"DNS security\", \"zone transfer\", \"AXFR\", \"DNSSEC\", \"DoH\", \"DoT\", \"open resolver\", \"DNS amplification\", \"DNS rebinding\", \"wildcard DNS\", \"TXT record\", \"SRV record\", \"PTR\", \"NAPTR\", \"DNAME\", \"dnsrecon\", \"dig\"."
---

# DNS Security Audit

Check the configuration of a zone and its nameservers. Every query is read-only. Zone transfer and open-recursion checks go only to the zone's own nameservers, and only when the program allows zone checks. Amplification, spoofing, and rate-flood tests are never run by this skill.

Checklist: `references/dns_checklist.md` (20 core checks plus supporting rows). Probe: `scripts/dns_probe.py` (uses Kali's `dig`, `dnsrecon`, `nmap`, and `openssl`).

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`. The zone must be listed in scope.
2. Run the read-only probe. Add `--axfr` only if the program allows zone checks, and `--ip` for in-scope addresses to check PTR records:

   ```
   python3 .agents/skills/dns-security-audit/scripts/dns_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --ip 203.0.113.10 --out artifacts/example.com/dns.json
   ```

3. Kali enumeration (bounded, zone's own nameservers): `dnsrecon -d example.com -t std` and `dnsrecon -d example.com -t axfr` if zone checks are allowed.
4. Review the results against the checklist: DNSSEC presence and validation (`dig +dnssec`), TXT and SRV disclosure, wildcard behaviour, DoT and DoH reachability, and recursion status.
5. Passive items (cache poisoning on the local network, tunneling detection, rate limiting) are reviewed from configuration and logs. Do not send spoofed responses or floods to test them.
6. Save evidence to `artifacts/<target>/dns.json`.

## Classes

- `passive`: configuration, record content, and logs.
- `bounded`: a few read-only queries to the zone's own nameservers (AXFR only with approval).
- `authorized-only`: spoofing, cache poisoning, amplification, rate tests, tunneling generation.

## Rules

- Never test amplification. Detect open recursion only and report it.
- Do not query third-party resolvers on behalf of the target. Test only the nameservers of the in-scope zone.
- Report record content that discloses internal hostnames or services, and redact any secret in TXT records.
