---
name: network-portscan
description: Scan every TCP port on explicitly authorized hosts, then identify listening services and versions with Naabu, Nmap, or Masscan. Use for network-level reconnaissance, especially after subdomain enumeration has produced artifacts/live_subdomains.txt. Do not use for web-only endpoint discovery or targets whose infrastructure is not in scope.
---

# Network Port Scan

Map exposed TCP services while preserving the relationship between a discovered hostname, its resolved address, an open port, and the confirming service evidence.

## Authorization gate

Before sending packets, confirm that every destination is explicitly authorized for port scanning. A domain being in scope does not automatically authorize scanning a shared CDN, cloud load balancer, or third-party address. Exclude shared infrastructure unless the program explicitly permits it. Respect published rate limits and stop on abuse reports, instability, or scope uncertainty.

The bundled runner refuses to scan unless `--authorized` is supplied. That flag records the operator's confirmation; it does not establish authorization by itself.

## Target inheritance

Use targets in this order:

1. A user-supplied file.
2. `artifacts/live_subdomains.txt` from `subdomainenum`.
3. Hosts extracted from `artifacts/resolved_subdomains.json`.

Normalize URLs to hostnames, remove duplicates, and retain `artifacts/resolved_subdomains.json` as hostname-to-address evidence. Do not silently replace hostnames with one address because round-robin DNS may expose multiple authorized origins. Keep DNS-dark virtual hosts out of network scans unless their destination address is separately authorized.

## Default workflow

1. Check required tools and record their versions.
2. Build the normalized target list and document exclusions.
3. Run full TCP discovery across ports 1–65535. Prefer Naabu for a domain list:

   ```bash
   naabu -list artifacts/live_subdomains.txt -top-ports full -c 50 -rate 1000 \
     -json -o artifacts/network_portscan/naabu.jsonl -silent
   ```

4. Run Nmap only against ports confirmed open, using `-Pn -sV -sC --open`. This is more reproducible and less wasteful than repeating `-p- -A` against every host.
5. Correlate hostname, address, port, protocol, service, product, and version. Treat version matches as fingerprints requiring validation, not proof of vulnerability.
6. Save raw output as well as normalized findings. Record failed, skipped, and rate-limited targets so coverage is explicit.

Use [scripts/run_portscan.sh](scripts/run_portscan.sh) for deterministic execution:

```bash
.agents/skills/network-portscan/scripts/run_portscan.sh --authorized
```

Useful options include `--input FILE`, `--out-dir DIR`, `--engine naabu|nmap|masscan`, `--rate N`, and `--concurrency N`. Use Masscan only when raw-packet scanning is supported and its IPv4 destination addresses are explicitly in scope. A rate such as `100000` packets/second must never be copied blindly from an example; begin conservatively and increase only with explicit authorization and observed target stability.

## Engine selection

- **Naabu (default):** full-port discovery over live recon hostnames, followed by targeted Nmap service detection.
- **Nmap:** smaller target sets or environments where accurate direct scanning matters more than speed. Equivalent discovery shape: `nmap -Pn -p- --min-rate 1000 -T4 --open` followed by service detection.
- **Masscan:** very large, explicitly authorized IPv4 ranges. Use `masscan -p1-65535 -iL ips.txt --rate RATE`; validate every result with Nmap.

Do not run `nmap -A` by default. It adds OS detection, traceroute, and scripts beyond the stated need. Add deeper probes only when the user requests them and scope permits them.

## Required artifacts

- `artifacts/network_portscan/targets.txt`
- `artifacts/network_portscan/target_ip_map.tsv`
- `artifacts/network_portscan/open_ports.tsv`
- `artifacts/network_portscan/naabu.jsonl` or engine-equivalent raw discovery output
- `artifacts/network_portscan/nmap/` with normal, XML, and grepable evidence
- `artifacts/network_portscan/services.tsv`
- `artifacts/network_portscan/run_metadata.txt`
- `artifacts/network_portscan/coverage.tsv`

Report open management or data services with exact evidence and a non-destructive validation recommendation. Do not attempt default credentials, data extraction, state changes, denial-of-service checks, or exploitation as part of this skill.
