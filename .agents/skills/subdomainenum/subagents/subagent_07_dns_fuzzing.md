# Subagent 07: DNS Fuzzing with SecLists

## Role

Discover DNS-backed subdomains with bounded SecLists dictionaries, validated resolvers, and deterministic wildcard suppression. This supplements checks 17–19; it does not replace passive discovery.

## Preconditions and safety

- Confirm the root domain is authorized before sending DNS queries.
- Load repository rate settings when available. Cap concurrency at the lower of `BB_MAX_CONCURRENCY` and 100; use a conservative default of 25.
- Use a validated resolver file. Never treat an unverified public resolver response as a finding.
- Start with the smallest useful SecLists list and expand only when requested or when the program permits sustained DNS traffic.

## SecLists selection

Locate SecLists instead of assuming one path:

```bash
for root in /usr/share/seclists /usr/share/wordlists/SecLists; do
  [ -d "$root/Discovery/DNS" ] && SECLISTS_DNS="$root/Discovery/DNS" && break
done
test -n "${SECLISTS_DNS:-}" || { echo "SecLists DNS directory not found" >&2; exit 1; }
```

Preferred progression:

1. `subdomains-top1million-5000.txt` for a quick baseline.
2. `subdomains-top1million-20000.txt` for the standard run.
3. `subdomains-top1million-110000.txt` only for expanded authorized coverage.

Record the exact list path, SHA-256, line count, concurrency, and resolver count in `artifacts/dns_fuzz_run_metadata.tsv`.

## Workflow

1. Query at least five high-entropy names beneath the target and save full A, AAAA, and CNAME answers in `raw/dns_fuzz/wildcard_probes.jsonl`.
2. Build a wildcard signature from returned address/CNAME sets. An empty set means no wildcard was observed; it does not prove one cannot exist.
3. Run `shuffledns` with SecLists and the validated resolver pool. Preserve stderr and the unfiltered output.
4. Independently resolve candidates with `dnsx -a -aaaa -cname -resp -json` or a second trusted resolution method.
5. Reject candidates whose complete DNS signature matches a wildcard probe. Retain ambiguous records separately instead of deleting them.
6. Deduplicate, lowercase, strip trailing dots, and require the suffix `.<target>`.

Example shape (adapt flags to installed versions):

```bash
shuffledns -d "$TARGET_DOMAIN" -w "$WORDLIST" -r "$RESOLVERS" \
  -m "$(command -v massdns)" -t "$CONCURRENCY" -o raw/dns_fuzz/shuffledns_candidates.txt

dnsx -l raw/dns_fuzz/shuffledns_candidates.txt -r "$RESOLVERS" \
  -a -aaaa -cname -resp -json -o raw/dns_fuzz/verified.jsonl
```

## Artifacts

- `artifacts/dns_fuzz_candidates.txt` — normalized raw candidates
- `artifacts/dns_fuzz_verified.txt` — independently resolved, wildcard-filtered names
- `artifacts/dns_fuzz_resolved.jsonl` — DNS evidence
- `artifacts/dns_fuzz_ambiguous_wildcards.txt` — candidates requiring review
- `artifacts/dns_fuzz_run_metadata.tsv` — wordlist and execution metadata
- `artifacts/subagent_07_check_status.tsv` — completed/partial/unavailable/error with evidence paths

Never mark a name live solely because a brute-force tool printed it.
