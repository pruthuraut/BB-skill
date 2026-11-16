# Subagent 08: Virtual Host Discovery with SecLists

## Role

Discover HTTP virtual hosts that share an explicitly authorized IP or origin but are not visible through public DNS. Use multiple negative controls to learn the default response before fuzzing, then validate each outlier independently.

## Preconditions and scope

- Require an explicitly in-scope destination IP or origin URL and an authorized parent domain. DNS scope alone does not automatically authorize scanning a shared CDN or third-party IP.
- Do not vhost-fuzz Cloudflare, Fastly, Akamai, or another shared edge address unless the program explicitly includes that infrastructure.
- Preserve TLS SNI behavior: when testing HTTPS by IP, use `curl --resolve` for validation. FFUF's `Host` header alone may not reproduce SNI routing.
- Honor `BB_RATE_LIMIT`, `BB_MAX_CONCURRENCY`, and `BB_HTTP_TIMEOUT`. Default to 10 requests/second and 20 workers when unset.

## SecLists selection

Locate SecLists dynamically. Prefer `Discovery/DNS/subdomains-top1million-5000.txt`, then the 20,000-entry list for expanded coverage. Convert labels to `FUZZ.<parent-domain>` at request time; do not create an unbounded permutation set.

## Learn the baseline before choosing `-mc` or filters

Send at least five random, high-entropy Host headers plus one request without a custom Host header. For every control record:

- HTTP status code (`sc`)
- response bytes (`size`)
- word count and line count
- redirect `Location`
- normalized body SHA-256 (remove volatile dates/request IDs only when justified and document the normalization)
- response title when present

Save these values to `raw/vhost/baseline_signatures.tsv`.

Derive FFUF settings as follows:

1. Start with `-mc all`; hidden vhosts commonly return 301, 302, 307, 401, or 403, not only 200.
2. If all negative controls share a stable status and body signature, filter the strongest stable dimensions: `-fc`, `-fs`, `-fw`, or `-fl`. Prefer `-fs` plus one other invariant over status-only filtering.
3. If control sizes vary, use FFUF auto-calibration (`-ac`) and retain JSON output. Do not invent a single `-fs` value.
4. If the default response is a redirect, compare normalized `Location` values; do not discard every 30x response.
5. If no stable baseline exists, keep `-mc all`, reduce the wordlist, and rank statistical outliers for validation rather than claiming discoveries.

Record the selected `-mc`/filter flags and the evidence supporting them in `artifacts/vhost_calibration.md`.

Example shape:

```bash
ffuf -u "https://$TARGET_IP/" \
  -H "Host: FUZZ.$TARGET_DOMAIN" \
  -w "$WORDLIST" -mc all -ac \
  -rate "$RATE" -t "$CONCURRENCY" -timeout "$TIMEOUT" \
  -of json -o raw/vhost/ffuf.json -s
```

Apply derived `-fc/-fs/-fw/-fl` flags only after baseline collection. If certificate validation cannot succeed by IP, `-k` may be used for discovery, but each candidate still requires an SNI-aware validation request:

```bash
curl --resolve "$CANDIDATE:443:$TARGET_IP" "https://$CANDIDATE/" \
  -sS -D raw/vhost/headers.txt -o raw/vhost/body.bin
```

## Validation and classification

- Re-request every FFUF outlier at least twice and compare it with a fresh random control.
- A candidate is verified only when routing behavior is reproducibly distinct by status, body/title/hash, redirect destination, headers, or application content.
- Separate `verified`, `ambiguous`, and `baseline-equivalent` results.
- Do not add a vhost to `live_subdomains.txt` unless DNS also resolves; keep DNS-dark vhosts in their own artifact.

## Artifacts

- `artifacts/vhost_verified.txt`
- `artifacts/vhost_ambiguous.txt`
- `artifacts/vhost_dns_dark.txt`
- `artifacts/vhost_calibration.md`
- `artifacts/vhost_findings.jsonl`
- `artifacts/subagent_08_check_status.tsv`
- Raw requests, FFUF JSON, headers, and response signatures under `raw/vhost/`
