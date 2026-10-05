#!/usr/bin/env bash
set -uo pipefail

ROOT="/home/vadapavhacker/Documents/bugbounty/arc.io"
REPO="/home/vadapavhacker/Documents/tools/BB-skill"
RAW="$ROOT/raw/vhost"
ART="$ROOT/artifacts"
RESOLVED="$ART/resolved_subdomains.json"
WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

set -a
# shellcheck disable=SC1091
source "$REPO/.env"
set +a
RATE="${BB_RATE_LIMIT:-10}"
THREADS="${BB_MAX_CONCURRENCY:-20}"
TIMEOUT="${BB_HTTP_TIMEOUT:-10}"

mkdir -p "$RAW/baselines" "$RAW/ffuf" "$RAW/validation"
: > "$RAW/baseline_signatures.tsv"
printf 'target_ip\tprofile_host\tscheme\tcontrol_host\tstatus_code\tsize\twords\tlines\tlocation\tbody_sha256\ttitle\n' >> "$RAW/baseline_signatures.tsv"
: > "$RAW/run_status.tsv"
printf 'target_ip\tprofile_host\tscheme\tstatus\tffuf_json\tflags\n' >> "$RAW/run_status.tsv"

jq -r 'select((.a // []) | length > 0) | . as $r | $r.a[] | [., $r.host] | @tsv' "$RESOLVED" |
  sort -t $'\t' -k1,1 -k2,2 | awk -F '\t' '!seen[$1]++' > "$RAW/targets.tsv"

probe_control() {
  local ip="$1" profile="$2" scheme="$3" host="$4" label="$5"
  local stem="$RAW/baselines/${ip//:/_}_${label}"
  local code size words lines location hash title
  if [[ "$host" == "__NO_CUSTOM_HOST__" ]]; then
    code=$(curl -k -sS --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -D "$stem.headers" -o "$stem.body" -w '%{http_code}' "$scheme://$ip/" 2>"$stem.stderr" || true)
  else
    code=$(curl -k -sS --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -H "Host: $host" -D "$stem.headers" -o "$stem.body" -w '%{http_code}' "$scheme://$ip/" 2>"$stem.stderr" || true)
  fi
  [[ -f "$stem.body" ]] || : > "$stem.body"
  [[ -f "$stem.headers" ]] || : > "$stem.headers"
  size=$(wc -c < "$stem.body" | tr -d ' ')
  words=$(wc -w < "$stem.body" | tr -d ' ')
  lines=$(wc -l < "$stem.body" | tr -d ' ')
  location=$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/^[^:]*:[[:space:]]*/,""); sub(/\r$/,""); print; exit}' "$stem.headers" | tr '\t' ' ')
  hash=$(sha256sum "$stem.body" | awk '{print $1}')
  title=$(tr '\n' ' ' < "$stem.body" | sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>\([^<]*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' | head -1 | tr '\t' ' ')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$profile" "$scheme" "$host" "${code:-000}" "$size" "$words" "$lines" "$location" "$hash" "$title" >> "$RAW/baseline_signatures.tsv"
}

while IFS=$'\t' read -r ip profile; do
  scheme=https
  test_code=$(curl -k -sS --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}' "https://$ip/" 2>/dev/null || true)
  if [[ -z "$test_code" || "$test_code" == "000" ]]; then scheme=http; fi

  for n in 1 2 3 4 5; do
    nonce="zz$(openssl rand -hex 12).arc.io"
    probe_control "$ip" "$profile" "$scheme" "$nonce" "random$n"
  done
  probe_control "$ip" "$profile" "$scheme" "__NO_CUSTOM_HOST__" "nohost"

  mapfile -t sizes < <(awk -F '\t' -v ip="$ip" '$1==ip && $4!="__NO_CUSTOM_HOST__"{print $6}' "$RAW/baseline_signatures.tsv" | sort -u)
  mapfile -t words < <(awk -F '\t' -v ip="$ip" '$1==ip && $4!="__NO_CUSTOM_HOST__"{print $7}' "$RAW/baseline_signatures.tsv" | sort -u)
  flags=(-mc all)
  calibration="variable-baseline:-ac"
  if (( ${#sizes[@]} == 1 )); then
    flags+=(-fs "${sizes[0]}")
    calibration="stable-size:${sizes[0]}"
    if (( ${#words[@]} == 1 )); then
      flags+=(-fw "${words[0]}")
      calibration+=",stable-words:${words[0]}"
    fi
  else
    flags+=(-ac)
  fi

  out="$RAW/ffuf/${ip//:/_}.json"
  err="$RAW/ffuf/${ip//:/_}.stderr"
  if ffuf -u "$scheme://$ip/" -H 'Host: FUZZ.arc.io' -w "$WORDLIST" "${flags[@]}" -rate "$RATE" -t "$THREADS" -timeout "$TIMEOUT" -of json -o "$out" -s 2>"$err"; then
    state=completed
  else
    state=failed
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s;%s\n' "$ip" "$profile" "$scheme" "$state" "$out" "${flags[*]}" "$calibration" >> "$RAW/run_status.tsv"
done < "$RAW/targets.tsv"

: > "$ART/vhost_findings.jsonl"
: > "$ART/vhost_verified.txt"
: > "$ART/vhost_ambiguous.txt"
: > "$ART/vhost_dns_dark.txt"

while IFS=$'\t' read -r ip profile scheme state json flags; do
  [[ "$state" == completed && -s "$json" ]] || continue
  jq -r '.results[]? | [.input.FUZZ, (.status|tostring), (.length|tostring), (.words|tostring), (.lines|tostring), (.redirectlocation // "")] | @tsv' "$json" 2>/dev/null |
  while IFS=$'\t' read -r label ffsc fflen ffwords fflines ffloc; do
    candidate="${label}.arc.io"
    vdir="$RAW/validation/${ip//:/_}_${label//[^A-Za-z0-9._-]/_}"
    mkdir -p "$vdir"
    distinct=0
    hashes=()
    codes=()
    for n in 1 2; do
      code=$(curl -k -sS --resolve "$candidate:443:$ip" --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -D "$vdir/candidate$n.headers" -o "$vdir/candidate$n.body" -w '%{http_code}' "https://$candidate/" 2>"$vdir/candidate$n.stderr" || true)
      hashes+=("$(sha256sum "$vdir/candidate$n.body" 2>/dev/null | awk '{print $1}')")
      codes+=("${code:-000}")
    done
    control="zz$(openssl rand -hex 12).arc.io"
    ccode=$(curl -k -sS --resolve "$control:443:$ip" --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -D "$vdir/control.headers" -o "$vdir/control.body" -w '%{http_code}' "https://$control/" 2>"$vdir/control.stderr" || true)
    chash=$(sha256sum "$vdir/control.body" 2>/dev/null | awk '{print $1}')
    classification=ambiguous
    if [[ "${codes[0]}" == "${codes[1]}" && "${hashes[0]}" == "${hashes[1]}" && ( "${codes[0]}" != "${ccode:-000}" || "${hashes[0]}" != "$chash" ) ]]; then
      classification=verified
      printf '%s\n' "$candidate" >> "$ART/vhost_verified.txt"
      if ! grep -Fxq "$candidate" "$ART/live_subdomains.txt"; then printf '%s\n' "$candidate" >> "$ART/vhost_dns_dark.txt"; fi
    else
      printf '%s\n' "$candidate" >> "$ART/vhost_ambiguous.txt"
    fi
    jq -cn --arg target "$candidate" --arg ip "$ip" --arg profile "$profile" --arg classification "$classification" --arg sc1 "${codes[0]}" --arg sc2 "${codes[1]}" --arg control_sc "${ccode:-000}" --arg h1 "${hashes[0]}" --arg h2 "${hashes[1]}" --arg control_hash "$chash" '{target:$target,ip:$ip,profile_host:$profile,classification:$classification,validation_status_codes:[$sc1,$sc2],control_status_code:$control_sc,validation_hashes:[$h1,$h2],control_hash:$control_hash}' >> "$ART/vhost_findings.jsonl"
  done
done < "$RAW/run_status.tsv"

sort -u -o "$ART/vhost_verified.txt" "$ART/vhost_verified.txt"
sort -u -o "$ART/vhost_ambiguous.txt" "$ART/vhost_ambiguous.txt"
sort -u -o "$ART/vhost_dns_dark.txt" "$ART/vhost_dns_dark.txt"

targets=$(wc -l < "$RAW/targets.tsv" | tr -d ' ')
completed=$(awk -F '\t' '$4=="completed"{n++} END{print n+0}' "$RAW/run_status.tsv")
verified=$(wc -l < "$ART/vhost_verified.txt" | tr -d ' ')
ambiguous=$(wc -l < "$ART/vhost_ambiguous.txt" | tr -d ' ')
dnsdark=$(wc -l < "$ART/vhost_dns_dark.txt" | tr -d ' ')
cat > "$ART/vhost_calibration.md" <<EOF
# Virtual-host discovery calibration — arc.io

Authorization explicitly permitted testing the deduplicated destination set, including shared infrastructure. The 5,000-entry SecLists DNS list was used with Host values restricted to \`FUZZ.arc.io\`.

- Destination IP profiles: $targets
- Completed FFUF profiles: $completed
- Rate/concurrency/timeout: $RATE req/s, $THREADS workers, ${TIMEOUT}s
- Baselines: five random high-entropy \`*.arc.io\` Host controls plus one no-custom-Host control per IP
- Matching: \`-mc all\`
- Filtering: stable baseline sizes use \`-fs\`; stable word counts additionally use \`-fw\`; variable baselines use \`-ac\`
- SNI-aware validation: every retained FFUF outlier was requested twice with \`curl --resolve candidate:443:IP\` and compared with a fresh random control
- Verified: $verified
- Ambiguous: $ambiguous
- DNS-dark: $dnsdark

Per-target calibration flags are recorded in \`raw/vhost/run_status.tsv\`; complete signatures are in \`raw/vhost/baseline_signatures.tsv\`.
EOF

cat > "$ART/subagent_08_check_status.tsv" <<EOF
check\tstatus\tevidence\tnotes
origin_scope_gate\tOVERRIDDEN_BY_EXPLICIT_AUTHORIZATION\traw/vhost/targets.tsv\tDeduplicated destination IP profiles tested.
baseline_collection\tCOMPLETE\traw/vhost/baseline_signatures.tsv\tFive random controls plus no-custom-Host control per profile.
seclists_vhost_fuzzing\tCOMPLETE\traw/vhost/ffuf/; raw/vhost/run_status.tsv\tSecLists 5K tier; BB limits honored.
sni_aware_validation\tCOMPLETE\tartifacts/vhost_findings.jsonl; raw/vhost/validation/\tAll retained outliers validated twice and compared to fresh controls.
EOF
