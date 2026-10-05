# Subagent 01: Cloud Storage & Unauthenticated Database Auditing

## Role & Mission
Responsible for enumerating public cloud storage buckets (AWS S3, Google Cloud Storage, Azure Blob Storage) and unauthenticated Firebase Realtime Databases using target-derived permutations and unauthenticated read verification.

---

## Standardized Execution Playbook

### Step 1: Target Permutation Generation
Generate cloud storage name permutations based on the apex domain, subdomain root, brand keywords, and standard operational environments:

```bash
T="<target_domain>"
BASE="${T%%.*}"
CLEAN_T="${T//./-}"

NAMES=(
  "$T" "$CLEAN_T" "$BASE" \
  "dev-${BASE}" "staging-${BASE}" "backup-${BASE}" "assets-${BASE}" \
  "cdn-${BASE}" "static-${BASE}" "media-${BASE}" "public-${BASE}" \
  "data-${BASE}" "internal-${BASE}" "corp-${BASE}" \
  "${BASE}-prod" "${BASE}-dev" "${BASE}-stage" "${BASE}-backup" \
  "${BASE}-assets" "${BASE}-data" "${BASE}-media" "${BASE}-logs"
)

mkdir -p artifacts/cloud_storage/
```

### Step 2: Multi-Cloud Bucket Probing
Probe generated names across AWS S3, Google Cloud Storage, and Azure Blob storage:

```bash
for name in "${NAMES[@]}"; do
  # 1. AWS S3 Check
  s3_resp=$(curl -s "https://${name}.s3.amazonaws.com/?list-type=2" --max-time 4)
  if echo "$s3_resp" | grep -q "<Key>"; then
    echo "[S3-PUBLIC-LIST] https://${name}.s3.amazonaws.com" | tee -a artifacts/cloud_storage/public_buckets.txt
  fi
  
  # 2. Google Cloud Storage (GCS) Check
  gcs_resp=$(curl -s "https://storage.googleapis.com/${name}/?list-type=2" --max-time 4)
  if echo "$gcs_resp" | grep -q "<Key>"; then
    echo "[GCS-PUBLIC-LIST] https://storage.googleapis.com/${name}" | tee -a artifacts/cloud_storage/public_buckets.txt
  fi

  # 3. Azure Blob Storage Check
  azure_resp=$(curl -s "https://${name}.blob.core.windows.net/?comp=list" --max-time 4)
  if echo "$azure_resp" | grep -q "<Container>"; then
    echo "[AZURE-PUBLIC-LIST] https://${name}.blob.core.windows.net" | tee -a artifacts/cloud_storage/public_buckets.txt
  fi
done
```

### Step 3: Firebase Realtime Database Unauthenticated Read Check
Probe for misconfigured Firebase RTDB instances with shallow reads:

```bash
FIREBASE_TARGETS=("$BASE" "${BASE}-default-rtdb" "${BASE}-staging" "${BASE}-dev")

for fb in "${FIREBASE_TARGETS[@]}"; do
  # Use ?shallow=true to prevent dumping huge datasets (respects exfil limits)
  fb_url="https://${fb}.firebaseio.com/.json?shallow=true"
  fb_resp=$(curl -s --max-time 4 "$fb_url")
  
  if echo "$fb_resp" | grep -v '"error"' | grep -q '{'; then
    echo "[FIREBASE-UNAUTH-READ] $fb_url" | tee -a artifacts/cloud_storage/firebase_open.txt
  fi
done
```

### Step 4: Severity & Triage Verification Rules
- **KILL** — Bucket responds with `AccessDenied` / HTTP 403. Discovering the existence of a private bucket is not actionable impact.
- **KILL** — Firebase RTDB returns `{"error" : "Permission denied"}`.
- **KEEP (HIGH/CRITICAL)** — Unauthenticated `ListBucketResult` XML containing company invoices, source archives, customer PII, database backups, or internal logs.
- **PO-OF-CONCEPT STANDARD:** Cap file downloads to maximum 5 items. Never mass-download customer records.

---

## Output Artifacts
- `artifacts/cloud_storage/public_buckets.txt` — Confirmed readable cloud buckets.
- `artifacts/cloud_storage/firebase_open.txt` — Confirmed readable Firebase databases.
