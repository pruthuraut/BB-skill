# Subagent 03: High-Fidelity Secrets, Token Mining & TruffleHog Verification

## Role & Mission
Responsible for static analysis across all beautified JavaScript files and unpacked source trees: executing a battle-tested 60+ regex detection catalog (AWS, GCP, Firebase, Stripe, Slack, Discord, JWT, GitHub, Twilio, OpenAI, Anthropic, Private Keys), running TruffleHog for cryptographic secret verification, and correlating exposed tokens.

---

## 1. 60+ High-Fidelity Secret Regex Pattern Suite

Scan all files in `artifacts/js_recon/js_beautified/` and `artifacts/js_recon/source_unpacked/`:

```bash
mkdir -p artifacts/js_recon/findings/

# Scan using the consolidated patterns
cat << 'EOF' > run_patterns.sh
#!/usr/bin/env bash
TARGET_DIR="$1"
OUT_FILE="$2"
: > "$OUT_FILE"

declare -A PATTERNS=(
  ["AWS Access Key ID"]="\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"
  ["AWS Secret Key"]="aws.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]"
  ["AWS S3 Bucket"]="[a-z0-9.-]+\.s3([.-][a-z0-9-]+)?\.amazonaws\.com"
  ["AWS Cognito Pool"]="[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com"
  ["Google API Key"]="AIza[0-9A-Za-z_-]{35}"
  ["Google OAuth Client"]="[0-9]{10,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"
  ["Firebase DB"]="https?://[a-z0-9-]+\.firebaseio\.com"
  ["Firebase Config"]="(apiKey|authDomain|databaseURL|storageBucket|messagingSenderId)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]"
  ["Stripe Secret"]="sk_(live|test)_[A-Za-z0-9]{24,}"
  ["Stripe Publishable"]="pk_(live|test)_[A-Za-z0-9]{24,}"
  ["Slack Token"]="xox[baprs]-[0-9A-Za-z-]{10,}"
  ["Slack Webhook"]="https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}"
  ["Discord Webhook"]="https://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}"
  ["GitHub Token"]="(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"
  ["GitLab PAT"]="glpat-[A-Za-z0-9_-]{20}"
  ["Twilio SID"]="AC[a-f0-9]{32}"
  ["Twilio Key"]="SK[a-f0-9]{32}"
  ["SendGrid Key"]="SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"
  ["OpenAI Key"]="sk-(proj-)?[A-Za-z0-9_-]{20,}"
  ["Anthropic Key"]="sk-ant-[A-Za-z0-9_-]{20,}"
  ["JWT Token"]="eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
  ["Private Key Block"]="-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"
  ["Basic Auth URL"]="[a-zA-Z][a-zA-Z0-9+.-]{2,10}://[^/[:space:]:@'\"]{2,40}:[^/[:space:]:@'\"]{3,40}@[^[:space:]/'\"]+"
  ["Bearer Token"]="[Bb]earer\s+[A-Za-z0-9._~+/-]{15,}={0,2}"
  ["Generic API Key"]="(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9-_.]{16,}['\"]"
)

for title in "${!PATTERNS[@]}"; do
  regex="${PATTERNS[$title]}"
  grep -roEi "$regex" "$TARGET_DIR" 2>/dev/null | head -n 25 | while read -r line; do
    printf '[%s] %s\n' "$title" "$line" >> "$OUT_FILE"
  done
done
EOF
chmod +x run_patterns.sh
./run_patterns.sh artifacts/js_recon/js_beautified/ artifacts/js_recon/findings/pattern_findings.txt
```

---

## 2. TruffleHog & Gitleaks Deep Verification Pipeline
Verify cryptographic credentials against upstream provider APIs (AWS STS, Stripe, GitHub, Slack) to eliminate false positives:

```bash
# 1. Run TruffleHog on beautified bundles and unpacked sources
trufflehog filesystem artifacts/js_recon/js_beautified/ \
  --json \
  --only-verified \
  --no-update > artifacts/js_recon/findings/trufflehog_raw.jsonl

# Parse verified findings
jq -r '[.DetectorName, .SourceMetadata.Data.Filesystem.file, .Raw] | @tsv' \
  artifacts/js_recon/findings/trufflehog_raw.jsonl > artifacts/js_recon/findings/trufflehog_verified.txt

# 2. Run Gitleaks detect on JS filesystem
gitleaks detect --source=artifacts/js_recon/js_beautified/ \
  --report-path=artifacts/js_recon/findings/gitleaks.json \
  --no-git 2>/dev/null
```

---

## 3. Live Secret Confirmation Probes (Immediate Impact Check)
Whenever high-risk tokens are uncovered, confirm active permissions immediately via standard read-only probes:

```bash
# OpenAI Key Validation
curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $KEY" | jq '.data[0].id'

# Anthropic Key Validation
curl -s https://api.anthropic.com/v1/models -H "x-api-key: $KEY" -H "anthropic-version: 2023-06-01" | jq '.models[0].id'

# AWS Credentials (Identity verification only — never execute destructive calls)
aws sts get-caller-identity --no-cli-pager 2>/dev/null

# GitHub Token Validation
curl -s https://api.github.com/user -H "Authorization: token $KEY" | jq '.login'

# Stripe API Key Validation
curl -s https://api.stripe.com/v1/charges -u "$KEY:" | jq '.object'
```

### Severity & Triage Rules for Leaked Secrets
- **KEEP** — Any secret that passes `sts get-caller-identity`, `/user`, `auth.test`, or `/models` returning authenticated identity.
- **DOWNGRADE P1 -> P2** — Secret confirmed live but limited to strict read-only / public viewer scope without data mutation or pivot capabilities.
- **KILL** — Secrets returning 401 Unauthorized, invalid token signatures, or revoked API credentials.

---

## 3. GitHub & Public Repository Correlation (`gitGraber`)
Correlate target domains and extracted client credentials with exposed GitHub repositories:

```bash
# When configured with GitHub Personal Access Tokens and Slack Webhooks:
python3 gitGraber.py -q "<target_domain>" -s
```

---

## Output Artifacts
- `artifacts/js_recon/findings/pattern_findings.txt` — Grepped credential matches.
- `artifacts/js_recon/findings/trufflehog_verified.txt` — Confirmed active, verified credentials.
- `artifacts/js_recon/findings/summary.txt` — Count and breakdown by detector type.
