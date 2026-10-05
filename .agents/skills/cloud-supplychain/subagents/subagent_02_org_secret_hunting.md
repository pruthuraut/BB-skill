# Subagent 02: Organization & Public Repository Secret Hunting

## Role & Mission
Responsible for enumerating public organization accounts on GitHub and GitLab, crawling public repositories, auditing commit histories for leaked production secrets using TruffleHog and Gitleaks, and running deep pattern searches with NoseyParker.

---

## Standardized Execution Playbook

### Step 1: Corporate Organization Repository Enumeration
Retrieve repository lists using the official GitHub CLI (`gh`):

```bash
ORG_NAME="<target_org_name>"
GITHUB_TOKEN="<token>"

mkdir -p artifacts/org_secrets/

# List all public repositories in target GitHub organization
gh repo list "$ORG_NAME" --limit 200 --json nameWithOwner,isPrivate \
  | jq -r '.[] | select(.isPrivate == false) | .nameWithOwner' \
  | tee artifacts/org_secrets/org_repos.txt
```

### Step 2: TruffleHog Organization-Wide Scanning
Execute automated verified secret detection across the target organization:

```bash
# Scan GitHub Organization using verified detector pipelines
trufflehog github --org="$ORG_NAME" --token="$GITHUB_TOKEN" \
  --only-verified \
  --json 2>/dev/null | tee artifacts/org_secrets/trufflehog_org.jsonl
```

### Step 3: Gitleaks High-Speed Repository Commit Auditing
Scan top organization repositories for commit history secrets:

```bash
cat artifacts/org_secrets/org_repos.txt | head -n 30 | while read -r repo; do
  SAFE_REPO=$(echo "$repo" | tr '/' '_')
  echo "[*] Scanning repository commit history: $repo"
  
  gitleaks detect --repo="https://github.com/${repo}" \
    --report-path="artifacts/org_secrets/gitleaks_${SAFE_REPO}.json" \
    --no-git 2>/dev/null
done
```

### Step 4: NoseyParker Deep Regex Pass
Run NoseyParker against the organization root for exhaustive key extraction:

```bash
noseyparker scan --git-url "https://github.com/${ORG_NAME}" \
  -o artifacts/org_secrets/noseyparker_results/ 2>/dev/null
```

### Step 5: Secret Verification & Triage Rules
Verify all detected credentials against standard read-only verification endpoints:
- **AWS:** `aws sts get-caller-identity --no-cli-pager`
- **GitHub:** `curl -s https://api.github.com/user -H "Authorization: token $KEY"`
- **OpenAI:** `curl -s https://api.openai.com/v1/models -H "Authorization: Bearer $KEY"`
- **Stripe:** `curl -s https://api.stripe.com/v1/charges -u "$KEY:"`

- **KILL** — Sample test keys or dummy mock values in unit tests (e.g. `AKIAIOSFODNN7EXAMPLE`).
- **DOWNGRADE P1 -> P2** — Confirmed active token with read-only/viewer access only.
- **KEEP (CRITICAL)** — Production root credentials, admin PATs, or AWS keys with operational IAM permissions.

---

## Output Artifacts
- `artifacts/org_secrets/org_repos.txt` — Discovered public organization repositories.
- `artifacts/org_secrets/trufflehog_org.jsonl` — Cryptographically verified credential leaks.
