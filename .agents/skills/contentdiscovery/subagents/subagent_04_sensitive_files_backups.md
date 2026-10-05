# Subagent 04: Sensitive Files, Source Leaks, Backups & Credentials

## Role & Mission
Responsible for locating critical exposures: backup archives, exposed `.git`/VCS repositories, `.DS_Store` directory structures, configuration files (`.env`, `wp-config.php`, `database.yml`), package manifests, `.htpasswd` files, and database dumps.

## Assigned Checklist Tasks (12 Checks)
- **Check 08:** Backup files (`.bak`, `.old`, `.orig`, `.save`, `.swp`, `.tmp`, `~`)
- **Check 09:** Configuration files (`.env`, `.htaccess`, `.htpasswd`, `web.config`, `app.config`)
- **Check 10:** Source code repositories (`.git`, `.svn`, `.hg`, `.bzr` directories)
- **Check 11:** Exposed `.git` directory verification (`HEAD`, `config`, `index`, `objects`)
- **Check 12:** `.DS_Store` file parsing for macOS directory listings
- **Check 13:** Framework configuration files (`wp-config.php`, `config.php`, `database.yml`, `settings.py`)
- **Check 14:** Backup archives (`.zip`, `.tar.gz`, `.rar`, `.7z`, `.bak.zip`)
- **Check 27:** `.env` file exposure with database credentials and API keys
- **Check 28:** `docker-compose.yml` and `Dockerfile` exposure in root web directories
- **Check 29:** Dependency manifests (`package.json`, `composer.json`, `requirements.txt`)
- **Check 30:** `.htpasswd` files with credential hash exposure
- **Check 31:** Database dump files (`.sql`, `.db`, `.sqlite`, `.mdb`)

---

## Standardized Execution Playbook

### Step 1: VCS Repository & `.git` Extraction (Checks 10, 11)
```bash
# 1. Probe for .git/HEAD and .git/config using git_config.txt
WORDLIST_GIT="wordlists/git_config.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_GIT" \
  -mc 200 \
  -o artifacts/git_probe.json -of json

# 2. Check if .git/HEAD contains ref: refs/heads/
HEAD_CHECK=$(curl -sL "https://<target>/.git/HEAD")
if echo "$HEAD_CHECK" | grep -q "ref: refs/"; then
  echo "[!] CRITICAL: Complete .git directory exposed! Dumping via git-dumper..."
  git-dumper "https://<target>/.git/" artifacts/dumped_git_repo/
fi

# 3. Check SVN, Mercurial, Bazaar
for vcs in "/.svn/entries" "/.svn/wc.db" "/.hg/dirstate" "/.bzr/README"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${vcs}")
  [ "$STATUS" = "200" ] && echo "[!] VCS repository found: ${vcs}" >> artifacts/vcs_exposures.txt
done
```

### Step 2: Environment & Secret Configuration Files (Checks 09, 27, 30)
```bash
# Fuzz using env.txt and dotfiles.txt
WORDLIST_ENV="wordlists/env.txt"
WORDLIST_DOT="wordlists/dotfiles.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_ENV" \
  -mc 200 \
  -o artifacts/env_files.json -of json

# Verify if returned .env contains real secrets
curl -sL "https://<target>/.env" | grep -iE "(DB_PASSWORD|SECRET_KEY|API_KEY|AWS_SECRET|JWT_SECRET)" > artifacts/leaked_env_secrets.txt
```

### Step 3: High-Priority Batch Configuration & Backup File Sweep
Run a rapid cross-host probe for the top 21 critical exposure files across discovered subdomains:

```bash
PATHS=("/.env" "/.env.production" "/.env.local" "/config.json" "/config.yaml" \
       "/wp-config.php.bak" "/database.yml" "/.htpasswd" "/web.config" \
       "/settings.py" "/config.php" "/.DS_Store" "/composer.json" \
       "/package.json" "/Dockerfile" "/docker-compose.yml" \
       "/actuator/env" "/actuator/heapdump" "/.aws/credentials" \
       "/swagger.json" "/openapi.json" "/api-docs" "/graphql")

head -n 50 artifacts/live_subdomains.txt | while read -r host; do
  for path in "${PATHS[@]}"; do
    code=$(curl -so /dev/null -w '%{http_code}' --max-time 4 "$host$path")
    if [ "$code" = "200" ]; then
      echo "[EXPOSED] $host$path ($code)" | tee -a artifacts/exposed_configs_confirmed.txt
    fi
  done
done
```

### Step 4: Severity Kill Rules for Source/Config Leakage
- **KILL** — `.git` exposed where only local empty metadata exists with no remote repo URL, object trees, or commits.
- **KILL** — False positive 200 responses returning soft-404 HTML custom error pages or landing redirect loops.
- **KEEP** — Confirmed `.git` allowing commit reconstruction, unauthenticated Spring `/actuator/heapdump` or `/actuator/env`, plaintext `.env` secrets, or readable AWS/cloud credentials.
if [ -s "artifacts/leaked_env_secrets.txt" ]; then
  echo "[!] CRITICAL: Production secrets leaked in .env file!"
fi

# Fuzz for .htpasswd and web.config (Checks 09, 30)
for conf in "/.htpasswd" "/.htpasswd.bak" "/web.config" "/app.config"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${conf}")
  [ "$STATUS" = "200" ] && echo "[!] Config exposed: ${conf}" >> artifacts/config_exposures.txt
done
```

### Step 3: Application Framework Configs & Database Dumps (Checks 13, 31)
```bash
# Fuzz for Database dumps using sql.txt
WORDLIST_SQL="wordlists/sql.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_SQL" \
  -mc 200 \
  -o artifacts/sql_dumps.json -of json

# Fuzz for Application configs using config.txt
WORDLIST_CONF="wordlists/config.txt"
ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_CONF" \
  -mc 200 \
  -o artifacts/app_configs.json -of json
```

### Step 4: Backup Archives & Compressed Files (Checks 08, 14)
```bash
# Fuzz using zip.txt (Contains target-specific archive variations)
WORDLIST_ZIP="wordlists/zip.txt"

ffuf -u "https://<target>/FUZZ" \
  -w "$WORDLIST_ZIP" \
  -mc 200 \
  -o artifacts/zip_archives.json -of json
```

### Step 5: Container Manifests & Dependency Files (Checks 28, 29)
```bash
# Check Docker and Dependency Manifests
CONTAINER_FILES=(
  "/Dockerfile"
  "/docker-compose.yml"
  "/docker-compose.yaml"
  "/package.json"
  "/package-lock.json"
  "/composer.json"
  "/composer.lock"
  "/requirements.txt"
  "/Pipfile"
  "/Gemfile"
)

for cf in "${CONTAINER_FILES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${cf}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] HIGH: Sensitive manifest exposed at: ${cf}" >> artifacts/manifest_exposures.txt
  fi
done
```

### Step 6: `.DS_Store` Extraction (Check 12)
```bash
# Check and parse macOS .DS_Store
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/.DS_Store")
if [ "$STATUS" = "200" ]; then
  echo "[+] .DS_Store exposed. Parsing strings..."
  curl -sL "https://<target>/.DS_Store" | strings | grep -E "[a-zA-Z0-9_\-\.]{3,50}" | sort -u > artifacts/ds_store_entries.txt
fi
```

---

## Output Artifact
Aggregate all sensitive findings into:
`artifacts/subagent_04_sensitive_leaks.md`
