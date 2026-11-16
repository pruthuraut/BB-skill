# Subagent 05: Enumeration, Timing Attacks & Defensive Controls

## Role & Mission
Responsible for identifying information leakage and defensive implementation flaws: username and email enumeration via response timing differences, forceful browsing to unauthenticated routes, timing side-channels in cryptographic comparisons, CAPTCHA validation failures, weak security questions, and case-sensitive account lockout circumvention.

## Assigned Checklist Tasks (6 Checks)
- **Check 01:** Username and email enumeration via response timing differences on login
- **Check 07:** Authentication bypass via forceful browsing to authenticated and administrative pages
- **Check 20:** Timing side-channel attacks on authentication comparison functions
- **Check 21:** CAPTCHA bypass on registration and login forms
- **Check 24:** Weak or guessable password reset security questions (KBA OSINT vulnerabilities)
- **Check 27:** Account lockout bypass via email case sensitivity variations (`User@` vs `user@`)

---

## Standardized Execution Playbook

### Step 1: Username & Email Enumeration via Response Timing (Check 01)
When backend authentication looks up a user and executes a heavy password hash (bcrypt / PBKDF2) ONLY if the user exists, valid accounts will take significantly longer to respond than non-existent accounts:

```bash
python3 -c "
import requests, statistics, time

url = 'https://<target>/api/auth/login'
headers = {'Content-Type': 'application/json'}

def measure_latency(username, attempts=10):
    latencies = []
    for _ in range(attempts):
        start = time.perf_counter()
        requests.post(url, json={'username': username, 'password': 'WrongPassword123!'}, headers=headers)
        latencies.append(time.perf_counter() - start)
    return statistics.mean(latencies)

# Test valid user vs non-existent random user
time_valid = measure_latency('admin')
time_invalid = measure_latency('non_existent_user_9918237')

print(f'Mean latency valid username: {time_valid:.4f}s')
print(f'Mean latency invalid username: {time_invalid:.4f}s')

delta = abs(time_valid - time_invalid)
if delta > 0.2:
    print(f'[!] HIGH: Timing difference of {delta:.4f}s enables reliable user enumeration!')
"
```

### Step 2: Forceful Browsing to Authenticated Endpoints (Check 07)
Audit whether server-side controllers enforce session authorization or rely on frontend routing guards:

```bash
# Strip all cookies and Authorization headers
PROTECTED_ENDPOINTS=(
  "/admin"
  "/admin/users"
  "/dashboard"
  "/api/v1/users"
  "/api/v1/orders"
  "/settings/billing"
)

for pe in "${PROTECTED_ENDPOINTS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${pe}")
  echo "Unauthenticated GET ${pe} -> HTTP ${STATUS}"
  if [ "$STATUS" = "200" ]; then
    echo "[!] CRITICAL: Forceful browsing bypass! Unauthenticated access to: ${pe}" >> artifacts/auth_bypasses_confirmed.txt
  fi
done
```

### Step 3: Account Lockout Bypass via Case Sensitivity (Check 27)
*Vulnerability Identification:* If the database lookup is case-insensitive (e.g. MySQL `utf8_general_ci` or PostgreSQL `ILIKE`), but the rate-limiter or lockout table in Redis is case-sensitive:
- `admin@target.com` (locks out after 5 attempts)
- `Admin@target.com` (locks out after 5 attempts)
- `aDmin@target.com` (locks out after 5 attempts)
- `ADMIN@target.com` (locks out after 5 attempts)

An attacker can brute-force the account indefinitely without ever triggering the lockout threshold by altering character casing.

### Step 4: CAPTCHA Bypass Verification (Check 21)
```bash
# Test 1: Remove captcha parameter completely
curl -s -X POST "https://<target>/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test_captcha1@target.com", "password":"Pass123!@#"}'

# Test 2: Send empty string for captcha
curl -s -X POST "https://<target>/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test_captcha2@target.com", "password":"Pass123!@#", "g-recaptcha-response":""}'
```

### Step 5: Weak Security Questions Auditing (Check 24)
Evaluate Knowledge-Based Authentication (KBA) for password resets:
- "What is your pet's name?" (Brute-forceable via top 50 pet names).
- "What high school did you attend?" (Easily discovered on LinkedIn / Facebook OSINT).
- "What is your mother's maiden name?" (Public records / voter databases).

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_05_enumeration_report.md`
