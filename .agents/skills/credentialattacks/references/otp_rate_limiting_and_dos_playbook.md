# OTP Rate Limiting, Throttling Bypass & Financial Resource Exhaustion Playbook

This reference playbook provides step-by-step auditing instructions for credential attacks, focusing on OTP rate-limiting circumvention, proxy header IP rotation, and SMS financial denial-of-service vulnerabilities based on real-world bug bounty engagements.

---

## 1. Vulnerability 1: OTP Rate Limit / Throttling Bypass via IP Spoofing

### Conceptual Overview
Applications frequently protect OTP verification endpoints against brute-force attacks by rate-limiting requests per IP address. However, poorly configured reverse proxies, load balancers, or Cloudflare/Cloudfront setups blindly trust client-supplied headers to extract the "client IP". By rotating these headers on each request, an attacker can bypass rate-limiting and exhaust the 4-digit or 6-digit OTP keyspace.

### Target Headers for Rate-Limit Spoofing
- `X-Forwarded-For: 127.0.0.1`
- `X-Originating-IP: 127.0.0.1`
- `X-Remote-IP: 127.0.0.1`
- `X-Remote-Addr: 127.0.0.1`
- `X-Client-IP: 127.0.0.1`
- `X-Real-IP: 127.0.0.1`
- `Client-IP: 127.0.0.1`
- `True-Client-IP: 127.0.0.1`

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Identify the OTP Submission Endpoint:**
   - Capture the request when submitting an invalid OTP code:
     ```http
     POST /api/v1/auth/verify-code HTTP/1.1
     Host: target.com
     Content-Type: application/json

     {"identifier": "+15551234567", "code": "0001"}
     ```
2. **Determine Normal Rate-Limit Threshold:**
   - Send the request to **Burp Repeater**.
   - Resend the request with an invalid code 5–10 times.
   - Observe if the application blocks subsequent attempts with `429 Too Many Requests` or `{"error": "Too many attempts. Try again in 15 minutes."}`.
3. **Configure Header Injection in Burp Intruder:**
   - Send the request to **Burp Intruder**.
   - Set the attack type to **Pitchfork** or **Battering Ram**.
   - Add the spoofing header to the request template:
     ```http
     POST /api/v1/auth/verify-code HTTP/1.1
     Host: target.com
     Content-Type: application/json
     X-Forwarded-For: 192.168.1.§payload1§

     {"identifier": "+15551234567", "code": "§payload2§"}
     ```
4. **Set Payloads:**
   - **Payload 1 (IP Counter):** Numbers from `1` to `1000` (step 1).
   - **Payload 2 (OTP code):** Numerical list from `0000` to `9999`.
5. **Execute Attack & Monitor Status Codes:**
   - If the application continues responding with `400 Bad Request` or `200 OK` (instead of `429 Too Many Requests`), the rate limit is effectively bypassed via header manipulation.

---

## 2. Vulnerability 2: SMS OTP Flooding & Financial Resource Exhaustion

### Conceptual Overview
SMS dispatch services (Twilio, AWS SNS, Vonage, Sinch) charge application operators on a per-SMS basis. If an application provides an unthrottled or client-manipulated endpoint to trigger SMS generation, an attacker can script thousands of requests, causing financial exhaustion (telecom toll fraud) and carrier account suspension.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Locate the Trigger Endpoint:**
   - Navigate to the registration or password recovery page.
   - Enter your test phone number and click **Send OTP**.
   - Inspect the request:
     ```http
     POST /api/v1/otp/generate HTTP/1.1
     Host: target.com
     Content-Type: application/json

     {"phone": "+15551234567"}
     ```
2. **Check for Cooldown Logic:**
   - Immediately resend the request in Burp Repeater without waiting for the frontend countdown timer (usually 60 seconds).
   - **Observation:** Does the server return `200 OK` and dispatch another SMS, or does it enforce server-side cooldown (`{"error": "Please wait 60s"}`)?
3. **Test Parameter and Case Variation:**
   - Test if modifying the phone number formatting resets the cooldown:
     - `+15551234567`
     - `0015551234567`
     - `+1-555-123-4567`
     - `+1 555 123 4567`
4. **Evaluate CAPTCHA / Proof of Work:**
   - Check if the endpoint requires a server-validated reCAPTCHA, hCaptcha, or Cloudflare Turnstile token.
   - If no CAPTCHA is enforced, or if removing the `captcha_token` parameter still results in `200 OK`, velocity controls are absent.

---

## 3. Vulnerability 3: Password Reset Token Leakage & Entropy Deficiencies

### Conceptual Overview
Password reset flows often generate one-time tokens. Common flaws include:
1. **Referer Header Leakage:** The reset link sent to email contains the token in the URL (`https://target.com/reset?token=XYZ`). If the reset page loads external analytics scripts (Google Analytics, Hotjar) or external images, the full URL with the secret token leaks in the `Referer` header to third-party servers.
2. **Predictable Tokens:** Timestamp-based tokens (`md5(timestamp)` or `sha1(username + timestamp)`) allows offline reconstruction of reset tokens.

### Verification Checklist
- Check if reset links contain tokens in URL fragments (`#token=XYZ`) rather than query parameters (`?token=XYZ`), preventing HTTP transmission in referers.
- Test whether the password reset token is invalidated immediately upon first use or if it can be reused multiple times.
- Verify whether changing the password from within an authenticated session terminates all other active sessions and invalidates all prior reset tokens.
