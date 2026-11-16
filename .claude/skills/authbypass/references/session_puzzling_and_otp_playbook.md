# Session Puzzling, Response Manipulation & HPP Authentication Playbook

This reference playbook provides step-by-step auditing and reproduction instructions for high-impact authentication bypass patterns extracted from real-world bug bounty assessments, including Session Puzzling, Response Manipulation, and HTTP Parameter Pollution.

---

## 1. Vulnerability 1: Session Puzzling (Session Variable Overloading)

### Conceptual Overview
Session Puzzling occurs when an application uses a single session variable for multiple disparate contexts or fails to reset session state flags between sequential workflow phases. This allows an attacker to:
1. Skip mandatory verification phases (e.g. phone/email OTP verification).
2. Inherit elevated permissions by initiating a secondary workflow within an existing authenticated session.

### Field Case Study: Multi-Phase Bypass (Synology Account Model)
In multi-phase workflows (such as updating a critical account attribute like phone number or recovery email):
- **Intended Flow:** Input New Phone -> Server sends OTP -> User submits OTP -> Server validates OTP -> Server updates phone number.
- **Flawed Flow:** Application marks the session as having an "in-flight update" upon sending the OTP, but fails to check whether OTP validation actually completed when the form is re-submitted after a page reload.

### Step-by-Step Reproduction Instructions

#### Prerequisites
- Burp Suite Community or Professional configured with browser proxy.
- Two test accounts (or one account with an alternate phone number/email).

#### Execution Steps
1. **Initiate the Target Action:**
   - Log into your test account.
   - Navigate to the **Profile / Security Settings** page.
   - Select **Update Phone Number** (or Update Recovery Email).
2. **Trigger the First Stage:**
   - Enter your new secondary phone number and click **Send Verification Code**.
   - Note the outgoing request in Burp Suite (e.g., `POST /api/v1/user/phone/send-otp`).
3. **Interrupt the Sequence:**
   - **Do NOT enter the received OTP code.**
   - Hard refresh the page (`Ctrl + F5`) or navigate back to the dashboard and re-open the Phone Number settings.
4. **Re-Submit the Target Phone Number:**
   - Re-enter the exact same new phone number.
   - Click **Save** or submit the update form.
5. **Analyze Server Behavior:**
   - Observe if the application accepts the change immediately without requesting or verifying the OTP code.
   - Check if the backend response returns `200 OK` with updated profile data.

#### Verification Criteria
- **Vulnerable:** The phone number/email updates directly on the user record without submitting an OTP token or after bypassing the intermediate verification state.
- **Secure:** The backend returns `400 Bad Request` or `403 Forbidden` (`{"error": "OTP verification required"}`) until a one-time validation token issued by the OTP verification endpoint is presented.

---

## 2. Vulnerability 2: Account Takeover via Response Manipulation

### Conceptual Overview
Client-side response manipulation occurs when modern Single-Page Applications (React, Vue, Angular) determine authentication and session state based on frontend interpretation of JSON response flags (e.g., `status: true`, `isSuccess: 1`, `token: ...`) rather than enforcing server-side session cookies or cryptographic JWT signatures on subsequent authenticated API calls.

### Field Case Study: Koo App Account Takeover Model
When logging in via mobile OTP:
- Attacker provides victim's phone number.
- Server sends OTP to victim.
- Attacker submits an arbitrary incorrect OTP (`0000` or `1234`).
- Server returns `400 Bad Request` (`{"status": false, "message": "Invalid OTP"}`).
- Attacker manipulates the HTTP response into `200 OK` containing a valid profile response structure, causing the client app to transition into an authenticated session.

### Step-by-Step Reproduction Instructions

#### Prerequisites
- Burp Suite Interceptor enabled.
- Account A (Attacker test account) and Account B (Victim test account).

#### Execution Steps
1. **Capture a Valid Authentication Response Baseline (Account A):**
   - Log into Account A using a valid OTP.
   - In Burp Suite, right-click the OTP submission request (`POST /api/v1/auth/verify-otp`) -> **Do intercept** -> **Response to this request**.
   - Capture and copy the complete valid HTTP response body and headers:
     ```http
     HTTP/1.1 200 OK
     Content-Type: application/json; charset=utf-8

     {
       "status": true,
       "code": 200,
       "data": {
         "user_id": 102938,
         "token": "valid_session_token_sample",
         "isNewUser": false,
         "profileComplete": true
       }
     }
     ```
2. **Initiate Verification for Target Account (Account B):**
   - Log out completely.
   - Navigate to the login portal and input the phone number or email of Account B.
   - Request an OTP.
3. **Submit an Arbitrary/Bogus OTP:**
   - Submit `000000` as the verification code.
   - Enable **Burp Intercept**: Intercept the outgoing request to `POST /api/v1/auth/verify-otp`.
4. **Intercept the Server Response:**
   - In Burp Suite, right-click the intercepted request -> **Do intercept** -> **Response to this request**.
   - Forward the request to the server.
   - The intercepted response will arrive from the server:
     ```http
     HTTP/1.1 400 Bad Request
     Content-Type: application/json

     {"status": false, "message": "Incorrect OTP entered"}
     ```
5. **Replace Response with Valid Baseline:**
   - Overwrite the HTTP response status code to `HTTP/1.1 200 OK`.
   - Replace the response body with the baseline JSON captured in Step 1 (updating user identifiers if known).
   - Forward the modified response to the browser.
6. **Evaluate Session State:**
   - Observe the browser application. Does the frontend dashboard load the victim's account feed or profile?
   - Crucial Verification: Attempt to perform an authenticated action (e.g. view private profile data, send a message). If subsequent requests are accepted by the backend, full Account Takeover is confirmed.

---

## 3. Vulnerability 3: HTTP Parameter Pollution (HPP) in Auth & OTP

### Conceptual Overview
HTTP Parameter Pollution involves injecting duplicate query or body parameters (e.g. `identifier=victim&identifier=attacker` or duplicate JSON keys). Web servers, application frameworks, and API gateways parse duplicates differently:
- Node.js / Express: Arrays (`["victim", "attacker"]`)
- ASP.NET: Concatenation (`victim,attacker`)
- PHP: Last parameter wins
- Python / Django: Last parameter wins

If the application uses the first parameter to look up the database record and the last parameter to route the SMS/Email, the OTP gets sent to the attacker's device.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Locate the OTP Generation Request:**
   - Trigger an OTP dispatch in your test account:
     ```http
     POST /api/v1/auth/send-otp HTTP/1.1
     Host: target.com
     Content-Type: application/json

     {"identifier": "+15550001111", "channel": "sms"}
     ```
2. **Test JSON Key Duplication:**
   - Send the request to Burp Repeater.
   - Duplicate the `identifier` key with an attacker-controlled number:
     ```json
     {
       "identifier": "+15550001111",
       "identifier": "+15559998888",
       "channel": "sms"
     }
     ```
3. **Test URL-Encoded Form Duplication:**
   - For form-encoded submissions:
     ```http
     POST /api/v1/auth/send-otp HTTP/1.1
     Content-Type: application/x-www-form-urlencoded

     identifier=+15550001111&identifier=+15559998888&channel=sms
     ```
4. **Evaluate Behavior:**
   - Check if an SMS arrives on `+15559998888`.
   - Submit that received OTP against Account 1 (`+15550001111`).
   - If verified, HPP routing vulnerability is confirmed.

---

## Remediation & Defensive Controls
1. **Server-Side State Binding:** Strictly bind OTP tokens to a single server-side session ID stored in secure, HttpOnly, SameSite cookies.
2. **Eliminate Client-Side Trust:** Never trust client-modified responses for authorization; every subsequent API call must re-authenticate the session token server-side.
3. **Strict Schema Validation:** Reject requests containing duplicate JSON keys or unexpected parameter arrays with `400 Bad Request`.
