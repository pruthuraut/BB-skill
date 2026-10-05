# Real-World Business Logic Flaws & Workflow Integrity Playbook

This reference playbook provides actionable auditing and reproduction instructions for complex application logic flaws, client-side trust assumptions, and multi-step state machine circumvention extracted from field bug bounty reports.

---

## 1. Vulnerability 1: Rich Text / Customer Portal Comment & Link Injection

### Conceptual Overview
Enterprise customer communities, support ticketing portals, and collaboration platforms often provide rich text (WYSIWYG) editors allowing users to format posts, attach media, or switch to "Source Code View" (`< >`). When the server relies on client-side JavaScript sanitizers (e.g. TinyMCE, CKEditor, Froala) and fails to enforce robust server-side HTML purifiers, an attacker can inject:
1. External service interaction links triggering automated metadata fetches or link previews.
2. Deceptive phishing links masquerading as legitimate incentives or official announcements.
3. Stored Cross-Site Scripting (XSS) vectors targeting support agents or community administrators.

### Field Case Study: Community Forum Source Injection (Bentley Model)
In a product community forum:
- Form allows users to post questions or replies.
- The editor offers a "View Source Code" button.
- Submitting raw HTML directly through the source view:
  ```html
  <p>OFFICIAL SUPPORT UPDATE: <a href="https://attacker.burpcollaborator.net/support">Click here to re-authenticate</a></p>
  ```
- The backend stores the raw anchor and renders it verbatim in notifications sent to email subscribers and administrators.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Identify the Rich Text Input Surface:**
   - Locate forum threads, ticket reply boxes, comment sections, or user bios.
2. **Access Source Code View:**
   - In the WYSIWYG toolbar, click the source code icon (`< >`, `HTML`, or `Source`).
   - If no button exists, intercept the HTTP POST request in Burp Suite and inspect the raw payload format.
3. **Inject Test Anchor & External Interaction Payload:**
   - Insert an anchor with an external collaborator URL:
     ```html
     <p>Claim Reward: <a href="https://YOUR-SUBDOMAIN.burpcollaborator.net/voucher">Verification Link</a></p>
     ```
4. **Inspect Server Storage & Response:**
   - Submit the comment.
   - Reload the discussion thread as an unauthenticated visitor or secondary user.
   - Inspect the rendered DOM:
     - Is the anchor tag preserved with the external `href` attribute intact?
     - Did the backend strip `target="_blank"` or add `rel="noopener noreferrer nofollow"`?
     - Did the server make an automated SSRF request to fetch link metadata (OpenGraph tags)?

---

## 2. Vulnerability 2: Unauthenticated Email Notification & Invitation Abuse

### Conceptual Overview
Applications frequently allow users to invite team members, share documents, or send reminders via email. When these endpoints fail to restrict recipient domains, lack velocity controls, or accept arbitrary HTML/text in the email body, attackers can abuse the enterprise's high-reputation mail server (SendGrid, Postmark, Amazon SES) to send phishing campaigns or spam.

### Field Case Study: Organization Invite Parameter Tampering
An endpoint designed to invite collaborators to a workspace:
```http
POST /api/v1/workspaces/invite HTTP/1.1
Host: app.target.com
Content-Type: application/json

{
  "workspace_id": "ws_12345",
  "recipients": ["colleague@company.com"],
  "custom_message": "Join our workspace"
}
```
If an attacker can alter the `recipients` list to arbitrary external addresses, inject HTML/formatting into `custom_message`, or trigger hundreds of emails without authentication or payment verification, the application becomes a free phishing relay.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Capture the Invitation / Notification Request:**
   - In your test account, trigger an invite or notification to your secondary test email.
2. **Test Recipient Validation:**
   - Check if you can add external email addresses from other domains.
   - Test array flooding: Supply 50–100 emails in the array to check if bulk dispatch occurs without rate limiting.
3. **Test HTML Injection in Email Template:**
   - In the `custom_message` or `user_name` field, insert basic formatting:
     ```json
     {
       "custom_message": "<b>Urgent:</b> Please review document <a href='https://attacker.com'>here</a>"
     }
     ```
   - Check the delivered email in your inbox: Does the email client render the hyperlink and bold formatting?
4. **Test Sender Spoofing (`from` header):**
   - Check if parameters allow overriding the sender address:
     `"from": "security@target.com"` or `"reply_to": "attacker@evil.com"`.

---

## 3. Vulnerability 3: State Machine Skipping & Step Circumvention

### Conceptual Overview
Workflows involving sequential stages (e.g., Step 1: Select Plan -> Step 2: Input Payment -> Step 3: Confirmation -> Step 4: Provision Service) often fail to verify that previous stages were legitimately passed.

### Step-by-Step Reproduction Instructions
1. **Map the Complete Flow:**
   - Step through the entire wizard in Burp Suite and record every endpoint:
     - `POST /checkout/step-1-plan`
     - `POST /checkout/step-2-payment`
     - `POST /checkout/step-3-review`
     - `POST /checkout/step-4-provision`
2. **Attempt Direct Provisioning:**
   - In Burp Repeater, issue the `POST /checkout/step-4-provision` request directly after Step 1, omitting Step 2 (payment).
   - Check if the backend provisions the subscription based merely on the presence of an active session cookie.
3. **State Rollback & Re-Verification:**
   - Initiate Step 2 (payment), deliberately cancel or provide invalid payment details, then re-issue Step 3.
   - Observe if the application state persists as "authorized" despite the payment rejection.

---

## Remediation & Defensive Controls
1. **Server-Side HTML Sanitization:** Use strict allowlist HTML purifiers (e.g., DOMPurify on frontend, Bleach or sanitize-html on backend) and strictly strip dangerous tags (`<script>`, `<iframe>`, `<object>`, `<embed>`, `onload=`).
2. **Add Security Attributes to User Links:** Force `rel="nofollow noopener noreferrer"` on all user-submitted anchors.
3. **Enforce State Validation Gates:** Maintain workflow state machine transitions in the database or Redis session store; refuse state `N` if state `N-1` is not cryptographically confirmed as completed.
