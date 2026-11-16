# Real-World IDOR & Access Control Vulnerability Playbook

This reference playbook details step-by-step auditing and reproduction procedures for Insecure Direct Object References (IDOR), broken object-level authorization (BOLA), and multi-tenant access control flaws based on real-world field writeups and API testing endpoints.

---

## 1. Vulnerability 1: Horizontal IDOR in State & Verification APIs

### Conceptual Overview
Horizontal IDOR occurs when an authenticated user (User A) can view or modify records belonging to another user of the same privilege level (User B) simply by tampering with an object identifier (e.g. numeric ID, UUID) in a request path or query parameter.

### Field Case Study: KYC Verification & Identity Document Disclosure (Marktplaats Model)
In peer-to-peer marketplace payment and identity verification systems:
```http
GET /p2p-payment/v1/kyc-state/1050889 HTTP/1.1
Host: api.target.com
Authorization: Bearer <User_A_Token>
```
When User A substitutes `1050889` with User B's user ID (`10714750`):
- The server checks if User A's token is valid.
- The server fails to verify whether `10714750` belongs to User A.
- The backend returns User B's sensitive KYC state, banking status, and national identity verification details.

### Step-by-Step Reproduction Instructions

#### Execution Steps
1. **Identify Object Identifiers in API Requests:**
   - Browse the application while logged in as User A.
   - Look for endpoints with direct resource identifiers:
     - `/api/v1/kyc-state/{userId}`
     - `/user-review-api/v1/user-reviews/{userId}`
     - `/api/v1/orders/{orderId}`
     - `/api/v1/invoices/{invoiceId}/download`
2. **Setup Two Distinct Test Accounts:**
   - Account A (Attacker): ID `1050889`, Auth Token A.
   - Account B (Victim): ID `10714750`, Auth Token B.
3. **Execute Horizontal Cross-Account Test in Burp Repeater:**
   - In Burp Suite, open the request for Account A:
     ```http
     GET /p2p-payment/v1/kyc-state/1050889 HTTP/1.1
     Host: api.target.com
     Authorization: Bearer <Token_A>
     ```
   - Change the target ID in the URL to Account B's ID (`10714750`):
     ```http
     GET /p2p-payment/v1/kyc-state/10714750 HTTP/1.1
     Host: api.target.com
     Authorization: Bearer <Token_A>
     ```
   - Send the request.
4. **Evaluate the Server Response:**
   - **Vulnerable:** The server returns `200 OK` with Account B's personal data.
   - **Secure:** The server returns `403 Forbidden` (`{"error": "Unauthorized access to object"}`) or `404 Not Found`.

---

## 2. Vulnerability 2: Multi-Tenant Workspace & Organization Boundary Violations

### Conceptual Overview
SaaS applications organize users into organizations, teams, or tenants. A severe authorization flaw occurs when API requests accept an `organization_id` or `tenant_id` header or body parameter, and an authenticated member of Org 1 can view data from Org 2.

### Step-by-Step Reproduction Instructions
1. **Capture an Authenticated Organization API Call:**
   ```http
   GET /api/v1/team/projects HTTP/1.1
   Host: saas.target.com
   Authorization: Bearer <Org1_User_Token>
   X-Organization-Id: org_111
   ```
2. **Tamper with Tenant Header:**
   - Replace `org_111` with `org_222` (the target victim organization).
   - If the API returns projects belonging to Org 2, multi-tenant isolation has failed.
3. **Test Parameter Pollution & Alternate Headers:**
   - Test injecting alternate tenant parameters:
     - `?org_id=org_222`
     - `?tenant=org_222`
     - `X-Tenant-Id: org_222`

---

## Remediation & Defensive Controls
1. **Context-Based Access Control:** Always look up resources using the authenticated session's user ID (e.g. `SELECT * FROM kyc WHERE user_id = :session_user_id AND kyc_id = :requested_id`).
2. **Use Unguessable UUIDv4:** Avoid sequential, predictable auto-incrementing integers (`1050889`, `1050890`) for sensitive object identifiers.
3. **Enforce Tenant Isolation in ORM / Middleware:** Ensure all database queries automatically inject the active organization context.
