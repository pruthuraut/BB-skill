# Broken Access Control & IDOR Vulnerability Audit Checklist

This checklist guides systematic auditing against Insecure Direct Object References (IDOR), Broken Object-Level Authorization (BOLA), and privilege escalation flaws based on TBHM Module 14 and repository writeups (`Broken Access Control/IDOR WRITEUP.txt`).

**Progress:** `[ 0 / 25 Complete ]`

---

## Audit Matrix

| # | Check Description | Subagent | Focus / Verification Criteria | Status |
|---|-------------------|----------|-------------------------------|--------|
| **01** | Identify numeric object identifiers in API routes | Subagent 01 | Audit parameters matching `/api/v1/resource/{id}` (integers, sequential IDs) | `[ ]` |
| **02** | Identify UUID / GUID object identifiers | Subagent 01 | Locate endpoints passing UUIDs and evaluate if server validates tenant ownership | `[ ]` |
| **03** | Audit horizontal IDOR on read endpoints (GET) | Subagent 01 | Verify User A cannot read User B's profile, invoices, documents, or data | `[ ]` |
| **04** | Audit horizontal IDOR on write/update endpoints (PUT/PATCH) | Subagent 01 | Verify User A cannot update User B's settings, password, or profile info | `[ ]` |
| **05** | Audit horizontal IDOR on deletion endpoints (DELETE) | Subagent 01 | Verify User A cannot delete User B's resources, tickets, or media | `[ ]` |
| **06** | Audit IDOR via parameter pollution | Subagent 01 | Test duplicate ID parameters: `id=userA&id=userB` or `ids[]=userA&ids[]=userB` | `[ ]` |
| **07** | Audit IDOR via nested JSON body objects | Subagent 01 | Test object ownership tampering in JSON: `{"account": {"id": 1002}}` | `[ ]` |
| **08** | Audit vertical privilege escalation to administrative endpoints | Subagent 02 | Verify regular users cannot access `/admin`, `/manage`, `/super` routes | `[ ]` |
| **09** | Audit vertical privilege escalation via HTTP method switching | Subagent 02 | Test accessing protected action using GET/PUT/PATCH when POST is restricted | `[ ]` |
| **10** | Audit role-based access control (RBAC) matrix consistency | Subagent 02 | Test every user role (Anonymous, Viewer, Editor, Admin) across all endpoints | `[ ]` |
| **11** | Audit parameter tampering on role definitions | Subagent 02 | Verify updating own user profile cannot accept `role=admin` or `tier=super` | `[ ]` |
| **12** | Audit multi-tenant organization boundaries | Subagent 03 | Verify Tenant A cannot query or modify Tenant B's data via `org_id` tampering | `[ ]` |
| **13** | Audit cross-organization invitation / sharing flows | Subagent 03 | Verify team invite tokens cannot be claimed across unauthorized organizations | `[ ]` |
| **14** | Audit static file & attachment access controls | Subagent 03 | Verify uploaded PDFs, receipts, and images enforce session authorization checks | `[ ]` |
| **15** | Audit export and report generation access controls | Subagent 03 | Verify CSV/PDF export endpoints do not dump data belonging to sibling tenants | `[ ]` |
| **16** | Audit batch / bulk API endpoint access controls | Subagent 03 | Verify batch operations validate ownership on every single item in the array | `[ ]` |
| **17** | Audit state machine and workflow transitions | Subagent 04 | Verify order, approval, or verification status cannot be forced by unprivileged users | `[ ]` |
| **18** | Audit GraphQL field-level authorization | Subagent 04 | Verify GraphQL resolvers validate viewer permissions on every requested node | `[ ]` |
| **19** | Audit password reset token authorization binding | Subagent 04 | Verify reset token is strictly tied to target user account and cannot update others | `[ ]` |
| **20** | Audit API key and personal access token scoping | Subagent 04 | Verify generated API keys respect permission scopes (read-only cannot write) | `[ ]` |
| **21** | Audit centralized authorization middleware enforcement | Subagent 04 | Verify controllers do not rely on ad-hoc, per-route manual checks | `[ ]` |
| **22** | Audit database query ownership binding | Subagent 04 | Ensure queries enforce `WHERE user_id = :session_user_id` at the data layer | `[ ]` |
| **23** | Audit indirect reference maps (session-based mapping) | Subagent 04 | Evaluate replacing raw IDs with randomized, session-scoped index references | `[ ]` |
| **24** | Audit caching layer access control separation | Subagent 04 | Ensure CDN/Reverse proxy caches do not serve User A's private responses to User B | `[ ]` |
| **25** | Audit audit logging on access control failures | Subagent 04 | Verify unauthorized object access attempts trigger security alerts and logs | `[ ]` |
