# Subagent 03: Object & Function Authorization (BOLA/BFLA) & Mass Assignment

## Role & Mission
Responsible for evaluating Broken Object Level Authorization (BOLA/IDOR), Broken Function Level Authorization (BFLA/Privilege Escalation), JSON Mass Assignment, and HTTP verb tampering across discovered API endpoints.

## Assigned Checklist Tasks (7 Checks)
- **Check 11:** Broken Object Level Authorization (BOLA/IDOR) on entity endpoints (`/api/users/{id}`)
- **Check 12:** Broken Function Level Authorization (BFLA) on administrative endpoints (`/api/admin/users`)
- **Check 13:** Mass Assignment through undocumented JSON parameter binding
- **Check 14:** HTTP method tampering (`GET` vs `POST` vs `PUT` vs `DELETE`)
- **Check 15:** Verb tunneling via `X-HTTP-Method-Override`, `X-Method-Override`, and `_method`
- **Check 16:** Content-Type negotiation bypasses (`application/json` to `application/xml` or `application/x-www-form-urlencoded`)
- **Check 17:** Excessive data exposure in JSON responses (filtering client-side vs backend)

---

## Standardized Execution Playbook

### Step 1: BOLA / IDOR Verification
Identify endpoints accepting user/tenant identifiers in path or query strings:

```bash
# Test swapping identifiers with standard unprivileged test credentials
curl -sk -X GET "https://<target>/api/v1/users/<victim_id>" \
  -H "Authorization: Bearer <attacker_token>" \
  -H "Accept: application/json"
```

### Step 2: HTTP Verb Override & BFLA Testing
Test administrative routes using standard user tokens with method manipulation:

```bash
# Method overriding
curl -sk -X POST "https://<target>/api/admin/system/settings" \
  -H "X-HTTP-Method-Override: GET" \
  -H "Authorization: Bearer <user_token>"
```

### Step 3: Mass Assignment Testing
Fuzz object creation and update endpoints (`POST` / `PUT`) with privileged fields (`isAdmin`, `role`, `verified`, `plan`, `credits`):

```bash
curl -sk -X PUT "https://<target>/api/v1/profile" \
  -H "Authorization: Bearer <user_token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"Tester","isAdmin":true,"role":"admin","is_verified":true}'
```

---

## Output Artifacts
- `artifacts/api_bola_matrix.json` — Evaluated BOLA/IDOR endpoints.
- `artifacts/api_mass_assignment.json` — Identified accepted privileged fields.
