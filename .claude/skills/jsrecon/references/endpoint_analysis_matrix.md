# Endpoint Analysis & Triage Matrix

This reference guide provides an analytical framework for interpreting endpoints extracted from JavaScript bundles, mapping them directly to bug bounty test workflows.

---

## 1. Versioning Differential Matrix (`/v1/`, `/v2/`, `/v3/`)

When inspecting API routes, compare parallel versions:

```
[ Frontend Client ]
       │
       ├───> GET  /api/v2/user/profile  (Strict rate limit, modern authorization checks)
       │
       └───> POST /api/v1/user/profile  (Legacy endpoint: often vulnerable to BOLA / IDOR)
```

### Audit Protocol
- If `/v2/users/123` returns `403 Forbidden` on horizontal object tampering, test the exact same request against `/v1/users/123`.
- Test deprecated HTTP verbs: if `POST` requires CSRF tokens or MFA, test `PUT` or `PATCH` on older version prefixes.

---

## 2. Sensitivity Classification

Group extracted paths into prioritized testing queues:

| Sensitivity Tier | Target Patterns | Vulnerability Vectors |
| :--- | :--- | :--- |
| **Tier 1: Admin & Internal** | `/admin/`, `/staff/`, `/internal/`, `/manage/`, `/console/` | Vertical privilege escalation, authentication bypass, unauthenticated dashboards. |
| **Tier 2: Data Leakage** | `/export/`, `/backup/`, `/dump/`, `/download/`, `/report/` | PII leakage, unauthorized bulk data downloads. |
| **Tier 3: Debug & Development** | `/debug/`, `/test/`, `/temp/`, `/beta/`, `/actuator/`, `/trace/` | Verbose stack traces, environment variable exposure, remote code execution. |
| **Tier 4: State Mutations** | `/invite`, `/delete`, `/update`, `/promote`, `/transfer` | CSRF, business logic skipping, race conditions. |

---

## 3. IDOR / BOLA Indicators

| Pattern in JavaScript | Meaning | Test Action |
| :--- | :--- | :--- |
| `/{id}` or `/{userId}` | REST dynamic resource parameter | Substitute victim user UUID or integer ID in Burp Suite. |
| `/me` or `/profile` | Current session context | Check if adding `?userId=victim` or `/me?user_id=123` overrides the session binding. |
| `${teamId}` or `${orgId}` | Multi-tenant boundary | Attempt cross-tenant identifier substitution. |

---

## 4. High-Value Body & Query Parameters to Fuzz

When reviewing extracted parameters from `artifacts/js_recon/body_parameters.txt`:

1. **Privilege Escalation:** `role`, `isAdmin`, `isOwner`, `accountType`, `tier`, `permissions`.
2. **Multi-Tenancy:** `tenantId`, `orgId`, `companyId`, `workspaceId`, `groupId`.
3. **Data Exposure:** `export=true`, `format=json`, `debug=1`, `verbose=true`, `include_deleted=1`.
