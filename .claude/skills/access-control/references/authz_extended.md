# Access Control and Privilege Escalation Extension (extension)

Use two self-owned accounts at different privilege levels when possible. Class key as in idor references.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| AC-X-001 | Role parameter | role, isAdmin, admin=true accepted on profile update | bounded | Own account update with field, check response and reload |
| AC-X-002 | JWT claims | Role claim trusted without signature check | bounded | See session-management JWT-002, JWT-006 |
| AC-X-003 | Cookies | Role stored in cookie and trusted | bounded | Own cookie edited to role value, expect 403 |
| AC-X-004 | Admin routes | Admin page reachable by regular user | bounded | GET /admin paths as user A |
| AC-X-005 | Admin routes | URL-encoded or case-changed admin path bypass | bounded | Variants as user A |
| AC-X-006 | Feature flags | Feature toggle API callable by any user | bounded | GET toggle list, attempt toggle on own account only if approved |
| AC-X-007 | Multi-tenant | Org or tenant ID swap in request | bounded | Own two orgs, swap ID |
| AC-X-008 | Team membership | Invitation or group membership grants access beyond role | bounded | Own two accounts, invite and check access |
| AC-X-009 | Gateway | API gateway enforces auth, backend does not (and reverse) | bounded | Same endpoint through gateway and direct backend in scope |
| AC-X-010 | UI vs API | Button hidden in UI but API accepts action | bounded | Call API action as low-privilege own account |
| AC-X-011 | Method override | X-HTTP-Method-Override changes effective method past check | bounded | Header differential on own object |
| AC-X-012 | Content-type | Switching content type bypasses authorization path | bounded | Same request in two formats |
| AC-X-013 | Backup and import | Import or restore sets privileges | bounded | Own export and import of own role data |
| AC-X-014 | Shared resources | Shared link grants more than documented | bounded | Own share link opened by second account |
| AC-X-015 | Referer or location checks | Access only checked by Referer header | bounded | Remove or change Referer on own request |
| AC-X-016 | Multi-step admin flow | Later step reachable without earlier approval | bounded | Own test flow skipping step |
| AC-X-017 | Demotion | Privileges retained after demotion | bounded | Own account demoted by admin test account, retest |
| AC-X-018 | Impersonation | Impersonation endpoint without audit or limits | authorized-only | Review only |
| AC-X-019 | API key scope | Key with read scope can write | bounded | Own key, one harmless write attempt on own object |
| AC-X-020 | Step-up auth | Sensitive action without re-authentication | bounded | Own account, check reauth prompt |
| AC-X-021 | Plan entitlements | Premium feature reachable on free plan | bounded | Own free account, call feature endpoint |
| AC-X-022 | Hidden debug parameters | `?debug=1`, `?staff=true`, `?admin=1` change behaviour | bounded | Own account, parameter with marker |
| AC-X-023 | Cache layer | Authorization-dependent response cached and served to others | bounded | See http-protocol-cache CACHE-004 |
| AC-X-024 | Races | Role assignment race condition | authorized-only | Approved test on own objects only |
