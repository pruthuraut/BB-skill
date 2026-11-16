# Cookies, Session Lifecycle, and JWT (extension)

Class key: `passive` = header or token inspection on your own session. `bounded` = a few requests on two of your own accounts. `authorized-only` = forging or altering tokens against a live target.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SM-COOK-001 | Session cookie | Secure flag missing | passive | `curl -sI` Set-Cookie |
| SM-COOK-002 | Session cookie | HttpOnly flag missing | passive | Set-Cookie attributes |
| SM-COOK-003 | Session cookie | SameSite missing or None | passive | Set-Cookie attributes |
| SM-COOK-004 | Session cookie | __Host- or __Secure- prefix not used | passive | Set-Cookie names |
| SM-COOK-005 | Session cookie | Domain scope too broad (parent domain) | passive | Set-Cookie Domain attribute |
| SM-COOK-006 | Session cookie | Long Max-Age or no expiry on session token | passive | Set-Cookie Expires/Max-Age |
| SM-FIX-001 | Login | Session ID not rotated after login | bounded | Own account: note session before and after login |
| SM-FIX-002 | Login | Session fixation by setting cookie before login | bounded | Own test: set a known cookie, log in, compare |
| SM-ENT-001 | Token | Session token entropy and length | passive | Collect 20 own tokens, check length and charset |
| SM-ENT-002 | Token | Predictable token (sequential, time-based) | bounded | Own tokens over short time, compare |
| SM-LOG-001 | Logout | Session still valid after logout | bounded | Own account: logout then replay cookie |
| SM-LOG-002 | Password change | Other sessions remain valid after password change | bounded | Own two sessions: change password in one, test other |
| SM-LOG-003 | Timeout | Idle timeout not enforced | bounded | Own session: wait configured idle time, test |
| SM-TOK-001 | Token in URL | Session or JWT in query string (Referer leak) | passive | Grep links and redirects for token params |
| SM-TOK-002 | Token in logs | Token logged server-side or in error output | passive | Review error responses for token text |
| SM-REF-001 | Refresh token | Refresh token not rotated or reusable | bounded | Own account: refresh twice, replay old token |
| JWT-001 | JWT | alg none accepted | bounded | Own token re-signed with alg none, expect rejection |
| JWT-002 | JWT | RS256 to HS256 confusion with public key | bounded | Own token, check verification result on own endpoint |
| JWT-003 | JWT | Weak HMAC secret | authorized-only | Offline cracking only with approval, on your own token |
| JWT-004 | JWT | kid header injection (path or SQL) | authorized-only | Approved test with harmless marker |
| JWT-005 | JWT | jku or x5u accepts attacker URL | bounded | Own OOB host in jku, expect rejection |
| JWT-006 | JWT | Claim tampering (role, user_id) accepted | bounded | Own token with changed claim, expect 401 or 403 |
| JWT-007 | JWT | Expired token accepted | bounded | Own expired token, expect rejection |
| JWT-008 | JWT | No revocation on logout | bounded | See SM-LOG-001 |
| JWT-009 | JWT | Sensitive data in payload (PII, internal IDs) | passive | Decode own token, review claims |
