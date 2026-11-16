# Brute Force, Password Policy, MFA, Enumeration, and Login Pages (extension)

Class key: `passive` = policy and page review. `bounded` = at most 10 requests against your own accounts or a fixed username list you have permission to use. `authorized-only` = spraying, brute force, or credential tests of any kind.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CRED-X-001 | Login | Brute-force protection (lockout, CAPTCHA, delay) | bounded | 10 failed attempts on own account; compare response on attempt 10 |
| CRED-X-002 | Login | Username enumeration via response text or status | bounded | Known-valid vs invalid username on own list |
| CRED-X-003 | Login | Username enumeration via timing | bounded | 5 timed requests each; compare medians |
| CRED-X-004 | Login | Default credentials on product admin pages | authorized-only | Only with approval, from the tech-stack-audit list |
| CRED-X-005 | Login | Password spraying exposure (OWA, VPN, SSO) | authorized-only | Lockout review and approved spray only |
| CRED-X-006 | Password policy | Minimum length, complexity, breached-password check | passive | Test signup with own weak sample value rejected or accepted (no login attempt) |
| CRED-X-007 | Password policy | Maximum length limit (DoS through bcrypt) | bounded | One 4 KB password on own signup |
| CRED-X-008 | Password policy | Password reuse allowed | bounded | Own account, change to previous password |
| CRED-X-009 | MFA | MFA not enforced on all login paths (API, legacy) | bounded | Own account: login via alternate endpoint |
| CRED-X-010 | MFA | OTP brute force without rate limit (6-digit space) | authorized-only | Compute attempts needed from policy; do not brute force |
| CRED-X-011 | MFA | OTP reuse across sessions | bounded | Own account two sessions |
| CRED-X-012 | MFA | Push fatigue (MFA prompt flooding) | authorized-only | Policy review only |
| CRED-X-013 | MFA | Backup codes predictable or unlimited | passive | Review code format and count |
| CRED-X-014 | Reset | Reset OTP not rate limited | bounded | 10 requests on own account |
| CRED-X-015 | Reset | Token in URL leaked through Referer | passive | Check reset page resources |
| CRED-X-016 | Active Directory | Kerberoastable accounts and AS-REP roastable accounts | authorized-only | Inventory from approved AD view; no ticket requests without approval |
| CRED-X-017 | LDAP | Anonymous bind allowed | bounded | Anonymous rootDSE query |
| CRED-X-018 | Okta / SSO | Legacy auth protocols allow password-only login | authorized-only | Policy review |
| CRED-X-019 | Forms | Login over HTTP or mixed content | passive | Form action scheme |
| CRED-X-020 | Forms | Credentials in query string | passive | Form method and action review |
