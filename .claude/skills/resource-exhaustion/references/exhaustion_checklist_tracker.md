# Application Resource Exhaustion & Rate Limit Auditing Checklist

This checklist guides systematic auditing of application-layer resource management, velocity controls, sensitive state re-authentication, and denial of service mitigations across 25 verification points.

**Progress:** `[ 0 / 25 Complete ]`

---

## Audit Matrix

| # | Check Description | Subagent | Focus / Verification Criteria | Status |
|---|-------------------|----------|-------------------------------|--------|
| **01** | Audit re-authentication requirement on account deletion | Subagent 01 | Verify password or MFA confirmation is required prior to deleting an account | `[ ]` |
| **02** | Audit re-authentication on project and workspace destruction | Subagent 01 | Ensure destructive project removal actions require credential re-validation | `[ ]` |
| **03** | Audit rate limiting on customer feedback and contact forms | Subagent 02 | Verify forms enforce submission velocity limits and reject rapid automation | `[ ]` |
| **04** | Audit rate limiting on abuse and content reporting workflows | Subagent 02 | Verify mass-reporting cannot be used to automate denial of service on accounts | `[ ]` |
| **05** | Audit rate limiting on resume and document uploads | Subagent 02 | Ensure file upload endpoints restrict submissions per user and IP | `[ ]` |
| **06** | Audit payload byte limits on JSON request bodies | Subagent 03 | Verify server rejects request bodies exceeding defined size thresholds (e.g. 100KB) | `[ ]` |
| **07** | Audit maximum file size limits on multipart uploads | Subagent 03 | Verify server enforces strict maximum upload size limits (e.g. 5MB, 10MB) | `[ ]` |
| **08** | Audit image decompression and pixel flood limits | Subagent 03 | Test if oversized image dimensions (e.g. 50,000x50,000 px) are rejected early | `[ ]` |
| **09** | Audit archive decompression bomb resilience | Subagent 03 | Ensure unzipping routines enforce maximum uncompressed size and recursion limits | `[ ]` |
| **10** | Audit XML entity expansion and external entity limits | Subagent 03 | Ensure XML parsers disable external entities and restrict entity expansion depth | `[ ]` |
| **11** | Audit regex pattern execution time (ReDoS resilience) | Subagent 03 | Evaluate regex patterns on input fields for polynomial or exponential complexity | `[ ]` |
| **12** | Audit database query pagination limit enforcement | Subagent 04 | Verify API endpoints enforce a maximum `limit` ceiling (e.g. max 100 records) | `[ ]` |
| **13** | Audit batch operation array element limits | Subagent 04 | Verify endpoints accepting arrays enforce a strict maximum element count | `[ ]` |
| **14** | Audit asynchronous worker job queue limits | Subagent 04 | Verify background tasks (email, export, PDF generation) have rate limits | `[ ]` |
| **15** | Audit disk storage quota enforcement per account | Subagent 04 | Ensure user accounts cannot exceed assigned storage allocations | `[ ]` |
| **16** | Audit session cache and in-memory store eviction | Subagent 04 | Verify Redis/Memcached rate limit keys have explicit TTL expiration policies | `[ ]` |
| **17** | Audit HTTP connection timeout configurations | Subagent 04 | Ensure webservers enforce read, write, and idle timeouts against Slowloris | `[ ]` |
| **18** | Audit HTTP request header count and size limits | Subagent 04 | Verify reverse proxies limit total header size (e.g. max 8KB per request) | `[ ]` |
| **19** | Audit rate limiting response headers and status codes | Subagent 02 | Verify servers return `HTTP 429 Too Many Requests` with `Retry-After` headers | `[ ]` |
| **20** | Audit IP header spoofing resilience on velocity controls | Subagent 02 | Ensure rate limiters do not trust client-supplied `X-Forwarded-For` without upstream trust | `[ ]` |
| **21** | Audit user-tier based rate limiting | Subagent 02 | Ensure rate limits track authenticated user ID in addition to client IP | `[ ]` |
| **22** | Audit CAPTCHA challenge activation on velocity thresholds | Subagent 02 | Verify repeated form submissions trigger interactive CAPTCHA verification | `[ ]` |
| **23** | Audit transactional concurrency locks during deletion | Subagent 01 | Verify account and resource deletions acquire exclusive database row locks | `[ ]` |
| **24** | Audit soft-deletion and recovery grace period policies | Subagent 01 | Ensure destructive deletions support grace-period recovery and audit logging | `[ ]` |
| **25** | Audit centralized anomaly alerting on resource exhaustion | Subagent 04 | Verify sudden traffic spikes and repeated 429 status codes trigger alerts | `[ ]` |
