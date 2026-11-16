# OAuth, OIDC, and Provider Checks (extension)

Class key: `passive` = config and flow review. `bounded` = the flow run on your own client and accounts with OOB redirect hosts. `authorized-only` = anything touching real users or client secrets.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| OAUTH-X-001 | OAuth | Authorization code theft via open redirect chained into redirect_uri | bounded | Own client; `redirect_uri=<registered>?next=<oob>` |
| OAUTH-X-002 | OAuth | redirect_uri with @ or subdomain tricks (`evil%2F@target.com/callback`) | bounded | Own client; check acceptance |
| OAUTH-X-003 | OAuth | state parameter missing or not verified | bounded | Own client; drop state, check callback acceptance |
| OAUTH-X-004 | OAuth | PKCE not enforced for public clients | bounded | Own client; omit code_verifier |
| OAUTH-X-005 | OAuth | Authorization code reuse | bounded | Own client; exchange same code twice |
| OAUTH-X-006 | OAuth | Scope escalation beyond consent | bounded | Own client; request extra scope, compare granted |
| OAUTH-X-007 | OAuth | client_secret exposed in JS or mobile app | passive | Grep bundles for client_secret |
| OAUTH-X-008 | OAuth | Implicit flow with tokens in fragment | passive | Review response_type values |
| OAUTH-X-009 | OIDC | id_token signature not verified | bounded | Own token with changed signature |
| OAUTH-X-010 | OIDC | id_token aud, iss, nonce not validated | bounded | Own token with changed aud |
| OAUTH-X-011 | OIDC | Token substitution across clients | bounded | Own two clients, reuse token |
| OAUTH-X-012 | OIDC | Account linking on unverified email | bounded | Own provider account with unverified email matching an existing own account |
| OAUTH-X-013 | OIDC | Dynamic client registration open to anonymous | bounded | Anonymous POST to registration endpoint, expect rejection |
| OAUTH-X-014 | OIDC | acr/amr MFA downgrade | bounded | Own account with MFA; request lower acr |
| OAUTH-X-015 | DPoP / mTLS | Token not sender-constrained | passive | Review token type and binding config |
| SAML-001 | SAML | XML Signature Wrapping (XSW) | bounded | Own IdP test or captured own assertion; wrapper test with harmless markers |
| SAML-002 | SAML | XML comment injection in NameID | bounded | Own assertion, marker in comment |
| SAML-003 | SAML | Signature exclusion accepted | bounded | Own assertion with signature removed |
| SAML-004 | SAML | Assertion replay accepted | bounded | Own assertion replayed twice |
| SAML-005 | SAML | XSLT or XXE in SAML parsing | bounded | OOB-host entity probe |
| SAML-006 | SAML | Metadata exposure of certificates and endpoints | passive | GET metadata URL |
| SSO-001 | SSO session | Logout does not propagate to SSO IdP session | bounded | Own two apps on same IdP; logout one |
| SSO-002 | SSO | Kerberos, NTLM, or LDAP fallback enables relay | authorized-only | Approved review of auth config |
| PROVIDER-001 | Keycloak | Admin default credentials | authorized-only | Credential test only if approved |
| PROVIDER-002 | Okta | MFA fatigue exposure and legacy protocols | authorized-only | Policy review only |
| PROVIDER-003 | Auth0 | Brute-force protection on password grant | bounded | Up to 10 attempts on own account |
| PROVIDER-004 | Apereo CAS | Management actuator RCE CVE-2020-1952 | passive | Version check |
| PROVIDER-005 | Palo Alto / Pulse / Ivanti SAML | SAML auth bypass and SSRF | passive | Version check (see tech-stack-audit) |
| PROVIDER-006 | Rocket.Chat | SAML bypass CVE-2023-28314 | passive | Version check |
| PROVIDER-007 | Zabbix | SAML session setting bypass CVE-2022-23131 | passive | Version check |
