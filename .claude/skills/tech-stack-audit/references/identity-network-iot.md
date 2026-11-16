# Identity/SSO, VPN and Network Appliances, Routers, IoT/ICS, Hardware Management

Class key: see cms-ecommerce.md.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TS-ID-001 | Keycloak | Admin console default admin/admin | authorized-only | Credential test only if approved; check /auth/admin/ status |
| TS-ID-002 | Keycloak | Wildcard redirect URIs enable open redirect in OAuth | bounded | Review client redirect URI list; test with own OOB host |
| TS-ID-003 | Okta | MFA fatigue and legacy auth allowed | authorized-only | Review policy settings; no push bombing |
| TS-ID-004 | Auth0 | Rate limit on password grant | bounded | Up to 10 failed attempts on own test account, check throttling |
| TS-ID-005 | Auth0 | Management API token exposure | passive | Grep client JS for management tokens |
| TS-ID-006 | Auth0 | Impersonation enabled | authorized-only | Review tenant settings only |
| TS-ID-007 | Casdoor | SQLi /api/get-organizations CVE-2022-24124 | passive | Version check |
| TS-ID-008 | Apereo CAS | Management webapp actuator RCE CVE-2020-1952 (<6.1.5) | passive | Version check |
| TS-ID-009 | Apereo CAS | Reflected XSS in ticket validation CVE-2017-5461 (<4.0) | passive | Version check |
| TS-ID-010 | Apereo CAS | Management dashboard exposed | passive | GET /cas/actuator status |
| TS-ID-011 | SimpleSAMLphp | SAML metadata and SSO config exposed | passive | GET /simplesaml/module.php/saml/sp/metadata.php status |
| TS-ID-012 | LDAP | Anonymous bind and user enumeration | bounded | Anonymous rootDSE query, check if naming contexts readable |
| TS-ID-013 | Active Directory | Kerberoasting and AS-REP roasting exposure | authorized-only | Review accounts with SPNs and pre-auth disabled (no ticket requests without approval) |
| TS-ID-014 | LoginRadius / Clerk | Publishable vs secret key exposure | passive | Grep client JS; secret key must never appear |
| TS-ID-015 | FortiGate | SSL VPN path traversal CVE-2018-13379 | passive | Version check |
| TS-ID-016 | FortiGate | Management auth bypass CVE-2022-40684 | passive | Version check |
| TS-ID-017 | FortiGate | SSL VPN heap overflow CVE-2023-27997 | passive | Version check |
| TS-ID-018 | FortiGate / FortiNAC | Management interface exposed to internet | passive | Port 443/8443 reachability and banner |
| TS-ID-019 | FortiNAC | File upload CVE-2022-39952 | passive | Version check |
| TS-ID-020 | Palo Alto PAN-OS | GlobalProtect command injection CVE-2024-3400 | passive | Version check |
| TS-ID-021 | Palo Alto PAN-OS | GlobalProtect buffer overflow CVE-2019-1579; SAML auth bypass CVE-2020-2021 | passive | Version check |
| TS-ID-022 | Palo Alto Expedition | SQLi CVE-2024-9463 | passive | Version check |
| TS-ID-023 | Ivanti Connect Secure / Pulse | Arbitrary file read CVE-2019-11510; auth bypass CVE-2023-46805; SAML SSRF CVE-2024-21893 | passive | Version check |
| TS-ID-024 | Citrix ADC / NetScaler | Path traversal RCE CVE-2019-19781 | passive | Version check |
| TS-ID-025 | F5 BIG-IP | TMUI RCE CVE-2020-5902; iControl CVE-2021-22986 and auth bypass CVE-2022-1388 | passive | Version check; TMUI exposure status |
| TS-ID-026 | SonicWall | SQLi auth bypass CVE-2019-7481 | passive | Version check |
| TS-ID-027 | Juniper J-Web | PHP env pre-auth RCE CVE-2023-36845 | passive | Version check |
| TS-ID-028 | Cisco IOS XE | Web UI admin creation CVE-2023-20198; command injection CVE-2023-20273 | passive | Version check |
| TS-ID-029 | Cisco ISE | Exposed admin portal; path traversal RCE CVE-2023-20198 family | passive | Version check; portal banner |
| TS-ID-030 | Cisco devices | Default web management credentials | authorized-only | Credential test only if approved |
| TS-ID-031 | Cisco Prime Infrastructure | Unauthenticated file upload CVE-2019-1821 | passive | Version check |
| TS-ID-032 | Sophos XG / UTM | Pre-auth SQLi CVE-2020-12271; WebAdmin RCE CVE-2020-25223 | passive | Version check |
| TS-ID-033 | OpenVPN Access Server | Default admin credentials on 943 | authorized-only | Credential test only if approved |
| TS-ID-034 | Zyxel USG / ZyWALL | Hardcoded backdoor accounts CVE-2022-0342 | passive | Version check |
| TS-ID-035 | Sangfor SSL VPN | Pre-auth RCE CVE-2019-17414 | passive | Version check |
| TS-ID-036 | OPNsense | Management UI with default credentials | authorized-only | Credential test only if approved |
| TS-ID-037 | HAProxy | Stats page public (/haproxy?stats) | bounded | GET /haproxy?stats status (no changes) |
| TS-ID-038 | Varnish | Cache poisoning via unkeyed headers | bounded | Own-header probe (see http-protocol-cache) |
| TS-ID-039 | IBM DataPower | Default admin/admin | authorized-only | Credential test only if approved |
| TS-ID-040 | Zscaler | Portal references | passive | Grep response for portal domain (no probing) |
| TS-ID-041 | VMware vCenter / ESXi | vCenter RCE CVE-2021-21985; ESXi OpenSLP CVE-2021-21974; Workspace ONE SSTI CVE-2022-22954; Tools auth bypass CVE-2023-20867 | passive | Version check |
| TS-ID-042 | Imperva / Incapsula | Origin exposure and WAF bypass | bounded | See techfingerprint waf_cdn_origin.md |
| TS-ID-043 | Hikvision | Unauthenticated command injection CVE-2021-36260 | passive | Firmware/version check on devices in scope |
| TS-ID-044 | Hikvision / Dahua | Default credentials and exposed RTSP | authorized-only | Credential test only if approved |
| TS-ID-045 | HP iLO | Default Administrator/password on web interface | authorized-only | Credential test only if approved; banner check passive |
| TS-ID-046 | HP iLO | Web interface exposed to internet | passive | GET login page status |
| TS-ID-047 | NUUO NVR | Unauthenticated file upload CVE-2024-4192; default credentials | passive | Version check; credential test only if approved |
| TS-ID-048 | Home Assistant | API or instance without authentication | bounded | GET /api/ returns 401 vs 200 (no state changes) |
| TS-ID-049 | Home Assistant | Websocket exposure | bounded | GET /api/websocket upgrade check |
| TS-ID-050 | Repetier-Server | Unauthenticated printer control | bounded | GET login/dashboard anonymous status |
| TS-ID-051 | FUXA SCADA | Unauthenticated process controls | bounded | GET dashboard anonymous status; no commands to PLCs |
| TS-ID-052 | Altenergy Power Control | OS command injection CVE-2023-28343 | passive | Version check |
| TS-ID-053 | Linear eMerge E3 | Command injection CVE-2019-7256 | passive | Version check |
| TS-ID-054 | Ubiquiti UniFi | Default ubnt/ubnt; API auth bypass CVE-2021-22914 | authorized-only | Version check; credential test only if approved |
| TS-ID-055 | Ruckus | Command injection CVE-2023-24816; default super/sp-admin | passive | Version check; credential test only if approved |
| TS-ID-056 | TOTOLINK | Unauthenticated command injection CVE-2024-33038; hardcoded accounts | passive | Firmware version check |
| TS-ID-057 | D-Link | Unauthenticated command injection CVE-2019-16920; hardcoded backdoors | passive | Firmware version check |
| TS-ID-058 | Netgear | Unauthenticated command injection CVE-2021-45732 | passive | Firmware version check |
| TS-ID-059 | Tenda | Command injection and stack overflow CVE-2020-10987 | passive | Firmware version check |
| TS-ID-060 | Lansweeper | Default credentials exposing inventory | authorized-only | Credential test only if approved |
| TS-ID-061 | Webmin | See cms-ecommerce.md TS-CMS-125 | passive | See that file |
| TS-ID-062 | Dell EMC Unisphere | Auth bypass and data exposure CVE-2020-5377 | passive | Version check |
| TS-ID-063 | Qlik Sense | Path traversal and HTTP tunneling CVE-2023-41265/41266 | passive | Version check |
| TS-ID-064 | Cloudera Manager | Port 7180/7183 exposed; default credentials | passive | GET login status; credential test only if approved |
| TS-ID-065 | Nexus / Artifactory | Covered in devops-containers.md | passive | See that file |
