# Local File Inclusion and Path Traversal Extension (extension)

Read-only detection. Use a harmless target such as a file you know exists in the test app or a benign system file (for example `/etc/hostname`). Do not read credential stores, private keys, or secrets; if reached, record the path and stop.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LFI-X-001 | Generic | `../` traversal in file parameter | bounded | `?file=../../../../etc/hostname` |
| LFI-X-002 | Generic | Encoded traversal (`%2e%2e%2f`, double encoding) | bounded | Same target, encoded variants |
| LFI-X-003 | Generic | Non-recursive strip bypass (`....//`) | bounded | Same target |
| LFI-X-004 | Generic | Null byte or extension bypass (historic) | bounded | Version check and one probe |
| LFI-X-005 | Windows | Drive, UNC, 8.3 and ADS tricks | bounded | `..\..\windows\win.ini` marker |
| LFI-X-006 | PHP | php://filter read of source (base64) | bounded | Own page source only |
| LFI-X-007 | PHP | data:, zip://, phar:// wrappers | authorized-only | Approved lab only |
| LFI-X-008 | PHP | Log poisoning to code execution | authorized-only | Not performed; report include of log file only |
| LFI-X-009 | Download | Download endpoint accepts path | bounded | Own file ID path with traversal to harmless file |
| LFI-X-010 | Image | Image endpoint reads arbitrary file | bounded | Traversal to harmless file |
| LFI-X-011 | PDF or template | Template path parameter reads files | bounded | Harmless path |
| LFI-X-012 | Log viewer | Log path parameter reads arbitrary logs | bounded | Harmless log path, redact content |
| LFI-X-013 | Config | Config path parameter exposes secrets | passive | Review parameter; report, do not read secrets |
| LFI-X-014 | Cloud storage keys | Traversal reveals cloud credential files | authorized-only | Report location only if reached; do not read |
| LFI-X-015 | Zip slip | Extraction writes outside target | bounded | See file-upload-audit UP-011 |
| LFI-X-016 | Symlink | Archive symlink extraction reads host files | bounded | See file-upload-audit UP-011 |
| LFI-X-017 | RFI | Remote file include from attacker URL | bounded | OOB host with marker content only |
| LFI-X-018 | UNC | Windows UNC path leaks NTLM hash | bounded | Own OOB SMB or HTTP listener (approved) |
| LFI-X-019 | Language path join | Path join pitfalls (Node, Python, Java) | passive | Code review |
| LFI-X-020 | Server-level | Tomcat, Spring, Nginx alias, Apache CVE-2021-41773 and CVE-2021-42013 | passive | Version check (see server-config-audit) |
| LFI-X-021 | Impact | Safe mapping of /proc/self/* and cloud metadata files | passive | Report what is reachable, no secrets read |
