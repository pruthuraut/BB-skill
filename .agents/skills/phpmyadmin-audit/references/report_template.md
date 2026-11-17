# phpMyAdmin Security Assessment Report

## Executive summary

- Target: `<https://host/path>`
- Installed version: `<version and source>` (verified against advisory: yes / no)
- Assessment date: `<YYYY-MM-DD>`
- Scope and authorization: `<program or written approval reference>`
- Tester: `<name or handle>`
- Tooling: `scripts/pma_probe.py` (version `<git commit>`), Kali tools listed in the appendix

## Findings summary

| Severity | Count |
|---|---|
| Critical | |
| High | |
| Medium | |
| Low | |
| Info | |

## Detailed findings

Repeat this block for each finding.

### `<PMA-ID>` `<short title>`

- Severity: `<critical / high / medium / low / info>`
- Checklist row: `PMA-xxx`
- Affected URL or parameter: `<url>`
- Class: `<passive / bounded / authorized-only>`
- Description: what the weakness is and why it matters for this install.
- Reproduction: numbered steps, with the exact request. Redact secrets.

  ```
  curl -sk -i 'https://host/phpmyadmin/config.inc.php'
  ```

- Evidence: the matched signature and a redacted excerpt. Do not include table rows or credentials.
- Impact: what an attacker can do, stated plainly and limited to what was verified.
- Remediation: the specific fix (for example, remove the file, restrict the path, upgrade to a fixed version, enable a token and cookie flags).

## Version and advisory cross-check

| Advisory | Affected range | Installed | Match | Verified against vendor advisory |
|---|---|---|---|---|
| CVE-2025-24530 | 5.x below 5.2.2 | | | |
| CVE-2025-24529 | 5.x below 5.2.2 | | | |
| CVE-2020-26935 | 4.9 below 4.9.6, 5.0 below 5.0.3 | | | |
| CVE-2020-10802 | 4.9 below 4.9.5, 5.0 below 5.0.2 | | | |
| CVE-2018-12613 | 4.8.0, 4.8.1 | | | |
| CVE-2015-6830 | 4.3 below 4.3.13.2, 4.4 below 4.4.14.1 | | | |
| CVE-2005-3299 | 2.6.4 series | | | |

## Scope, limits, and what was not tested

- Requests sent: `<count>` of `<budget>`; delay `<seconds>`.
- Authorized-only checks run: `<list with approval reference>`, or "none".
- Checks not run and why: `<list>`.
- Data retained: none, or the list of retained artifacts with the deletion date.

## Appendix: Kali commands used

```
<commands run, with timestamps>
```

## Responsible disclosure

Report privately to the program or owner. Do not publish until they have fixed the issue and agreed to disclosure.
