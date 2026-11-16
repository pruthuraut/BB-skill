---
name: ldap-injection-audit
description: Audit authorized applications for LDAP filter injection in login forms, directory search, and any feature that builds an LDAP filter from user input. Covers wildcard (*) matching, parenthesis and boolean (&, |) manipulation, backslash escapes, error-based syntax signals, attribute and boolean oracles, and authentication bypass shapes tested on your own account. Differential probe with an escaped-wildcard control. Triggers on "LDAP injection", "LDAP filter", "directory search", "Active Directory login", "uid=", "cn=", "(|(", "(&(", or when route_target.py routes username, cn, uid, search, or dn parameters.
---

# LDAP Injection Audit

Find where user input is written into an LDAP search filter without escaping. The probe compares a wildcard with an escaped wildcard control and a true boolean with a false one. A finding requires both signals. No directory entries are enumerated.

Checklist: `references/ldap_checklist.md`. Tool: `scripts/ldap_probe.py`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. Find filter-backed inputs: login username, directory search, employee or contact lookup, group membership checks, and SSO connectors. Route with `route_target.py --params`.
3. Run the differential probe:

   ```
   python3 .agents/skills/ldap-injection-audit/scripts/ldap_probe.py --target example.com \
     --workspace ~/Documents/bugbounty --url https://example.com/search --param cn \
     --out artifacts/example.com/ldap.json
   ```

   For login forms add `--method POST --other password=<wrong-password-on-own-account>`. The probe sends at most 25 requests.
4. Read `wildcard_differs`, `boolean_pair_differs`, and `escaped_wildcard_literal`. Report `ldap-filter-injection-indicated` only when the escaped control behaves like a literal and the boolean pair differs.
5. Check for error-based syntax signals only as supporting evidence; do not use them to read attribute names.
6. Source review (if in scope): look for filter strings built with concatenation or string formatting from request values, and whether the code escapes `*`, `(`, `)`, `\`, and NUL.
7. Save evidence to `artifacts/<target>/ldap.json`.

## Classes

- `passive`: source review and error text.
- `bounded`: wildcard, boolean, syntax, and escape differential tests on your own account or a benign search term.
- `authorized-only`: attribute or value enumeration through the boolean oracle, and any authentication bypass attempt beyond a wrong password on your own account.

## Rules

- Do not enumerate users, groups, or attributes. Stop at the boolean oracle.
- Login probes use your own account with a wrong password. Never attempt a bypass against accounts you do not own.
- Redact directory data in any response you save.
- Report the filter construction, the escaping gap, and the fix: escape the RFC 4515 special characters (`*`, `(`, `)`, `\`, NUL) before building the filter, or use parameterized LDAP query APIs.
