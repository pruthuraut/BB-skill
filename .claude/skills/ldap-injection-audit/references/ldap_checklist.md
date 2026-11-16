# LDAP Injection Checklist

Class key: `passive` = source and error text. `bounded` = differential tests on your own account or benign terms, at most 25 requests per field. `authorized-only` = enumeration through the boolean oracle and any authentication bypass attempt beyond a wrong password on your own account.

## Wildcard and filter behaviour

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-WC-001 | Login form | `*` as username changes the response (wildcard match) | bounded | `ldap_probe.py --method POST --other password=<wrong>` |
| LDAP-WC-002 | Search | `*` returns more results than a random term | bounded | `ldap_probe.py`; control must match baseline |
| LDAP-WC-003 | Search | Escaped wildcard `\2a` behaves like a literal (not a wildcard) | bounded | Control probe; must match baseline when filter escaping is correct |
| LDAP-WC-004 | Login form | `*` as username returns a different error than wrong password | bounded | Compare responses |
| LDAP-WC-005 | Directory search | Wildcard in multiple fields (name, mail) | bounded | One probe per field |

## Parentheses and boolean logic

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-PAR-001 | Search | `)(` closes and opens a clause and changes the response or error | bounded | `ldap_probe.py` syntax probe |
| LDAP-PAR-002 | Search | `*)(&` and `*)(|(` change filter logic | bounded | Boolean pair with objectClass |
| LDAP-PAR-003 | Search | Boolean TRUE `*)(objectClass=*` vs FALSE `*)(objectClass=<random>-never` differ | bounded | `ldap_probe.py` boolean pair |
| LDAP-PAR-004 | Login | Authentication bypass shape `*)(&` with a wrong password | bounded | Own account; wrong password; never against accounts you do not own |
| LDAP-PAR-005 | Login | OR injection `)(|(cn=*` changes result | bounded | Same restriction as LDAP-PAR-004 |
| LDAP-LOG-001 | Search | `&` and `|` operators alter result sets | bounded | Differential only |

## Escaping and encoding

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-ESC-001 | Any | Backslash escape (`\`) alone causes a parse error | bounded | Lone backslash probe |
| LDAP-ESC-002 | Any | Hex escapes (`\2a`, `\28`, `\29`, `\5c`) are decoded in the filter | bounded | Escaped-wildcard control result |
| LDAP-ESC-003 | Any | NUL character (`%00`) truncates the filter | bounded | Own term with NUL; differential |
| LDAP-ESC-004 | Any | Double-escaping mismatch between app and LDAP layer | passive | Review the escaping function and its call sites |

## Error and blind signals

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-ERR-001 | Any | Error text names LDAP filter errors (Bad search filter, invalid filter) | bounded | Syntax probe; grep error signatures |
| LDAP-ERR-002 | Any | Error-based attribute name disclosure | authorized-only | Not run by this skill |
| LDAP-BLD-001 | Any | Boolean oracle via response differences (true vs false condition) | bounded | Boolean pair only; stop there |
| LDAP-BLD-002 | Any | Attribute-value extraction through the oracle | authorized-only | Not run by this skill |

## Directory and feature contexts

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-DIR-001 | Active Directory | Login via sAMAccountName or UPN with filter concatenation | bounded | Own account, wrong password |
| LDAP-DIR-002 | Corporate directory | Employee or contact lookup with partial names | bounded | Own name only; differential |
| LDAP-DIR-003 | SSO connectors | Group or membership checks built from user input | passive | Review code |
| LDAP-DIR-004 | Anonymous bind | Anonymous rootDSE readable | bounded | Anonymous rootDSE query (no search) |
| LDAP-DIR-005 | Null bind | Anonymous search returns entries | authorized-only | Approval; report count only |

## Source review

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-SRC-001 | Java (JNDI) | `(uid=" + user + ")` concatenation into search filters | passive | Grep for `"(` and `+` near `search(` |
| LDAP-SRC-002 | Python (ldap3, python-ldap) | Filter built with f-strings or `%` formatting | passive | Grep `search_s`, `search_ext`, and `Connection.search` arguments |
| LDAP-SRC-003 | .NET (DirectorySearcher) | `Filter` string built from input | passive | Grep `DirectorySearcher` and `Filter =` |
| LDAP-SRC-004 | PHP (ldap_search) | Filter string concatenation | passive | Grep `ldap_search(` |

## Reporting

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| LDAP-RPT-001 | Evidence | Request, control result, boolean pair result | passive | Include in report |
| LDAP-RPT-002 | Fix | Escape RFC 4515 special characters (`*`, `(`, `)`, `\`, NUL) before building the filter | passive | Recommendation |
| LDAP-RPT-003 | Fix | Use parameterized LDAP query APIs or allowlist the input | passive | Recommendation |
| LDAP-RPT-004 | Fix | Use a service account with minimal read rights and no anonymous search | passive | Recommendation |
