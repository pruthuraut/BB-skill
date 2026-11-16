# Deserialization and SSI Injection Checklist (extension)

Class key: `passive` = detection of serialized formats and source review. `bounded` = harmless SSI echo and own-session tests. `authorized-only` = gadget chains, ysoserial or PHPGGC payloads, and any execution. This skill never sends gadget payloads.

## Deserialization

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| DSX-001 | Java | Serialized objects in cookies, params, or bodies (rO0AB, aced0005) | passive | `deser_detect.py` on captured traffic |
| DSX-002 | Java | ObjectInputStream reads untrusted data | passive | Source review (`readObject`, `ObjectInputStream`) |
| DSX-003 | Java | Gadget chain present (ysoserial class list) | authorized-only | Dependency review only (no payloads) |
| DSX-004 | PHP | Serialized strings (`O:`, `a:`) in cookies or params | passive | `deser_detect.py` |
| DSX-005 | PHP | `unserialize()` on user input | passive | Source review; `pp_scan.py`-style grep for unserialize |
| DSX-006 | PHP | PHPGGC gadget chain available in dependencies | authorized-only | Composer dependency review only |
| DSX-007 | Python | Pickle data reaches `pickle.loads` | passive | `deser_detect.py` (gASV, 0x80 headers); source review |
| DSX-008 | Python | Pickle RCE payloads | authorized-only | Never sent |
| DSX-009 | YAML | `yaml.load` without SafeLoader, `!!python/object` | passive | `deser_detect.py` YAML pattern; source review |
| DSX-010 | YAML | `!!python/object/apply` accepted | authorized-only | Lab only |
| DSX-011 | .NET | BinaryFormatter on untrusted input (AAEAAAD) | passive | `deser_detect.py` |
| DSX-012 | .NET | ViewState without MAC or with known machineKey | passive | Review web.config (machineKey present, validation on) |
| DSX-013 | .NET | JSON.NET TypeNameHandling enabled | passive | Source review |
| DSX-014 | Ruby | Marshal.load on untrusted data (BAh, 0x04 0x08) | passive | `deser_detect.py` |
| DSX-015 | Node.js | node-serialize with function markers (`_$$ND_FUNC$$_`) | passive | `deser_detect.py` |
| DSX-016 | JSON | Type confusion from attacker-chosen class or type fields | bounded | Own request with a type field changed to an invalid type; compare errors |
| DSX-017 | XML | XML deserialization combined with XXE | bounded | See xml-xxe-audit |
| DSX-018 | Queues | Consumers deserialize messages from a queue | passive | Review consumer code; message format |
| DSX-019 | Sessions | Cached session objects deserialized from storage | passive | Review session store and serializer |
| DSX-020 | Files and DB | Import features and BLOB reads deserialize content | passive | Review import code; own file with marker only |
| DSX-021 | Caches | Memcached or Redis cached objects deserialized | passive | Review cache serializer config |

## SSI injection

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| SSIX-001 | SSI | `<!--#echo var="DATE_LOCAL" -->` evaluated | bounded | `ssi_probe.py` |
| SSIX-002 | SSI | `<!--#echo var="DOCUMENT_NAME" -->` evaluated | bounded | `ssi_probe.py` |
| SSIX-003 | SSI | SSI directives in an uploaded `.shtml` file | bounded | Own file with harmless echo |
| SSIX-004 | SSI | SSI in user-generated content rendered server-side | bounded | Own profile or comment with echo |
| SSIX-005 | SSI | SSI in error pages reflecting input | bounded | Malformed path with echo marker |
| SSIX-006 | SSI | SSI in search results | bounded | Own search term with echo |
| SSIX-007 | SSI | SSI in email templates | bounded | Own address with echo marker |
| SSIX-008 | SSI | `exec` directive runs commands | authorized-only | Not sent by this skill |
| SSIX-009 | SSI | `include` directive reads local files | authorized-only | Not sent by this skill |
| SSIX-010 | SSI | Reporting: evidence and fix (disable SSI or escape directives) | passive | Recommendation |
