# Prototype Pollution Checklist

Class key: `passive` = source and bundle review. `bounded` = marker probes on your own page or your own test endpoint. `authorized-only` = anything that could reach execution or change security policy beyond a marker.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| PPX-001 | Client | Pollution via `__proto__` in URL or hash (`?__proto__[x]=1`) | bounded | Own page, marker name; check `Object.prototype` in console |
| PPX-002 | Client | Pollution via `constructor.prototype` | bounded | Same, with constructor path |
| PPX-003 | Client | `Object.assign` copies attacker keys including `__proto__` | passive | `pp_scan.py` (Object.assign sink) |
| PPX-004 | Node.js | Server-side pollution through merge of JSON body | bounded | Own endpoint, `{"__proto__":{"ppx_marker":"1"}}`, then check a later response for the marker |
| PPX-005 | JSON | JSON body parsing copies `__proto__` keys | bounded | Same as PPX-004 |
| PPX-006 | Query string | Query parser (qs) creates nested keys reaching prototypes | bounded | `?__proto__[ppx]=1` on own endpoint |
| PPX-007 | Deep merge | Deep merge helpers (deepmerge, merge, extend) recursive copy | passive | `pp_scan.py` helper sinks |
| PPX-008 | lodash | `_.merge` with attacker input | passive | `pp_scan.py`; check lodash version |
| PPX-009 | lodash | `_.defaultsDeep` with attacker input | passive | `pp_scan.py` |
| PPX-010 | jQuery | `$.extend(true, ...)` with attacker input | passive | `pp_scan.py` |
| PPX-011 | Gadget | Polluted `src` used by script loader (XSS) | bounded | Marker `src` value on own page; check requested URL |
| PPX-012 | Gadget | Polluted `innerHTML` default used in templates (XSS) | bounded | Marker value; check rendered DOM only |
| PPX-013 | Gadget | Polluted `isAdmin` or role property read by app | bounded | Marker property on own session; check UI or API difference |
| PPX-014 | Gadget | Polluted CSRF token property accepted by app | bounded | Own session marker; review token check code |
| PPX-015 | Gadget | Polluted security policy or feature flag object | bounded | Marker property; check behaviour change only |
| PPX-016 | Express | Middleware reading options from polluted objects | passive | Review middleware code |
| PPX-017 | hapi | Config merge with prototype keys | passive | Review config merge code |
| PPX-018 | node-config | Environment or config merge with prototype keys | passive | Review config loading code |
| PPX-019 | Environment | Environment variable names injected into process env | authorized-only | Review only; no environment writes |
| PPX-020 | RCE | Polluted `child_process` options (shell, env, execArgv) | authorized-only | Code review and lab only; never probe in production |
