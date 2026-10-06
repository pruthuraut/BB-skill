# Server Configuration Deep Audit — 102 Checks

**Progress:** `[ 0 / 102 assessed ]`

Statuses and evidence thresholds are defined in the parent skill. A check is assessed only when its evidence path or applicability reason is recorded. Produce one row per `(target, check_id)`; an absent stack is `NOT_APPLICABLE`, not `PASS`.

Execution classes are defined in the parent skill: `P`, `B`, `C`, `M`, and `L`.

## Default content, modules, and routing

| # | Class | Check | Safe verification requirement |
|---:|:---:|---|---|
| 001 | P | Default Apache installation page | Compare `/` title/body hash and server evidence with a random-path baseline; do not rely on the banner alone |
| 002 | P | Default Nginx installation page | Confirm default welcome content and origin attribution, excluding CDN-generated pages |
| 003 | P | Default IIS installation page | Confirm IIS welcome content, headers, and target ownership |
| 004 | P | Default Tomcat installation page | Confirm Tomcat root application content without invoking management functions |
| 005 | P | Apache `server-status` exposure | One GET; record whether access is public and whether client/request details are disclosed |
| 006 | P | Apache `server-info` exposure | One GET; record module/configuration disclosure without following sensitive links |
| 007 | P | Apache `mod_status` enabled | Correlate status-handler evidence and configuration review; module presence alone is informational |
| 008 | P | Apache `mod_info` enabled | Correlate info-handler evidence and configuration review |
| 009 | B | Apache `mod_autoindex` directory listing | Request only known in-scope directories; confirm actual file index behavior |
| 010 | B | Apache `mod_userdir` exposure | Probe only owner-approved synthetic usernames; never enumerate real system users |
| 011 | B | Apache `.htaccess` processing bypass | Compare harmless path-encoding/canonicalization variants; no protected-file retrieval |
| 012 | P | Nginx `stub_status` exposure | Check documented/common status locations once and record connection counters disclosed |
| 013 | P | Nginx `nginx_status` exposure | Verify whether an alternate status route is public; dedupe with Check 012 when identical |
| 014 | B | Nginx autoindex directory listing | Request known directories and distinguish application listings from Nginx autoindex |
| 015 | B | Nginx alias path traversal | Use a harmless, owner-provided canary path adjacent to the alias; never read OS secrets |
| 016 | B | Nginx off-by-slash location traversal | Compare canonical and single boundary-variation paths against a harmless canary |
| 017 | B | Nginx `merge_slashes off` path manipulation | Compare one duplicate-slash request with baseline routing and authorization behavior |
| 018 | B | Nginx `sub_filter` bypass | Test a harmless marker/encoding variant on content explicitly known to use substitution |
| 019 | P | IIS detailed error disclosure | Request one nonexistent benign path and record stack, filesystem, module, or version details |
| 020 | B | IIS directory browsing | Request only known in-scope directories and confirm generated listing behavior |
| 021 | P/M | IIS WebDAV enabled and writable | P: OPTIONS/Allow/DAV headers only; actual write is M with disposable canary and cleanup |
| 022 | B | IIS HTTP Redirect manipulation | Test one benign path/query variation and document unsafe external or scheme redirects |
| 023 | P/B | IIS Application Request Routing security | Identify ARR/reverse-proxy headers; bounded host/scheme consistency checks only |
| 024 | B | IIS URL Rewrite rule bypass | Compare canonical and harmless encoded path variants without accessing protected data |

## Java and enterprise application servers

| # | Class | Check | Safe verification requirement |
|---:|:---:|---|---|
| 025 | P | Tomcat Manager exposure | Verify reachability and authentication boundary; do not invoke manager actions |
| 026 | P | Tomcat Host Manager exposure | Verify reachability and authentication boundary only |
| 027 | C | Tomcat default credential risk | One attempt only with owner-supplied credentials; never automatically use `tomcat/tomcat` |
| 028 | P | Tomcat documentation application exposure | Confirm public docs and disclosed version/sample configuration |
| 029 | P | Tomcat examples application exposure | Confirm examples are deployed; do not execute state-changing examples |
| 030 | C | Tomcat Manager default credential risk | Manager-specific credential boundary; cross-reference Check 027 rather than duplicate a finding |
| 031 | P/B | Jetty default servlet exposure | Confirm static/default servlet behavior with benign paths |
| 032 | P/B | Jetty JSP servlet exposure | Confirm JSP handling using an existing benign page; never upload a JSP |
| 033 | P | Jetty default welcome-file list | Review welcome-file behavior and directory fallback without file creation |
| 034 | P | WildFly management console exposure | Verify console reachability and authentication boundary |
| 035 | C | WildFly default credential risk | One owner-authorized, owner-supplied credential attempt only |
| 036 | P | WebLogic admin console exposure | Verify reachability, version clues, and authentication boundary |
| 037 | C | WebLogic default credential risk | Never automatically try `weblogic/weblogic`; use only owner-supplied credentials |
| 038 | P | WebSphere admin console exposure | Verify reachability and authentication boundary |
| 039 | C | WebSphere default credential risk | One owner-authorized, owner-supplied credential attempt only |
| 040 | P | JBoss admin console exposure | Verify reachability and authentication boundary; correlate legacy JBoss/WildFly naming |
| 041 | C | JBoss default credential risk | Never automatically try `admin/admin`; use only owner-supplied credentials |
| 042 | P | GlassFish admin console exposure | Verify reachability and authentication boundary |
| 043 | C | GlassFish default credential risk | Never automatically try `admin/adminadmin`; use only owner-supplied credentials |
| 044 | B | Apache directory listing via `.htaccess` bypass | Test harmless canonicalization variants; cross-reference Checks 009 and 011 |

## Cross-origin and browser security headers

| # | Class | Check | Safe verification requirement |
|---:|:---:|---|---|
| 045 | B | Apache CORS configuration | Use a synthetic session and allowlisted Origin values; compare absent, trusted, and untrusted origins, credentials, and `Vary: Origin` |
| 046 | B | Nginx CORS configuration | Same bounded synthetic-session origin matrix; attribute headers to the correct layer |
| 047 | B | IIS CORS configuration | Same bounded synthetic-session origin matrix; preflight only an existing safe method |
| 048 | P | Apache HSTS configuration | Check HTTPS response, max-age, subdomain scope, preload intent, and HTTP redirect behavior |
| 049 | P | Nginx HSTS configuration | Same; verify headers are present on error responses where relevant |
| 050 | P | IIS HSTS configuration | Same; distinguish IIS from upstream proxy injection |
| 051 | P | Apache CSP configuration | Evaluate policy on content that executes active resources; report unsafe directives contextually |
| 052 | P | Nginx CSP configuration | Evaluate effective policy and duplicates introduced by proxies |
| 053 | P | IIS CSP configuration | Evaluate effective policy and report-only versus enforced mode |
| 054 | P | Apache frame-embedding protection | Evaluate CSP `frame-ancestors` and `X-Frame-Options` consistency |
| 055 | P | Nginx frame-embedding protection | Same; do not report missing XFO when an effective CSP supersedes it |
| 056 | P | IIS frame-embedding protection | Same; account for application and proxy-added headers |
| 057 | P/L | Server tokens and proxy buffer-overflow exposure | Record separate subresults: P for banner/version minimization; L for overflow resistance in an isolated replica. The passive subresult cannot pass the overflow claim |

## HTTP/2 behavior and defensive controls

HTTP/2 production checks are limited to negotiation, settings capture, and a few bounded conformance requests. Any check whose purpose is flood, exhaustion, starvation, cache poisoning, desynchronization, or availability impact is `L`.

| # | Class | Check | Safe verification requirement |
|---:|:---:|---|---|
| 058 | L | Server push abuse for cache poisoning | Review push/cache configuration and test only in an isolated cache namespace |
| 059 | P/B | Connection coalescing security | Inspect certificate SAN, origin authority, DNS, and one harmless cross-authority request if explicitly in scope |
| 060 | L | Stream multiplexing abuse | Configuration/load-test review in isolated staging only |
| 061 | L | HPACK compression attack resistance | Version/config/advisory review or isolated protocol harness only |
| 062 | L | Priority manipulation denial of service | Lab only; legacy priority signaling is deprecated but remains wire-compatible |
| 063 | L | Flow-control window manipulation | Lab only; inspect configured bounds and RFC-conformant error handling |
| 064 | L | SETTINGS frame flood | No production flood; verify patched versions, limits, and lab behavior |
| 065 | L | PING frame flood | No production flood; inspect rate limiting and lab behavior |
| 066 | L | RST_STREAM flood | No production flood; inspect mitigations and lab behavior |
| 067 | L | CONTINUATION frame denial of service | Version/advisory review and isolated malformed-frame test only |
| 068 | L | HTTP/2 rapid reset | No production execution; verify vendor mitigation/version and staging limits |
| 069 | L | Header table size manipulation | Isolated HPACK/settings harness only |
| 070 | P/L | Maximum concurrent streams | P: record advertised setting; L: exhaustion/limit enforcement test |
| 071 | P/L | Initial window size manipulation | P: record setting; L: boundary/error behavior |
| 072 | P/L | Maximum frame size manipulation | P: record setting; L: invalid/boundary frame tests |
| 073 | P/L | Maximum header-list size manipulation | P: record setting; L: oversized header enforcement test |
| 074 | L | Server push cache injection | Isolated cache namespace only; cross-reference Check 058 when same root cause |
| 075 | P/B | `Alt-Svc` protocol downgrade risk | Inspect advertisement and perform one safe negotiation consistency check |
| 076 | P/L | ORIGIN frame cross-origin handling | Review origin set and authority rules; crafted-frame testing in lab only |
| 077 | B/L | Trailer header injection | Use a dedicated echo endpoint with harmless header; proxy-chain mutation testing in lab |
| 078 | B/L | Pseudo-header manipulation | One malformed idempotent request may test rejection; routing/desync variants are lab only |
| 079 | L | Connection prefetch resource exhaustion | Configuration and isolated capacity test only |
| 080 | L | Dependency-tree priority inversion | Legacy priority-tree lab test only |
| 081 | L | Exclusive-bit priority abuse | Legacy priority lab test only |
| 082 | L | Weight manipulation resource starvation | Legacy priority lab test only |
| 083 | L | Stream dependency-cycle handling | Malformed dependency graph in lab only |
| 084 | P/L | DATA-frame padding and traffic analysis | Review padding/privacy behavior; volume analysis only in lab |
| 085 | L | SETTINGS acknowledgment race | Isolated protocol state-machine test only |
| 086 | B/L | GOAWAY error handling | One graceful bounded connection test; retry/race behavior in lab |
| 087 | L | WINDOW_UPDATE manipulation | Isolated flow-control state-machine test only |
| 088 | L | CONTINUATION frame-limit bypass | Isolated malformed/long fragment sequence only |
| 089 | L | Header-field fragmentation | Isolated field-block fragmentation limits only |
| 090 | L | Dynamic-table size update manipulation | Isolated HPACK state-machine test only |
| 091 | L | Indexed header-field information disclosure | Review compression-context isolation and test only with synthetic secrets in lab |
| 092 | L | Literal header-field injection | Isolated parser/proxy-chain test with harmless synthetic headers |
| 093 | P/L | Never-indexed sensitive-header handling | Configuration/code review; synthetic-secret compression test in lab |
| 094 | L | Dynamic-table eviction attack | Isolated memory/CPU-bound test only |
| 095 | L | Connection preface mismatch handling | One malformed connection in an isolated lab; expect prompt protocol error without instability |
| 096 | L | Client magic-string validation | One invalid-preface connection in a lab; cross-reference Check 095 as one network action/finding when identical |
| 097 | B/L | HTTP/1.1 Upgrade-to-h2 security | B: one standards-conformant upgrade on an idempotent endpoint; L: invalid upgrade messages |
| 098 | B | Prior-knowledge fallback security | One direct h2 attempt and normal fallback comparison |
| 099 | P/B | ALPN negotiation manipulation | Capture supported protocols; one safe preference-order comparison |
| 100 | P/B | NPN downgrade behavior | Determine whether legacy NPN is exposed; one safe negotiation check |
| 101 | P/B | Cleartext HTTP/2 (`h2c`) security | Detect upgrade/prior-knowledge support and verify authentication/routing consistency |
| 102 | L | HTTP/2 proxy to HTTP/1.1 backend smuggling | Architecture/config review and isolated canary environment only; never desynchronize production connections |

## Protocol references

Interpret frame behavior against current HTTP/2 semantics in RFC 9113. Legacy dependency/weight priority signaling is deprecated, while RFC 9218 defines extensible priorities; retain the legacy checks only for implementations that still process those wire-compatible signals.
