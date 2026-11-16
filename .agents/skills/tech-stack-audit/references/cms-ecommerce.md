# CMS, Blogs, Forums, Ecommerce, Hosting Panels

Class: `passive` = header/body/known-path GET only. `bounded` = a few safe requests (no login attempts, no writes). `authorized-only` = anything that could exploit, authenticate, or change state.
Version checks compare the detected version with the fixed release in the advisory. Never run the exploit as part of a version check.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| TS-CMS-001 | WordPress | Admin login page exposed (/wp-admin/, /wp-login.php) | passive | GET /wp-login.php status and title |
| TS-CMS-002 | WordPress | XML-RPC enabled (brute-force amplification, pingback SSRF) | bounded | POST `system.listMethods` only, no credentials |
| TS-CMS-003 | WordPress | User enumeration via REST API | passive | GET /wp-json/wp/v2/users (record HTTP code and names only) |
| TS-CMS-004 | WordPress | Core version vs fixed release (CVE-2022-21661 WP_Query SQLi fixed 5.8.3; CVE-2021-29447 XXE fixed 5.7.1; CVE-2023-2745 traversal fixed 6.2.1) | passive | Version from readme.html / meta generator, compare to release |
| TS-CMS-005 | WordPress | Vulnerable plugins/themes by version | passive | Read /wp-content/plugins/<slug>/readme.txt "Stable tag", match with WPScan database |
| TS-CMS-006 | Drupal | Version disclosure (CHANGELOG, X-Generator) | passive | GET /CHANGELOG.txt, X-Generator header |
| TS-CMS-007 | Drupal | Drupalgeddon2 CVE-2018-7600 (Drupal <7.58, 8.x fixed per SA) | passive | Version check only; do not send the form-API exploit |
| TS-CMS-008 | Drupal | Drupalgeddon3 CVE-2018-7602 (7.x <7.59, 8.5.x <8.5.3) | passive | Version check only |
| TS-CMS-009 | Drupal | REST API unauthenticated RCE CVE-2019-6340 (8.5.x <8.5.11, 8.6.x <8.6.10) | passive | Version check only |
| TS-CMS-010 | Drupal | install.php / update.php still reachable post-install | passive | GET /core/install.php, /update.php status |
| TS-CMS-011 | Joomla | Admin panel exposed at /administrator/ | passive | GET /administrator/ status and title |
| TS-CMS-012 | Joomla | Outdated extensions with known CVEs (SQLi, LFI, RCE) | passive | Extension list from manifest XML, check Joomla Vulnerable Extensions List |
| TS-CMS-013 | Magento | Admin panel exposed (/admin, /admin_<hash>) | passive | GET /admin status |
| TS-CMS-014 | Magento | Shoplift SQLi CVE-2015-1397 (old versions) | passive | Version check only |
| TS-CMS-015 | OpenCart | Default admin credentials (admin/admin) | authorized-only | Requires approved credential test |
| TS-CMS-016 | OpenCart | Admin path exposed | passive | GET /admin/ |
| TS-CMS-017 | PrestaShop | Vulnerable modules (CVE-2023-30839 SQLi) | passive | Module list in /modules/, version check |
| TS-CMS-018 | PrestaShop | /install directory left after setup | passive | GET /install/ status |
| TS-CMS-019 | TYPO3 | Backend login default credentials (admin/password) | authorized-only | Requires approved credential test |
| TS-CMS-020 | TYPO3 | Phar deserialization CVE-2019-12747 (<8.7.27, <9.5.8) | passive | Version check only |
| TS-CMS-021 | Ghost | Admin login weak credentials | authorized-only | Requires approved credential test |
| TS-CMS-022 | Ghost | Webhook/integration SSRF to internal services | bounded | Review integration settings; test only with OOB callback host |
| TS-CMS-023 | Craft CMS | Twig SSTI from unescaped user content | bounded | Harmless arithmetic probe (`{{7*7}}` in own-account content) |
| TS-CMS-024 | Craft Commerce | Order data exposed to unauthenticated users | passive | GET /commerce/orders/ and /commerce/my-orders status |
| TS-CMS-025 | Craft Commerce | Price tampering in cart update | authorized-only | Requires approved test on own test cart |
| TS-CMS-026 | Strapi | Unauthenticated admin registration (CVE-2019-19609, <3.0.0-beta.17.8) | passive | Version check; check /admin/auth/register status |
| TS-CMS-027 | Strapi | Missing object-level permissions in REST/GraphQL | bounded | Anonymous GET of each content type, compare with permissions |
| TS-CMS-028 | MediaWiki | Private content through API or Special:Export | bounded | Anonymous api.php?action=query requests |
| TS-CMS-029 | Moodle | Spellcheck command injection CVE-2020-14321 | passive | Version check only |
| TS-CMS-030 | phpBB | SQLi in search and post parameters (historic) | passive | Version check only |
| TS-CMS-031 | vBulletin | Pre-auth RCE CVE-2019-16759 (5.x) | passive | Version check only |
| TS-CMS-032 | SharePoint | Pre-auth deserialization CVE-2019-0604 | passive | Version check only |
| TS-CMS-033 | SharePoint | Anonymous access to document libraries | bounded | Anonymous list request on library URL |
| TS-CMS-034 | Roundcube | Stored XSS via email CVE-2023-43770 | passive | Version check only |
| TS-CMS-035 | Shopify | App webhooks accepted without HMAC validation | bounded | Send a webhook with a bad HMAC to own test app; expect rejection |
| TS-CMS-036 | Shopify | Storefront API token in client JS with broad scope | passive | Grep JS bundles for `storefrontAccessToken` |
| TS-CMS-037 | BigCommerce | Storefront API and credentials in theme JS | passive | Grep theme JS for X-Auth-Token / client secrets |
| TS-CMS-038 | Bitrix / 1C-Bitrix | Unauthenticated SQLi in components | passive | Version check; no injection probes |
| TS-CMS-039 | Bitrix / 1C-Bitrix | Source disclosure via /bitrix/ or unprocessed .php | passive | GET /bitrix/ listings and .php source responses |
| TS-CMS-040 | Bitrix24 | Admin pages reachable without auth | passive | GET /bitrix/admin/ status |
| TS-CMS-041 | WHMCS | Admin panel exposed | passive | GET /whmcs/admin, /admin status |
| TS-CMS-042 | Cachet | Admin/dashboard exposed; API token in source | passive | GET /dashboard/, /api/v1/components; grep for X-Cachet-Token |
| TS-CMS-043 | Canvas LMS | Anonymous API data and role changes | bounded | Anonymous GET of /api/v1/courses and /api/v1/accounts |
| TS-CMS-044 | Chamilo | SQLi and unauthenticated file upload CVE-2023-4220 | passive | Version check only |
| TS-CMS-045 | CiviCRM | Exposed REST API and settings file | passive | GET civicrm/ajax/rest status, civicrm.settings.php status |
| TS-CMS-046 | CKAN | Private datasets reachable anonymously | bounded | GET /api/action/package_list and current_package_list_with_resources |
| TS-CMS-047 | Coppermine | Config include file reachable | passive | GET include/config.inc.php status |
| TS-CMS-048 | Concrete CMS | File import endpoint upload | authorized-only | Requires approved upload test |
| TS-CMS-049 | Contao | Install tool reachable / localconfig exposed | passive | GET /contao/install.php, /system/config/localconfig.php status |
| TS-CMS-050 | DNN (DotNetNuke) | web.config and App_Data exposed | passive | GET /web.config, /App_Data/ status |
| TS-CMS-051 | DNN (DotNetNuke) | ViewArticle SQLi (historic module) | authorized-only | Requires approved SQLi test |
| TS-CMS-052 | DSpace | Admin pages reachable without authentication | passive | GET /xmlui/admin, /jspui/admin status |
| TS-CMS-053 | DataLife Engine | engine/ directories and admin.php exposed | passive | GET /engine/, /admin.php status |
| TS-CMS-054 | Discuz! X | Config files and install directory exposed | passive | GET /config/config_global.php, /install/ status |
| TS-CMS-055 | Divi / Elementor | Plugin version and file upload endpoint | passive | readme.txt stable tag; check known CVEs for version |
| TS-CMS-056 | Elgg | Installation and admin exposed | passive | GET /install.php, /admin status |
| TS-CMS-057 | ERPNext / Frappe | Default Administrator account | authorized-only | Requires approved credential test |
| TS-CMS-058 | Flarum | Admin panel exposed at /admin | passive | GET /admin status |
| TS-CMS-059 | FluxBB | search.php SQLi (historic) | passive | Version check only |
| TS-CMS-060 | FilamentPHP | Admin panel exposed; resource policies missing | bounded | GET /admin status; anonymous request to each resource list |
| TS-CMS-061 | GetSimple | Admin panel and public data/pages XML | passive | GET /admin/, /data/pages/ listing |
| TS-CMS-062 | Grav | Admin panel and user YAML exposed | passive | GET /admin, /user/accounts/ status (do not fetch password hashes beyond evidence) |
| TS-CMS-063 | Gravity Forms | Upload extension validation; entries exposed via REST | bounded | GET /wp-json/gf/v2/forms with no auth |
| TS-CMS-064 | Hesk | Admin panel and ticket ID predictability | bounded | GET /admin/ status; compare ticket ID sequence |
| TS-CMS-065 | HumHub | Admin panel reachable anonymously | passive | GET /admin status |
| TS-CMS-066 | Invision Community / IPB | Admin panel and historic SQLi | passive | GET /admin/ status; version check |
| TS-CMS-067 | Joomla J2Store | SQLi in extension (historic) | passive | Extension version check |
| TS-CMS-068 | Kentico | /cms and /admin exposed | passive | GET /cms/, /admin/ status |
| TS-CMS-069 | Kirby | Panel exposed | passive | GET /panel/ status |
| TS-CMS-070 | MODX | Manager and connectors exposed | passive | GET /manager/, /connectors/ status |
| TS-CMS-071 | Mautic | Admin exposed | passive | GET /mautic/ status |
| TS-CMS-072 | ProcessWire | Admin exposed | passive | GET /processwire/ status |
| TS-CMS-073 | PyroCMS | Admin exposed | passive | GET /admin/ status |
| TS-CMS-074 | Plone | Admin and /manage exposed | passive | GET /plone/, /manage status |
| TS-CMS-075 | Shopware | Admin exposed without rate limiting | bounded | GET /backend status; check for rate-limit headers only |
| TS-CMS-076 | Spree | Admin exposed | passive | GET /admin status |
| TS-CMS-077 | Statamic | Control panel exposed | passive | GET /cp status |
| TS-CMS-078 | Silverstripe | Version in page source | passive | Grep for Silverstripe version |
| TS-CMS-079 | Simple Machines Forum | Version disclosure | passive | Grep for smf version strings |
| TS-CMS-080 | Tiki Wiki | Admin exposed; SQLi and RCE (historic) | passive | GET /tiki-admin.php status; version check |
| TS-CMS-081 | Umbraco | Backoffice exposed | passive | GET /umbraco status |
| TS-CMS-082 | Wagtail | Admin exposed | passive | GET /admin status |
| TS-CMS-083 | WooCommerce | Version disclosure | passive | Grep for wc- version; readme.txt |
| TS-CMS-084 | WPForms / Wordfence / Yoast / RankMath / WP Rocket | Plugin version disclosure | passive | readme.txt stable tag per plugin |
| TS-CMS-085 | bbPress | Version disclosure | passive | Grep bbp- version |
| TS-CMS-086 | WPBakery | Version exposure and stored XSS via shortcodes | passive | Grep js_composer version; check version advisory |
| TS-CMS-087 | X-Cart | Version disclosure and SQLi/XSS (historic) | passive | Version check only |
| TS-CMS-088 | XenForo | Version disclosure | passive | Grep xenforo version |
| TS-CMS-089 | XWiki | Exposed content and accounts | bounded | Anonymous access to view URLs |
| TS-CMS-090 | Zen Cart | Version disclosure, SQLi/XSS (historic) | passive | Version check only |
| TS-CMS-091 | Ektron / Episerver / Optimizely | /ektron, /WorkArea, /EPiServer exposed | passive | GET status for each path |
| TS-CMS-092 | Easy Digital Downloads | Price manipulation and version | passive | readme.txt stable tag |
| TS-CMS-093 | Ecwid | API key in client JS | passive | Grep JS for ecwid key |
| TS-CMS-094 | EasyEngine | Server header disclosure | passive | Response headers |
| TS-CMS-095 | Gutentor | Stored XSS via block attributes | bounded | Review block output encoding on own draft |
| TS-CMS-096 | Emlog | SQLi and plugin upload RCE (historic) | passive | Version check only |
| TS-CMS-097 | Adminer | Exposed adminer.php and editor.php | passive | GET /adminer.php, /adminer/adminer.php, /editor.php status |
| TS-CMS-098 | Adminer | Connect-to-server SSRF | authorized-only | Requires approved test against own callback host |
| TS-CMS-099 | Backdrop CMS | Install/update pages and version | passive | GET /core/install.php, /core/update.php, CHANGELOG |
| TS-CMS-100 | Bludit | Brute-force protection bypass via X-Forwarded-For; upload RCE | authorized-only | Requires approved test; version check first |
| TS-CMS-101 | Bolt CMS | Database file in app/database exposed | passive | GET /app/database/bolt.db status (do not download) |
| TS-CMS-102 | Bolt CMS | Admin panel exposed | passive | GET /bolt/ status |
| TS-CMS-103 | Blesta | Admin panel and config/blesta.php exposed | passive | GET /admin/, /config/blesta.php status |
| TS-CMS-104 | Bugzilla | Installation, user list, localconfig | passive | GET /bugzilla/ pages, /localconfig status |
| TS-CMS-105 | Cakephp / Croogo | Debug kit and config exposed | passive | GET /debug_kit/, /config/app.php status |
| TS-CMS-106 | Cherokee / CherryPy / Bottle / Dancer | Server or framework header disclosure, debug pages | passive | Response headers; 404 page content |
| TS-CMS-107 | Combodo iTop | Config and UI exposed | passive | GET /conf/production/config-itop.php status |
| TS-CMS-108 | CodeIgniter | Debug/profiler and database config exposed | passive | GET ?DEBUG=1 pages; /application/config/database.php status |
| TS-CMS-109 | Concrete CMS | Dashboard and install paths | passive | GET /dashboard/, /index.php/tools/ status |
| TS-CMS-110 | Cotonti | /datas/, /plugins/ listings | passive | GET listing status |
| TS-CMS-111 | Countly | Dashboard and default credentials | authorized-only | Requires approved credential test |
| TS-CMS-112 | CubeCart | Admin and global.inc.php exposed | passive | GET /admin/, /includes/global.inc.php status |
| TS-CMS-113 | Dolibarr | PHP file creation via website module (CVE-2023-30253) | passive | Version check only |
| TS-CMS-114 | DokuWiki | Open registration and @ALL read ACL | bounded | Anonymous access to a sample page |
| TS-CMS-115 | BookStack | SSRF via image/attachment upload (historic) | passive | Version check only |
| TS-CMS-116 | Discourse | SSRF via onebox; exposed admin/sidekiq/logs | passive | GET /admin/, /sidekiq/, /logs/ status |
| TS-CMS-117 | Drupal Commerce / Multisite | settings.php exposed across sites | passive | GET sites/*/settings.php status |
| TS-CMS-118 | Ghost / Hexo / Hugo / Jekyll / Gatsby | Config files exposed | passive | GET /config.toml, /_config.yml, /config.yaml status |
| TS-CMS-119 | Joomla Multiple | /administrator/ and default admin | passive | GET status; default credentials only if approved |
| TS-CMS-120 | Typo3 backend / Cachet / Croogo | Admin login path discovery | passive | GET admin login status |
| TS-CMS-121 | Hosting panel: cPanel / WHM | Interfaces on 2083/2087/2096 reachable from internet | passive | GET ports 2083/2087/2096 status |
| TS-CMS-122 | Hosting panel: Plesk | Admin on 8443 | passive | GET https://host:8443 status |
| TS-CMS-123 | Hosting panel: DirectAdmin | Admin on 2222 and CMD_API_ADMIN | passive | GET port 2222 status |
| TS-CMS-124 | Hosting panel: Hostinger / Hostgator / IONOS / Infomaniak | Control panel exposed to internet | passive | GET control panel URLs on known ports |
| TS-CMS-125 | Webmin | Backdoor 1.882-1.921 (CVE-2019-15107) and package-update RCE | passive | Version check (Webmin login page version) |
| TS-CMS-126 | Zenfolio / Wix / Squarespace / Webflow / Tilda / Weebly | Site builder identifiers and internal data | passive | Grep HTML for builder markers; no further probing |
