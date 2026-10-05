# Content & URL Discovery: 50-Item Master Audit Checklist

This checklist tracks execution progress across all 50 content and URL discovery checks. It maps directly into the 6 specialized subagents and incorporates tailored wordlists from `wordlists/` and `wordlists/`.

**Progress:** `[ 0 / 50 Complete ]`

---

## Task Audit Matrix

| # | Check Description | Subagent | Wordlist / Method | Status |
|---|-------------------|----------|-------------------|--------|
| **01** | Use ffuf for fast directory & file fuzzing with recursion | Subagent 01 | `ffuf -u <target>/FUZZ -w MiniFuzz.txt -recursion -mc 200,301,302,403` | `[ ]` |
| **02** | Use gobuster for directory/file brute forcing with threads | Subagent 01 | `gobuster dir -u <target> -w MiniFuzz.txt -t 40` | `[ ]` |
| **03** | Use dirsearch for recursive directory scanning with extensions | Subagent 01 | `dirsearch -u <target> -e php,asp,aspx,jsp,html,json,txt -r` | `[ ]` |
| **04** | Use feroxbuster for recursive discovery with smart filtering | Subagent 01 | `feroxbuster -u <target> --smart -w MiniFuzz.txt` | `[ ]` |
| **05** | Check robots.txt and analyze disallowed entries for hidden paths | Subagent 03 | `curl -sL <target>/robots.txt` (extract all `Disallow:` and `Allow:`) | `[ ]` |
| **06** | Check sitemap.xml for hidden URLs & site structure | Subagent 03 | `curl -sL <target>/sitemap.xml` (extract all `<loc>` tags) | `[ ]` |
| **07** | Check for .well-known/ directory | Subagent 03 | Probe `/.well-known/` index and common files | `[ ]` |
| **08** | Look for backup files (.bak, .old, .orig, .save, .swp, .tmp) | Subagent 04 | Generate extensions for index & discovered endpoints (`.bak`, `.swp`, `~`) | `[ ]` |
| **09** | Check for configuration files (.env, .htaccess, web.config) | Subagent 04 | Fuzz using `env.txt`, `dotfiles.txt`, `webconfig.txt` | `[ ]` |
| **10** | Look for source code repositories (.git, .svn, .hg, .bzr) | Subagent 04 | Probe `/.git/`, `/.svn/entries`, `/.hg/`, `/.bzr/` | `[ ]` |
| **11** | Check for exposed .git directory (HEAD, config, index) | Subagent 04 | Fuzz `/.git/HEAD`, `/.git/config` using `git_config.txt`, test `git-dumper` | `[ ]` |
| **12** | Search for .DS_Store files for macOS directory listings | Subagent 04 | Probe `/.DS_Store` and parse extracted file strings | `[ ]` |
| **13** | Check for WP-config.php, config.php, database.yml, settings.py | Subagent 04 | Fuzz using `config.txt` and `wordpress-random.txt` | `[ ]` |
| **14** | Look for backup archives (.zip, .tar.gz, .rar, .7z, .bak.zip) | Subagent 04 | Fuzz using `zip.txt` (e.g. `backup.zip`, `<target>.zip`) | `[ ]` |
| **15** | Search for log files (error.log, access.log, debug.log) | Subagent 05 | Fuzz using `log.txt` (108KB log list) | `[ ]` |
| **16** | Check for debug endpoints (/debug, /trace, /status, /healthz) | Subagent 05 | Probe `/debug`, `/trace`, `/status`, `/healthz`, `/metrics` | `[ ]` |
| **17** | Look for test files (test.php, test.html, info.php, phpinfo.php) | Subagent 05 | Fuzz using `phpunit.txt` and `php.txt` | `[ ]` |
| **18** | Check for API documentation (/api-docs, /swagger, /redoc, /graphql) | Subagent 05 | Fuzz using `api.txt` and Swagger path matrix | `[ ]` |
| **19** | Look for admin panels (/admin, /administrator, /manager, /cpanel) | Subagent 06 | Fuzz using `adminer.txt` and `MiniFuzz.txt` | `[ ]` |
| **20** | Check for phpMyAdmin (/phpmyadmin, /pma, /dbadmin, /mysql) | Subagent 06 | Fuzz using `phpmyadmin.txt` | `[ ]` |
| **21** | Look for CMS admin (/wp-admin, /wp-login.php, /administrator) | Subagent 06 | Fuzz using `WPfuzz.txt` and Joomla paths | `[ ]` |
| **22** | Check for staging/dev environments on subdomains | Subagent 02 | Match prefixes `dev.`, `staging.`, `test.`, `uat.` across live subdomains | `[ ]` |
| **23** | Search for public Google Docs/Sheets with sensitive target data | Subagent 02 | Google Dork: `site:docs.google.com/spreadsheets/ "<target>"` | `[ ]` |
| **24** | Use waybackurls for historical URL discovery | Subagent 02 | `echo <target> \| waybackurls \| sort -u > waybackurls.txt` | `[ ]` |
| **25** | Use gau for URLs from AlienVault, Wayback, Common Crawl | Subagent 02 | `gau <target> --providers wayback,commoncrawl,otx > gau_urls.txt` | `[ ]` |
| **26** | Extract URLs & endpoints from JavaScript files systematically | Subagent 02 | Run `katana -jc` + regex extractor on crawled JS | `[ ]` |
| **27** | Check for .env file exposure with credentials & API keys | Subagent 04 | Probe `/.env`, `/.env.local`, `/.env.production` using `env.txt` | `[ ]` |
| **28** | Look for docker-compose.yml and Dockerfile exposure | Subagent 04 | Fuzz using `yaml.txt` (`docker-compose.yml`, `Dockerfile`) | `[ ]` |
| **29** | Check for package.json, composer.json, requirements.txt | Subagent 04 | Probe `/package.json`, `/composer.json`, `/requirements.txt`, `/package-lock.json` | `[ ]` |
| **30** | Search for .htpasswd files with credential exposure | Subagent 04 | Fuzz `/.htpasswd`, `/.htpasswd.bak` using `htaccess` wordlist | `[ ]` |
| **31** | Look for database dump files (.sql, .db, .sqlite, .mdb) | Subagent 04 | Fuzz using `sql.txt` (`dump.sql`, `backup.sql`, `users.sql`) | `[ ]` |
| **32** | Check for Jenkins script console access at /script | Subagent 06 | Probe `/script`, `/jenkins/script`, `/manage/script` | `[ ]` |
| **33** | Look for exposed Grafana dashboards at /grafana/ or :3000 | Subagent 06 | Probe `/grafana/`, `http://<target>:3000/login` | `[ ]` |
| **34** | Check for Prometheus metrics endpoint at /metrics | Subagent 05 | Probe `/metrics`, `/actuator/prometheus` | `[ ]` |
| **35** | Look for Kibana dashboard on port 5601 with no auth | Subagent 06 | Probe `http://<target>:5601/app/kibana`, `/app/home` | `[ ]` |
| **36** | Check for Airflow web UI on port 8080 with DAG access | Subagent 06 | Probe `http://<target>:8080/home`, `/admin/airflow` | `[ ]` |
| **37** | Look for RabbitMQ management on port 15672 | Subagent 06 | Probe `http://<target>:15672/`, check default guest:guest | `[ ]` |
| **38** | Check for Solr admin on port 8983 with core access | Subagent 06 | Probe `http://<target>:8983/solr/`, `/solr/admin/info/system` | `[ ]` |
| **39** | Look for MinIO console on port 9001 with bucket listing | Subagent 06 | Probe `http://<target>:9001/login`, `/minio/health/live` | `[ ]` |
| **40** | Check for Apache Tomcat manager at /manager/html | Subagent 06 | Probe `/manager/html`, `/manager/status`, `/host-manager/html` | `[ ]` |
| **41** | Look for JBoss admin console at /admin-console/ | Subagent 06 | Probe `/admin-console/`, `/jmx-console/`, `/web-console/` | `[ ]` |
| **42** | Check for WebLogic admin at /console/ | Subagent 06 | Probe `/console/login/LoginForm.jsp` | `[ ]` |
| **43** | Look for IBM WebSphere admin at /ibm/console/ | Subagent 06 | Probe `/ibm/console/`, `/ibm/console/login.do` | `[ ]` |
| **44** | Check for Confluence admin at /admin/ | Subagent 06 | Probe `/confluence/admin/`, `/admin/` (check CVEs/default creds) | `[ ]` |
| **45** | Look for Jira admin at /secure/admin/ | Subagent 06 | Probe `/secure/admin/` using `JiraFuzz.txt` | `[ ]` |
| **46** | Check for exposed .well-known/openid-configuration | Subagent 03 | Probe `/.well-known/openid-configuration` (leaks endpoints & scopes) | `[ ]` |
| **47** | Look for .well-known/oauth-authorization-server | Subagent 03 | Probe `/.well-known/oauth-authorization-server` | `[ ]` |
| **48** | Check for .well-known/assetlinks.json for Android linking | Subagent 03 | Probe `/.well-known/assetlinks.json` (leaks package names & SHA256) | `[ ]` |
| **49** | Look for .well-known/apple-app-site-association for iOS | Subagent 03 | Probe `/.well-known/apple-app-site-association` (leaks app IDs & paths) | `[ ]` |
| **50** | Check for .well-known/security.txt for security contact info | Subagent 03 | Probe `/.well-known/security.txt` and `/security.txt` | `[ ]` |
