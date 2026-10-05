# Content Discovery Wordlists Guide & Resource Mapping

This guide maps each fuzzing category to the battle-tested wordlists stored in `wordlists/` and `wordlists/`.

---

## 1. General Path & Directory Bruting
- **Quick Hits & High Frequency:**
  - `wordlists/MiniFuzz.txt` (121 KB, ~10,000 entries) — Use for fast initial crawling and recursion.
- **Deep & Massive Fuzzing:**
  - `wordlists/God-Fuzz.txt` (18.7 MB) — Use for exhaustive parameter and directory fuzzing.

---

## 2. Configuration Files & Environment Variables (Checks 09, 27, 28, 29)
- **Environment Files (`.env`, `.env.local`):**
  - `wordlists/env.txt` (12 KB)
- **Dotfiles & Hidden Files (`.htaccess`, `.htpasswd`, `.DS_Store`):**
  - `wordlists/dotfiles.txt` (18 KB)
  - `wordlists/htaccess`
  - `wordlists/npmrc.txt`
  - `wordlists/keys.txt`
- **Application & Server Configs:**
  - `wordlists/config.txt`
  - `wordlists/webconfig.txt`
  - `wordlists/yaml.txt` (docker-compose, k8s configs)
  - `wordlists/k8s.txt`

---

## 3. Source Repositories & Backups (Checks 08, 10, 11, 14, 31)
- **Git Exposure:**
  - `wordlists/git_config.txt`
- **Compressed Archives (`.zip`, `.tar.gz`, `.bak`):**
  - `wordlists/zip.txt` (71 KB)
- **Database Dumps (`.sql`, `.db`, `.sqlite`):**
  - `wordlists/sql.txt` (12 KB)

---

## 4. Administrative Panels & Databases (Checks 19, 20, 21, 45)
- **phpMyAdmin & Database Managers:**
  - `wordlists/phpmyadmin.txt`
  - `wordlists/adminer.txt`
- **WordPress Admin & Content:**
  - `wordlists/WPfuzz.txt` (409 KB)
  - `wordlists/wordpress-random.txt`
  - `wordlists/wp-content.txt`
- **Atlassian Jira & Confluence Panels:**
  - `wordlists/JiraFuzz.txt`
  - `wordlists/JIra-Domains.txt`

---

## 5. API Documentation & Endpoints (Check 18)
- **API Paths (`/swagger`, `/v1/api`, `/graphql`):**
  - `wordlists/api.txt` (13 KB)
  - `wordlists/wad.txt`
  - `wordlists/svc.txt`

---

## 6. Logs, Testing & Debugging (Checks 15, 16, 17)
- **Exposed Logs:**
  - `wordlists/log.txt` (108 KB)
- **PHPUnit & Test Files:**
  - `wordlists/phpunit.txt` (40 KB)
  - `wordlists/php.txt` (149 KB)
