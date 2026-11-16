# LFI / Traversal Target Files

Class **R** = benign proof, may be read by default (keep the first matching line only).
Class **S** = sensitive (secrets, hashes, credentials, personal data) — do not request without explicit permission; prove reachability another way and describe impact.
Class **I** = infer only (never request; use `/proc/self/status` UID or differential evidence).

## Linux / Unix

| File | Signature (regex) | Class | Why it matters |
|---|---|---|---|
| `/etc/passwd` | `root:[^:]*:0:0:` | R | Standard traversal proof; user list |
| `/etc/hosts` | `localhost` | R | Benign proof |
| `/etc/hostname` | single hostname line | R | Benign proof |
| `/etc/issue`, `/etc/os-release` | `Ubuntu\|Debian\|CentOS\|Alpine\|NAME=` | R | OS fingerprint |
| `/proc/version` | `Linux version` | R | Kernel fingerprint, `/proc` access |
| `/proc/self/status` | `^Uid:` | R | Process UID (Uid 0 ⇒ root read ⇒ shadow readable) |
| `/proc/1/cgroup` | `docker\|kubepods\|containerd` | R | Container detection |
| `/.dockerenv` | (existence) | R | Container detection |
| `/proc/self/cmdline` | NUL-separated args | S | App path; may contain secrets |
| `/proc/self/environ` | `PATH=` | S | Env vars: credentials, API keys |
| `/proc/self/cwd/<app file>` | app source | S | Source disclosure |
| `/proc/self/fd/N`, `/proc/<pid>/fd/N` | varies | S | Open files incl. logs/uploads (LFI2RCE) |
| `/etc/group` | `root:x:0:` | R | Group list |
| `/etc/motd` | varies | R | Banner |
| `/etc/shadow` | `root:[^:]*:` | I | Password hashes — never request by default |
| `/etc/mysql/my.cnf`, `/etc/my.cnf` | `\[mysqld\]` | S | DB config |
| `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/httpd/access_log` | your request line | S | Log poisoning precondition (PT-30) |
| `/var/log/auth.log`, `/var/log/mail.log`, `/var/log/vsftpd.log` | varies | S | Log poisoning precondition |
| `/var/lib/php/sessions/sess_<id>`, `/var/lib/php5/sess_<id>`, `/tmp/sess_<id>` | your session data | S | Session poisoning precondition |
| `/usr/local/lib/php/pearcmd.php` | `PEAR` | R | pearcmd LFI2RCE precondition |
| `~/.ssh/id_rsa`, `/root/.ssh/id_rsa` | `PRIVATE KEY` | I | Private keys — never request |
| `~/.aws/credentials`, `/root/.aws/credentials` | `aws_access_key_id` | I | Cloud credentials — never request |
| `/var/run/secrets/kubernetes.io/serviceaccount/token` | JWT | I | k8s service-account token — never request |
| `/root/.docker/config.json` | `auths` | I | Registry credentials |
| `<webroot>/.env` | `APP_KEY=\|DB_PASSWORD=` | S | App secrets |
| `<webroot>/.git/config` | `\[core\]` | R | Repo metadata (then `.git/` dump is `contentdiscovery`) |
| `<webroot>/wp-config.php` | `DB_PASSWORD` | S | WordPress secrets |
| `<webroot>/config/database.yml`, `settings.py`, `application.properties` | varies | S | Framework configs |

## Windows

| File | Signature | Class | Why |
|---|---|---|---|
| `C:\Windows\win.ini` | `\[fonts\]\|for 16-bit app support` | R | Standard proof |
| `C:\Windows\System32\drivers\etc\hosts` | `localhost` | R | Benign proof |
| `C:\Windows\System32\license.rtf` | `rtf` | R | Benign proof |
| `C:\inetpub\wwwroot\web.config` | `<configuration` | S | Connection strings, machineKey |
| `C:\inetpub\logs\LogFiles\W3SVC1\` | log lines | S | Log poisoning precondition |
| `C:\Windows\System32\config\SAM` | binary | I | Never request |
| `C:\Windows\repair\SAM`, `C:\Windows\Panther\Unattend.xml` | varies | I | Credentials |

Discovery list: `wordlists/windows-lfi.txt` (6,610 Windows paths).

## Java / application servers

| File | Signature | Class |
|---|---|---|
| `/WEB-INF/web.xml` | `<web-app` | S |
| `/WEB-INF/classes/application.properties` | `spring\.` | S |
| `/META-INF/MANIFEST.MF` | `Manifest-Version` | R |
| `$CATALINA_HOME/conf/tomcat-users.xml` | `<tomcat-users` | I |
