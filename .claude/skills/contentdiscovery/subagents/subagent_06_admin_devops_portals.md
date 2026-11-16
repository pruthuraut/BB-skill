# Subagent 06: Admin Consoles, DevOps Panels & Enterprise Portals

## Role & Mission
Responsible for locating sensitive administrative entry points: database managers (phpMyAdmin, Adminer), CMS administration panels (WordPress, Joomla), DevOps & CI/CD dashboards (Jenkins, Grafana, Kibana, Airflow, RabbitMQ, MinIO), enterprise middleware consoles (Tomcat, JBoss, WebLogic, WebSphere), and Atlassian suites (Jira, Confluence).

## Assigned Checklist Tasks (16 Checks)
- **Check 19:** Generic admin panels (`/admin`, `/administrator`, `/manager`, `/cpanel`, `/backend`)
- **Check 20:** Database management consoles (`/phpmyadmin`, `/pma`, `/dbadmin`, `/mysql`)
- **Check 21:** CMS admin login portals (`/wp-admin`, `/wp-login.php`, `/administrator/index.php`)
- **Check 32:** Jenkins script console (`/script`, `/jenkins/script`)
- **Check 33:** Grafana dashboards (`/grafana/` or `:3000`)
- **Check 35:** Kibana dashboard (`:5601`) with no authentication
- **Check 36:** Apache Airflow web UI (`:8080`) with DAG access
- **Check 37:** RabbitMQ management console (`:15672`)
- **Check 38:** Apache Solr admin (`:8983`) with core access
- **Check 39:** MinIO storage console (`:9001`)
- **Check 40:** Apache Tomcat manager (`/manager/html`)
- **Check 41:** JBoss application server admin console (`/admin-console/`)
- **Check 42:** Oracle WebLogic console (`/console/`)
- **Check 43:** IBM WebSphere administration console (`/ibm/console/`)
- **Check 44:** Atlassian Confluence administration panel (`/admin/`)
- **Check 45:** Atlassian Jira administration panel (`/secure/admin/`)

---

## Standardized Execution Playbook

### Step 1: Database Management Interfaces (Checks 20 & adminer.txt / phpmyadmin.txt)
```bash
# Fuzz using phpmyadmin.txt and adminer.txt from resources
WORDLIST_PMA="wordlists/phpmyadmin.txt"
WORDLIST_ADMINER="wordlists/adminer.txt"

ffuf -u "https://<target>/FUZZ" -w "$WORDLIST_PMA" -mc 200 -o artifacts/pma_found.json -of json
ffuf -u "https://<target>/FUZZ" -w "$WORDLIST_ADMINER" -mc 200 -o artifacts/adminer_found.json -of json
```

### Step 2: CMS & Generic Admin Panels (Checks 19, 21 & WPfuzz.txt)
```bash
# Fuzz using WPfuzz.txt for WordPress admin endpoints
WORDLIST_WP="wordlists/WPfuzz.txt"

ffuf -u "https://<target>/FUZZ" -w "$WORDLIST_WP" -mc 200,302 -o artifacts/wp_admin.json -of json

# Probe generic and Joomla admin paths
for ap in "/admin" "/administrator" "/backend" "/cpanel" "/controlpanel" "/dashboard"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${ap}")
  [ "$STATUS" = "200" ] && echo "[!] Admin panel reachable: ${ap}" >> artifacts/admin_panels.txt
done
```

### Step 3: CI/CD & DevOps Dashboards (Checks 32, 33, 35, 36, 37, 38, 39)
Probe default DevOps web ports and reverse-proxy paths:

```bash
# 1. Jenkins Script Console (Check 32)
for jpath in "/script" "/jenkins/script" "/manage/script"; do
  curl -sL "https://<target>${jpath}" | grep -qi "Groovy script" && echo "[!] CRITICAL: Unauthenticated Jenkins Script Console: ${jpath}" >> artifacts/devops_critical.txt
done

# 2. DevOps Port Probing Matrix
DEVOPS_PORTS=(
  "3000:Grafana:/login"
  "5601:Kibana:/app/kibana"
  "8080:Airflow:/home"
  "15672:RabbitMQ:/"
  "8983:Solr:/solr/"
  "9001:MinIO:/login"
)

for entry in "${DEVOPS_PORTS[@]}"; do
  PORT=$(echo "$entry" | cut -d':' -f1)
  NAME=$(echo "$entry" | cut -d':' -f2)
  URI=$(echo "$entry" | cut -d':' -f3)
  
  RESP=$(curl -sL --max-time 4 "http://<target>:${PORT}${URI}")
  if echo "$RESP" | grep -qi "$NAME"; then
    echo "[!] HIGH VALUE: Unprotected ${NAME} console reachable on port ${PORT}" >> artifacts/devops_critical.txt
  fi
done
```

### Step 4: Enterprise Middleware Application Consoles (Checks 40, 41, 42, 43)
```bash
# Tomcat Manager (Check 40)
curl -sL "https://<target>/manager/html" | grep -qi "Tomcat Web Application Manager" && echo "[!] Tomcat Manager Exposed" >> artifacts/enterprise_consoles.txt

# JBoss Admin (Check 41)
curl -sL "https://<target>/admin-console/" | grep -qi "JBoss" && echo "[!] JBoss Admin Exposed" >> artifacts/enterprise_consoles.txt

# WebLogic (Check 42)
curl -sL "https://<target>/console/login/LoginForm.jsp" | grep -qi "WebLogic" && echo "[!] WebLogic Console Exposed" >> artifacts/enterprise_consoles.txt

# IBM WebSphere (Check 43)
curl -sL "https://<target>/ibm/console/login.do" | grep -qi "WebSphere" && echo "[!] WebSphere Console Exposed" >> artifacts/enterprise_consoles.txt
```

### Step 5: Atlassian Jira & Confluence Panels (Checks 44, 45 & JiraFuzz.txt)
```bash
# Fuzz using JiraFuzz.txt from resources
WORDLIST_JIRA="wordlists/JiraFuzz.txt"

ffuf -u "https://<target>/FUZZ" -w "$WORDLIST_JIRA" -mc 200,302 -o artifacts/jira_endpoints.json -of json

# Confluence check (Check 44)
curl -sL "https://<target>/confluence/login.action" | grep -qi "Confluence" && echo "[!] Confluence portal active" >> artifacts/atlassian_portals.txt
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_06_admin_portals.md`
