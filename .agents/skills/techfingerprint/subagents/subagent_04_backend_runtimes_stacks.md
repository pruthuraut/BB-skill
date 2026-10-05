# Subagent 04: Backend Runtimes, Server Frameworks & Enterprise Stacks

## Role & Mission
Responsible for identifying backend server languages (PHP, Python, Java, Ruby, .NET, Node.js), application frameworks (Laravel, Django, Rails, Spring Boot, Express, Flask, FastAPI), and probing known debugging or administrative endpoints.

## Assigned Checklist Tasks (10 Checks)
- **Check 13:** Identify backend language from error messages, stack traces, and file extensions
- **Check 26:** Identify Laravel framework (`/telescope`, `/_debugbar`, `/horizon`, `/nova`)
- **Check 27:** Detect Django admin portal (`/admin/`, `/django-admin/`, `csrfmiddlewaretoken`)
- **Check 28:** Detect Ruby on Rails (`_session_id`, `X-CSRF-Token`, Rails routes)
- **Check 29:** Probe Spring Boot Actuator endpoints (`/actuator/health`, `/actuator/env`, `/heapdump`)
- **Check 30:** Identify Microsoft ASP.NET via `__VIEWSTATE` and `__EVENTVALIDATION`
- **Check 31:** Identify PHP via `X-Powered-By: PHP`, `.php` endpoints, and error messages
- **Check 32:** Detect Node.js via `X-Powered-By: Express` and `connect.sid`
- **Check 39:** Identify Flask via Werkzeug headers and client session cookies
- **Check 40:** Detect FastAPI via `/docs` (Swagger UI) and `/redoc` schema endpoints

---

## Standardized Execution Playbook

### Step 1: Deliberate Error Generation & Stack Trace Probing (Check 13)
Send malformed inputs or non-existent URLs to trigger verbose error pages:

```bash
# 1. Trigger 404/500 error
curl -sL "https://<target>/non_existent_page_probe_%27%22" > artifacts/error_page.html

# 2. Analyze for Framework-Specific Error Signatures
# Django: "DisallowedHost", "Page not found (404)", "You're seeing this error because you have DEBUG = True"
# Laravel / Whoops: "Whoops! There was an error.", "Illuminate\Http"
# Rails: "Routing Error", "ActionController::RoutingError"
# Spring Boot: "Whitelabel Error Page", "There was an unexpected error (type=Not Found, status=404)"
# Express: "Cannot GET /path", "TypeError: Cannot read property"
# ASP.NET: "Server Error in '/' Application.", "Runtime Error", "Yellow Screen of Death"
# PHP: "Fatal error: Uncaught Error:", "Warning: include()", "Notice: Undefined index"
# Werkzeug / Flask: "Werkzeug Debugger", "Traceback (most recent call last):"
```

### Step 2: Probing Backend Framework Endpoints

#### A. Laravel Probing (Check 26)
```bash
for endpoint in "/_debugbar/open-handler" "/telescope" "/horizon" "/nova/login" "/storage/logs/laravel.log"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${endpoint}")
  echo "Laravel probe: ${endpoint} -> HTTP ${STATUS}"
done
```

#### B. Django Probing (Check 27)
```bash
for endpoint in "/admin/" "/admin/login/" "/django-admin/"; do
  curl -sL "https://<target>${endpoint}" | grep -qiE "(Django site admin|csrfmiddlewaretoken)" && echo "Django Admin confirmed at ${endpoint}"
done
```

#### C. Ruby on Rails Probing (Check 28)
```bash
# Check headers and default development routes
curl -sI "https://<target>" | grep -iE "(X-Runtime|X-Request-Id)"
curl -sL "https://<target>/rails/info/routes" | grep -qi "Routes" && echo "Rails debug routes exposed!"
```

#### D. Spring Boot Actuators Probing (Check 29)
*High-Impact Audit:* Unprotected Actuators leak heap dumps, environment variables, API routes, and DB credentials.
```bash
for actuator in "/actuator" "/actuator/health" "/actuator/env" "/actuator/mappings" "/actuator/beans" "/actuator/heapdump" "/actuator/configprops"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${actuator}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] CRITICAL: Exposed Spring Actuator: ${actuator}" >> artifacts/exposed_actuators.txt
  fi
done
```

#### E. ASP.NET State Analysis (Check 30)
```bash
# Check for ViewState fields
curl -sL "https://<target>" | grep -E "(__VIEWSTATE|__EVENTVALIDATION|__VIEWSTATEGENERATOR)" > artifacts/aspnet_viewstate.txt
if [ -s "artifacts/aspnet_viewstate.txt" ]; then
  echo "[+] Confirmed: ASP.NET WebForms detected via ViewState"
fi
```

#### F. PHP & Node.js / Express Checks (Checks 31, 32)
```bash
# PHP check
curl -sI "https://<target>" | grep -iE "X-Powered-By:.*PHP"
# Node.js / Express check
curl -sI "https://<target>" | grep -iE "X-Powered-By:.*Express"
```

#### G. Python Flask & FastAPI Checks (Checks 39, 40)
```bash
# Flask: Check Werkzeug headers and console
curl -sI "https://<target>" | grep -iE "Server:.*Werkzeug"
curl -sL "https://<target>/console" | grep -qi "Werkzeug" && echo "[!] Werkzeug PIN console exposed!"

# FastAPI (Check 40): Swagger UI / ReDoc
for api_docs in "/docs" "/redoc" "/openapi.json"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>${api_docs}")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Confirmed FastAPI API Documentation at: ${api_docs}" >> artifacts/fastapi_endpoints.txt
  fi
done
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_04_backend_stacks.md`
