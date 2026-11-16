# Subagent 04: Real-time, Streaming, WebSockets & Event Handlers

## Role & Mission
Responsible for analyzing asynchronous and duplex communication channels: discovering WebSocket endpoints (`ws://`, `wss://`), Server-Sent Events (SSE), long-polling loops, microservice gateway topologies, WebSocket frame structures, and cross-origin `window.postMessage` listeners.

## Assigned Checklist Tasks (6 Checks)
- **Check 11:** Discover WebSocket endpoints (`ws://`, `wss://`, `/socket.io/`, `/cable`, `/ws`)
- **Check 12:** Discover Server-Sent Events (SSE) streaming endpoints (`text/event-stream`)
- **Check 13:** Identify polling and long-polling connection routines
- **Check 14:** Map microservices architecture and multiple API gateway routes
- **Check 30:** Analyze client-side `postMessage` handlers for cross-origin vulnerabilities
- **Check 40:** Extract WebSocket message framing formats and JSON RPC schemas from JS

---

## Standardized Execution Playbook

### Step 1: WebSocket Discovery & Probing (Checks 11, 40)
Search JavaScript bundles and network connections for WebSocket instantiations:

```bash
# 1. Regex search client-side bundles for WebSocket constructors
python3 -c "
import glob, re

ws_pattern = re.compile(r'(wss?:\/\/[a-zA-Z0-9_\-\.\/:]+|new WebSocket\([\"\\\']([^\"\\\']+)[\"\\\']|\/socket\.io\/|\/ws|\/cable|\/signalr)')

for js in glob.glob('artifacts/js_bundles/*.js'):
    with open(js, 'r', encoding='utf-8', errors='ignore') as f:
        matches = ws_pattern.findall(f.read())
        for m in matches:
            val = m[0] if isinstance(m, tuple) else m
            if val:
                print(f'[+] WebSocket match: {val}')
                with open('artifacts/websocket_endpoints.txt', 'a') as out:
                    out.write(val + '\n')
"

# 2. Probe WebSocket upgrade request using websocat or curl
curl -sIL \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://<target>/socket.io/?EIO=4&transport=websocket" > artifacts/ws_upgrade_response.txt

# 3. Analyze WebSocket Message Framing & JSON-RPC Schemas (Check 40)
# Look for: JSON.stringify({action: "...", payload: ...}) or send() invocations in JS
grep -rnE "(socket\.send|ws\.send|socket\.emit)" artifacts/js_bundles/ > artifacts/ws_message_schemas.txt
```

### Step 2: Server-Sent Events (SSE) & Polling (Checks 12, 13)
```bash
# 1. Discover EventSource implementations (SSE)
grep -rnE "new EventSource\(" artifacts/js_bundles/ > artifacts/sse_endpoints.txt

# 2. Probe discovered streaming paths
for sse in "/events" "/stream" "/sse" "/api/stream" "/live/feed"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Accept: text/event-stream" "https://<target>${sse}")
  if [ "$STATUS" = "200" ]; then
    echo "[!] Active Server-Sent Events (SSE) endpoint: ${sse}" >> artifacts/live_sse.txt
  fi
done

# 3. Long-polling loops (Check 13)
grep -rnE "(setInterval|setTimeout)\(.*(fetch|axios|\$\.ajax)" artifacts/js_bundles/ > artifacts/polling_routines.txt
```

### Step 3: Microservice Architecture & Gateway Topology (Check 14)
Identify if traffic routes through distinct backend services via reverse proxy headers:

```bash
# Check headers disclosing microservice routing
curl -sIL "https://<target>/api/v1/" | grep -iE "(Via|X-Forwarded-Host|X-Envoy-|X-Kong-|X-Gateway|X-Service-Name)" > artifacts/microservice_headers.txt

# Gateway Route Mapping:
# /api/auth/     -> Auth Microservice
# /api/billing/  -> Billing Microservice
# /api/users/    -> User Service
# /api/orders/   -> Order Service
```

### Step 4: `postMessage` Cross-Origin Listener Analysis (Check 30)
*High-Impact Audit:* `window.addEventListener("message", ...)` handlers that do not validate `event.origin` allow attackers to execute DOM XSS, steal tokens, or trigger state changes via iframes.

```bash
# Extract all postMessage event listeners from JavaScript files
python3 -c "
import glob, re

pm_pattern = re.compile(r'window\.addEventListener\([\"\\\']message[\"\\\']\s*,\s*function\s*\(([^)]+)\)\s*\{([^}]+)\}', re.DOTALL)

for js in glob.glob('artifacts/js_bundles/*.js'):
    with open(js, 'r', encoding='utf-8', errors='ignore') as f:
        matches = pm_pattern.findall(f.read())
        for arg, body in matches:
            has_origin_check = 'origin' in body or '.origin' in body
            print(f'[!] Found postMessage listener in {js}: Origin Check: {has_origin_check}')
            with open('artifacts/postmessage_handlers.txt', 'a') as out:
                out.write(f'File: {js}\nOrigin Check: {has_origin_check}\nHandler: {body[:300]}\n---\n')
"
```

---

## Output Artifact
Aggregate findings into:
`artifacts/subagent_04_realtime_protocols.md`
