# Subagent 05: Dynamic Runtime Hooking, DOM Sinks & Notification Dispatch

## Role & Mission
Responsible for dynamic runtime inspection: deploying in-browser console hooks (`window.fetch`, `XMLHttpRequest`) to log hidden background API calls, auditing JavaScript for client-side DOM XSS sinks and insecure `postMessage` listeners, and dispatching real-time notifications to team channels (Slack, Discord via `slackcat` and Webhooks).

---

## 1. In-Browser Dynamic Console Hooking

Developers often build administrative or hidden actions into frontend Single-Page Applications that have no visible button in the user interface. By monkeypatching browser network APIs, every background request is exposed in real time.

### Snippet 1: Hooking `window.fetch()` in Developer Console
Paste this snippet into Chrome DevTools / Firefox Console:

```javascript
// Hook window.fetch to log all outgoing HTTP calls
(function() {
  const origFetch = window.fetch;
  window.fetch = function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : args[0].url;
    const method = args[1] && args[1].method ? args[1].method : 'GET';
    const body = args[1] && args[1].body ? args[1].body : null;
    
    console.group(`%c[JS RECON FETCH] ${method} -> ${url}`, 'color: #00ff88; font-weight: bold;');
    console.log('Headers:', args[1] ? args[1].headers : 'None');
    if (body) console.log('Payload:', body);
    console.trace('Call Origin');
    console.groupEnd();
    
    return origFetch.apply(this, args);
  };
  console.log('%c[+] window.fetch() hooked successfully!', 'color: #00ffff;');
})();
```

### Snippet 2: Hooking `XMLHttpRequest` (XHR)
```javascript
// Hook XMLHttpRequest for legacy or Axios requests
(function() {
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url) {
    this._reconMethod = method;
    this._reconUrl = url;
    return origOpen.apply(this, arguments);
  };
  
  XMLHttpRequest.prototype.send = function(data) {
    console.group(`%c[JS RECON XHR] ${this._reconMethod} -> ${this._reconUrl}`, 'color: #ffaa00; font-weight: bold;');
    if (data) console.log('Data:', data);
    console.groupEnd();
    return origSend.apply(this, arguments);
  };
  console.log('%c[+] XMLHttpRequest hooked successfully!', 'color: #00ffff;');
})();
```

---

## 2. Dangerous Client-Side DOM Sinks & PostMessage Auditing

Analyze beautified JavaScript bundles for insecure DOM operations:

```bash
mkdir -p artifacts/js_recon/dom_analysis/

# 1. Search for Dangerous HTML Execution Sinks (DOM XSS)
grep -roiE "(innerHTML|outerHTML|insertAdjacentHTML)\s*=" artifacts/js_recon/js_beautified/ > artifacts/js_recon/dom_analysis/html_sinks.txt
grep -roiE "\beval\s*\(|\bnew\s+Function\s*\(" artifacts/js_recon/js_beautified/ > artifacts/js_recon/dom_analysis/eval_sinks.txt
grep -roiE "(dangerouslySetInnerHTML|v-html\s*=|\$sce\.trustAsHtml)" artifacts/js_recon/js_beautified/ > artifacts/js_recon/dom_analysis/framework_sinks.txt

# 2. Search for Insecure postMessage Event Listeners
grep -roiE "addEventListener\s*\(\s*['\"]message['\"]" artifacts/js_recon/js_beautified/ > artifacts/js_recon/dom_analysis/postmessage_listeners.txt

# 3. Open Redirect Sinks (Location Manipulation)
grep -roiE "location\.(href|replace|assign)\s*=\s*[^;]{0,100}(location|search|hash|URLSearchParams)" artifacts/js_recon/js_beautified/ > artifacts/js_recon/dom_analysis/redirect_sinks.txt
```

---

## 3. Real-Time Alerting Engine (Slack & Discord via `slackcat`)

When critical credentials (AWS keys, Slack tokens, private keys) are identified, immediately dispatch alerts to incident response or bug bounty channels:

```bash
# 1. Slackcat integration (from AUTOMATION2.0 & INFODIS notes)
if command -v slackcat >/dev/null 2>&1; then
  cat artifacts/js_recon/findings/trufflehog_verified.txt | \
    slackcat -u "$SLACK_WEBHOOK_URL" -c "recon-alerts"
fi

# 2. Direct Webhook notification via curl
if [ -s artifacts/js_recon/findings/trufflehog_verified.txt ]; then
  COUNT=$(wc -l < artifacts/js_recon/findings/trufflehog_verified.txt)
  curl -s -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"🚨 [CRITICAL ALERT] Found ${COUNT} verified secrets on target! Check artifacts/js_recon/\"}" \
    "$SLACK_WEBHOOK_URL"
fi
```

---

## Output Artifacts
- `artifacts/js_recon/dom_analysis/html_sinks.txt` — Identified direct DOM insertion points.
- `artifacts/js_recon/dom_analysis/eval_sinks.txt` — Insecure code execution calls.
- `artifacts/js_recon/dom_analysis/postmessage_listeners.txt` — PostMessage handlers.
- `artifacts/js_recon/dom_analysis/redirect_sinks.txt` — Client-side redirect vectors.
