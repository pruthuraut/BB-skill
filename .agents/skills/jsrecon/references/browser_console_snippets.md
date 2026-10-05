# Browser Console Snippets for Dynamic JavaScript Reconnaissance

These snippets can be pasted directly into the Chrome DevTools / Firefox Developer Console (`F12`) while navigating a target application to monitor network behavior and harvest client-side data.

---

## 1. Complete Network Traffic Interceptor (`fetch` + `XHR`)

Captures every API call, method, custom header, and request payload made by the frontend, including background analytics and hidden endpoints:

```javascript
(function() {
  console.log('%c[+] JS Recon Dynamic Network Monitor Initialized', 'background: #222; color: #00ff66; font-size: 14px; padding: 4px;');
  
  // 1. Hook fetch
  const origFetch = window.fetch;
  window.fetch = function(...args) {
    const url = typeof args[0] === 'string' ? args[0] : (args[0] ? args[0].url : 'Unknown');
    const opts = args[1] || {};
    const method = opts.method || 'GET';
    
    console.groupCollapsed(`%c[FETCH] ${method} -> ${url}`, 'color: #00e5ff; font-weight: bold;');
    if (opts.headers) console.log('Headers:', opts.headers);
    if (opts.body) console.log('Payload:', opts.body);
    console.trace('Stack Trace');
    console.groupEnd();
    
    return origFetch.apply(this, args);
  };

  // 2. Hook XMLHttpRequest
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  
  XMLHttpRequest.prototype.open = function(method, url) {
    this._rMethod = method;
    this._rUrl = url;
    return origOpen.apply(this, arguments);
  };
  
  XMLHttpRequest.prototype.send = function(data) {
    console.groupCollapsed(`%c[XHR] ${this._rMethod} -> ${this._rUrl}`, 'color: #ff9100; font-weight: bold;');
    if (data) console.log('Payload:', data);
    console.trace('Stack Trace');
    console.groupEnd();
    return origSend.apply(this, arguments);
  };
})();
```

---

## 2. Extract All Registered React Router / Vue Router Routes

Inspects frontend Single-Page Application memory to dump all client-side routes:

```javascript
// Dump routes from React Router (v5/v6) or Vue Router
(function() {
  let routes = [];
  
  // Vue Router check
  if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__ && window.__VUE_DEVTOOLS_GLOBAL_HOOK__.apps) {
    window.__VUE_DEVTOOLS_GLOBAL_HOOK__.apps.forEach(app => {
      if (app.$router) {
        app.$router.options.routes.forEach(r => routes.push(r.path));
      }
    });
  }
  
  // Scrape anchors and history links
  document.querySelectorAll('a[href^="/"]').forEach(a => routes.push(a.getAttribute('href')));
  
  console.log('[+] Client-Side Routes Discovered:', [...new Set(routes)]);
})();
```

---

## 3. Extract All Loaded Script URLs on the Page

Quickly exports all `<script src="...">` tags loaded into the current DOM session:

```javascript
(function() {
  const scripts = Array.from(document.querySelectorAll('script[src]'))
    .map(s => s.src)
    .filter(src => !src.includes('analytics') && !src.includes('gtag'));
  
  console.log('[+] Active Application Scripts:');
  console.log(scripts.join('\n'));
  copy(scripts.join('\n'));
  console.log('[*] Copied to clipboard!');
})();
```
