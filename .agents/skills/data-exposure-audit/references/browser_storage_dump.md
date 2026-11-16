# Browser Storage Dump (own session only)

Paste into the DevTools console on the target origin while logged in to your own account. Run again after logout to see what persists (DE-014, DE-015). Copy the output into your notes and redact tokens.

```js
(async () => {
  const red = v => (typeof v === "string" && v.length > 12) ? v.slice(0, 4) + "…" + v.slice(-4) + ` (${v.length})` : v;
  const flag = s => /token|jwt|auth|session|secret|key|password|email|phone|ssn|card|refresh/i.test(s);
  const out = {origin: location.origin, localStorage: {}, sessionStorage: {}, cookies: {}, indexedDB: {}, caches: []};
  for (const [name, st] of [["localStorage", localStorage], ["sessionStorage", sessionStorage]]) {
    for (let i = 0; i < st.length; i++) {
      const k = st.key(i), v = st.getItem(k);
      out[name][k] = {value: red(v), sensitive: flag(k) || flag(v || "") || /^eyJ/.test(v || "")};
    }
  }
  document.cookie.split(";").filter(Boolean).forEach(c => {
    const [k, ...v] = c.trim().split("="); out.cookies[k] = {value: red(v.join("=")), note: "readable by JS (not HttpOnly)"};
  });
  if (indexedDB.databases) {
    for (const db of await indexedDB.databases()) {
      out.indexedDB[db.name] = {};
      await new Promise(res => {
        const req = indexedDB.open(db.name);
        req.onsuccess = () => {
          const d = req.result, stores = Array.from(d.objectStoreNames);
          if (!stores.length) { d.close(); return res(); }
          const tx = d.transaction(stores, "readonly"); let left = stores.length;
          stores.forEach(s => {
            const r = tx.objectStore(s).getAll(null, 3);
            r.onsuccess = () => {
              const sample = JSON.stringify(r.result).slice(0, 300);
              out.indexedDB[db.name][s] = {sample_records: r.result.length, sensitive: flag(sample), sample: sample.replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, "<jwt>")};
              if (--left === 0) { d.close(); res(); }
            };
            r.onerror = () => { if (--left === 0) { d.close(); res(); } };
          });
        };
        req.onerror = () => res();
      });
    }
  }
  if (window.caches) for (const n of await caches.keys()) out.caches.push({name: n, entries: (await (await caches.open(n)).keys()).length});
  console.log(JSON.stringify(out, null, 2));
  return out;
})();
```

What to report:

- Access or refresh tokens, JWTs, API keys in localStorage/sessionStorage (any XSS can steal them; raise severity of XSS findings).
- PII or full user objects stored client-side, especially if they persist after logout.
- IndexedDB or Cache Storage holding authenticated responses after logout (also see client-side-js-security SW-003).
- Non-HttpOnly cookies that carry session or auth values.
