# JWT Deep Testing Checklist (extension)

Class key: `passive` = token decoding and review. `bounded` = variant tokens sent to your own endpoint and account (`jwt_variant_probe.py`). `authorized-only` = cracking and key-recovery tests (approval only, on your own token). No signing key is used by the probe.

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| JWX-001 | Algorithm | `alg` none, None, NONE accepted | bounded | `jwt_variant_probe.py` alg variants |
| JWX-002 | Algorithm | RS256 to HS256 confusion (public key as HMAC secret) | authorized-only | Use jwt_tool (`-X k`) on own token and lab only |
| JWX-003 | Header | JWK injection via jwk header | bounded | `jwt_variant_probe.py` jwk variant to own host |
| JWX-004 | Header | JKU pointing to attacker-controlled key set | bounded | `jwt_variant_probe.py --oob-host` |
| JWX-005 | Header | X5U pointing to attacker certificate | bounded | Own host in x5u; expect rejection |
| JWX-006 | kid | Path traversal in `kid` (`../`) | bounded | Own token with benign kid path; check the error type |
| JWX-007 | kid | SQL injection in `kid` | bounded | Own token with a quote in kid; compare error text (no extraction) |
| JWX-008 | kid | Command injection in `kid` | authorized-only | Review how kid is used; no injection payloads |
| JWX-009 | Signature | Empty signature accepted | bounded | `jwt_variant_probe.py` empty signature |
| JWX-010 | Signature | Truncated signature accepted | bounded | `jwt_variant_probe.py` truncated signature |
| JWX-011 | Claims | Claims read without signature verification | bounded | Changed claim with original signature (expect rejection) |
| JWX-012 | exp | Expired token accepted (negative or past exp) | bounded | `jwt_variant_probe.py` exp in the past |
| JWX-013 | nbf | Not-before in the future accepted | bounded | `jwt_variant_probe.py` nbf in the future |
| JWX-014 | iat | Issued-at in the future accepted | bounded | `jwt_variant_probe.py` iat in the future |
| JWX-015 | aud | Audience not checked | bounded | `jwt_variant_probe.py` aud changed |
| JWX-016 | iss | Issuer not checked | bounded | `jwt_variant_probe.py` iss changed |
| JWX-017 | sub | Subject changed to another own account | bounded | Own second account: swap sub with original signature |
| JWX-018 | jti | Token replay accepted after logout or use | bounded | Replay original token after logout (compare behaviour) |
| JWX-019 | JWE | Encryption algorithm downgrade (alg none on JWE, weak enc) | passive | Decode the header: check enc and alg values |
| JWX-020 | Weak secret | HMAC secret guessable (dictionary, short key) | authorized-only | Kali hashcat mode 16500 or jwt_tool on own token only |
