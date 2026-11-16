# Cryptographic Implementation Checklist

Class key: `passive` = source, config, app, and repo review; offline analysis of own tokens. `bounded` = requests with your own tokens and ciphertexts. `authorized-only` = other users' data, full oracle decryption, large timing runs, real-user hash cracking, use of exposed production keys.

## Core checks (15)

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CRY-001 | Passwords | Weak hashing for password storage (MD5, SHA1, SHA-256 single pass, NTLM, CRC, base64 "encryption") | passive | crypto_scan.py `weak-password-hash`; config review; black-box hints (password reminders, plaintext emails) |
| CRY-002 | Encryption | Weak algorithms or modes: DES, 3DES, RC4, RC2, Blowfish, ECB, unauthenticated CBC/CTR, RSA PKCS#1 v1.5 encryption, RSA without padding | passive | crypto_scan.py `weak-cipher`, `ecb-mode` |
| CRY-003 | Keys | Hardcoded encryption keys, HMAC secrets, JWT secrets, private keys in source, config, mobile apps, JS bundles, Docker images | passive | crypto_scan.py `hardcoded-key`, `private-key`; trufflehog/gitleaks; jsrecon |
| CRY-004 | Key management | Key storage (plaintext env files, DB, client side), rotation (never rotated, no versioning), access (shared across environments or tenants) | passive | Config and infra review; ask for KMS usage; note same key in dev and prod |
| CRY-005 | IV / nonce | IV reuse in CBC (static or zero IV), nonce reuse in GCM/CTR, IV derived from key or predictable counter exposed | bounded | crypto_scan.py `static-iv`; encrypt same own value twice and compare (cipher_analyze.py) |
| CRY-006 | Padding oracle | Different responses for bad padding vs bad MAC/data on CBC-encrypted parameters (cookies, tokens, ViewState, encrypted IDs) | bounded | Flip a byte in the penultimate block of your own token; compare status, body, timing; detection only |
| CRY-007 | ECB | ECB detection: repeated 16-byte (or 8-byte) ciphertext blocks for repeated plaintext | bounded | Own field set to 48+ repeated chars; cipher_analyze.py `repeated_blocks` |
| CRY-008 | KDF | Weak key derivation: PBKDF2 under 600k (SHA-256), bcrypt cost under 10, scrypt N under 2^15, key = hash(password), no salt | passive | crypto_scan.py `low-iterations`, `key-from-hash` |
| CRY-009 | Randomness | Weak RNG for security values: `Math.random`, `java.util.Random`, `rand()`/`mt_rand`, `random` module, `uniqid`, time or PID seeds, UUIDv1 tokens | passive | crypto_scan.py `insecure-random`; cipher_analyze.py on own reset/invite tokens |
| CRY-010 | Timing | Non-constant-time comparison of secrets (HMAC, API keys, tokens, signatures) with `==`, `equals`, `strcmp` | bounded | crypto_scan.py `non-constant-compare`; gentle statistical test on own token only |
| CRY-011 | Pinning | Certificate pinning bypass techniques on own device (Frida, objection, SSL Kill Switch, network security config override); note what is pinned and how it fails | bounded | Own device and app build only; record result for tls-audit TLSX-013 |
| CRY-012 | Passwords | Weak password hashing details: no salt, global static salt, short salt, fast algorithm, truncation, case folding, pepper in DB | passive | Source review; black-box: same password on two own accounts never reveals equality in any output |
| CRY-013 | Passwords | Proper adaptive hashing: bcrypt/scrypt/Argon2id/PBKDF2 used with sane parameters, rehash on login when parameters are old, 72-byte bcrypt input limit handled | passive | Source review; black-box: password over 72 bytes with only the tail changed should fail login when bcrypt is used without pre-hashing |
| CRY-014 | JWT | JWT algorithm confusion (RS256→HS256 with public key as HMAC secret), `alg: none`, `kid` path or SQL injection, `jku`/`x5u` to attacker URL, embedded `jwk`, weak HMAC secret | bounded | Own token with `jwt_tool -X a/k/s/i`, offline secret cracking of own token (hashcat 16500); see session-management |
| CRY-015 | Repository | Cryptographic key exposure in source repositories (current tree and history, forks, gists, CI logs, packages) | passive | trufflehog git/github, gitleaks, GitHub code search; cloud-supplychain |

## Variants

| ID | Product | Check | Class | Safe verification |
|---|---|---|---|---|
| CRY-V-001 | Integrity | Encryption without MAC, or MAC-then-encrypt, allowing CBC bit-flipping (change own role or ID byte) | bounded | Flip a bit in own ciphertext block N-1 and watch a predictable change in block N |
| CRY-V-002 | MAC | Hash length extension on `hash(secret + data)` signatures (MD5, SHA1, SHA-256) | bounded | hash_extender on own signed value; append harmless parameter |
| CRY-V-003 | Tokens | Predictable reset, invite, or API tokens (sequential, time-based, MD5 of email/time) | passive | cipher_analyze.py; hash known values (email, user ID, time) |
| CRY-V-004 | Encoding | Base64, hex, or XOR presented as encryption | passive | Decode own tokens |
| CRY-V-005 | Deterministic | Deterministic encryption of IDs allowing equality checks or swapping between users | bounded | Same plaintext gives same ciphertext across own accounts |
| CRY-V-006 | RSA | Small RSA keys, e=1/3 without padding, shared modulus, textbook RSA | passive | Key inspection |
| CRY-V-007 | ViewState | .NET ViewState / machineKey MAC disabled or default key (ysoserial use is authorized-only) | passive | `__VIEWSTATE` decode, MAC presence; Blacklist3r for known keys (offline) |
| CRY-V-008 | Framework secrets | Default or leaked framework secrets (Rails `secret_key_base`, Django `SECRET_KEY`, Flask `SECRET_KEY`, Laravel `APP_KEY`, Express session secret) | passive | Source and env review; `flask-unsign --unsign` offline on own cookie |
| CRY-V-009 | TLS in code | Certificate verification disabled in clients (`verify=False`, `InsecureSkipVerify`, `rejectUnauthorized: false`, trust-all managers) | passive | crypto_scan.py `tls-verify-disabled` |
| CRY-V-010 | Homemade | Custom crypto (own cipher, XOR loops, reversible "hash") | passive | Code review |
| CRY-V-011 | Client side | Encryption or signing done in the browser or app with a key shipped to the client | passive | JS/app review (jsrecon) |
| CRY-V-012 | Compression | Secrets compressed together with attacker input before encryption (CRIME/BREACH-style length leaks) | passive | Design review |

## Black-box procedures

### Detect ECB

1. Set an own field that is encrypted into a cookie or token (name, email local part) to `A` × 64.
2. Capture the token, decode (base64/base64url/hex).
3. `cipher_analyze.py` reports repeated 16-byte blocks. Two or more identical blocks = ECB (or a deterministic block mode).

### Detect IV reuse / deterministic encryption

1. Trigger encryption of the same own value twice (log in twice, request the same token twice).
2. Identical ciphertexts, or identical first blocks with different later blocks, indicate a static IV (CBC) or deterministic scheme.
3. For CTR/GCM, identical keystream implies nonce reuse: XOR of two ciphertexts equals XOR of plaintexts.

### Detect a padding oracle (detection only)

1. Take an own CBC token of at least two blocks.
2. Send: the original (success), last byte of the second-to-last block changed (likely padding error), a full block changed earlier (likely data or MAC error).
3. Distinct, stable responses for padding errors vs other errors indicate an oracle. Stop here; full decryption is authorized-only.

### Detect weak randomness

1. Collect 20+ own reset or invite tokens in quick succession.
2. Look for monotonic increases, timestamps, short length, low character set, or hashes of known values (`cipher_analyze.py --known email userid`).

### Timing comparison (own token only)

1. Send 200–500 requests per variant at a gentle rate: correct first byte vs wrong first byte of your own API key or HMAC.
2. Compare medians and distributions; network noise usually hides differences. Report only clear, repeatable gaps.

## Safe-parameter reference

| Use | Acceptable |
|---|---|
| Password hashing | Argon2id (m≥19 MiB, t≥2, p=1), scrypt (N≥2^17, r=8, p=1), bcrypt cost ≥10 (12 preferred), PBKDF2-HMAC-SHA256 ≥600,000 |
| Symmetric encryption | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305, AES-GCM-SIV |
| MAC | HMAC-SHA256 or better |
| Signatures | Ed25519, ECDSA P-256 with deterministic nonces, RSA-PSS 3072 |
| Key exchange | X25519, ECDHE P-256 |
| Random tokens | ≥128 bits from a CSPRNG |

## Cross-references

| CRY row | Related rows |
|---|---|
| CRY-014 | session-management JWT rows |
| CRY-009, CRY-V-003 | csrf-audit token analyzer, authbypass reset tokens |
| CRY-003, CRY-015 | jsrecon, cloud-supplychain |
| CRY-011 | tls-audit TLSX-013 |
| CRY-V-009 | tls-audit |
