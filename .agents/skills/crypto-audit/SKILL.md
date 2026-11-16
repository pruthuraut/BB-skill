---
name: crypto-audit
description: Audit authorized applications for cryptographic implementation flaws across 15 checks — weak password hashing (MD5, SHA1, unsalted, fast hashes), weak encryption (DES, 3DES, RC4, Blowfish, ECB mode), hardcoded keys in source or config, key management (storage, rotation, access), IV/nonce reuse (CBC, GCM, CTR), padding oracles, ECB detection via repeated ciphertext blocks, weak key derivation (low PBKDF2 iterations, no KDF), weak random number generation (Math.random, java.util.Random, rand, time seeds), timing attacks on secret comparison, certificate-pinning bypass on own devices, missing bcrypt/scrypt/Argon2, JWT algorithm confusion (RS256 to HS256, alg none, kid/jku), and key exposure in repositories — plus variants (static salts, encrypt-without-MAC, MAC-then-encrypt, CBC bit-flipping, hash length extension, predictable reset tokens, UUIDv1, homemade crypto). Includes a passive source/config scanner, a ciphertext ECB and token analyzer, and black-box test procedures. Triggers on "crypto", "cryptography", "encryption", "MD5", "SHA1", "bcrypt", "Argon2", "PBKDF2", "ECB", "CBC", "IV reuse", "padding oracle", "hardcoded key", "secret key", "random token", "Math.random", "timing attack", "certificate pinning", "JWT alg", "RS256 HS256", or when encrypted tokens, cookies, or IDs appear in traffic.
---

# Cryptographic Implementation Audit (15 checks + variants)

Find places where the application uses cryptography wrongly: weak primitives, bad modes, reused IVs, guessable randomness, leaked keys, unsafe comparisons, or token formats the server can be tricked into accepting. Black-box tests look at tokens and ciphertexts in traffic; white-box tests read source, configs, and mobile app code.

- Checklist: `references/crypto_checklist.md` (CRY-001 to CRY-015 core, CRY-V-* variants, black-box procedures, safe-parameter table).
- Tracker: `references/crypto_tracker.md`.
- `scripts/crypto_scan.py`: offline scanner for source, configs, and decompiled apps (weak hashes for passwords, weak ciphers and ECB, static IVs, hardcoded keys and private keys, low KDF iterations, insecure RNG, non-constant-time comparisons, JWT `none`/verify disabled, TLS verification disabled).
- `scripts/cipher_analyze.py`: offline analyzer for captured ciphertexts or tokens (encoding detection, block-size guess, repeated blocks for ECB, shared prefixes suggesting IV reuse or deterministic encryption, entropy, embedded timestamps).
- Related: `session-management` (JWT attack rows, token entropy), `csrf-audit` (`csrf_token_analyze.py`), `jsrecon` and `cloud-supplychain` (secrets in JS and repos), `server-config-audit` (transport, pinning detection), `authbypass` and `credentialattacks` (reset tokens), `api-security`.

## Procedure

1. Confirm scope with `scripts/scope_check.sh TARGET`.
2. White-box (when source, configs, mobile apps, or public repos of the target are in scope):

   ```bash
   python3 .agents/skills/crypto-audit/scripts/crypto_scan.py <source-or-decompiled-dir> --out artifacts/<target>/crypto_scan.json
   trufflehog filesystem <dir> ; gitleaks detect -s <dir>     # key exposure (CRY-003, CRY-015)
   ```

3. Black-box token collection: from your own accounts, collect encrypted cookies, reset tokens, invite tokens, IDs, API keys, and JWTs (20+ samples each, across sessions and accounts). Run:

   ```bash
   python3 .agents/skills/crypto-audit/scripts/cipher_analyze.py tokens.txt
   ```

4. ECB and structure (CRY-007): register or set your own fields to long repeated values (for example 48 `A` characters) and watch for repeated blocks in the encrypted cookie or token.
5. IV reuse (CRY-005): encrypt the same own value twice; identical ciphertexts or identical first blocks mean a static IV or deterministic encryption.
6. Padding oracle (CRY-006): on an encrypted parameter you own, flip the last byte of the second-to-last block and compare error responses (padding error vs MAC error vs success). Detection only, a few requests; full decryption with PadBuster is authorized-only.
7. JWT (CRY-014): use session-management JWT rows and `jwt_tool` on your own tokens (alg none, RS256→HS256 with the public key, kid/jku/x5u injection, weak HMAC secret offline cracking).
8. Randomness (CRY-009): compare many own reset or invite tokens for sequence, timestamps, or short length.
9. Timing (CRY-010): only on your own tokens or API keys, with statistical sampling at a gentle rate; report as a lead unless strongly significant.
10. Pinning (CRY-011): on your own device only, record whether Frida/objection bypass is needed to proxy the app; pinning bypass itself is a testing technique, not a finding.
11. Password storage (CRY-001, 012, 013): from source, config, or leaked-hash evidence in scope (never crack real users' hashes). Black-box hints: password length limit of 72 bytes (bcrypt), truncation, case-insensitive login, password emailed in plaintext.
12. Save findings to `artifacts/<target>/crypto.json` and the tracker to `artifacts/<target>/crypto_tracker.md`.

## Classes

- `passive`: source, config, app, and repository review; offline analysis of your own tokens.
- `bounded`: requests with your own tokens and ciphertexts (structure tests, a few padding-oracle detection requests, JWT tests on your own token).
- `authorized-only`: decrypting or forging other users' data, full padding-oracle decryption, large-scale timing measurements, cracking hashes that belong to real users, and using exposed production keys.

## Rules

- If a key or secret is found, record where, its type, and a redacted fingerprint; do not use it against production systems.
- Never crack or test real users' password hashes or tokens.
- Keep timing and oracle tests low-rate and short.

## Mitigation guidance for reports

- Passwords: Argon2id (or scrypt, or bcrypt cost 12+, or PBKDF2-HMAC-SHA256 600k+ iterations) with per-user salts; optional pepper in a KMS/HSM.
- Encryption: AES-GCM or ChaCha20-Poly1305 with unique nonces from a CSPRNG (or a counter), never ECB; if CBC is unavoidable, encrypt-then-MAC with constant-time verification.
- Keys: KMS/HSM or a secrets manager, least-privilege access, rotation, never in source, images, or client apps; rotate any exposed key.
- Randomness: `secrets`, `crypto.randomBytes`/`crypto.getRandomValues`, `SecureRandom`, `random_bytes`; 128+ bits for tokens.
- Comparisons: `hmac.compare_digest`, `crypto.timingSafeEqual`, `MessageDigest.isEqual`, `hash_equals`.
- JWT: pin the algorithm server-side, separate keys per algorithm, validate `kid`/`jku` against allowlists, reject `none`.
- Use vetted libraries (libsodium, Tink); do not build custom crypto.

## Sources

OWASP Cryptographic Storage, Password Storage, Key Management, and JSON Web Token cheat sheets; OWASP WSTG-CRYP-02/03/04; OWASP MASVS-CRYPTO and MASTG; NIST SP 800-63B, SP 800-132, SP 800-38A/D; CWE-327, 328, 329, 330, 321, 916, 208; PortSwigger JWT labs; cryptopals exercises.
