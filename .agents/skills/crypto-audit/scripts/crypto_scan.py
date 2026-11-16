#!/usr/bin/env python3
"""Offline scanner for cryptographic misuse in source, configs, and decompiled apps.

Rules cover Python, JavaScript/TypeScript, Java/Kotlin, C#, PHP, Go, Ruby, and
config files. Matches are leads; read the code around each hit. Secret values
are redacted in output (first 4 chars + length).

Example:
  crypto_scan.py ./src ./decompiled_apk --out artifacts/example.com/crypto_scan.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv", "target", ".gradle"}
EXTS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt", ".cs", ".php", ".go", ".rb", ".swift",
        ".m", ".c", ".cpp", ".h", ".scala", ".yml", ".yaml", ".json", ".xml", ".properties", ".env", ".ini", ".conf",
        ".config", ".toml", ".smali", ".tf", ".gradle", ".plist"}

R = lambda p: re.compile(p, re.I)
RULES = [
    # id, CRY row, severity, regex, description
    ("weak-password-hash", "CRY-001", "high",
     R(r"(md5|sha1|sha-1)\s*\(\s*[\w.$\[\]'\"]*pass|hashlib\.(md5|sha1)\([^)]*pass|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"\)[\s\S]{0,200}?pass|"
       r"createHash\(\s*['\"](md5|sha1)['\"]\)[\s\S]{0,120}?pass|password_hash\s*=\s*(md5|sha1)"), "password hashed with MD5/SHA1"),
    ("fast-hash-password", "CRY-012", "medium",
     R(r"(sha256|sha512|hashlib\.sha256|createHash\(\s*['\"]sha(256|512)['\"]\))[\s\S]{0,80}?pass"), "password hashed with a fast unsalted hash"),
    ("weak-hash", "CRY-002", "low", R(r"\b(MD5|SHA1)\b\s*\(|hashlib\.(md5|sha1)\(|getInstance\(\s*\"(MD5|SHA-?1)\"|createHash\(\s*['\"](md5|sha1)['\"]"),
     "MD5/SHA1 use (fine for checksums, not for security)"),
    ("weak-cipher", "CRY-002", "high",
     R(r"\b(DES|DESede|TripleDES|3DES|RC4|ARC4|RC2|Blowfish)\b[\"'/]|Cipher\.getInstance\(\s*\"(DES|DESede|RC4|ARCFOUR|Blowfish)|"
       r"createCipheriv?\(\s*['\"](des|des-ede3|rc4|bf)|openssl_encrypt\([^)]*['\"](des|rc4|bf)|ARC4\.new|DES3?\.new|Blowfish\.new"),
     "weak cipher (DES/3DES/RC4/RC2/Blowfish)"),
    ("ecb-mode", "CRY-002", "high",
     R(r"/ECB/|MODE_ECB|['\"]aes-\d+-ecb['\"]|AES/ECB|CipherMode\.ECB|Cipher\.getInstance\(\s*\"AES\"\s*\)|modes\.ECB\("),
     "ECB mode (Java 'AES' alone defaults to ECB)"),
    ("rsa-no-oaep", "CRY-002", "medium", R(r"RSA/ECB/(NoPadding|PKCS1Padding)|RSA_PKCS1_PADDING|PKCS1_v1_5\.new|padding\.PKCS1v15\(\)"),
     "RSA encryption without OAEP"),
    ("static-iv", "CRY-005", "high",
     R(r"\b(iv|IV|nonce)\s*[:=]\s*(b?['\"][^'\"]{8,}['\"]|new byte\[\s*16\s*\]|bytes\(16\)|Buffer\.alloc\(\s*16\s*\)|\[0(,\s*0){7,}\])|"
       r"IvParameterSpec\(\s*(new byte\[|\"|key)|createCipheriv\([^,]+,[^,]+,\s*(['\"]|Buffer\.alloc|key)"),
     "static, zero, or key-derived IV/nonce"),
    ("hardcoded-key", "CRY-003", "high",
     R(r"(secret[_-]?key|encryption[_-]?key|aes[_-]?key|jwt[_-]?secret|hmac[_-]?(key|secret)|signing[_-]?key|private[_-]?key|app[_-]?key|"
       r"secret_key_base|SECRET_KEY|api[_-]?secret|client[_-]?secret)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
     "hardcoded secret or key"),
    ("private-key", "CRY-003", "critical", R(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "private key material"),
    ("secretkeyspec-literal", "CRY-003", "high", R(r"SecretKeySpec\(\s*\"[^\"]+\"\.getBytes|SecretKeySpec\(\s*new byte\[\]\s*\{"),
     "key built from a literal"),
    ("low-iterations", "CRY-008", "medium",
     R(r"(?:\b(?:iterations?|iter|rounds|log_rounds|cost)\s*[:=]\s*|PBEKeySpec\([^,()]+,[^,()]+,\s*|Rfc2898DeriveBytes\([^,()]+,[^,()]+,\s*|"
       r"pbkdf2_hmac\([^,()]+,[^,()]+,[^,()]+,\s*|pbkdf2Sync\([^,()]+,[^,()]+,\s*|hash_pbkdf2\([^,()]+,[^,()]+,[^,()]+,\s*)([1-9]\d{0,5})\b(?!\d)"),
     "KDF with low iteration count or cost (check the number)"),
    ("key-from-hash", "CRY-008", "medium", R(r"(key|secret)\s*=\s*(hashlib\.)?(md5|sha1|sha256)\s*\(\s*\w*pass"), "key derived by hashing a password"),
    ("insecure-random", "CRY-009", "high",
     R(r"Math\.random\(\)|new\s+Random\(|java\.util\.Random|\brand\(\)|\bmt_rand\(|\brandom\.(random|randint|choice|choices|getrandbits)\(|"
       r"\buniqid\(|srand\(\s*time|math/rand|Random\.new\b|rand\.Intn|uuid1\(\)|UUID\.randomUUID\(\)\.toString\(\)\.substring"),
     "non-cryptographic RNG (check if used for tokens, keys, IDs, OTPs)"),
    ("non-constant-compare", "CRY-010", "medium",
     R(r"(signature|hmac|digest|mac|token|api_?key|secret|hash)\w*\s*(==|===|!=|!==)\s*\w+|"
       r"(signature|hmac|digest|token|hash)\w*\.equals\(|strcmp\(\s*\$?\w*(sig|hmac|token|hash)"),
     "secret compared with a non-constant-time operator"),
    ("jwt-none-or-noverify", "CRY-014", "high",
     R(r"algorithms\s*[:=]\s*\[[^\]]*['\"]none['\"]|verify\s*[:=]\s*False|options\s*=\s*\{[^}]*verify_signature['\"]?\s*:\s*False|"
       r"jwt\.decode\([^)]*verify\s*=\s*False|\.decode\(\s*token\s*\)\s*;|ignoreExpiration\s*:\s*true|parseUnsecuredClaims|setSigningKey\(\s*\""),
     "JWT verification disabled, alg none allowed, or literal signing key"),
    ("jwt-alg-from-token", "CRY-014", "medium", R(r"algorithms\s*[:=]\s*\[?\s*(header|decoded|unverified)\w*\[?['\"]?alg"),
     "JWT algorithm taken from the token header"),
    ("tls-verify-disabled", "CRY-V-009", "high",
     R(r"verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|"
       r"TrustAllCerts|X509TrustManager[\s\S]{0,200}checkServerTrusted\([^)]*\)\s*\{\s*\}|ServerCertificateValidationCallback\s*=.*true|"
       r"CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier"),
     "TLS certificate or hostname verification disabled"),
    ("hash-secret-concat", "CRY-V-002", "medium", R(r"(md5|sha1|sha256)\s*\(\s*(secret|key|salt)\w*\s*(\+|\.)\s*\w+"),
     "hash(secret + data) signature (length extension)"),
    ("static-salt", "CRY-012", "medium", R(r"\bsalt\s*[:=]\s*['\"][^'\"]{2,}['\"]"), "static salt"),
    ("base64-as-crypto", "CRY-V-004", "low", R(r"(encrypt|cipher)\w*\s*=\s*(base64|btoa|Base64\.encode)"), "encoding presented as encryption"),
]
SECRET_RULES = {"hardcoded-key"}


def redact(s: str) -> str:
    return s[:4] + "..." + f"({len(s)} chars)" if len(s) > 6 else "..."


def scan(path: str) -> list[dict]:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    if len(text) > 5_000_000:
        return []
    out = []
    for rid, row, sev, rx, desc in RULES:
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = text[m.start(): m.end()][:200].replace("\n", " ")
            if rid in SECRET_RULES and m.lastindex:
                val = m.group(m.lastindex)
                if re.fullmatch(r"(changeme|change_me|your[_-]?\w+|xxx+|\*+|<[^>]+>|\$\{[^}]+\}|%\w+%|process\.env\.\w+|test|example)", val, re.I):
                    continue
                snippet = snippet.replace(val, redact(val))
            if rid == "low-iterations":
                n = int(m.group(m.lastindex))
                if n >= 600000 or (n >= 10 and re.search(r"cost|rounds", m.group(0), re.I) and n <= 31 and n >= 10):
                    continue
            out.append({"file": path, "line": line, "rule": rid, "row": row, "severity": sev, "desc": desc, "match": snippet})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--min-severity", default="low", choices=["low", "medium", "high", "critical"])
    ap.add_argument("--out")
    args = ap.parse_args()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    files = []
    for p in args.paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for n in names:
                    if os.path.splitext(n)[1].lower() in EXTS or n.startswith(".env"):
                        files.append(os.path.join(root, n))
        else:
            files.append(p)
    findings = [f for fp in files for f in scan(fp) if order[f["severity"]] <= order[args.min_severity]]
    findings.sort(key=lambda f: (order[f["severity"]], f["row"], f["file"], f["line"]))
    for f in findings:
        print(f"[{f['severity']}] {f['row']} {f['rule']} {f['file']}:{f['line']}  {f['match'][:120]}")
    by_row: dict[str, int] = {}
    for f in findings:
        by_row[f["row"]] = by_row.get(f["row"], 0) + 1
    print(f"files {len(files)}, findings {len(findings)}, by row {dict(sorted(by_row.items()))}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump({"files": len(files), "findings": findings}, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
