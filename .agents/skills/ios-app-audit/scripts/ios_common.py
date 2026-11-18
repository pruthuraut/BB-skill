"""Shared helpers for the iOS audit scripts (standard library only).

IPA contents, container files and device output are untrusted data: archives are extracted with
zip-slip and symlink guards, values are redacted before they reach a report, and nothing from the
target is executed. Run the scripts with `python3 -I`.
"""
from __future__ import annotations

import json
import math
import os
import plistlib
import re
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(SKILLS_DIR, "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
CHECKLIST_JSON = os.path.join(HERE, "..", "references", "checklist.json")
FRIDA_DIR = os.path.join(HERE, "frida")
ARTIFACTS = os.environ.get("IOS_AUDIT_ARTIFACTS") or os.path.join(REPO, "artifacts")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    where: str = ""
    evidence: str = ""
    checklist: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


# ---------------------------------------------------------------- checklist
_ROWS: list[dict] | None = None


def checklist_rows() -> list[dict]:
    global _ROWS
    if _ROWS is None:
        try:
            with open(CHECKLIST_JSON, encoding="utf-8") as fh:
                _ROWS = json.load(fh)
        except (OSError, json.JSONDecodeError):
            _ROWS = []
    return _ROWS


def ids(*patterns: str, limit: int = 10) -> list[str]:
    """Checklist IDs whose check text matches any of the regex patterns (case-insensitive)."""
    rx = [re.compile(p, re.I) for p in patterns]
    out = []
    for row in checklist_rows():
        if any(r.search(row["check"]) for r in rx):
            out.append(row["id"])
            if len(out) >= limit:
                break
    return out


# ---------------------------------------------------------------- processes
def which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run(cmd: list[str], timeout: int = 120, cwd: str | None = None, stdin: str | None = None) -> tuple[int, str, str]:
    """Run a tool with a timeout. Returns (rc, stdout, stderr); rc=-1 if it could not start, -2 on timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, input=stdin,
                           errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, "", f"timeout after {timeout}s"
    except OSError as e:
        return -1, "", str(e)


def scope_ok(host: str, workspace: str | None, program: str | None) -> tuple[bool, str]:
    """Run scripts/scope_check.sh HOST [ROOT] [PROGRAM]. Returns (ok, message)."""
    if not os.path.exists(SCOPE):
        return False, "scripts/scope_check.sh not found"
    bash = which("bash")
    if not bash:
        return False, "bash not found for scope_check.sh"
    rc, out, err = run([bash, SCOPE, host, workspace or "", program or ""], timeout=30)
    return rc == 0, (out or err).strip()


# ---------------------------------------------------------------- redaction
SENSITIVE_NAME_RE = re.compile(
    r"pass(word|wd|code)?|pwd|secret|token|session|auth|bearer|cookie|api[_-]?key|private[_-]?key|credential|"
    r"cvv|cvc|card|pan\b|ssn|social|pin\b|otp|mfa|refresh|jwt|iban|account[_-]?number|dob|birth", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
KV_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|bearer|cvv|ssn|session)"
                   r"(['\"]?\s*[:=]\s*['\"]?)([^'\"\s;&,<)]{3,})")


def redact_value(v) -> str:
    v = str(v).strip()
    if len(v) <= 8:
        return "<redacted>"
    return f"{v[:4]}...{v[-2:]} (len {len(v)})"


def redact(text: str) -> str:
    text = KV_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)
    text = JWT_RE.sub(lambda m: "<jwt " + redact_value(m.group(0)) + ">", text)
    return text


def snippet(text: str, n: int = 160) -> str:
    return redact(re.sub(r"\s+", " ", str(text)).strip())[:n]


def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", digits)]
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def classify_value(text: str) -> list[str]:
    """Tags for a value read from app storage: jwt, email, card (Luhn), ssn."""
    tags = []
    if JWT_RE.search(text):
        tags.append("jwt")
    if EMAIL_RE.search(text):
        tags.append("email")
    if any(luhn_ok(m.group(0)) for m in CARD_RE.finditer(text)):
        tags.append("card-number")
    if SSN_RE.search(text):
        tags.append("ssn-like")
    return tags


# ---------------------------------------------------------------- secrets
SECRET_PATTERNS = [
    ("aws-access-key", "high", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", "medium", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google-oauth-client", "info", re.compile(r"\b\d{6,}-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("firebase-db-url", "info", re.compile(r"https://[a-z0-9-]+\.(firebaseio\.com|firebasedatabase\.app)")),
    ("stripe-secret-key", "critical", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("stripe-publishable-key", "info", re.compile(r"\bpk_live_[0-9A-Za-z]{20,}\b")),
    ("slack-token", "high", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("slack-webhook", "high", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("github-token", "high", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("private-key-pem", "critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("jwt", "medium", JWT_RE),
    ("twilio-key", "high", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("sendgrid-key", "high", re.compile(r"\bSG\.[\w-]{22}\.[\w-]{43}\b")),
    ("mailgun-key", "high", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("branch-live-key", "low", re.compile(r"\bkey_live_[0-9a-zA-Z]{32}\b")),
    ("mapbox-secret", "high", re.compile(r"\bsk\.eyJ[0-9A-Za-z_\-.]{20,}")),
    ("openai-key", "high", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("azure-storage-conn", "critical", re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}")),
    ("basic-auth-url", "high", re.compile(r"https?://[A-Za-z0-9._%-]{2,}:[^@\s/:]{3,}@[A-Za-z0-9.-]+")),
    ("generic-assigned-secret", "medium", re.compile(
        r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b"
        r"[\"'\s:=]{1,6}([A-Za-z0-9_\-+/=]{16,})")),
]


def find_secrets(text: str, where: str, limit: int = 50) -> list[dict]:
    hits = []
    seen = set()
    for name, sev, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(2) if name == "generic-assigned-secret" else m.group(0)
            if name == "generic-assigned-secret" and shannon(val) < 3.5:
                continue
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            hits.append({"type": name, "severity": sev, "where": where, "value": redact_value(val)})
            if len(hits) >= limit:
                return hits
    return hits


# ---------------------------------------------------------------- files
def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def load_plist(path: str):
    """plistlib for XML and binary plists; returns None when the file is not a plist."""
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:  # noqa: BLE001 - untrusted input, any parse error means "not a plist"
        return None


def load_plist_bytes(data: bytes):
    try:
        return plistlib.loads(data)
    except Exception:  # noqa: BLE001
        return None


def safe_extract_zip(zip_path: str, dest: str, max_total: int = 4 * 1024 ** 3) -> dict:
    """Extract an IPA/zip with zip-slip, symlink and size guards. Returns stats."""
    stats = {"files": 0, "skipped_symlinks": 0, "skipped_unsafe": 0, "bytes": 0}
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            name = info.filename
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                stats["skipped_symlinks"] += 1
                continue
            target = os.path.realpath(os.path.join(dest, name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)) or "\x00" in name:
                stats["skipped_unsafe"] += 1
                continue
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            stats["bytes"] += info.file_size
            if stats["bytes"] > max_total:
                raise ValueError("archive larger than the extraction limit")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
            stats["files"] += 1
    return stats


def printable_strings(data: bytes, min_len: int = 4) -> list[str]:
    return [m.group(0).decode("ascii", "replace") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]


def is_macho(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return False
    return head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["rule"]))
