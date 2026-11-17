"""Shared helpers for the Android audit scripts (no third-party imports).

Everything here treats APK contents, decompiled code and device output as untrusted data:
values are redacted before they go into a report, and nothing from the target is executed.
"""
from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
SKILLS_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.abspath(os.path.join(SKILLS_DIR, "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
CHECKLIST_JSON = os.path.join(HERE, "..", "references", "checklist.json")
FRIDA_DIR = os.path.join(HERE, "frida")

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


_CHECKLIST: list[dict] | None = None


def checklist_rows() -> list[dict]:
    global _CHECKLIST
    if _CHECKLIST is None:
        try:
            with open(CHECKLIST_JSON, encoding="utf-8") as fh:
                _CHECKLIST = json.load(fh)
        except (OSError, json.JSONDecodeError):
            _CHECKLIST = []
    return _CHECKLIST


def checklist_ids(phrase: str, limit: int = 3) -> list[str]:
    """Return checklist IDs whose check text contains every word of `phrase` (case-insensitive)."""
    words = [w.lower() for w in re.split(r"\s+", phrase.strip()) if w]
    hits = []
    for row in checklist_rows():
        text = row["check"].lower()
        if all(w in text for w in words):
            hits.append(row["id"])
            if len(hits) >= limit:
                break
    return hits


def which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run(cmd: list[str], timeout: int = 120, cwd: str | None = None) -> tuple[int, str, str]:
    """Run a tool with a timeout. Returns (rc, stdout, stderr); rc=-1 if it could not start."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, "", f"timeout after {timeout}s"
    except OSError as e:
        return -1, "", str(e)


def redact_value(v: str) -> str:
    v = v.strip()
    if len(v) <= 8:
        return "<redacted>"
    return f"{v[:4]}...{v[-2:]} (len {len(v)})"


SECRET_KV_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cvv|ssn)(['\"]?\s*[:=,]\s*['\"]?)([^'\"\s;<,)]{3,})")


def redact(text: str) -> str:
    return SECRET_KV_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", text)


def snippet(text: str, n: int = 160) -> str:
    return redact(re.sub(r"\s+", " ", text).strip())[:n]


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def scope_ok(host: str, workspace: str | None, program: str | None) -> tuple[bool, str]:
    """Run scripts/scope_check.sh. Returns (ok, message)."""
    if not os.path.exists(SCOPE):
        return False, "scripts/scope_check.sh not found"
    rc, out, err = run([SCOPE, host, workspace or "", program or ""], timeout=30)
    return rc == 0, (out or err).strip()
