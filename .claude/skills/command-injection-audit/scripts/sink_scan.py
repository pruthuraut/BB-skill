#!/usr/bin/env python3
"""Passive scan of source code for OS command execution sinks.

Read-only. Use it on source you are authorized to review (client repositories,
an approved code drop, or open-source code you are auditing). It never runs the
code it scans.

Output: JSON lines with file, line, language, sink class, and a risk hint:
  high   = sink with a string that looks built from request or user data
  review = sink with constant-looking arguments (confirm the input path)

Usage:
  sink_scan.py /path/to/source [--out artifacts/<target>/sinks.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "target"}
EXTS = {".py": "python", ".js": "node", ".ts": "node", ".mjs": "node", ".cjs": "node",
        ".java": "java", ".kt": "java", ".groovy": "java", ".rb": "ruby", ".php": "php",
        ".go": "go", ".cs": "dotnet", ".sh": "shell"}

# (language, sink class, regex)
SINKS = [
    ("python", "shell=True", re.compile(r"subprocess\.(run|call|Popen|check_call|check_output)\s*\([^)]*shell\s*=\s*True")),
    ("python", "os.system/popen", re.compile(r"\bos\.(system|popen|spawn\w*|exec\w*)\s*\(")),
    ("python", "commands/getoutput", re.compile(r"subprocess\.(getoutput|getstatusoutput)\s*\(")),
    ("node", "child_process.exec", re.compile(r"\b(child_process\.)?exec(Sync)?\s*\(")),
    ("node", "child_process.spawn shell", re.compile(r"\bspawn(Sync)?\s*\([^)]*shell\s*:\s*true")),
    ("node", "execa/shelljs", re.compile(r"\b(shelljs\.exec|execa\w*\s*\(|\$`)")),
    ("java", "Runtime.exec/ProcessBuilder", re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(")),
    ("java", "script engine eval", re.compile(r"ScriptEngine\w*.*\.eval\s*\(|GroovyShell\b.*\.(evaluate|parse)")),
    ("ruby", "backticks/%x", re.compile(r"`[^`]*`|%x[\(\[\{|/\"]")),
    ("ruby", "system/exec/spawn/popen", re.compile(r"\b(system|exec|spawn)\s*\(|IO\.popen|Open3\.\w+|Kernel\.open\s*\(")),
    ("php", "shell/exec family", re.compile(r"\b(shell_exec|exec|system|passthru|popen|proc_open)\s*\(|`[^`]*\$")),
    ("go", "exec.Command", re.compile(r"exec\.Command(Context)?\s*\(|syscall\.(Exec|ForkExec|StartProcess)\s*\(")),
    ("dotnet", "Process.Start", re.compile(r"Process\.Start\s*\(|new\s+ProcessStartInfo")),
    ("shell", "eval/command substitution", re.compile(r"\beval\s|\$\(|`[^`]+`")),
]

USER_HINT = re.compile(r"(request\.|req\.|params|query\[|getParameter|\$_(GET|POST|REQUEST|COOKIE)|input\(|argv|form\[|body\.|\bparams\[|c\.Query|r\.FormValue|Request\.)", re.I)


def scan_file(path: str, lang: str, out: list[dict]) -> None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        for sink_lang, sink_class, rx in SINKS:
            if sink_lang != lang:
                continue
            if rx.search(line):
                window = "".join(lines[max(0, idx - 3): idx + 2])
                risk = "high" if USER_HINT.search(window) else "review"
                out.append({"file": path, "line": idx, "language": lang, "sink": sink_class,
                            "risk": risk, "snippet": stripped[:200]})
                break


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="directory of source to scan (read-only)")
    ap.add_argument("--out", help="write JSON to this path")
    args = ap.parse_args()
    if not os.path.isdir(args.root):
        ap.error("root must be a directory")

    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(args.root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXTS:
                scan_file(os.path.join(dirpath, name), EXTS[ext], findings)

    findings.sort(key=lambda f: (f["risk"] != "high", f["file"], f["line"]))
    summary = {"root": args.root, "total": len(findings),
               "high": sum(1 for f in findings if f["risk"] == "high"),
               "review": sum(1 for f in findings if f["risk"] == "review"),
               "findings": findings}
    text = json.dumps(summary, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
