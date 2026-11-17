#!/usr/bin/env python3
"""On-device checks for an Android app on a test device you own (adb).

Read-only modes run by default and need --test-device SERIAL (must match the connected device).
Modes that change state or send intents need --active-approved and are never run by default.
Backup needs --backup-approved and still requires you to confirm on the device screen.

Read-only:
  --devices                      list attached devices
  --permissions PKG              granted runtime permissions and requested permissions (dumpsys)
  --components PKG               component filters from dumpsys (exported status is in the manifest audit)
  --storage PKG                  shared_prefs, databases, cache: permissions and file names
                                 (run-as works only for debuggable builds; otherwise needs root)
  --logcat PKG                   sensitive-pattern hits in the current logcat buffer (redacted)
  --residue PKG                  data directories still present after uninstall or clearing
  --notifications PKG            notification record count for the package (text is not stored)
Approval-gated:
  --backup-approved PKG          adb backup to a scratch file; reports header and encryption flag only
  --active-approved --launch-exported PKG      am start on each exported activity (no extras)
  --active-approved --provider-query PKG       content query (no selection) on each exported provider
  --active-approved --view-url URL             one VIEW intent for a deep link you supplied
Print-only (sends nothing):
  --print-drozer PKG             Drozer commands for the package
  --print-frida PKG              Frida and Objection commands using scripts/frida/*.js

Examples:
  android_device.py --devices
  android_device.py --test-device emulator-5554 --storage com.example.app --logcat com.example.app
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from android_common import FRIDA_DIR, Finding, REPO, checklist_ids, redact, run, snippet, which, write_json  # noqa: E402

SENSITIVE = re.compile(r"password|passwd|token|session|authorization|cookie|cvv|card|ssn|secret|otp", re.I)


def adb(serial: str | None, *args: str, timeout: int = 60) -> tuple[int, str, str]:
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    return run(cmd, timeout=timeout)


def devices() -> list[str]:
    rc, out, _ = run(["adb", "devices"], timeout=30)
    return [l.split()[0] for l in out.splitlines()[1:] if l.strip().endswith("device")]


def require_test_device(args) -> str:
    attached = devices()
    if not args.test_device:
        sys.exit("refusing: give --test-device SERIAL (a device you own; see --devices)")
    if args.test_device not in attached:
        sys.exit(f"refusing: {args.test_device} is not attached (attached: {attached})")
    return args.test_device


def pkg_path(serial: str, pkg: str) -> str | None:
    rc, out, _ = adb(serial, "shell", "pm", "path", pkg)
    m = re.search(r"package:(\S+)", out)
    return m.group(1) if m else None


def permissions(serial: str, pkg: str) -> dict:
    rc, out, _ = adb(serial, "shell", "dumpsys", "package", pkg, timeout=90)
    granted = re.findall(r"(android\.permission\.\S+|com\.\S+\.permission\.\S+): granted=true", out)
    requested = re.findall(r"^\s+(android\.permission\.\S+|\S+\.permission\.\S+)$", out, re.M)
    return {"granted": sorted(set(granted)), "requested_listing_lines": len(requested)}


def components(serial: str, pkg: str) -> dict:
    rc, out, _ = adb(serial, "shell", "dumpsys", "package", pkg, timeout=90)
    filters = sorted(set(re.findall(rf"({re.escape(pkg)}/\S+)\s+filter", out)))
    activities = sorted(set(re.findall(rf"({re.escape(pkg)}/[\w.$]+)", out)))
    return {"components_with_filters": filters, "component_refs": activities[:200]}


def storage(serial: str, pkg: str) -> dict:
    res: dict = {"run_as": None, "dirs": {}}
    denied = False
    for d in ("shared_prefs", "databases", "cache", "files"):
        rc, out, err = adb(serial, "shell", "run-as", pkg, "ls", "-l", d)
        text = (err + out).lower()
        if rc == 0 and out.strip():
            files = [l.split()[-1] for l in out.splitlines() if l and not l.startswith("total")]
            # ls -l: index 7 is the "other" read bit; 'r' there means world-readable
            world = [l.split()[-1] for l in out.splitlines() if len(l) > 9 and l[0] == "-" and l[7] == "r"]
            res["dirs"][d] = {"files": files[:200], "world_readable": world[:50]}
        elif "not debuggable" in text or "unknown package" in text:
            denied = True
    res["run_as"] = True if res["dirs"] else (False if denied else None)
    if not res["dirs"]:
        res["note"] = "run-as needs a debuggable build; otherwise root is needed to read /data/data/<pkg>"
    return res


def logcat(serial: str, pkg: str) -> dict:
    rc, out, _ = adb(serial, "logcat", "-d", "-v", "brief", timeout=60)
    lines = out.splitlines()[-5000:]
    hits = [redact(l.strip())[:200] for l in lines if SENSITIVE.search(l)]
    return {"lines_scanned": len(lines), "sensitive_hits": len(hits), "samples": hits[:20],
            "note": "pid of the package is not filtered; review context before reporting"}


def residue(serial: str, pkg: str) -> dict:
    installed = pkg_path(serial, pkg) is not None
    rc, out, _ = adb(serial, "shell", "ls", "-ld", f"/sdcard/Android/data/{pkg}", "/data/data/" + pkg)
    present = [l for l in out.splitlines() if l.strip() and "No such file" not in l]
    return {"installed": installed, "remaining_paths": present[:10],
            "note": "after uninstall, a surviving data directory is residue; record location only"}


def notifications(serial: str, pkg: str) -> dict:
    rc, out, _ = adb(serial, "shell", "dumpsys", "notification", timeout=60)
    blocks = [b for b in out.split("NotificationRecord") if pkg in b]
    return {"records_for_package": len(blocks), "text_stored": False}


def backup(serial: str, pkg: str, scratch: str) -> dict:
    path = os.path.join(scratch, f"{pkg}.ab")
    print("confirm the backup prompt on the device screen...", file=sys.stderr)
    rc, out, err = adb(serial, "backup", "-noapk", "-f", path, pkg, timeout=900)
    res = {"rc": rc, "file": path, "bytes": os.path.getsize(path) if os.path.exists(path) else 0}
    if res["bytes"]:
        with open(path, "rb") as fh:
            head = fh.read(256)
        lines = head.split(b"\n")
        res["header"] = lines[0].decode(errors="replace")[:32] if lines else ""
        res["encryption"] = lines[3].decode(errors="replace") if len(lines) > 3 else "unknown"
    res["note"] = "contents are not extracted; delete the scratch file after reporting"
    return res


def launch_exported(serial: str, pkg: str, limit: int) -> dict:
    comps = [c for c in components(serial, pkg)["component_refs"] if "/" in c]
    results = []
    for c in comps[:limit]:
        rc, out, err = adb(serial, "shell", "am", "start", "-n", c)
        results.append({"component": c, "rc": rc, "status": "Error" if "Error" in out + err else "launched"})
    return {"attempted": len(results), "results": results}


def provider_query(serial: str, pkg: str, limit: int) -> dict:
    rc, out, _ = adb(serial, "shell", "dumpsys", "package", pkg, timeout=90)
    auths = sorted(set(re.findall(r"authority[=:]\s*([\w.\-]+)", out) + re.findall(r"Provider\{[^}]*?(" + re.escape(pkg) + r"[\w.]*)", out)))
    results = []
    for a in auths[:limit]:
        rc, out, err = adb(serial, "shell", "content", "query", "--uri", f"content://{a}/")
        results.append({"authority": a, "rc": rc, "rows_or_error": snippet((out or err), 160)})
    return {"authorities_found": auths[:limit], "results": results}


def view_url(serial: str, url: str) -> dict:
    rc, out, err = adb(serial, "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", url)
    return {"rc": rc, "output": snippet(out + err, 200)}


def drozer_commands(pkg: str) -> list[str]:
    return [
        "adb forward tcp:31415 tcp:31415   # Drozer agent must be running on the device",
        "drozer console connect",
        f"run app.package.info -a {pkg}",
        f"run app.package.attacksurface {pkg}",
        f"run app.activity.info -a {pkg} -u",
        f"run app.provider.info -a {pkg}",
        f"run app.service.info -a {pkg}",
        f"run app.broadcast.info -a {pkg}",
        "# run app.activity.start --component <pkg> <activity>   (authorized-only: changes app state)",
        "# run scanner.provider.injection -a <pkg>                (authorized-only: sends crafted queries)",
    ]


def frida_commands(pkg: str) -> list[str]:
    scripts = sorted(f for f in os.listdir(FRIDA_DIR) if f.endswith(".js")) if os.path.isdir(FRIDA_DIR) else []
    cmds = [f"frida -U -f {pkg} -l {os.path.join(FRIDA_DIR, s)} --no-pause   # {s}" for s in scripts]
    cmds.append(f"objection -g {pkg} explore   # then: android sslpinning disable / android root disable")
    cmds.append("# Run one hook at a time against your own build, with approval.")
    return cmds


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test-device")
    ap.add_argument("--devices", action="store_true")
    ap.add_argument("--permissions")
    ap.add_argument("--components")
    ap.add_argument("--storage")
    ap.add_argument("--logcat")
    ap.add_argument("--residue")
    ap.add_argument("--notifications")
    ap.add_argument("--backup-approved", metavar="PKG")
    ap.add_argument("--active-approved", action="store_true")
    ap.add_argument("--launch-exported", metavar="PKG")
    ap.add_argument("--provider-query", metavar="PKG")
    ap.add_argument("--view-url")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--print-drozer", metavar="PKG")
    ap.add_argument("--print-frida", metavar="PKG")
    ap.add_argument("--out", help="JSON output (default artifacts/<pkg>/android-device.json)")
    args = ap.parse_args()

    if not (args.print_drozer or args.print_frida) and not which("adb"):
        sys.exit("adb not installed (see setup.sh)")
    if args.devices:
        print("\n".join(devices()) or "no devices attached")
        if not any([args.permissions, args.components, args.storage, args.logcat, args.residue, args.notifications,
                    args.backup_approved, args.launch_exported, args.provider_query, args.view_url]):
            return 0
    if args.print_drozer:
        print("\n".join(drozer_commands(args.print_drozer)))
        return 0
    if args.print_frida:
        print("\n".join(frida_commands(args.print_frida)))
        return 0

    serial = require_test_device(args)
    pkg = args.storage or args.logcat or args.permissions or args.components or args.residue or \
        args.notifications or args.backup_approved or args.launch_exported or args.provider_query
    report: dict = {"device": serial, "package": pkg, "checks": {}}
    findings: list[Finding] = []

    if args.permissions:
        report["checks"]["permissions"] = permissions(serial, args.permissions)
    if args.components:
        report["checks"]["components"] = components(serial, args.components)
    if args.storage:
        s = storage(serial, args.storage)
        report["checks"]["storage"] = s
        for d, v in s.get("dirs", {}).items():
            if v["world_readable"]:
                findings.append(Finding("device-world-readable", "high", f"world-readable files in {d}", args.storage,
                                        ", ".join(v["world_readable"][:5]), checklist_ids("world-readable")))
    if args.logcat:
        lc = logcat(serial, args.logcat)
        report["checks"]["logcat"] = lc
        if lc["sensitive_hits"]:
            findings.append(Finding("logcat-sensitive", "medium", "sensitive-looking text in logcat buffer", args.logcat,
                                    f"{lc['sensitive_hits']} lines (redacted)", checklist_ids("logcat")))
    if args.residue:
        r = residue(serial, args.residue)
        report["checks"]["residue"] = r
        if r["remaining_paths"] and not r["installed"]:
            findings.append(Finding("residue", "low", "app data remains after uninstall", args.residue,
                                    "; ".join(r["remaining_paths"][:3]), checklist_ids("data recovery")))
    if args.notifications:
        report["checks"]["notifications"] = notifications(serial, args.notifications)
    if args.backup_approved:
        if not args.active_approved:
            sys.exit("backup needs --active-approved --backup-approved PKG (written approval for this check)")
        scratch = tempfile.mkdtemp(prefix="pkg-backup-", dir=os.path.join(REPO, "artifacts"))
        b = backup(serial, args.backup_approved, scratch)
        report["checks"]["backup"] = b
        if b.get("bytes"):
            findings.append(Finding("adb-backup", "high" if b.get("encryption") == "none" else "medium",
                                    "app data extractable with adb backup", args.backup_approved,
                                    f"encryption={b.get('encryption')}", checklist_ids("adb backup")))
    if args.active_approved:
        if args.launch_exported:
            report["checks"]["launch_exported"] = launch_exported(serial, args.launch_exported, args.limit)
        if args.provider_query:
            report["checks"]["provider_query"] = provider_query(serial, args.provider_query, args.limit)
        if args.view_url:
            report["checks"]["view_url"] = view_url(serial, args.view_url)
    elif args.launch_exported or args.provider_query or args.view_url:
        sys.exit("active checks need --active-approved (written approval for each check)")

    report["findings"] = [f.as_dict() for f in findings]
    out = args.out or os.path.join(REPO, "artifacts", pkg or "device", "android-device.json")
    write_json(out, report)
    print(json.dumps(report["checks"], indent=2, default=str)[:4000])
    print(f"findings: {len(findings)}  report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
