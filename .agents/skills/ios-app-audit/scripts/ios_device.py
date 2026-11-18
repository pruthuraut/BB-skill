#!/usr/bin/env python3
"""On-device helpers for an iOS app on a test device you own (libimobiledevice + SSH).

Every mode except --devices and the print-only helpers needs --test-device UDID, and the UDID must be
attached (idevice_id -l). Modes that change device state or drive the app need --active-approved.
Backups need --backup-approved. Container pulls and keyboard cache reads need SSH to a jailbroken
test device (`iproxy 2222 22` then --ssh root@127.0.0.1 --ssh-port 2222, key-based login).

Read-only:
  --devices                       attached devices with model and iOS version
  --apps                          installed user apps (ideviceinstaller)
  --syslog NAME --seconds N       capture N seconds of syslog for a process; report sensitive hits (redacted)
  --crashlogs NAME                copy crash reports (kept on the device) and keep only NAME's reports
  --find-container BUNDLE         data, group and bundle container paths (SSH)
  --pull-container BUNDLE         tar the data and app group containers over SSH into --dest (read-only on device)
  --keyboard-cache --marker M     pull the keyboard cache, search for the marker, delete the local copy (SSH)
Approval-gated:
  --backup-approved               idevicebackup2 full backup into --dest (confirm on device; encrypted backups need your password)
  --active-approved --open-url U  open one URL in the app (SSH uiopen, or --via simctl on a simulator)
Print-only (send nothing):
  --print-frida BUNDLE            Frida and Objection commands for every bundled hook
  --print-decrypt BUNDLE          commands to decrypt your own authorized install for static analysis

Examples:
  ios_device.py --devices
  ios_device.py --test-device UDID --syslog MyApp --seconds 60 --marker 'Pw!mark-7731'
  ios_device.py --test-device UDID --ssh root@127.0.0.1 --ssh-port 2222 --pull-container com.x --dest artifacts/com.x/container
"""
from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ios_common import ARTIFACTS, FRIDA_DIR, find_secrets, redact, run, snippet, which, write_json  # noqa: E402

SENSITIVE_LINE = re.compile(r"(?i)password|passwd|token|bearer|authorization|cookie|session|secret|cvv|card ?number|ssn|otp|api[_-]?key")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9.\-]{3,200}$")


def tool(name: str) -> str:
    p = which(name)
    if not p:
        sys.exit(f"{name} not found: install libimobiledevice-utils / ideviceinstaller (apt) or see setup.sh")
    return p


def devices() -> list[str]:
    p = which("idevice_id")
    if not p:
        return []
    rc, out, _ = run([p, "-l"], timeout=20)
    return [l.strip() for l in out.splitlines() if l.strip()]


def require_device(args) -> str:
    if not args.test_device:
        sys.exit("refusing: give --test-device UDID (a device you own; see --devices)")
    if args.via != "simctl" and args.test_device not in devices():
        sys.exit(f"refusing: {args.test_device} is not attached (attached: {devices()})")
    return args.test_device


def check_bundle(b: str) -> str:
    if not BUNDLE_RE.match(b or ""):
        sys.exit(f"refusing: '{b}' is not a bundle id")
    return b


def ssh_base(args) -> list[str]:
    if not args.ssh:
        sys.exit("this mode needs --ssh user@host (jailbroken test device; use iproxy 2222 22 for USB)")
    return [tool("ssh"), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(args.ssh_port), args.ssh]


def ssh(args, command: str, timeout: int = 120) -> tuple[int, str, str]:
    return run(ssh_base(args) + [command], timeout=timeout)


# --------------------------------------------------------------------------- read-only
def list_devices() -> None:
    info = which("ideviceinfo")
    for udid in devices():
        line = udid
        if info:
            vals = []
            for k in ("DeviceName", "ProductType", "ProductVersion"):
                rc, out, _ = run([info, "-u", udid, "-k", k], timeout=20)
                vals.append(out.strip())
            line += "  " + "  ".join(vals)
        print(line)
    if not devices():
        print("no devices (is usbmuxd running and the device trusted?)")


def list_apps(udid: str) -> None:
    p = tool("ideviceinstaller")
    rc, out, err = run([p, "-u", udid, "list", "--user"], timeout=60)
    if rc != 0:
        rc, out, err = run([p, "-u", udid, "-l"], timeout=60)
    print(out or err)


def capture_syslog(udid: str, name: str, seconds: int, markers: list[str], out_path: str) -> dict:
    p = tool("idevicesyslog")
    cmd = [p, "-u", udid]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    lines, hits = 0, []
    end = time.time() + seconds
    try:
        while time.time() < end:
            line = proc.stdout.readline()
            if not line:
                break
            if name and name not in line:
                continue
            lines += 1
            marker = [m for m in markers if m and m in line]
            if marker or SENSITIVE_LINE.search(line) or find_secrets(line, "syslog", limit=1):
                hits.append({"marker": bool(marker), "line": snippet(line.replace(marker[0], "<MARKER>") if marker else line, 300)})
    finally:
        proc.terminate()
    rep = {"process": name, "seconds": seconds, "lines": lines, "hits": hits[:300],
           "marker_hits": sum(1 for h in hits if h["marker"])}
    write_json(out_path, rep)
    print(f"syslog: {lines} lines from {name}, {len(hits)} sensitive hits ({rep['marker_hits']} with the marker) -> {out_path}")
    return rep


def crashlogs(udid: str, name: str, dest: str) -> None:
    p = tool("idevicecrashreport")
    tmp = tempfile.mkdtemp(prefix="ioscrash-")
    try:
        run([p, "-u", udid, "-k", "-e", tmp], timeout=600)
        os.makedirs(dest, exist_ok=True)
        kept = 0
        for dp, dn, fn in os.walk(tmp):
            for f in fn:
                if name.lower() in f.lower():
                    shutil.copy2(os.path.join(dp, f), os.path.join(dest, f))
                    kept += 1
        print(f"kept {kept} crash reports for {name} in {dest} (others discarded). Scan with: "
              f"ios_container_audit.py --logs {dest} --marker ...")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def find_container(args, bundle: str) -> dict:
    q = shlex.quote(bundle)
    res = {}
    for kind, glob_ in (("data", "/var/mobile/Containers/Data/Application/*/.com.apple.mobile_container_manager.metadata.plist"),
                        ("group", "/var/mobile/Containers/Shared/AppGroup/*/.com.apple.mobile_container_manager.metadata.plist"),
                        ("plugin", "/var/mobile/Containers/Data/PluginKitPlugin/*/.com.apple.mobile_container_manager.metadata.plist")):
        rc, out, err = ssh(args, f"grep -l -a -F {q} {glob_} 2>/dev/null", timeout=60)
        res[kind] = [os.path.dirname(l.strip()) for l in out.splitlines() if l.strip()]
    rc, out, _ = ssh(args, f"grep -l -a -F {q} /var/containers/Bundle/Application/*/*.app/Info.plist 2>/dev/null", timeout=60)
    res["bundle"] = [os.path.dirname(l.strip()) for l in out.splitlines() if l.strip()]
    return res


def safe_untar(stream, dest: str) -> int:
    n = 0
    dest_real = os.path.realpath(dest)
    with tarfile.open(fileobj=stream, mode="r|") as tf:
        for m in tf:
            name = m.name.lstrip("./")
            if not name or m.issym() or m.islnk() or m.isdev() or ".." in name.split("/") or name.startswith("/"):
                continue
            target = os.path.realpath(os.path.join(dest, name))
            if not target.startswith(dest_real + os.sep):
                continue
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            if not m.isfile():
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, m.mode & 0o777)
            os.utime(target, (m.mtime, m.mtime))
            n += 1
    return n


def pull_dir(args, remote: str, dest: str) -> int:
    os.makedirs(dest, exist_ok=True)
    cmd = ssh_base(args) + [f"tar -C {shlex.quote(remote)} -cf - ."]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        n = safe_untar(proc.stdout, dest)
    finally:
        proc.wait(timeout=600)
    return n


def pull_container(args, bundle: str, dest: str) -> None:
    paths = find_container(args, bundle)
    if not paths["data"]:
        sys.exit(f"no data container found for {bundle}")
    n = pull_dir(args, paths["data"][0], os.path.join(dest, "data"))
    print(f"data container {paths['data'][0]} -> {dest}/data ({n} files)")
    for g in paths["group"]:
        gd = os.path.join(dest, "groups", os.path.basename(g))
        print(f"group container {g} -> {gd} ({pull_dir(args, g, gd)} files)")
    for p in paths["plugin"]:
        pd = os.path.join(dest, "plugins", os.path.basename(p))
        print(f"extension container {p} -> {pd} ({pull_dir(args, p, pd)} files)")
    write_json(os.path.join(dest, "container-paths.json"), paths)
    print(f"next: ios_container_audit.py --container {dest}/data " + " ".join(f"--group {dest}/groups/{os.path.basename(g)}" for g in paths["group"]))


def keyboard_cache(args, markers: list[str]) -> None:
    if not markers:
        sys.exit("--keyboard-cache needs --marker (only marker presence is reported)")
    tmp = tempfile.mkdtemp(prefix="ioskbd-")
    try:
        n = pull_dir(args, "/var/mobile/Library/Keyboard", tmp)
        found = []
        for dp, dn, fn in os.walk(tmp):
            for f in fn:
                with open(os.path.join(dp, f), "rb") as fh:
                    data = fh.read()
                for m in markers:
                    if m.encode() in data or m.encode("utf-16-le") in data:
                        found.append(f)
        print(f"keyboard cache: {n} files read, marker found in: {sorted(set(found)) or 'none'} (local copy deleted)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- gated
def backup(udid: str, dest: str) -> None:
    p = tool("idevicebackup2")
    os.makedirs(dest, exist_ok=True)
    print("starting backup; confirm on the device if prompted. Encrypted backups need your own backup password to decrypt.")
    rc, out, err = run([p, "-u", udid, "backup", "--full", dest], timeout=7200)
    print(out[-2000:] or err[-2000:])
    print(f"next: ios_container_audit.py --backup {dest}/{udid} --bundle BUNDLE")


def open_url(args, url: str) -> None:
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", url) or "\n" in url:
        sys.exit("refusing: not a URL")
    if args.via == "simctl":
        rc, out, err = run([tool("xcrun"), "simctl", "openurl", args.test_device or "booted", url], timeout=30)
    else:
        rc, out, err = ssh(args, f"uiopen {shlex.quote(url)}", timeout=30)
    print(f"opened ({rc}): {url}" + (f"  {err.strip()[:200]}" if rc else ""))


# --------------------------------------------------------------------------- print-only
FRIDA_HOOKS = [
    ("jailbreak_detect_trace.js", "trace", "which jailbreak checks run at launch"),
    ("antidebug_trace.js", "trace", "ptrace, sysctl P_TRACED, getppid, isatty (set BYPASS=true only with approval)"),
    ("keychain_dump.js", "trace", "own keychain items with accessibility class and access control; values hashed"),
    ("userdefaults_dump.js", "trace", "NSUserDefaults keys with redacted values"),
    ("file_protection.js", "trace", "protection class of every container file (feed to --protection-json)"),
    ("url_handler_trace.js", "trace", "URL scheme, universal link and outbound openURL calls"),
    ("pasteboard_monitor.js", "trace", "pasteboard writes and reads with options"),
    ("crypto_trace.js", "trace", "CCCrypt algorithm, mode, IV reuse, PBKDF2 rounds"),
    ("network_trace.js", "trace", "NSURLSession requests (names of sensitive params, cleartext)"),
    ("webview_inspect.js", "trace", "live WKWebView configuration"),
    ("sqlite_trace.js", "trace", "SQL text and NSPredicate format strings"),
    ("notification_trace.js", "trace", "notification categories, action options, payload keys"),
    ("ipc_trace.js", "trace", "app groups, Darwin notifications, user activities, Spotlight, share sheet"),
    ("ui_input_audit.js", "trace", "text fields: secureTextEntry, autocorrection, accessibility value"),
    ("storekit_trace.js", "trace", "StoreKit payments and receipt access"),
    ("memory_marker_scan.js", "trace", "search process memory for a test marker (-P '{\"markers\":[\"...\"]}')"),
    ("biometric_trace.js", "approval", "LAContext evaluatePolicy; BYPASS=true tests a boolean-only gate"),
    ("jailbreak_bypass.js", "approval", "hide jailbreak paths and schemes"),
    ("ssl_pinning_bypass.js", "approval", "disable trust evaluation for Burp interception"),
]


def print_frida(bundle: str) -> None:
    print(f"# Frida hooks for {bundle} (run one at a time; 'approval' hooks need written approval)")
    for f, kind, what in FRIDA_HOOKS:
        print(f"frida -U -f {bundle} -l {os.path.join(FRIDA_DIR, f)}    # [{kind}] {what}")
    print("\n# Objection (same rules)")
    for c in ("ios info binary", "ios keychain dump --json artifacts/keychain.json", "ios nsuserdefaults get",
              "ios cookies get --json", "ios pasteboard monitor", "ios plist cat <file>", "env",
              "ios sslpinning disable    # approval", "ios jailbreak disable    # approval",
              "ios ui biometrics_bypass    # approval"):
        print(f"objection -g {bundle} explore -s \"{c}\"")
    print("\n# Burp: set the test device Wi-Fi proxy to your Burp listener and install the Burp CA (Settings > General > About > Certificate Trust Settings)")


def print_decrypt(bundle: str) -> None:
    print(f"# Decrypt your own authorized install of {bundle} for static analysis (jailbroken test device):")
    print(f"bagbak -o artifacts/{bundle}/ {bundle}                    # npm i -g bagbak (frida based)")
    print(f"python3 dump.py {bundle}                                    # frida-ios-dump (AloneMonkey)")
    print(f"ipatool download -b {bundle} -o artifacts/{bundle}/         # encrypted App Store IPA, for metadata only")
    print("# then: ios_static.py --ipa <decrypted>.ipa")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test-device")
    ap.add_argument("--via", choices=["ssh", "simctl"], default="ssh", help="how --open-url reaches the app")
    ap.add_argument("--ssh", help="user@host for a jailbroken test device")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--devices", action="store_true")
    ap.add_argument("--apps", action="store_true")
    ap.add_argument("--syslog", metavar="PROCESS")
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--crashlogs", metavar="PROCESS")
    ap.add_argument("--find-container", metavar="BUNDLE")
    ap.add_argument("--pull-container", metavar="BUNDLE")
    ap.add_argument("--keyboard-cache", action="store_true")
    ap.add_argument("--marker", action="append", default=[])
    ap.add_argument("--dest")
    ap.add_argument("--backup-approved", action="store_true")
    ap.add_argument("--active-approved", action="store_true")
    ap.add_argument("--open-url")
    ap.add_argument("--print-frida", metavar="BUNDLE")
    ap.add_argument("--print-decrypt", metavar="BUNDLE")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.devices:
        list_devices()
        return 0
    if args.print_frida:
        print_frida(check_bundle(args.print_frida))
        return 0
    if args.print_decrypt:
        print_decrypt(check_bundle(args.print_decrypt))
        return 0

    udid = require_device(args)
    if args.apps:
        list_apps(udid)
    if args.syslog:
        capture_syslog(udid, args.syslog, args.seconds, args.marker,
                       args.out or os.path.join(ARTIFACTS, "ios-device", f"syslog-{args.syslog}.json"))
    if args.crashlogs:
        crashlogs(udid, args.crashlogs, args.dest or os.path.join(ARTIFACTS, "ios-device", f"crash-{args.crashlogs}"))
    if args.find_container:
        print(find_container(args, check_bundle(args.find_container)))
    if args.pull_container:
        b = check_bundle(args.pull_container)
        pull_container(args, b, args.dest or os.path.join(ARTIFACTS, b, "container"))
    if args.keyboard_cache:
        keyboard_cache(args, args.marker)
    if args.backup_approved:
        backup(udid, args.dest or os.path.join(ARTIFACTS, "ios-device", "backup"))
    if args.open_url:
        if not args.active_approved:
            sys.exit("refusing: --open-url needs --active-approved (approval for this deep link check)")
        open_url(args, args.open_url)
    return 0


if __name__ == "__main__":
    sys.exit(main())
