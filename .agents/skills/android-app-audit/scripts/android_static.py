#!/usr/bin/env python3
"""Static analysis driver for an authorized Android APK.

Pipeline (each step is skipped with a recorded reason if its tool or input is missing):
  1. Verify the APK is a zip with AndroidManifest.xml and record its SHA-256. Nothing is executed.
  2. apktool d   -> decoded resources and manifest        (Kali: apktool)
  3. jadx        -> Java sources                          (Kali: jadx)
  4. aapt2/aapt  -> package, SDK levels, permissions      (apt: aapt)
  5. apkid       -> packer and obfuscator signatures      (pip: apkid)
  6. apkleaks    -> secret candidates                     (pip: apkleaks)
  7. mobsfscan   -> SAST rules over decompiled code       (pip: mobsfscan)
  8. manifest_audit, code_rules -> checklist findings with file:line
  9. SDK inventory and obfuscation estimate from the jadx package names

Untrusted input: the APK is copied into a fresh work directory, and every tool is called with
the file path as an argument. Python helpers are run with -I by android_audit.sh.

Usage:
  android_static.py --apk app.apk --out artifacts/<pkg>/android-static.json
  android_static.py --decoded DIR --jadx DIR --out ...      # reuse earlier output, no tools needed
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from android_common import REPO, run, which, write_json  # noqa: E402
import code_rules  # noqa: E402
import manifest_audit  # noqa: E402

SDK_PREFIXES = {
    "com.google.firebase": "Firebase", "com.google.android.gms": "Google Play services", "com.google.android.material": "Material",
    "com.facebook": "Facebook SDK", "com.google.android.libraries.places": "Places", "com.mixpanel": "Mixpanel",
    "com.amplitude": "Amplitude", "com.segment": "Segment", "io.branch": "Branch", "com.appsflyer": "AppsFlyer",
    "com.adjust": "Adjust", "com.clevertap": "CleverTap", "com.leanplum": "Leanplum", "com.braze": "Braze",
    "com.onesignal": "OneSignal", "com.pusher": "Pusher", "com.pubnub": "PubNub", "io.ably": "Ably", "com.twilio": "Twilio",
    "com.stripe": "Stripe", "com.paypal": "PayPal", "com.braintreepayments": "Braintree", "com.razorpay": "Razorpay",
    "com.google.android.gms.ads": "AdMob", "com.mopub": "MoPub", "com.ironsource": "IronSource", "com.unity3d.ads": "Unity Ads",
    "com.vungle": "Vungle", "com.chartboost": "Chartboost", "com.applovin": "AppLovin", "com.inmobi": "InMobi",
    "com.smaato": "Smaato", "com.fyber": "Fyber", "okhttp3": "OkHttp", "retrofit2": "Retrofit", "com.bumptech.glide": "Glide",
    "com.squareup.picasso": "Picasso", "coil": "Coil", "androidx.room": "Room", "net.sqlcipher": "SQLCipher",
    "io.realm": "Realm", "io.objectbox": "ObjectBox", "androidx.security.crypto": "Jetpack Security",
    "androidx.work": "WorkManager", "com.amazonaws": "AWS SDK", "com.microsoft.azure": "Azure SDK", "io.sentry": "Sentry",
    "com.bugsnag": "Bugsnag", "com.crashlytics": "Crashlytics", "timber.log": "Timber",
}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_apk(path: str) -> dict:
    info = {"path": os.path.abspath(path), "sha256": sha256(path), "size": os.path.getsize(path)}
    if not zipfile.is_zipfile(path):
        info["valid_zip"] = False
        return info
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
    info["valid_zip"] = True
    info["has_manifest"] = "AndroidManifest.xml" in names
    info["dex_files"] = sorted(n for n in names if n.endswith(".dex"))
    info["native_libs"] = sorted({n.split("/")[2] for n in names if n.startswith("lib/") and n.count("/") >= 2})[:20]
    info["entries"] = len(names)
    return info


def decode(apk: str, out_dir: str, report: dict) -> str | None:
    d = os.path.join(out_dir, "apktool")
    if which("apktool"):
        rc, _, err = run(["apktool", "d", "-f", "-q", "-o", d, apk], timeout=900)
        report["tools"]["apktool"] = {"status": "ok" if rc == 0 else f"exit {rc}", "stderr": err[-400:]}
        if rc == 0 and os.path.isdir(d):
            return d
    else:
        report["tools"]["apktool"] = {"status": "skipped", "reason": "apktool not installed (see setup.sh)"}
    return None


def decompile(apk: str, out_dir: str, report: dict) -> str | None:
    d = os.path.join(out_dir, "jadx")
    if which("jadx"):
        rc, _, err = run(["jadx", "-d", d, "--no-res", "-j", "2", apk], timeout=1800)
        report["tools"]["jadx"] = {"status": "ok" if rc in (0, 1) else f"exit {rc}", "stderr": err[-400:]}
        if os.path.isdir(d):
            return d
    else:
        report["tools"]["jadx"] = {"status": "skipped", "reason": "jadx not installed (see setup.sh)"}
    return None


def aapt_badging(apk: str, report: dict) -> dict:
    tool = which("aapt2", "aapt")
    if not tool:
        report["tools"]["aapt"] = {"status": "skipped", "reason": "aapt/aapt2 not installed"}
        return {}
    cmd = [tool, "dump", "badging", apk] if tool.endswith("aapt2") else [tool, "dump", "badging", apk]
    rc, out, err = run(cmd, timeout=120)
    report["tools"]["aapt"] = {"status": "ok" if rc == 0 else f"exit {rc}", "stderr": err[-300:]}
    info = {}
    m = re.search(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'", out)
    if m:
        info.update(package=m.group(1), versionCode=m.group(2), versionName=m.group(3))
    for key in ("sdkVersion", "targetSdkVersion"):
        m = re.search(rf"{key}:'(\d+)'", out)
        if m:
            info[key] = int(m.group(1))
    info["launchable"] = re.findall(r"launchable-activity: name='([^']+)'", out)
    return info


def apkid(apk: str, report: dict) -> list:
    if not which("apkid"):
        report["tools"]["apkid"] = {"status": "skipped", "reason": "apkid not installed"}
        return []
    rc, out, err = run(["apkid", "-j", apk], timeout=300)
    report["tools"]["apkid"] = {"status": "ok" if rc == 0 else f"exit {rc}", "stderr": err[-300:]}
    try:
        data = json.loads(out)
        return data.get("files", data)
    except json.JSONDecodeError:
        return []


def apkleaks(apk: str, out_dir: str, report: dict) -> list:
    if not which("apkleaks"):
        report["tools"]["apkleaks"] = {"status": "skipped", "reason": "apkleaks not installed (pip)"}
        return []
    outf = os.path.join(out_dir, "apkleaks.json")
    rc, _, err = run(["apkleaks", "-f", apk, "-o", outf], timeout=900)
    report["tools"]["apkleaks"] = {"status": "ok" if rc == 0 else f"exit {rc}", "stderr": err[-300:]}
    if os.path.exists(outf):
        try:
            with open(outf, encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, list) else data.get("results", [])
        except (OSError, json.JSONDecodeError):
            return []
    return []


def mobsfscan(jadx_dir: str, out_dir: str, report: dict) -> dict:
    if not which("mobsfscan"):
        report["tools"]["mobsfscan"] = {"status": "skipped", "reason": "mobsfscan not installed (pip)"}
        return {}
    outf = os.path.join(out_dir, "mobsfscan.json")
    rc, _, err = run(["mobsfscan", "--json", "-o", outf, jadx_dir], timeout=900)
    report["tools"]["mobsfscan"] = {"status": "ok" if rc == 0 else f"exit {rc}", "stderr": err[-300:]}
    if os.path.exists(outf):
        try:
            with open(outf, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def sdk_inventory(jadx_dir: str | None, apktool_dir: str | None) -> dict:
    counts: Counter = Counter()
    versions = []
    if jadx_dir and os.path.isdir(jadx_dir):
        for dp, dn, fn in os.walk(jadx_dir):
            if os.sep + "sources" not in dp and not dp.endswith("sources"):
                continue
            for f in fn:
                if f.endswith(".java") or f.endswith(".kt"):
                    rel = os.path.relpath(os.path.join(dp, f), jadx_dir).replace(os.sep, ".")
                    for prefix in SDK_PREFIXES:
                        if rel.split("sources.", 1)[-1].startswith(prefix):
                            counts[SDK_PREFIXES[prefix]] += 1
                            break
    for root in (apktool_dir, jadx_dir):
        if not root:
            continue
        for dp, dn, fn in os.walk(root):
            for f in fn:
                if f == "pom.properties" or f.endswith(".version"):
                    p = os.path.join(dp, f)
                    try:
                        text = open(p, encoding="utf-8", errors="replace").read()
                    except OSError:
                        continue
                    m = re.search(r"version\s*[=:]\s*([^\s]+)", text)
                    if m:
                        versions.append({"file": os.path.relpath(p, root), "version": m.group(1)})
    return {"sdk_class_hits": dict(counts.most_common()), "version_files": versions[:200]}


def obfuscation(jadx_dir: str | None) -> dict:
    if not jadx_dir or not os.path.isdir(jadx_dir):
        return {"status": "skipped"}
    names = []
    for dp, dn, fn in os.walk(jadx_dir):
        for f in fn:
            if f.endswith(".java"):
                names.append(f[:-5])
    if not names:
        return {"status": "no sources"}
    short = sum(1 for n in names if len(n) <= 2)
    return {"classes": len(names), "short_name_classes": short, "short_name_ratio": round(short / len(names), 3),
            "note": "high ratio suggests R8/ProGuard renaming; low ratio means little obfuscation"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apk")
    ap.add_argument("--decoded", help="existing apktool output directory")
    ap.add_argument("--jadx", help="existing jadx output directory")
    ap.add_argument("--out", required=True, help="JSON report path")
    ap.add_argument("--work", help="work directory (default: a fresh temp dir under artifacts/)")
    args = ap.parse_args()
    if not args.apk and not (args.decoded or args.jadx):
        ap.error("give --apk, or --decoded/--jadx for existing output")

    report: dict = {"tools": {}, "findings": [], "inputs": {}}
    work = None
    if args.apk:
        os.makedirs(os.path.join(REPO, "artifacts"), exist_ok=True)
        work = args.work or tempfile.mkdtemp(prefix="apk-static-", dir=os.path.join(REPO, "artifacts"))
        os.makedirs(work, exist_ok=True)
    report["work_dir"] = work

    decoded, jadx_dir = args.decoded, args.jadx
    if args.apk:
        report["inputs"]["apk"] = verify_apk(args.apk)
        if not report["inputs"]["apk"].get("valid_zip"):
            report["error"] = "not a valid zip/APK"
            write_json(args.out, report)
            print("not a valid APK; see", args.out)
            return 2
        decoded = decoded or decode(args.apk, work, report)  # noqa: E501
        jadx_dir = jadx_dir or decompile(args.apk, work, report)
        report["aapt"] = aapt_badging(args.apk, report)
        report["apkid"] = apkid(args.apk, report)
        report["apkleaks"] = apkleaks(args.apk, work, report)
        report["mobsfscan"] = mobsfscan(jadx_dir, work, report) if jadx_dir else {}

    manifest = None
    for cand in (os.path.join(decoded or "", "AndroidManifest.xml"), os.path.join(jadx_dir or "", "resources", "AndroidManifest.xml")):
        if cand and os.path.isfile(cand):
            manifest = cand
            break
    res_dir = os.path.join(decoded, "res") if decoded else None
    if manifest:
        mres = manifest_audit.audit(manifest, res_dir if res_dir and os.path.isdir(res_dir) else None)
        report["manifest"] = {k: v for k, v in mres.items() if k != "findings"}
        report["findings"] += mres["findings"]
    else:
        report["manifest"] = {"status": "no AndroidManifest.xml found; run apktool or pass --decoded"}

    roots_src = [r for r in (jadx_dir and os.path.join(jadx_dir, "sources"), jadx_dir) if r and os.path.isdir(r)][:1]
    roots_res = [r for r in (decoded,) if r and os.path.isdir(r)]
    cf, stats = code_rules.scan(roots_src + roots_res)
    report["findings"] += [f.as_dict() for f in cf]
    report["code_scan"] = stats
    report["sdk"] = sdk_inventory(jadx_dir, decoded)
    report["obfuscation"] = obfuscation(os.path.join(jadx_dir, "sources") if jadx_dir and os.path.isdir(os.path.join(jadx_dir, "sources")) else jadx_dir)

    report["findings"].sort(key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 9), f["rule"]))
    write_json(args.out, report)
    counts = Counter(f["severity"] for f in report["findings"])
    print(f"findings: {len(report['findings'])} {dict(counts)}  report: {args.out}")
    for name, t in report["tools"].items():
        print(f"  tool {name}: {t['status']}" + (f" ({t['reason']})" if "reason" in t else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
