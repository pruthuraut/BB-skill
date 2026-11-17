#!/usr/bin/env python3
"""App Link verification probe for an authorized Android app (read-only, scope-gated per host).

For each web host declared with an http/https VIEW + BROWSABLE intent filter in the decoded
manifest, the probe fetches https://<host>/.well-known/assetlinks.json (one GET) and checks that:
  - the file exists and parses,
  - a delegate or handle_all_urls statement names this app's package,
  - the signing certificate SHA-256 (from --cert-sha256 or apksigner) is listed.
It also prints (never runs) the adb commands that exercise each declared link on a test device.

Every host must pass scripts/scope_check.sh. Hosts outside scope are skipped and reported.

Usage:
  deeplink_probe.py --manifest decoded/AndroidManifest.xml --workspace DIR --program NAME \
      [--cert-sha256 AA:BB:...] [--print-adb] [--out FILE]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from android_common import Finding, REPO, checklist_ids, run, scope_ok, which, write_json  # noqa: E402
import manifest_audit  # noqa: E402

UA = "Mozilla/5.0 (compatible; android-audit-probe/1.0)"


def web_links(manifest: str) -> tuple[str, list[dict]]:
    data = manifest_audit.audit(manifest)
    pkg = data.get("package", "")
    links = []
    for comp in data.get("components", []):
        for f in comp.get("filters", []):
            schemes = {d.get("scheme") for d in f.get("data", []) if d.get("scheme")}
            if schemes & {"http", "https"}:
                for d in f.get("data", []):
                    if d.get("host"):
                        links.append({"component": comp["name"], "host": d["host"], "scheme": d.get("scheme"),
                                      "pathPrefix": d.get("pathPrefix") or d.get("path") or "/",
                                      "autoVerify": f.get("autoVerify", False)})
    return pkg, links


TEST_BASE = os.environ.get("DEEPLINK_PROBE_BASE", "").rstrip("/")  # test harness only


def fetch_assetlinks(host: str) -> dict:
    url = f"https://{host}/.well-known/assetlinks.json"
    if TEST_BASE:
        url = TEST_BASE + "/" + host + "/.well-known/assetlinks.json"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            body = r.read(200_000).decode("utf-8", "replace")
            return {"status": r.status, "body": body}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": ""}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"status": None, "body": "", "error": str(e)[:160]}


def apk_cert(apk: str) -> str | None:
    tool = which("apksigner")
    if not tool or not apk:
        return None
    rc, out, err = run([tool, "verify", "--print-certs", apk], timeout=60)
    m = re.search(r"certificate SHA-256 digest:\s*([0-9a-f]{64})", out + err)
    return m.group(1).upper() if m else None


def norm_fp(fp: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", fp).upper()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--apk", help="APK to read the signing certificate from (needs apksigner)")
    ap.add_argument("--cert-sha256", help="signing certificate SHA-256 (hex, colons allowed)")
    ap.add_argument("--workspace")
    ap.add_argument("--program")
    ap.add_argument("--print-adb", action="store_true", help="print adb commands for each link (sends nothing)")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--out", default=os.path.join(REPO, "artifacts", "deeplinks", "deeplink-probe.json"))
    args = ap.parse_args()

    pkg, links = web_links(args.manifest)
    if not links:
        print("no http(s) VIEW/BROWSABLE filters with a host in this manifest")
    cert = norm_fp(args.cert_sha256) if args.cert_sha256 else (apk_cert(args.apk) if args.apk else None)

    if args.print_adb:
        for l in links:
            path = l["pathPrefix"].rstrip("*") or "/"
            print(f'adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "{l["scheme"]}://{l["host"]}{path}"  # {l["component"]}')
        return 0

    hosts: dict[str, dict] = {}
    findings: list[Finding] = []
    for l in links:
        hosts.setdefault(l["host"], {"components": [], "autoVerify": False})
        hosts[l["host"]]["components"].append(l["component"])
        hosts[l["host"]]["autoVerify"] = hosts[l["host"]]["autoVerify"] or l["autoVerify"]

    results = {}
    for host, info in hosts.items():
        ok, msg = scope_ok(host, args.workspace, args.program)
        if not ok:
            results[host] = {"skipped": msg}
            continue
        r = fetch_assetlinks(host)
        res = {"status": r["status"], "autoVerify_declared": info["autoVerify"], "components": info["components"]}
        if r["status"] != 200:
            res["verified"] = False
            findings.append(Finding("applink-missing", "medium", f"no assetlinks.json on {host}", host,
                                    f"status {r['status']}", checklist_ids("assetlinks.json")))
        else:
            try:
                statements = json.loads(r["body"])
            except json.JSONDecodeError:
                statements = []
                findings.append(Finding("applink-bad-json", "medium", f"assetlinks.json on {host} does not parse", host, "", checklist_ids("assetlinks.json")))
            pkg_match, fp_match = False, cert is None
            for st in statements if isinstance(statements, list) else []:
                t = st.get("target", {})
                if t.get("package_name") == pkg:
                    pkg_match = True
                    fps = [norm_fp(x) for x in t.get("sha256_cert_fingerprints", [])]
                    if cert and cert in fps:
                        fp_match = True
            res.update(package_listed=pkg_match, cert_listed=fp_match if cert else None)
            res["verified"] = pkg_match and fp_match
            if not pkg_match:
                findings.append(Finding("applink-package", "high", f"assetlinks.json on {host} does not name {pkg}", host, "",
                                        checklist_ids("app linking verification")))
            elif cert and not fp_match:
                findings.append(Finding("applink-cert", "high", f"assetlinks.json on {host} does not list the signing certificate",
                                        host, "", checklist_ids("assetlinks")))
            if not info["autoVerify"]:
                findings.append(Finding("applink-autoverify", "medium", f"intent filter for {host} lacks autoVerify", host, "",
                                        checklist_ids("auto-verify")))
        results[host] = res
        time.sleep(args.delay)

    report = {"package": pkg, "cert_sha256": cert, "hosts": results, "links": links,
              "findings": [f.as_dict() for f in findings]}
    write_json(args.out, report)
    print(json.dumps(results, indent=2))
    print(f"findings: {len(findings)}  report: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
