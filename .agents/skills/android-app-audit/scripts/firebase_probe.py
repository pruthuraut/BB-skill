#!/usr/bin/env python3
"""Read-only, unauthenticated checks on the Firebase backend of an authorized Android app.

Reads project settings from google-services.json (from the APK, the repo, or the decoded res/).
For each Firebase service it sends one unauthenticated GET and records whether anonymous read works.
It never writes, never signs in, never creates accounts, and never sends credentials.

Scope: the project id (or the database host) must appear as a literal line in the program's scope
file, because a Firebase project is a third-party host. Otherwise the probe refuses to run.

Checks:
  FBS  Realtime Database    GET <db>/.json?shallow=true
  FBS  Firestore            GET firestore.googleapis.com/v1/projects/<id>/databases/(default)/documents?pageSize=1
  FBS  Cloud Storage        GET firebasestorage.googleapis.com/v0/b/<bucket>/o?maxResults=1
  FBS  Remote Config        GET firebaseremoteconfig.googleapis.com/v1/projects/<id>/remoteConfig
  FBS  Maps key (optional)  GET maps.googleapis.com/maps/api/staticmap (one request, --maps-key)
  FBS  Served settings      GET <in-scope host>/google-services.json (--served-host)

Usage:
  firebase_probe.py --google-services PATH --workspace DIR --program NAME [--maps-key KEY]
                    [--served-host HOST] [--out FILE]
Test harness only: FIREBASE_PROBE_BASE=http://127.0.0.1:PORT redirects every request (not for real targets).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from android_common import Finding, checklist_ids, redact_value, scope_ok, snippet, write_json  # noqa: E402

UA = "Mozilla/5.0 (compatible; android-audit-probe/1.0)"
TEST_BASE = os.environ.get("FIREBASE_PROBE_BASE", "").rstrip("/")


def get(url: str, timeout: float = 15.0) -> dict:
    if TEST_BASE:
        p = urllib.parse.urlsplit(url)
        url = TEST_BASE + p.path + (("?" + p.query) if p.query else "")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(200_000).decode("utf-8", "replace")
            return {"status": r.status, "body": body, "url": url}
    except urllib.error.HTTPError as e:
        body = e.read(200_000).decode("utf-8", "replace") if e.fp else ""
        return {"status": e.code, "body": body, "url": url}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"status": None, "body": "", "error": str(e)[:200], "url": url}


def load_services(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    pi = data.get("project_info", {})
    keys = []
    for c in data.get("client", []):
        for k in c.get("api_key", []):
            keys.append(k.get("current_key", ""))
    return {"project_id": pi.get("project_id", ""), "database_url": pi.get("firebase_url", ""),
            "storage_bucket": pi.get("storage_bucket", ""), "api_keys": keys}


def scope_literal(scope_file: str, items: list[str]) -> tuple[bool, str]:
    if not os.path.isfile(scope_file):
        return False, f"no scope file at {scope_file}"
    lines = [l.strip().lower() for l in open(scope_file, encoding="utf-8", errors="replace")]
    for it in items:
        if it and it.lower() in lines:
            return True, it
    return False, f"none of {items} is listed as a line in {scope_file}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--google-services", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--program")
    ap.add_argument("--maps-key", help="Google Maps key from the manifest (one static map request)")
    ap.add_argument("--served-host", help="in-scope host that may serve google-services.json")
    ap.add_argument("--out", default="artifacts/firebase/firebase-probe.json")
    ap.add_argument("--delay", type=float, default=0.5)
    args = ap.parse_args()

    svc = load_services(args.google_services)
    pid = svc["project_id"]
    if not pid:
        sys.exit("no project_id in google-services.json")
    root = args.workspace or os.path.join(os.path.expanduser("~"), "Documents", "bugbounty")
    scope_file = os.path.join(root, args.program or pid, "scope.txt")
    host_db = urllib.parse.urlsplit(svc["database_url"]).hostname if svc["database_url"] else f"{pid}-default-rtdb.firebaseio.com"
    ok, msg = scope_literal(scope_file, [pid, host_db or ""])
    if not ok:
        sys.exit(f"SCOPE DENIED: {msg}")
    print(f"scope ok: {msg}")

    findings: list[Finding] = []
    checks: dict = {}

    db = svc["database_url"] or f"https://{pid}-default-rtdb.firebaseio.com"
    r = get(f"{db.rstrip('/')}/.json?shallow=true")
    checks["realtime_database"] = {"status": r["status"], "readable": r["status"] == 200 and r["body"].strip() not in ("null", "")}
    if checks["realtime_database"]["readable"]:
        findings.append(Finding("fbs-rtdb", "high", "Realtime Database readable without authentication", db,
                                snippet(r["body"], 120), checklist_ids("Realtime Database")))
    time.sleep(args.delay)

    r = get(f"https://firestore.googleapis.com/v1/projects/{pid}/databases/(default)/documents?pageSize=1")
    checks["firestore"] = {"status": r["status"], "readable": r["status"] == 200}
    if r["status"] == 200:
        findings.append(Finding("fbs-firestore", "high", "Firestore documents readable without authentication", pid,
                                snippet(r["body"], 120), checklist_ids("Firestore")))
    time.sleep(args.delay)

    if svc["storage_bucket"]:
        r = get(f"https://firebasestorage.googleapis.com/v0/b/{svc['storage_bucket']}/o?maxResults=1")
        checks["storage"] = {"status": r["status"], "listable": r["status"] == 200}
        if r["status"] == 200:
            findings.append(Finding("fbs-storage", "high", "Cloud Storage bucket listable without authentication",
                                    svc["storage_bucket"], snippet(r["body"], 120), checklist_ids("Storage")))
        time.sleep(args.delay)

    r = get(f"https://firebaseremoteconfig.googleapis.com/v1/projects/{pid}/remoteConfig")
    checks["remote_config"] = {"status": r["status"], "readable": r["status"] == 200}
    if r["status"] == 200:
        findings.append(Finding("fbs-remote-config", "medium", "Remote Config readable without authentication", pid,
                                snippet(r["body"], 120), checklist_ids("Remote Config")))
    time.sleep(args.delay)

    if args.maps_key:
        q = urllib.parse.urlencode({"center": "0,0", "zoom": "1", "size": "1x1", "key": args.maps_key})
        r = get(f"https://maps.googleapis.com/maps/api/staticmap?{q}")
        denied = any(s in r["body"] for s in ("not authorized", "API keys are not supported", "REQUEST_DENIED", "API key not valid"))
        checks["maps_key"] = {"status": r["status"], "key": redact_value(args.maps_key),
                              "restricted_to_api": denied or r["status"] != 200}
        if r["status"] == 200 and not denied:
            findings.append(Finding("fbs-maps-key", "medium", "Maps key works for Static Maps (check app and API restrictions)",
                                    "manifest meta-data", redact_value(args.maps_key), checklist_ids("Google Maps API key")))

    if args.served_host:
        from android_common import REPO  # noqa: F401
        ok2, msg2 = scope_ok(args.served_host, args.workspace, args.program)
        if not ok2:
            checks["served_settings"] = {"skipped": msg2}
        else:
            r = get(f"https://{args.served_host}/google-services.json")
            served = r["status"] == 200 and "project_id" in r["body"]
            checks["served_settings"] = {"status": r["status"], "served": served}
            if served:
                findings.append(Finding("fbs-served-json", "medium", "google-services.json served by the web host",
                                        args.served_host, f"project {pid}", checklist_ids("google-services.json")))

    report = {"project_id": pid, "scope_item": msg, "api_keys": [redact_value(k) for k in svc["api_keys"]],
              "checks": checks, "findings": [f.as_dict() for f in findings],
              "requests_note": "unauthenticated GET only; no writes, no sign-in"}
    write_json(args.out, report)
    print(json.dumps(checks, indent=2, default=str))
    print(f"findings: {len(findings)}  report: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
