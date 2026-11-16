#!/usr/bin/env python3
"""Check own file URLs for auth, IDOR, serving headers, listings, and signed URLs.

Per URL (your account A's files):
  1. GET with --cookie (owner)            -> baseline
  2. GET without credentials              -> FD-005 (auth required?)
  3. GET with --other-cookie (account B)  -> FD-006 (IDOR?)
  4. Header review: Content-Type vs extension, nosniff, Content-Disposition,
     Cache-Control (FD-003, FD-004, FD-V-001, FD-V-002)
  5. Signed URL analysis (X-Amz-Expires, Expires, se=, X-Goog-Expires) (FD-007, FD-V-008)
  6. Optional --listing: GET each parent folder and look for directory or
     bucket listings (FD-002)
Responses are compared by status, length, and SHA-256 of up to 2 MB of body.

Safety: every host (including bucket or CDN hosts) must pass
scripts/scope_check.sh; add those hosts to scope.txt if they are in scope.
GET only, delay 0.5 s by default.

Example:
  download_check.py --target example.com --workspace ~/Documents/bugbounty \
     --urls files.txt --cookie 'session=A' --other-cookie 'session=B' --listing \
     --out artifacts/example.com/file_download.json
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import mimetypes
import os
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import parse_qs, urlsplit

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
LISTING_RE = re.compile(r"<title>\s*Index of|Directory Listing For|<ListBucketResult|<EnumerationResults|"
                        r"\"kind\"\s*:\s*\"storage#objects\"|\[To Parent Directory\]|<h1>Index of", re.I)
RISKY_INLINE = ("text/html", "image/svg+xml", "application/xhtml+xml", "text/xml", "application/xml", "application/pdf")
mimetypes.add_type("image/svg+xml", ".svg")


def run_scope_check(host: str, workspace: str | None, program: str | None = None) -> None:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode or 3)


def get(url: str, cookie: str | None, extra: list[str], insecure: bool, timeout: float) -> dict:
    p = urlsplit(url)
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    if p.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
    headers = {"User-Agent": "Mozilla/5.0 file-download-audit", "Accept": "*/*"}
    if cookie:
        headers["Cookie"] = cookie
    for h in extra:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    try:
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        body = r.read(2_000_000)
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return {"status": r.status, "length": int(hdrs.get("content-length", len(body))),
                "sha256": hashlib.sha256(body).hexdigest()[:16], "headers": hdrs,
                "listing": bool(LISTING_RE.search(body[:200_000].decode("utf-8", errors="replace")))}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


def signed_url_info(url: str) -> dict | None:
    q = {k.lower(): v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    host = (urlsplit(url).hostname or "").lower()
    info: dict = {}
    if "x-amz-signature" in q or "x-amz-expires" in q:
        info = {"provider": "aws-s3-sigv4", "expires_seconds": int(q.get("x-amz-expires", "0") or 0),
                "signed_headers": q.get("x-amz-signedheaders")}
    elif "signature" in q and "expires" in q and ("awsaccesskeyid" in q or "amazonaws" in host):
        info = {"provider": "aws-s3-sigv2", "expires_epoch": int(q["expires"])}
    elif "x-goog-signature" in q:
        info = {"provider": "gcs-v4", "expires_seconds": int(q.get("x-goog-expires", "0") or 0)}
    elif "sig" in q and ("se" in q or "sv" in q):
        info = {"provider": "azure-sas", "expiry": q.get("se"), "permissions": q.get("sp"), "resource": q.get("sr")}
    elif "expires" in q and ("signature" in q or "key-pair-id" in q):
        info = {"provider": "cloudfront-signed", "expires_epoch": int(q["expires"]) if q["expires"].isdigit() else q["expires"]}
    if not info:
        if re.search(r"(s3[.-][\w-]*\.amazonaws\.com|\.s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|"
                     r"digitaloceanspaces\.com|r2\.cloudflarestorage\.com)", host):
            return {"provider": "cloud-storage-unsigned", "note": "unsigned cloud object URL: object or bucket may be public (FD-007)"}
        return None
    notes = []
    secs = info.get("expires_seconds")
    if secs and secs > 3600:
        notes.append(f"long-lived signed URL ({secs}s) (FD-007)")
    if "expires_epoch" in info and isinstance(info["expires_epoch"], int):
        left = info["expires_epoch"] - int(time.time())
        info["seconds_left"] = left
        if left > 86400:
            notes.append(f"signed URL valid for {left // 3600}h more (FD-007)")
    if info.get("provider") == "azure-sas":
        if info.get("resource") == "c":
            notes.append("SAS scoped to a whole container (FD-V-008)")
        if info.get("permissions") and set(info["permissions"]) - set("r"):
            notes.append(f"SAS permissions '{info['permissions']}' exceed read (FD-V-008)")
    info["notes"] = notes
    return info


def parents(url: str) -> list[str]:
    p = urlsplit(url)
    parts = [x for x in p.path.split("/") if x][:-1]
    out = []
    for i in range(len(parts), 0, -1):
        out.append(f"{p.scheme}://{p.netloc}/" + "/".join(parts[:i]) + "/")
    return out


def header_issues(url: str, r: dict) -> list[str]:
    h = r.get("headers", {})
    issues = []
    ctype = h.get("content-type", "").split(";")[0].strip().lower()
    ext = os.path.splitext(urlsplit(url).path)[1].lower()
    expected = mimetypes.guess_type("x" + ext)[0] if ext else None
    if not ctype:
        issues.append("no Content-Type (browser will sniff) (FD-003)")
    elif expected and expected != ctype and not (expected.startswith("text/") and ctype.startswith("text/")):
        issues.append(f"Content-Type {ctype} does not match extension {ext} ({expected}) (FD-003)")
    disp = h.get("content-disposition", "")
    if ctype in RISKY_INLINE and "attachment" not in disp.lower():
        issues.append(f"{ctype} served inline (no attachment disposition): XSS risk if user-controlled (FD-003, FD-004)")
    if not disp and ctype and not ctype.startswith("image/") and ctype not in ("text/plain",):
        issues.append("no Content-Disposition (FD-004)")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        issues.append("X-Content-Type-Options: nosniff missing (FD-V-001)")
    cc = h.get("cache-control", "").lower()
    if "no-store" not in cc and "private" not in cc:
        issues.append(f"authenticated file cacheable (Cache-Control: '{cc or 'missing'}') (FD-V-002)")
    return issues


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--urls", help="file with your own file URLs, one per line")
    ap.add_argument("--cookie", help="owner session (account A)")
    ap.add_argument("--other-cookie", help="second own account session (account B)")
    ap.add_argument("--header", action="append", default=[], help="extra header for authenticated requests")
    ap.add_argument("--listing", action="store_true", help="check parent folders for directory listing")
    ap.add_argument("--delay", type=float, default=0.5)
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    urls = list(args.url)
    if args.urls:
        urls += [l.strip() for l in open(args.urls, encoding="utf-8") if l.strip() and not l.startswith("#")]
    if not urls:
        sys.exit("give --url or --urls")
    target = args.target.lower()
    for h in sorted({(urlsplit(u).hostname or "").lower() for u in urls}):
        if not (h == target or h.endswith("." + target)):
            print(f"note: {h} is outside {target}; it must be listed in {target}/scope.txt", file=sys.stderr)
        run_scope_check(h, args.workspace, args.target.lower())

    results, first = [], True

    def pause():
        nonlocal first
        if not first:
            time.sleep(args.delay)
        first = False

    seen_dirs = set()
    for url in urls:
        rec: dict = {"url": url, "issues": []}
        pause(); own = get(url, args.cookie, args.header, args.insecure, args.timeout)
        rec["owner"] = {k: v for k, v in own.items() if k != "headers"}
        if "error" in own:
            results.append(rec); print(f"[error] {url}: {own['error']}"); continue
        rec["issues"] += header_issues(url, own)
        pause(); anon = get(url, None, [], args.insecure, args.timeout)
        rec["anonymous"] = {k: v for k, v in anon.items() if k != "headers"}
        if anon.get("status") == own["status"] == 200 and anon.get("sha256") == own["sha256"]:
            rec["issues"].append("file readable without authentication (FD-005)")
        if args.other_cookie:
            pause(); other = get(url, args.other_cookie, [], args.insecure, args.timeout)
            rec["other_account"] = {k: v for k, v in other.items() if k != "headers"}
            if other.get("status") == own["status"] == 200 and other.get("sha256") == own["sha256"]:
                rec["issues"].append("second account reads the owner's file (FD-006 IDOR)")
        su = signed_url_info(url)
        if su:
            rec["signed_url"] = su
            rec["issues"] += su.get("notes", []) + ([su["note"]] if su.get("note") else [])
        if args.listing:
            for d in parents(url):
                if d in seen_dirs:
                    continue
                seen_dirs.add(d)
                pause(); lr = get(d, args.cookie, args.header, args.insecure, args.timeout)
                if lr.get("listing"):
                    rec["issues"].append(f"directory or bucket listing at {d} (FD-002)")
        results.append(rec)
        print(f"[{len(rec['issues'])} issue(s)] {url}  owner={own['status']} anon={anon.get('status')}"
              + (f" other={rec['other_account'].get('status')}" if args.other_cookie else ""))
        for i in rec["issues"]:
            print(f"    - {i}")

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump({"target": target, "results": results}, open(args.out, "w", encoding="utf-8"), indent=2)
        print(f"results: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
