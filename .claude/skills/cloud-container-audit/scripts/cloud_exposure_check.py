#!/usr/bin/env python3
"""Read-only exposure checks for cloud storage, container, and orchestration services.

--hosts FILE      hosts or IPs (one per line); probes known ports with read-only GETs:
                  Docker API 2375/2376 (/version, /_ping), Kubernetes API 6443/8443/443 (/version, /api),
                  kubelet 10250/10255 (/pods status only), etcd 2379 (/version, /health),
                  Kubernetes dashboard 443/8443/30000 (/api/v1/login/status), Docker registry 5000/443 (/v2/_catalog)
--buckets FILE    bucket names: S3 and GCS anonymous listing (status and object count only)
--azure ACCT/CONT Azure Blob anonymous container listing (repeatable)
--functions FILE  function URLs: anonymous GET status
Response bodies are not stored beyond small, redacted facts (version strings, counts).

Safety: every host contacted (including bucket hosts) must pass scripts/scope_check.sh;
list cloud resource hostnames in scope.txt first. GET only; never create, exec, write, or read data.

Example:
  cloud_exposure_check.py --target example.com --hosts hosts.txt --buckets buckets.txt \
     --azure exampleacct/public --out artifacts/example.com/cloud_exposure.json
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
PROBES = [
    # (row, name, port, tls, path, detector)
    ("CC-005", "docker-api", 2375, False, "/version", lambda s, b: s == 200 and '"ApiVersion"' in b),
    ("CC-005", "docker-api-tls", 2376, True, "/version", lambda s, b: s == 200 and '"ApiVersion"' in b),
    ("CC-006", "k8s-api-version", 6443, True, "/version", lambda s, b: s == 200 and '"gitVersion"' in b),
    ("CC-006", "k8s-api-anon", 6443, True, "/api/v1/namespaces", lambda s, b: s == 200 and '"NamespaceList"' in b),
    ("CC-006", "k8s-api-version", 8443, True, "/version", lambda s, b: s == 200 and '"gitVersion"' in b),
    ("CC-006", "k8s-api-anon", 8443, True, "/api/v1/namespaces", lambda s, b: s == 200 and '"NamespaceList"' in b),
    ("CC-V-001", "kubelet", 10250, True, "/pods", lambda s, b: s == 200 and '"PodList"' in b),
    ("CC-V-001", "kubelet-readonly", 10255, False, "/pods", lambda s, b: s == 200 and '"PodList"' in b),
    ("CC-013", "etcd", 2379, False, "/version", lambda s, b: s == 200 and "etcdserver" in b),
    ("CC-013", "etcd-tls", 2379, True, "/version", lambda s, b: s == 200 and "etcdserver" in b),
    ("CC-014", "k8s-dashboard", 443, True, "/api/v1/login/status", lambda s, b: s == 200 and "tokenPresent" in b),
    ("CC-014", "k8s-dashboard", 8443, True, "/api/v1/login/status", lambda s, b: s == 200 and "tokenPresent" in b),
    ("CC-014", "k8s-dashboard", 30000, True, "/api/v1/login/status", lambda s, b: s == 200 and "tokenPresent" in b),
    ("CC-V-002", "docker-registry", 5000, False, "/v2/_catalog", lambda s, b: s == 200 and '"repositories"' in b),
    ("CC-V-002", "docker-registry", 443, True, "/v2/_catalog", lambda s, b: s == 200 and '"repositories"' in b),
]


def scope_ok(host: str, workspace: str | None, program: str | None = None) -> bool:
    cmd = ["bash", SCOPE, host, workspace or "", program or host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"[scope] {host}: {res.stderr.strip() or 'denied'}\n")
    return res.returncode == 0


def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def get(host: str, port: int, tls: bool, path: str, timeout: float) -> tuple[int | None, str, dict]:
    try:
        if tls:
            ctx = ssl._create_unverified_context()  # exposure check; many of these services use self-signed certs
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "cloud-container-audit"})
        r = conn.getresponse()
        body = r.read(200_000).decode("utf-8", errors="replace")
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return r.status, body, hdrs
    except Exception as e:
        return None, str(e), {}


def facts(name: str, body: str) -> dict:
    f = {}
    for key in ("ApiVersion", "Version", "gitVersion", "etcdserver", "etcdcluster", "Os", "KernelVersion"):
        m = re.search(r'"%s"\s*:\s*"([^"]+)"' % key, body)
        if m:
            f[key] = m.group(1)
    if '"items"' in body:
        f["items"] = body.count('"metadata":')
    m = re.search(r'"repositories"\s*:\s*\[([^\]]*)\]', body)
    if m:
        f["repositories"] = len([x for x in m.group(1).split(",") if x.strip()])
    return f


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--workspace")
    ap.add_argument("--hosts")
    ap.add_argument("--buckets")
    ap.add_argument("--azure", action="append", default=[], help="account/container")
    ap.add_argument("--functions")
    ap.add_argument("--ports", help="comma list to limit host probes to these ports")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument("--out")
    args = ap.parse_args()

    read = lambda f: [l.strip() for l in open(f, encoding="utf-8") if l.strip() and not l.startswith("#")] if f else []
    rep: dict = {"target": args.target, "hosts": [], "buckets": [], "azure": [], "functions": [], "findings": []}
    F = rep["findings"]
    ports = {int(p) for p in args.ports.split(",")} if args.ports else None

    for host in read(args.hosts):
        if not scope_ok(host, args.workspace, args.target.lower()):
            continue
        hrec = {"host": host, "probes": []}
        open_cache: dict[int, bool] = {}
        for row, name, port, tls, path, det in PROBES:
            if ports and port not in ports:
                continue
            if port not in open_cache:
                open_cache[port] = port_open(host, port, args.timeout)
            if not open_cache[port]:
                continue
            time.sleep(args.delay)
            st, body, _ = get(host, port, tls, path, args.timeout)
            hit = st is not None and det(st, body)
            rec = {"row": row, "service": name, "port": port, "path": path, "status": st, "exposed": hit}
            if hit:
                rec["facts"] = facts(name, body)
                F.append(f"{row}: {name} exposed on {host}:{port}{path} {rec['facts']}")
            hrec["probes"].append(rec)
            print(f"{host}:{port} {name:16} {path:24} {st} {'EXPOSED' if hit else ''}")
        hrec["open_ports"] = sorted(p for p, o in open_cache.items() if o)
        rep["hosts"].append(hrec)

    for b in read(args.buckets):
        for prov, host, path in (("s3", f"{b}.s3.amazonaws.com", "/"), ("gcs", "storage.googleapis.com", f"/{b}")):
            if not scope_ok(host if prov == "s3" else f"{b}.storage.googleapis.com", args.workspace, args.target.lower()):
                continue
            time.sleep(args.delay)
            st, body, _ = get(host, 443, True, path if prov == "s3" else f"/storage/v1/b/{b}/o?maxResults=5", args.timeout)
            if prov == "s3":
                state = ("public-list" if "<ListBucketResult" in body else "no-such-bucket" if "NoSuchBucket" in body
                         else "access-denied" if "AccessDenied" in body else f"status-{st}")
                count = body.count("<Key>")
            else:
                state = ("public-list" if st == 200 and '"kind"' in body else "no-such-bucket" if st == 404
                         else "access-denied" if st in (401, 403) else f"status-{st}")
                count = body.count('"name"')
            rec = {"bucket": b, "provider": prov, "state": state, "objects_in_first_page": count}
            rep["buckets"].append(rec)
            print(f"{prov}:{b:30} {state} {count if state == 'public-list' else ''}")
            if state == "public-list":
                F.append(f"{'CC-001' if prov == 's3' else 'CC-008'}: {prov} bucket {b} lists anonymously ({count} keys on first page)")
            if state == "no-such-bucket":
                F.append(f"CC-V-010 lead: {prov} bucket {b} does not exist; if referenced by the target, check takeover (subdomain-takeover)")

    for ac in args.azure:
        acct, _, cont = ac.partition("/")
        host = f"{acct}.blob.core.windows.net"
        if not scope_ok(host, args.workspace, args.target.lower()):
            continue
        time.sleep(args.delay)
        st, body, _ = get(host, 443, True, f"/{cont}?restype=container&comp=list&maxresults=5", args.timeout)
        state = ("public-list" if "<EnumerationResults" in body else "no-such-container" if "ContainerNotFound" in body
                 else "no-public-access" if st in (403, 404, 409) else f"status-{st}")
        rep["azure"].append({"account": acct, "container": cont, "state": state, "blobs_in_first_page": body.count("<Blob>")})
        print(f"azure:{ac:30} {state}")
        if state == "public-list":
            F.append(f"CC-008: Azure container {ac} lists anonymously")

    for url in read(args.functions):
        m = re.match(r"https?://([^/]+)(/.*)?", url)
        if not m:
            continue
        host, path = m.group(1).split(":")[0], m.group(2) or "/"
        if not scope_ok(host, args.workspace, args.target.lower()):
            continue
        time.sleep(args.delay)
        st, body, hd = get(host, 443, url.startswith("https"), path, args.timeout) if url.startswith("https") else get(host, 80, False, path, args.timeout)
        rec = {"url": url, "status": st, "server": hd.get("server"), "auth_required": st in (401, 403)}
        rep["functions"].append(rec)
        print(f"fn {url:50} {st}")
        if st and 200 <= st < 300:
            F.append(f"CC-010: function {url} responds {st} without auth (check intended exposure and data returned)")

    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        json.dump(rep, open(args.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
