#!/usr/bin/env python3
"""Passive scan of source code for XML parser configurations that allow external entities.

Read-only. Use it only on source you are authorized to review. It flags parser setups
that resolve DTDs or external entities by default, and marks files that also show
a hardening call (for example disallow-doctype-decl), which lowers the risk hint.

Usage: xml_parser_scan.py /path/to/source [--out artifacts/<target>/xml_parsers.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SKIP = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "target"}
EXTS = {".java": "java", ".kt": "java", ".py": "python", ".js": "node", ".ts": "node", ".mjs": "node",
        ".php": "php", ".cs": "dotnet", ".rb": "ruby", ".go": "go", ".xml": "config"}

SINKS = [
    ("java", "DocumentBuilderFactory/SAXParserFactory/XMLInputFactory", re.compile(r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)\.newInstance\s*\(")),
    ("java", "JAXB/Unmarshaller", re.compile(r"JAXBContext\.newInstance|unmarshal\s*\(")),
    ("python", "lxml parser", re.compile(r"lxml\.etree|etree\.(parse|fromstring|XMLParser)\s*\(")),
    ("python", "xml.dom/sax", re.compile(r"xml\.(dom|sax)\.|minidom\.parse")),
    ("node", "libxmljs/xml2js/xmldom", re.compile(r"libxmljs|xml2js|xmldom|DOMParser\s*\(")),
    ("php", "simplexml/DOMDocument", re.compile(r"simplexml_load_(string|file)\s*\(|DOMDocument\s*\(|->loadXML\s*\(")),
    ("dotnet", "XmlDocument/XmlReader/XPathDocument", re.compile(r"new\s+XmlDocument\s*\(|XmlReader\.Create|XPathDocument\s*\(|XmlTextReader\s*\(")),
    ("ruby", "Nokogiri/REXML", re.compile(r"Nokogiri::XML|REXML::Document")),
    ("go", "encoding/xml", re.compile(r"xml\.NewDecoder|xml\.Unmarshal")),
    ("config", "XML document with DOCTYPE or XSLT", re.compile(r"<!DOCTYPE|xsl:stylesheet")),
]

HARDENING = re.compile(r"disallow-doctype-decl|external-general-entities|external-parameter-entities|"
                       r"FEATURE_SECURE_PROCESSING|setExpandEntityReferences\s*\(\s*false|DtdProcessing\.Prohibit|"
                       r"DtdProcessing\.Ignore|XmlResolver\s*=\s*null|libxml_disable_entity_loader|"
                       r"resolve_entities\s*=\s*False|LIBXML_NONET|noent\s*:\s*false|NOENT\b.*not", re.I)
RISK_HINTS = re.compile(r"noent\s*:\s*true|LIBXML_NOENT|DtdProcessing\.Parse|resolve_entities\s*=\s*True|"
                        r"setFeature\s*\([^)]*external|setExpandEntityReferences\s*\(\s*true", re.I)


def scan(path: str, lang: str, out: list[dict]) -> None:
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    hardened = bool(HARDENING.search(text))
    risky_flags = bool(RISK_HINTS.search(text))
    for idx, line in enumerate(text.splitlines(), 1):
        if line.strip().startswith(("#", "//", "*")):
            continue
        for sink_lang, sink_class, rx in SINKS:
            if sink_lang == lang and rx.search(line):
                if risky_flags:
                    risk = "high"
                elif hardened:
                    risk = "low (hardening call present in file; confirm it applies to this parser)"
                else:
                    risk = "review (no hardening call found in file)"
                out.append({"file": path, "line": idx, "language": lang, "parser": sink_class,
                            "risk": risk, "snippet": line.strip()[:200]})
                break


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--out")
    args = ap.parse_args()
    if not os.path.isdir(args.root):
        ap.error("root must be a directory")
    findings: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(args.root):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXTS:
                scan(os.path.join(dirpath, name), EXTS[ext], findings)
    findings.sort(key=lambda f: (not f["risk"].startswith("high"), f["file"], f["line"]))
    summary = {"root": args.root, "total": len(findings),
               "high": sum(1 for f in findings if f["risk"].startswith("high")), "findings": findings}
    text = json.dumps(summary, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
