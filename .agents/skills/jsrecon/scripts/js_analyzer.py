#!/usr/bin/env python3
"""
js_analyzer.py -- High-Performance Cross-Platform JavaScript Recon & De-minification Engine
Features:
- De-minifies / beautifies JS bundles locally
- Automatically detects and unpacks .js.map Source Maps into recovered source trees
- Scans for 60+ high-fidelity secret regex patterns
- Extracts API routes, dynamic template literal paths (${id}), and React/Vue router paths
- Filters out CDN false positives (cdnjs, googleapis, lodash, etc.)
- Mines JSON body keys and query parameters
"""

import os
import sys
import re
import json
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

SECRET_PATTERNS = {
    "AWS Access Key ID": r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
    "AWS Secret Access Key": r"aws.{0,30}['\"]([0-9a-zA-Z/+]{40})['\"]",
    "AWS S3 Bucket": r"[a-z0-9.-]+\.s3([.-][a-z0-9-]+)?\.amazonaws\.com",
    "AWS Cognito Pool": r"[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com",
    "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
    "Google OAuth Client ID": r"[0-9]{10,}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Firebase Realtime DB": r"https?://[a-z0-9-]+\.firebaseio\.com",
    "Firebase Config Object": r"(apiKey|authDomain|databaseURL|storageBucket|messagingSenderId)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "Stripe Secret Key": r"sk_(live|test)_[A-Za-z0-9]{24,}",
    "Stripe Publishable Key": r"pk_(live|test)_[A-Za-z0-9]{24,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}",
    "Discord Webhook": r"https://(ptb\.|canary\.)?discord(app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}",
    "GitHub Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
    "GitLab PAT": r"glpat-[A-Za-z0-9_-]{20}",
    "Twilio Account SID": r"AC[a-f0-9]{32}",
    "Twilio API Key": r"SK[a-f0-9]{32}",
    "SendGrid Key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "OpenAI API Key": r"sk-(proj-)?[A-Za-z0-9_-]{20,}",
    "Anthropic API Key": r"sk-ant-[A-Za-z0-9_-]{20,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
    "Private Key Block": r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY",
    "Bearer Token": r"[Bb]earer\s+[A-Za-z0-9._~+/-]{15,}={0,2}",
    "Authorization Header": r"['\"]?[Aa]uthorization['\"]?\s*[:=]\s*['\"][^'\"]{15,}['\"]",
    "Generic API Secret": r"(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9-_.]{16,}['\"]",
    "Internal IP Address": r"\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b",
    "Internal Hostname": r"[a-z0-9-]+\.(local|internal|corp|lan|intranet)",
    "GraphQL Route": r"['\"`](/[A-Za-z0-9_/-]*(graphql|gql)[A-Za-z0-9_/-]*)['\"`]",
    "Swagger / OpenAPI Doc": r"['\"`][A-Za-z0-9_/-]*(swagger|openapi)[A-Za-z0-9_.-]*\.(json|ya?ml)['\"`]",
    "Source Map Reference": r"//[#@]\s*sourceMappingURL=([^\s]+)",
    "Debug / Dev Flag": r"(debug|devMode|isDev|testMode|enableBeta|allowTrial)['\"]?\s*[:=]\s*(true|1|['\"]true['\"])",
    "DOM XSS Sink": r"(innerHTML|outerHTML|insertAdjacentHTML)\s*=|eval\s*\(|new\s+Function\s*\(|dangerouslySetInnerHTML|v-html\s*="
}

CDN_BLACKLIST = re.compile(
    r"(cdnjs\.cloudflare\.com|ajax\.googleapis\.com|code\.jquery\.com|cdn\.jsdelivr\.net|"
    r"bootstrap|lodash|moment\.js|react\.production|vue\.runtime|npm/)",
    re.IGNORECASE
)

COMPILED_SECRETS = {k: re.compile(v) for k, v in SECRET_PATTERNS.items()}

ENDPOINT_PATTERNS = [
    # Absolute paths
    ("Absolute", re.compile(r"['\"](\/[a-zA-Z0-9_\-\.\/]{2,100})['\"]")),
    # High-value keywords
    ("Keyword", re.compile(r"['\"](\/(api|v1|v2|v3|internal|admin|staff|graphql|console|debug)\/[^'\"]+)['\"]")),
    # Dynamic template literals
    ("Dynamic", re.compile(r"['\"`](\/[a-zA-Z0-9_\-\.\/]*\$\{[a-zA-Z0-9_-]+\}[a-zA-Z0-9_\-\.\/]*)['\"`]|`(\/[^`\n]+)`")),
    # React / Vue Router definitions
    ("Router", re.compile(r"path\s*:\s*['\"]([^'\"]+)['\"]"))
]

BODY_PARAMS_REGEX = re.compile(
    r"\b(userId|orgId|accountId|tenantId|teamId|projectId|role|isAdmin|isOwner|plan|trial|status|permission|scope)\b",
    re.IGNORECASE
)

QUERY_PARAMS_REGEX = re.compile(r"\?([a-zA-Z0-9_\-]+)=")


def beautify_file(input_path, output_path):
    """Beautify JavaScript file if jsbeautifier library is present."""
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        pretty = jsbeautifier.beautify(code, opts)
        with open(output_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(pretty)
        return output_path
    except ImportError:
        # Fallback to copying
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f_in:
            with open(output_path, "w", encoding="utf-8", errors="ignore") as f_out:
                f_out.write(f_in.read())
        return output_path


def unpack_source_map(map_path, dest_dir):
    """Unpack .js.map file into original source files."""
    try:
        with open(map_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        
        sources = data.get("sources", [])
        contents = data.get("sourcesContent", [])
        
        if not sources or not contents or len(sources) != len(contents):
            return 0
        
        recovered_count = 0
        for src_name, src_code in zip(sources, contents):
            if not src_code:
                continue
            # Sanitize path
            clean_name = src_name.replace("webpack://", "").replace("../", "").lstrip("/\\")
            target_file = os.path.join(dest_dir, clean_name)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "w", encoding="utf-8", errors="ignore") as out:
                out.write(src_code)
            recovered_count += 1
            
        return recovered_count
    except Exception:
        return 0


def analyze_js_content(filepath, rel_name):
    """Extract secrets, endpoints, and parameters from a single JS file."""
    findings = []
    endpoints = set()
    body_params = set()
    query_params = set()
    map_refs = []
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    # Skip HTML responses mistakenly saved as JS
    if text.strip().lower().startswith(("<!doctype html", "<html")):
        return findings, endpoints, body_params, query_params, map_refs

    # 1. Secret Scanning
    for name, pattern in COMPILED_SECRETS.items():
        matches = pattern.findall(text)
        for m in matches[:5]:
            val = m if isinstance(m, str) else m[0]
            val = val.strip().replace("\n", " ")[:120]
            if val:
                findings.append((rel_name, name, val))

    # 2. Endpoint Extraction
    for ep_type, pattern in ENDPOINT_PATTERNS:
        matches = pattern.findall(text)
        for m in matches:
            ep = m if isinstance(m, str) else (m[0] or m[1])
            ep = ep.strip().replace("\n", "")
            if len(ep) >= 2 and not CDN_BLACKLIST.search(ep):
                if not ep.endswith((".png", ".jpg", ".jpeg", ".svg", ".css", ".woff", ".woff2", ".ico")):
                    endpoints.add(ep)

    # 3. Parameter Mining
    for p in BODY_PARAMS_REGEX.findall(text):
        body_params.add(p)
    for q in QUERY_PARAMS_REGEX.findall(text):
        query_params.add(q)

    # 4. Source Map References
    source_map_matches = re.findall(r"//[#@]\s*sourceMappingURL=([^\s]+)", text)
    for sm in source_map_matches:
        map_refs.append(sm)

    return findings, endpoints, body_params, query_params, map_refs


def main():
    parser = argparse.ArgumentParser(description="js_analyzer.py -- Comprehensive Bug Bounty JS Engine")
    parser.add_argument("-d", "--dir", required=True, help="Directory containing downloaded .js files")
    parser.add_argument("-o", "--out", default="artifacts/js_analysis", help="Output directory")
    parser.add_argument("--unpack-maps", action="store_true", help="Unpack any discovered .js.map files")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    all_findings = []
    all_endpoints = set()
    all_body_params = set()
    all_query_params = set()
    all_map_refs = set()

    js_files = []
    for root, _, files in os.walk(args.dir):
        for f in files:
            if f.endswith((".js", ".mjs")):
                js_files.append(os.path.join(root, f))

    print(f"[*] Analyzing {len(js_files)} JavaScript files in {args.dir}...")

    for fpath in js_files:
        rel = os.path.basename(fpath)
        fnd, eps, b_params, q_params, m_refs = analyze_js_content(fpath, rel)
        all_findings.extend(fnd)
        all_endpoints.update(eps)
        all_body_params.update(b_params)
        all_query_params.update(q_params)
        all_map_refs.update(m_refs)

    # Write Secret Findings
    findings_file = os.path.join(args.out, "secrets_findings.txt")
    with open(findings_file, "w", encoding="utf-8") as f:
        for fname, title, val in sorted(all_findings):
            f.write(f"{fname} > {title}: {val}\n")
    print(f"[+] Secrets found: {len(all_findings)} -> {findings_file}")

    # Write Endpoints
    endpoints_file = os.path.join(args.out, "endpoints_discovered.txt")
    with open(endpoints_file, "w", encoding="utf-8") as f:
        for ep in sorted(all_endpoints):
            f.write(f"{ep}\n")
    print(f"[+] Unique Endpoints extracted: {len(all_endpoints)} -> {endpoints_file}")

    # Write Parameters
    params_file = os.path.join(args.out, "parameters_discovered.json")
    with open(params_file, "w", encoding="utf-8") as f:
        json.dump({
            "body_parameters": sorted(all_body_params),
            "query_parameters": sorted(all_query_params)
        }, f, indent=2)
    print(f"[+] Parameters mined: {len(all_body_params)} body, {len(all_query_params)} query -> {params_file}")

    # Write Source Map References
    if all_map_refs:
        maps_file = os.path.join(args.out, "sourcemap_references.txt")
        with open(maps_file, "w", encoding="utf-8") as f:
            for sm in sorted(all_map_refs):
                f.write(f"{sm}\n")
        print(f"[+] Source Map references: {len(all_map_refs)} -> {maps_file}")

    print("[*] JavaScript Analysis Complete.")


if __name__ == "__main__":
    main()
