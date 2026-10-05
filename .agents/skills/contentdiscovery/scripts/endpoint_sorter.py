#!/usr/bin/env python3
"""
endpoint_sorter.py -- Advanced Bug Bounty URL Category Sorter
Partitions discovered/crawled URLs into actionable vulnerability categories:
- api: REST, GraphQL, versioned API endpoints, JSON-RPC, SOAP
- admin: Admin panels, dashboards, staff portals, management consoles
- debug: Debug routes, test scripts, actuator, metrics, trace, env dumps
- db: Database files, dumps (.sql, .db), management tools (phpmyadmin, adminer)
- php: PHP scripts, legacy handlers, phpinfo, install/setup files
- js: JavaScript bundles, service workers, chunks (.js, .mjs)
- auth: Login, logout, register, reset password, SSO, OAuth, SAML, 2FA
- sensitive: Config files (.env, .git, .yml, .xml), private keys, backups (.zip, .bak)
- upload: File upload forms, avatars, attachments, s3 uploads
- params: URLs with query parameters (?param=value) for SSRF/XSS/SQLi fuzzing
- idor: Endpoints containing dynamic IDs (/user/123, /order/UUID)
"""

import os
import sys
import re
import argparse
from urllib.parse import urlparse

CATEGORIES = {
    "api": re.compile(
        r"/(api|v[0-9]+|graphql|gql|rest|jsonrpc|xmlrpc|swagger|openapi|v[0-9]+/api)/"
        r"|(\.json|\.wsdl|\.wadl)(\?.*)?$",
        re.IGNORECASE
    ),
    "admin": re.compile(
        r"/(admin|administrator|adm|backend|dashboard|staff|moderator|manager|manage|portal|"
        r"cpanel|whm|webmin|superadmin|root|controlpanel)/",
        re.IGNORECASE
    ),
    "debug": re.compile(
        r"/(debug|trace|status|metrics|health|healthz|actuator|info|test|testing|demo|dev|stage|"
        r"staging|profiler|telescope|elmah|phpinfo|server-status|server-info)/",
        re.IGNORECASE
    ),
    "db": re.compile(
        r"/(phpmyadmin|pma|adminer|dbadmin|myadmin|sqladmin|pgadmin)/"
        r"|\.(sql|db|sqlite|sqlite3|mdb|dump|tar\.gz\.db)(\?.*)?$",
        re.IGNORECASE
    ),
    "php": re.compile(
        r"\.php[0-9]?(\?.*)?$",
        re.IGNORECASE
    ),
    "js": re.compile(
        r"\.(js|mjs)(\?.*)?$",
        re.IGNORECASE
    ),
    "auth": re.compile(
        r"/(login|signin|sign-in|auth|authenticate|oauth|sso|saml|register|signup|sign-up|"
        r"password|passwd|reset-password|forgot-password|logout|2fa|otp|verify|session)/",
        re.IGNORECASE
    ),
    "sensitive": re.compile(
        r"(\.env|\.git|\.svn|\.htaccess|\.htpasswd|\.aws|\.npmrc|\.docker|web\.config|app\.config|"
        r"\.bak|\.old|\.orig|\.save|\.swp|\.tmp|\.zip|\.tar|\.gz|\.7z|\.rar|\.conf|\.yml|\.yaml)(\?.*)?$",
        re.IGNORECASE
    ),
    "upload": re.compile(
        r"/(upload|uploader|uploads|file-upload|attachment|attachments|media|import|avatar|document)/",
        re.IGNORECASE
    ),
    "idor": re.compile(
        r"/([a-zA-Z0-9_\-]+)/([0-9]{1,10}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(/|$|\?)",
        re.IGNORECASE
    ),
    "params": re.compile(
        r"\?[a-zA-Z0-9_\-]+=",
        re.IGNORECASE
    )
}

# Static media extensions to drop from active vulnerability categories
STATIC_EXTENSIONS = re.compile(
    r"\.(jpg|jpeg|png|gif|svg|ico|css|woff|woff2|ttf|eot|mp4|mp3|avi|webm|webp)$",
    re.IGNORECASE
)


def sort_urls(urls, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    categorized = {k: set() for k in CATEGORIES.keys()}
    other_urls = set()

    for raw in urls:
        url = raw.strip()
        if not url or url.startswith("#"):
            continue

        # Check path without query for static extensions
        path = urlparse(url).path
        if STATIC_EXTENSIONS.search(path):
            continue

        matched = False
        for cat_name, pattern in CATEGORIES.items():
            if pattern.search(url):
                categorized[cat_name].add(url)
                matched = True

        if not matched:
            other_urls.add(url)

    # Write each category file
    summary = {}
    for cat_name, items in categorized.items():
        out_file = os.path.join(output_dir, f"{cat_name}_urls.txt")
        with open(out_file, "w", encoding="utf-8") as f:
            for u in sorted(items):
                f.write(f"{u}\n")
        summary[cat_name] = len(items)

    # Write unclassified non-static URLs
    with open(os.path.join(output_dir, "other_endpoints.txt"), "w", encoding="utf-8") as f:
        for u in sorted(other_urls):
            f.write(f"{u}\n")
    summary["other"] = len(other_urls)

    return summary


def main():
    parser = argparse.ArgumentParser(description="endpoint_sorter.py -- Bug Bounty URL Category Sorter")
    parser.add_argument("-i", "--input", required=True, help="Input file containing URLs (one per line)")
    parser.add_argument("-o", "--output-dir", default="artifacts/sorted_categories", help="Output directory for categorized URL files")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        urls = f.readlines()

    print(f"[*] Processing and sorting {len(urls)} URLs into categories...")
    summary = sort_urls(urls, args.output_dir)

    print("\n=== Categorization Results ===")
    for cat, count in summary.items():
        print(f"  - {cat:12} : {count:6} URLs -> {os.path.join(args.output_dir, cat + '_urls.txt')}")
    print(f"\n[+] All categories successfully written to: {args.output_dir}/")


if __name__ == "__main__":
    main()
