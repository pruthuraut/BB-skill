#!/usr/bin/env python3
"""Route a target to the right audit skills and checklist rows.

Passive only: this script never touches the network. It reads artifacts that
recon already produced and prints a plan. Active testing still requires
scripts/scope_check.sh TARGET to pass.

Inputs (all optional, combine freely):
  --fingerprint FILE   techfingerprint output, raw headers, or page HTML
  --params FILE        parameter names, one per line
  --urls FILE          URLs (query strings are parsed for parameter names)
  --scope-type TYPE    large | medium | small (auto-detected from scope.txt if given --workspace)
  --workspace DIR      workspace root holding <target>/scope.txt
  --target HOST       target name (used for scope check and output)
  --check-scope        run scripts/scope_check.sh before printing the plan
  --json               machine-readable output

Checklist rows are read from every markdown table under
.agents/skills/*/references/**/*.md whose header contains "Product" and "Class".
Expected columns: | ID | Product | Check | Class | Safe verification |
Class is one of: passive, bounded, authorized-only.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from urllib.parse import parse_qs, urlparse

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SKILLS = os.path.join(REPO, ".agents", "skills")

# Parameter name -> skills that should start when it appears. Names are lowercased.
PARAM_ROUTES: dict[str, list[str]] = {
    "ssrf-audit": ["url", "uri", "dest", "destination", "target", "fetch", "feed", "image", "img",
                   "src", "webhook", "callback_url", "proxy", "remote", "load", "import", "link"],
    "open-redirect-and-header-injection": ["redirect", "redirect_url", "redirect_uri", "return",
                   "returnurl", "return_to", "returnto", "next", "continue", "goto", "rurl",
                   "forward", "out", "to"],
    "path-traversal": ["file", "filename", "path", "folder", "dir", "document", "doc", "page",
                   "include", "inc", "view", "download", "read", "log", "name"],
    "command-injection-audit": ["cmd", "exec", "execute", "command", "ping", "traceroute", "dns",
                   "lookup", "process", "run", "exe", "payload", "code", "func", "option", "feature", "module"],
    "nosql-injection-audit": ["filter", "where", "regex", "sort", "username", "password"],
    "ldap-injection-audit": ["cn", "uid", "dn", "search", "samaccountname", "ldap"],
    "xml-xxe-audit": ["xml", "soap", "wsdl", "feed", "rss", "saml", "samlresponse", "xslt", "xpath", "svg"],
    "ssti-audit": ["template", "preview", "view", "activity", "content", "message", "tpl"],
    "server-side-injection": ["template", "tpl", "cmd", "command", "exec", "ping", "host",
                   "xml", "ldap", "filter", "where", "payload"],
    "sqli": ["id", "query", "q", "search", "sort", "order", "orderby", "category", "cat", "item",
             "product", "from", "limit", "offset", "column", "keyword"],
    "idor": ["uid", "user_id", "userid", "account", "account_id", "order_id", "invoice_id",
             "doc_id", "object_id", "ref", "profile", "owner"],
    "access-control": ["role", "roles", "admin", "isadmin", "is_admin", "group", "permission",
                   "permissions", "plan", "tier", "tenant", "org", "org_id", "team"],
    "xss": ["callback", "jsonp", "cb", "message", "msg", "comment", "text", "title", "s"],
    "oauth-sso": ["redirect_uri", "client_id", "state", "code", "id_token", "response_type",
                  "nonce", "saml", "samlresponse", "relaystate"],
    "session-management": ["token", "jwt", "session", "sessionid", "sid", "access_token",
                   "refresh_token", "auth", "authorization"],
    "file-upload-audit": ["upload", "attachment", "avatar", "photo", "import_file"],
    "credentialattacks": ["username", "user", "login", "password", "otp", "mfa", "pin", "2fa"],
    "authbypass": ["reset_token", "verify", "activation", "password_reset", "email"],
    "client-side-js-security": ["__proto__", "constructor", "prototype"],
    "api-security": ["operationname", "variables", "graphql", "swagger", "openapi"],
    "business-logic": ["price", "amount", "quantity", "qty", "discount", "coupon", "voucher",
                   "total", "currency"],
    "business-logic-vulns": ["price", "unit_price", "amount", "quantity", "qty", "currency",
                   "discount", "coupon", "promo", "voucher", "referral", "referral_code", "referrer",
                   "balance", "credits", "points", "wallet", "transfer", "rate", "apr", "interest",
                   "refund", "status", "state", "step", "stage", "plan", "tier", "subscription",
                   "trial", "trial_end", "expires_at", "feature", "beta", "flags", "verified",
                   "email_verified", "phone_verified", "skip_payment", "payment_method"],
    "race-conditions": ["coupon", "promo", "voucher", "redeem", "gift_card", "giftcard", "balance",
                   "transfer", "amount", "vote", "like", "poll", "otp", "resend", "code",
                   "reset_token", "verify", "invite", "quantity", "stock", "reserve", "credits"],
    "csrf-audit": ["csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken", "_csrf", "_csrf_token",
                   "xsrf", "_xsrf", "xsrf_token", "_token", "authenticity_token", "__requestverificationtoken",
                   "anticsrf", "_method", "new_password", "current_password", "new_email", "email"],
    "cors-audit": ["origin", "cors", "callback", "jsonp", "api_key", "apikey", "access_token", "token",
                   "graphql", "me", "profile", "account", "user"],
    "postmessage-audit": ["origin", "targetorigin", "parent_origin", "parentorigin", "embed", "widget", "iframe",
                   "message", "channel"],
    "file-download-audit": ["file", "filename", "download", "attachment", "export", "path", "doc", "document",
                   "report", "invoice", "pdf", "key", "object", "bucket", "fileid", "file_id"],
    "crypto-audit": ["token", "encrypted", "enc", "cipher", "iv", "nonce", "signature", "sig", "hmac", "hash",
                   "jwt", "viewstate", "__viewstate", "data"],
    "cache-poisoning-audit": ["utm_source", "utm_content", "utm_campaign", "fbclid", "gclid", "callback", "cb",
                   "lang", "locale", "currency", "_"],
    "server-config-audit": ["debug", "trace", "_method", "redirect", "next", "url", "return", "returnurl"],
    "cloud-container-audit": ["bucket", "s3", "blob", "container", "key", "object", "region", "function",
                   "lambda", "queue", "topic"],
    "data-exposure-audit": ["debug", "token", "access_token", "api_key", "apikey", "key", "secret", "email", "password",
                   "session", "sessionid", "sid", "ssn", "phone", "export", "backup", "log"],
    "error-handling-audit": ["id", "debug", "error", "format", "type", "sort", "order", "page", "limit"],
    "websocket-audit": ["ws", "wss", "socket", "websocket", "room", "channel", "topic", "subscribe", "eio", "transport"],
    "graphql-audit": ["query", "operationname", "variables", "extensions", "persistedquery", "graphql", "gql"],
    "rest-api-audit": ["sort", "order", "order_by", "orderby", "filter", "$filter", "$select", "$expand", "fields", "expand",
                   "include", "limit", "per_page", "page_size", "offset", "cursor", "version", "api-version"],
    "soap-api-audit": ["soap", "wsdl", "soapaction", "xml", "envelope", "singlewsdl", "disco"],
    "grpc-audit": ["grpc", "grpc-web", "proto", "protobuf"],
}

SCOPE_ROUTES = {
    "large": "recon-hunter: references/scope_playbooks.md (Large Scope: whole-org OSINT, IP ranges)",
    "medium": "recon-hunter: references/scope_playbooks.md (Medium Scope: wildcard enumeration)",
    "small": "recon-hunter: references/scope_playbooks.md (Small Scope: deep single-endpoint testing)",
}

# Generic "product" labels used for cross-cutting checks. They describe a
# check family, not a technology, so they must never match fingerprint text.
GENERIC_PRODUCTS = {
    "login", "content", "generic", "any", "all", "transport", "framing", "cookie", "cookies",
    "http", "http/2", "http/2 downgrade", "tls", "forms", "api", "email", "server", "web", "sso",
    "oauth", "saml", "jwt", "csp", "cors", "graphql", "websocket", "websockets", "dns", "mail",
    "input validation", "error pages", "pipeline", "waf", "cdn", "dom", "zone", "passive sources",
    "org-level", "search", "search engines", "code hosting", "paste sites", "shodan", "historical",
    "network", "mail server", "webmail", "sandbox", "impact", "ecommerce", "payments", "payment",
    "resolution", "probing", "brute force", "permutation", "wildcard", "methodology", "subdomains",
    "dangling", "any", "sensitive files", "rate limit", "parameters", "params", "crawl", "active",
    "static", "content discovery", "js files", "webhook", "webhooks", "upload", "import", "export",
}

# Only these skills carry real technology or vendor names in the Product column.
# Other skills use Product for a check family, so their rows must not match fingerprint text.
TECH_SKILLS = {
    "tech-stack-audit", "saas-third-party-exposure", "server-config-audit", "subdomain-takeover",
    "cloud-supplychain", "jsrecon", "techfingerprint", "ssti-audit", "file-upload-audit",
    "command-injection-audit",
}

CLASS_ORDER = {"passive": 0, "bounded": 1, "authorized-only": 2}


def load_rows() -> list[dict]:
    """Parse every checklist table in every skill's references/ folder."""
    rows: list[dict] = []
    for path in glob.glob(os.path.join(SKILLS, "*", "references", "**", "*.md"), recursive=True):
        header: list[str] | None = None
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.startswith("|"):
                    header = None
                    continue
                # Split on unescaped pipes only; "\\|" inside a cell is a literal pipe.
                inner = line.strip()[1:-1] if line.strip().endswith("|") else line.strip()[1:]
                cells = [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", inner)]
                if header is None:
                    lowered = [c.lower() for c in cells]
                    if "product" in lowered and "class" in lowered:
                        header = lowered
                    continue
                if set("".join(cells)) <= set("-: "):
                    continue  # separator row
                if len(cells) != len(header):
                    continue
                rec = dict(zip(header, cells))
                cls = rec.get("class", "").lower()
                if cls not in CLASS_ORDER:
                    continue
                skill = os.path.relpath(path, SKILLS).split(os.sep)[0]
                rows.append({
                    "id": rec.get("id", ""),
                    "product": rec.get("product", ""),
                    "check": rec.get("check", ""),
                    "class": cls,
                    "verify": rec.get("safe verification", ""),
                    "skill": skill,
                    "file": os.path.relpath(path, REPO),
                })
    return rows


def aliases(product: str) -> list[str]:
    """Split 'Apache Tomcat/Tomcat (Ghostcat)' into searchable aliases."""
    names: set[str] = set()
    for part in re.split(r"[/,]", re.sub(r"\(([^)]*)\)", r"/\1/", product)):
        part = part.strip().lower()
        if len(part) >= 4 and part not in GENERIC_PRODUCTS:
            names.add(part)
    return sorted(names)


def match_tech(rows: list[dict], text: str) -> list[dict]:
    hits = []
    seen_products: dict[str, bool] = {}
    for row in rows:
        key = row["product"]
        if row["skill"] not in TECH_SKILLS:
            continue
        if key.strip().lower() in GENERIC_PRODUCTS:
            continue
        if key not in seen_products:
            seen_products[key] = any(
                re.search(r"(?<![a-z0-9])" + re.escape(a) + r"(?![a-z0-9])", text)
                for a in aliases(key)
            )
        if seen_products[key]:
            hits.append(row)
    hits.sort(key=lambda r: (CLASS_ORDER[r["class"]], r["skill"], r["id"]))
    return hits


def param_names(paths: list[str]) -> set[str]:
    names: set[str] = set()
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "://" in line or "?" in line:
                    parsed = urlparse(line)
                    names.update(k.lower() for k in parse_qs(parsed.query, keep_blank_values=True))
                else:
                    names.add(line.lower())
    return names


def route_params(names: set[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for skill, keys in PARAM_ROUTES.items():
        hit = sorted(n for n in names if n in keys)
        if hit:
            out[skill] = hit
    return out


def detect_scope_type(workspace: str | None, target: str | None) -> str | None:
    if not (workspace and target):
        return None
    scope = os.path.join(workspace, target, "scope.txt")
    if not os.path.isfile(scope):
        return None
    with open(scope, encoding="utf-8", errors="replace") as fh:
        lines = [l.strip() for l in fh if l.strip() and not l.startswith(("#", "authorized-by", "date"))]
    if any(l.lower() in ("any", "*", "all assets", "any asset") or "any " in l.lower() for l in lines):
        return "large"
    if any(l.startswith("*.") for l in lines):
        return "medium"
    return "small"


def run_scope_check(target: str, workspace: str | None) -> None:
    cmd = [os.path.join(REPO, "scripts", "scope_check.sh"), target]
    if workspace:
        cmd.append(workspace)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stderr or "scope check failed\n")
        sys.exit(res.returncode)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target")
    ap.add_argument("--fingerprint", action="append", default=[])
    ap.add_argument("--params", action="append", default=[])
    ap.add_argument("--urls", action="append", default=[])
    ap.add_argument("--scope-type", choices=["large", "medium", "small"])
    ap.add_argument("--workspace")
    ap.add_argument("--check-scope", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.check_scope:
        if not args.target:
            ap.error("--check-scope needs --target")
        run_scope_check(args.target, args.workspace)

    fp_text = ""
    for path in args.fingerprint:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fp_text += fh.read().lower() + "\n"

    names = param_names(args.params + args.urls) if (args.params or args.urls) else set()
    rows = load_rows()
    scope_type = args.scope_type or detect_scope_type(args.workspace, args.target)

    plan = {
        "target": args.target,
        "scope_type": scope_type,
        "scope_playbook": SCOPE_ROUTES.get(scope_type or ""),
        "param_routes": route_params(names),
        "tech_checks": match_tech(rows, fp_text) if fp_text else [],
        "policy": "passive and bounded run automatically in scope; authorized-only needs explicit approval",
    }

    if args.json:
        print(json.dumps(plan, indent=2))
        return 0

    print(f"Target: {plan['target'] or '(none)'}")
    print(f"Scope type: {scope_type or 'unknown (pass --scope-type)'}")
    if plan["scope_playbook"]:
        print(f"  -> {plan['scope_playbook']}")
    print("\nParameter routes:")
    if not plan["param_routes"]:
        print("  (none)")
    for skill, keys in plan["param_routes"].items():
        print(f"  {skill}: {', '.join(keys)}")
    print(f"\nTechnology checks matched: {len(plan['tech_checks'])}")
    for skill in sorted({r['skill'] for r in plan['tech_checks']}):
        matched = [r for r in plan['tech_checks'] if r['skill'] == skill]
        print(f"  [{skill}] {len(matched)} rows")
        for r in matched[:25]:
            print(f"    {r['id']} [{r['class']}] {r['product']}: {r['check']}")
        if len(matched) > 25:
            print(f"    ... {len(matched) - 25} more in {matched[0]['file']}")
    print(f"\nPolicy: {plan['policy']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
