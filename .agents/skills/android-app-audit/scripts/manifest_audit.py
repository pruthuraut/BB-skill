#!/usr/bin/env python3
"""Audit a decoded AndroidManifest.xml (apktool output) for exposure and misconfiguration.

Reads XML only. Covers the manifest-level checklist rows: debuggable, allowBackup, cleartext
traffic, network security config, exported components (activity, service, receiver, provider,
activity-alias), intent filters and app links, provider permissions and URI grants, custom
permission protection levels, dangerous permissions, task affinity, legacy storage, the Maps key
and accessibility service declarations.

Usage:
  manifest_audit.py path/to/AndroidManifest.xml [--res-dir DIR] [--json]
  (run with python3 -I when the manifest came from a downloaded APK)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from android_common import Finding, checklist_ids, redact_value  # noqa: E402

NS = "{http://schemas.android.com/apk/res/android}"
DANGEROUS = {
    "android.permission.READ_SMS": "SMS read", "android.permission.RECEIVE_SMS": "SMS receive",
    "android.permission.READ_CALL_LOG": "call log", "android.permission.PROCESS_OUTGOING_CALLS": "outgoing calls",
    "android.permission.RECORD_AUDIO": "microphone", "android.permission.CAMERA": "camera",
    "android.permission.ACCESS_FINE_LOCATION": "fine location", "android.permission.ACCESS_BACKGROUND_LOCATION": "background location",
    "android.permission.READ_PHONE_STATE": "phone state (device fingerprinting risk)",
    "android.permission.SYSTEM_ALERT_WINDOW": "overlay (tapjacking/overlay risk)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install packages", "android.permission.WRITE_EXTERNAL_STORAGE": "legacy external storage write",
    "android.permission.READ_EXTERNAL_STORAGE": "legacy external storage read", "android.permission.QUERY_ALL_PACKAGES": "package visibility (all apps)",
    "android.permission.PACKAGE_USAGE_STATS": "usage stats (surveillance risk)", "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility service",
    "android.permission.READ_CONTACTS": "contacts", "android.permission.READ_CALENDAR": "calendar",
}
BROWSABLE = "android.intent.category.BROWSABLE"


def attr(el, name, default=None):
    return el.get(NS + name, default)


def truthy(v):
    return v is not None and v.lower() == "true"


def audit(manifest_path: str, res_dir: str | None = None) -> dict:
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    app = root.find("application")
    findings: list[Finding] = []
    components: list[dict] = []
    intent_rows: list[dict] = []
    package = root.get("package", "")

    def add(rule, sev, title, where="", evidence="", phrase=""):
        findings.append(Finding(rule, sev, title, where, evidence, checklist_ids(phrase) if phrase else []))

    sdk = root.find("uses-sdk")
    target = int(attr(sdk, "targetSdkVersion", "0") or 0) if sdk is not None else 0
    minsdk = int(attr(sdk, "minSdkVersion", "0") or 0) if sdk is not None else 0
    if target and target < 33:
        add("target-sdk", "low", f"targetSdkVersion {target} is old", "manifest", "", "Check for outdated or insecure library versions")

    if app is None:
        return {"package": package, "error": "no <application> element", "findings": []}

    if truthy(attr(app, "debuggable")):
        add("debuggable", "high", "android:debuggable=true in release manifest", "application",
            "run-as and debugger attach are possible on the device", "Check for debuggable flag")
    if truthy(attr(app, "testOnly")):
        add("test-only", "medium", "android:testOnly=true", "application", "", "Check for debuggable flag")

    backup = attr(app, "allowBackup")
    if backup is None:
        add("allowbackup-default", "info", "allowBackup not set (defaults to true)", "application", "", "Check for allowBackup flag")
    elif truthy(backup):
        add("allowbackup", "high", "android:allowBackup=true", "application",
            "app data can be extracted with adb backup on a debuggable or unlocked device", "Check for allowBackup flag")
    if attr(app, "fullBackupContent") is None and truthy(backup or "true"):
        add("fullbackup-missing", "low", "fullBackupContent rules not set while backup is enabled", "application", "",
            "Test for backup extraction via adb backup command")

    if truthy(attr(app, "usesCleartextTraffic")):
        add("cleartext", "high", "usesCleartextTraffic=true allows HTTP", "application", "", "Check for network security config (cleartext traffic allowed)")
    nsc = attr(app, "networkSecurityConfig")
    if nsc:
        add("network-security-config", "info", f"networkSecurityConfig={nsc}; review its rules", "application",
            "see res/xml; check cleartext, user trust anchors and pins", "Test for network security config domain-specific rules")
        if res_dir:
            add_nsc_findings(nsc, res_dir, add)

    if truthy(attr(app, "requestLegacyExternalStorage")):
        add("legacy-storage", "medium", "requestLegacyExternalStorage=true", "application", "",
            "Test if WRITE_EXTERNAL_STORAGE is not used when scoped storage is available")
    if attr(app, "sharedUserId") or root.get("sharedUserId"):
        add("shared-uid", "medium", "sharedUserId declared", "manifest", "", "Test for implicit intent interception by malicious apps")

    # Application-level permission element for custom permissions
    custom_perms = []
    for p in root.findall("permission"):
        pname = attr(p, "name", "")
        level = attr(p, "protectionLevel", "normal")
        custom_perms.append({"name": pname, "protectionLevel": level})
        if level in ("normal", "dangerous") or attr(p, "protectionLevel") is None:
            add("custom-perm", "medium", f"custom permission {pname} protectionLevel={level}", "permission",
                "any installed app can request a normal/dangerous custom permission", "Test if custom permissions use signature protection level")

    perms = [attr(p, "name", "") for p in root.findall("uses-permission")] + \
            [attr(p, "name", "") for p in root.findall("uses-permission-sdk-23")]
    for pn in perms:
        if pn in DANGEROUS:
            add("dangerous-perm", "info", f"requests {pn.split('.')[-1]} ({DANGEROUS[pn]})", "uses-permission",
                "justify and check runtime handling", "Check for dangerous permissions usage without justification")
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
        add("accessibility-declared", "info", "app requests accessibility-service binding", "uses-permission", "",
            "Test for accessibility service data theft vulnerability")

    # Components
    kinds = ["activity", "activity-alias", "service", "receiver", "provider"]
    for kind in kinds:
        for el in app.findall(kind):
            name = attr(el, "name", "")
            exported_attr = attr(el, "exported")
            filters = el.findall("intent-filter")
            exported = truthy(exported_attr) if exported_attr is not None else (len(filters) > 0 and kind != "provider")
            perm = attr(el, "permission")
            read_p, write_p = attr(el, "readPermission"), attr(el, "writePermission")
            rec = {"kind": kind, "name": name, "exported": exported, "exported_explicit": exported_attr is not None,
                   "permission": perm, "readPermission": read_p, "writePermission": write_p,
                   "authorities": attr(el, "authorities"), "grantUriPermissions": truthy(attr(el, "grantUriPermissions")),
                   "launchMode": attr(el, "launchMode"), "taskAffinity": attr(el, "taskAffinity"),
                   "filters": []}
            for f in filters:
                actions = [attr(a, "name", "") for a in f.findall("action")]
                cats = [attr(c, "name", "") for c in f.findall("category")]
                datas = []
                for d in f.findall("data"):
                    datas.append({k.replace(NS, ""): v for k, v in d.attrib.items()})
                frow = {"actions": actions, "categories": cats, "data": datas, "autoVerify": truthy(attr(f, "autoVerify"))}
                rec["filters"].append(frow)
                intent_rows.append({"component": name, "kind": kind, **frow})
            components.append(rec)

            if exported:
                guarded = bool(perm or (kind == "provider" and (read_p or write_p)))
                if kind == "provider":
                    if not guarded:
                        add("export-provider", "high", f"exported provider without permission: {name}", name,
                            f"authorities={rec['authorities']}", "Check for exported content providers with data access")
                    if rec["grantUriPermissions"]:
                        add("provider-uri-grant", "medium", f"grantUriPermissions on provider {name}", name, "",
                            "Test if application does not grant URI permissions to unauthorized packages")
                elif kind == "receiver":
                    add("export-receiver", "medium" if guarded else "high", f"exported receiver {name}", name,
                        "validate action and sender; intent injection risk" + ("" if guarded else " (no permission)"),
                        "Check for exported broadcast receivers for intent injection")
                elif kind == "service":
                    add("export-service", "medium" if guarded else "high", f"exported service {name}", name,
                        "bound by other apps" + ("" if guarded else " (no permission)"),
                        "Check for exported services accessible by other apps")
                else:
                    add("export-activity", "medium" if guarded else "high", f"exported {kind} {name}", name,
                        "reachable by other apps" + ("" if guarded else " (no permission)"),
                        "Check for exported activities accessible by other apps")
            if rec["taskAffinity"] and rec["taskAffinity"] != f"{package}":
                add("task-affinity", "low", f"custom taskAffinity on {name}", name, rec["taskAffinity"],
                    "Test for task hijacking (Strandhogg) vulnerability")

    # Intent filters: app links and custom schemes
    for row in intent_rows:
        schemes = {d.get("scheme") for d in row["data"] if d.get("scheme")}
        web = schemes & {"http", "https"}
        if web and BROWSABLE in row["categories"]:
            if not row["autoVerify"]:
                add("app-link-unverified", "medium", f"web deep link without autoVerify: {row['component']}", row["component"],
                    "hosts: " + ", ".join(sorted({d.get("host", "") for d in row["data"] if d.get("host")})),
                    "Check for app linking verification (assetlinks.json presence)")
            else:
                add("app-link", "info", f"verified App Link: {row['component']}", row["component"],
                    "verify /.well-known/assetlinks.json with deeplink_probe.py", "Test if app links with auto-verify properly validate domain ownership")
        custom = schemes - {"http", "https", "content", "file", "android.resource", ""}
        if custom and BROWSABLE in row["categories"]:
            add("custom-scheme", "medium", f"custom scheme deep link: {row['component']} -> {sorted(custom)}", row["component"],
                "any app can register the same scheme", "Analyze custom URL schemes (deep links) for hijacking potential")
        if "file" in schemes:
            add("file-scheme", "high", f"file:// scheme handled: {row['component']}", row["component"], "",
                "Test if deep links allow arbitrary file access via file:// scheme handling")

    # Meta-data (Maps key, Firebase)
    meta = []
    for md in app.iter("meta-data"):
        name, value = attr(md, "name", ""), attr(md, "value") or attr(md, "resource") or ""
        meta.append({"name": name, "value": redact_value(value) if value else None})
        if name == "com.google.android.geo.API_KEY" and value:
            add("maps-key", "info", "Google Maps API key in manifest; test key restriction", "meta-data",
                redact_value(value), "Check for Google Maps API key restriction (Android app restriction)")

    return {
        "package": package, "targetSdk": target, "minSdk": minsdk,
        "application": {"debuggable": truthy(attr(app, "debuggable")), "allowBackup": backup,
                        "usesCleartextTraffic": attr(app, "usesCleartextTraffic"), "networkSecurityConfig": nsc,
                        "fullBackupContent": attr(app, "fullBackupContent"), "testOnly": truthy(attr(app, "testOnly"))},
        "permissions": perms, "custom_permissions": custom_perms, "components": components,
        "meta_data": meta, "findings": [f.as_dict() for f in findings],
    }


def add_nsc_findings(nsc_attr: str, res_dir: str, add) -> None:
    name = nsc_attr.split("/")[-1]
    path = os.path.join(res_dir, "xml", name + ".xml")
    if not os.path.exists(path):
        return
    text = open(path, encoding="utf-8", errors="replace").read()
    if re.search(r'cleartextTrafficPermitted="true"', text):
        add("nsc-cleartext", "high", "network security config permits cleartext", "network-security-config",
            "cleartextTrafficPermitted=true", "Check for network security config (cleartext traffic allowed)")
    if re.search(r'<certificates[^>]*src="user"', text):
        add("nsc-user-ca", "medium", "network security config trusts user-installed CAs", "network-security-config",
            'src="user"', "Test for proxy detection and SSL interception resistance")
    if re.search(r"<pin-set", text):
        add("nsc-pin", "info", "certificate pins configured in network security config", "network-security-config",
            "check pin expiry and backup pins", "Check for certificate pinning implementation in network calls")
    if re.search(r"<debug-overrides", text):
        add("nsc-debug-overrides", "low", "debug-overrides present; confirm not in release", "network-security-config", "",
            "Test for debug-only certificate pinning bypass")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifest")
    ap.add_argument("--res-dir", help="decoded res directory (for the network security config file)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res_dir = args.res_dir or os.path.join(os.path.dirname(args.manifest), "res")
    data = audit(args.manifest, res_dir if os.path.isdir(res_dir) else None)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"package={data.get('package')} targetSdk={data.get('targetSdk')} components={len(data.get('components', []))}")
        for f in sorted(data.get("findings", []), key=lambda f: ["critical", "high", "medium", "low", "info"].index(f["severity"])):
            print(f"[{f['severity']:>6}] {f['rule']}: {f['title']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
