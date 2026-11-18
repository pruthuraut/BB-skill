#!/usr/bin/env python3
"""Offline self-test for the iOS audit scripts. Builds synthetic fixtures in a temp directory and
checks the expected findings. No device and no network (the AASA check uses a local HTTP server and
a temporary scope file).

Fixtures: a fat Mach-O with load commands, symbols, string sections and a code-signature superblob
(CodeDirectory + XML entitlements); an IPA with Info.plist, ATS exceptions, URL schemes, provisioning
profile, GoogleService-Info.plist, CoreData model, share and keyboard extensions, an old AFNetworking
framework, bundled secrets and a .p12; an app container with UserDefaults, SQLite with freelist
pages, Cache.db, binarycookies, Realm, snapshot and tmp residue; an unencrypted backup with a
path-traversal entry; keychain and file-protection dumps; and an AASA file with the wrong appID.

Usage: python3 -I selftest.py [--keep]
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import plistlib
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
BUNDLE = "com.example.testapp"
TEAM = "ABCDE12345"
MARKER = "Pw!mark-7731"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstu"


# --------------------------------------------------------------------------- Mach-O builder
def code_signature(ident: str, team: str, ents: dict | None) -> bytes:
    ident_b, team_b = ident.encode() + b"\0", team.encode() + b"\0"
    hdr = 52
    cd_len = hdr + len(ident_b) + len(team_b)
    cd = struct.pack(">IIIIIIIIIBBBBIII", 0xFADE0C02, cd_len, 0x20400, 0, cd_len, hdr, 0, 0, 0x1000, 32, 2, 0, 12, 0, 0,
                     hdr + len(ident_b)) + ident_b + team_b
    blobs = [(0, cd)]
    if ents is not None:
        x = plistlib.dumps(ents, fmt=plistlib.FMT_XML)
        blobs.append((5, struct.pack(">II", 0xFADE7171, 8 + len(x)) + x))
    off = 12 + 8 * len(blobs)
    index, body = b"", b""
    for typ, b in blobs:
        index += struct.pack(">II", typ, off + len(body))
        body += b
    total = 12 + len(index) + len(body)
    return struct.pack(">III", 0xFADE0CC0, total, len(blobs)) + index + body


def macho(imports, cstrings, methnames, classnames, ents, ident, pie=True, cryptid=0, fat=True) -> bytes:
    def strsect(items):
        return b"".join(s.encode() + b"\0" for s in items)
    secs = [("__cstring", strsect(cstrings)), ("__objc_methname", strsect(methnames)), ("__objc_classname", strsect(classnames))]
    dylibs = ["/System/Library/Frameworks/Foundation.framework/Foundation", "/usr/lib/swift/libswiftCore.dylib",
              "@rpath/AFNetworking.framework/AFNetworking"]
    cmds = []
    seg_size = 72 + 80 * len(secs)
    dl_cmds = []
    for d in dylibs:
        name = d.encode() + b"\0"
        size = (24 + len(name) + 7) & ~7
        dl_cmds.append(struct.pack("<IIIIII", 0xC, size, 24, 2, 0x10000, 0x10000) + name.ljust(size - 24, b"\0"))
    sizeofcmds = seg_size + sum(len(c) for c in dl_cmds) + 24 + 24 + 24 + 16
    data_off = 32 + sizeofcmds
    data_off = (data_off + 15) & ~15
    payload = b""
    sect_hdrs = b""
    for name, content in secs:
        off = data_off + len(payload)
        sect_hdrs += struct.pack("<16s16sQQIIIIIIII", name.encode(), b"__TEXT", 0x100000000 + off, len(content), off, 0, 0, 0, 0, 0, 0, 0)
        payload += content
    seg = struct.pack("<II16sQQQQiiII", 0x19, seg_size, b"__TEXT", 0x100000000, 0x4000, 0, 0x4000, 5, 5, len(secs), 0) + sect_hdrs
    strtab = b"\0"
    nlist = b""
    for imp in imports:
        nlist += struct.pack("<IBBHQ", len(strtab), 0x01, 0, 0, 0)
        strtab += imp.encode() + b"\0"
    symoff = data_off + len(payload)
    payload += nlist
    stroff = data_off + len(payload)
    payload += strtab
    while len(payload) % 16:
        payload += b"\0"
    sig = code_signature(ident, TEAM, ents)
    sigoff = data_off + len(payload)
    payload += sig
    cmds = [seg] + dl_cmds + [
        struct.pack("<IIIIII", 0x2C, 24, 0x4000, 0x1000, cryptid, 0),
        struct.pack("<IIIIII", 0x32, 24, 2, 0x000F0000, 0x00110000, 0),
        struct.pack("<IIIIII", 0x2, 24, symoff, len(imports), stroff, len(strtab)),
        struct.pack("<IIII", 0x1D, 16, sigoff, len(sig)),
    ]
    blob = b"".join(cmds)
    assert len(blob) == sizeofcmds, (len(blob), sizeofcmds)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, len(cmds), sizeofcmds, 0x00200085 if pie else 0x85, 0)
    thin = (header + blob).ljust(data_off, b"\0") + payload
    if not fat:
        return thin
    off = 0x4000
    return (struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">iiIII", 0x0100000C, 0, off, len(thin), 14)).ljust(off, b"\0") + thin


# --------------------------------------------------------------------------- fixtures
def build_ipa(root: str) -> str:
    app = os.path.join(root, "Payload", "TestApp.app")
    os.makedirs(app)
    info = {
        "CFBundleIdentifier": BUNDLE, "CFBundleExecutable": "TestApp", "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "45",
        "MinimumOSVersion": "15.0", "CFBundleURLTypes": [{"CFBundleURLSchemes": ["testapp", "app"]}],
        "LSApplicationQueriesSchemes": ["cydia"], "UIBackgroundModes": ["location", "fetch"],
        "NSCameraUsageDescription": "camera", "UIFileSharingEnabled": True, "API_SECRET_KEY": "s3cr3tvalue123456",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True, "NSExceptionDomains": {
            "api.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True, "NSIncludesSubdomains": True}}},
    }
    with open(os.path.join(app, "Info.plist"), "wb") as fh:
        plistlib.dump(info, fh, fmt=plistlib.FMT_BINARY)
    ents = {"application-identifier": f"{TEAM}.{BUNDLE}", "get-task-allow": True, "keychain-access-groups": [f"{TEAM}.*"],
            "com.apple.security.application-groups": [f"group.{BUNDLE}"], "aps-environment": "development",
            "com.apple.developer.associated-domains": ["applinks:links.example.com", "webcredentials:links.example.com"],
            "com.apple.developer.usernotifications.critical-alerts": True}
    imports = ["_NSLog", "_strcpy", "_rand", "_CC_MD5", "_CCCrypt", "_kSecAttrAccessibleAlways", "_SecItemAdd",
               "_OBJC_CLASS_$_LAContext", "_OBJC_CLASS_$_UIWebView", "_OBJC_CLASS_$_WKWebView", "_OBJC_CLASS_$_UIPasteboard",
               "_NSFileProtectionNone", "___stack_chk_guard", "_objc_release", "_sqlite3_exec", "_OBJC_CLASS_$_SKPaymentQueue",
               "_OBJC_CLASS_$_UNUserNotificationCenter", "__dyld_get_image_name", "_OBJC_CLASS_$_AVCaptureDevice",
               "_OBJC_CLASS_$_CLLocationManager", "_OBJC_CLASS_$_ASIdentifierManager", "_OBJC_CLASS_$_AFSecurityPolicy"]
    cstr = ["/Applications/Cydia.app", "http://api.example.com/v1/login", "https://api.example.com/v1/user?token=abcdef123456",
            "ws://chat.example.com/socket", "testapp://account/settings", "/account/transfer",
            "SELECT * FROM users WHERE name = '%@'", "allowFileAccessFromFileURLs", "https://buy.itunes.apple.com/verifyReceipt",
            "AKIAABCDEFGHIJKLMNOP", "redirect_url", "url", "token", JWT, "setAllowInvalidCertificates:"]
    meth = ["evaluatePolicy:localizedReason:reply:", "application:openURL:options:", "predicateWithFormat:",
            "addScriptMessageHandler:name:", "URLSession:didReceiveChallenge:completionHandler:", "appStoreReceiptURL"]
    with open(os.path.join(app, "TestApp"), "wb") as fh:
        fh.write(macho(imports, cstr, meth, ["AppDelegate", "FIRApp"], ents, BUNDLE))
    prof = {"Name": "Test Dev", "TeamIdentifier": [TEAM], "ProvisionedDevices": ["00008030-001"], "ExpirationDate": "2027-01-01",
            "Entitlements": {k: v for k, v in ents.items() if k != "com.apple.developer.usernotifications.critical-alerts"}}
    with open(os.path.join(app, "embedded.mobileprovision"), "wb") as fh:
        fh.write(b"0\x82\x10\x00junk-cms" + plistlib.dumps(prof) + b"trailer")
    with open(os.path.join(app, "GoogleService-Info.plist"), "wb") as fh:
        plistlib.dump({"API_KEY": "AIzaSyA1234567890abcdefghijklmnopqrstuv", "PROJECT_ID": "test-proj",
                       "DATABASE_URL": "https://test-proj.firebaseio.com", "STORAGE_BUCKET": "test-proj.appspot.com",
                       "GOOGLE_APP_ID": "1:123:ios:abc"}, fh)
    with open(os.path.join(app, "config.json"), "w") as fh:
        json.dump({"stripe": "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2", "aws": "AKIAQWERTYUIOPASDFGH", "host": "https://staging.example.com"}, fh)
    os.makedirs(os.path.join(app, "Model.momd"))
    with open(os.path.join(app, "Model.momd", "Model.mom"), "wb") as fh:
        plistlib.dump({"$objects": ["$null", "User", "password", "authToken", "email", "NSKeyedUnarchiveFromDataTransformerName"]}, fh,
                      fmt=plistlib.FMT_BINARY)
    share = os.path.join(app, "PlugIns", "Share.appex")
    os.makedirs(share)
    with open(os.path.join(share, "Info.plist"), "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": BUNDLE + ".share", "CFBundleExecutable": "Share", "NSExtension": {
            "NSExtensionPointIdentifier": "com.apple.share-services", "NSExtensionAttributes": {"NSExtensionActivationRule": "TRUEPREDICATE"}}}, fh)
    with open(os.path.join(share, "Share"), "wb") as fh:
        fh.write(macho(["_objc_release", "___stack_chk_guard"], ["share"], [], [], {"com.apple.security.application-groups": ["group.other"],
                       "keychain-access-groups": [f"{TEAM}.*"]}, BUNDLE + ".share", fat=False))
    kb = os.path.join(app, "PlugIns", "Keys.appex")
    os.makedirs(kb)
    with open(os.path.join(kb, "Info.plist"), "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": BUNDLE + ".keys", "NSExtension": {"NSExtensionPointIdentifier": "com.apple.keyboard-service",
                       "NSExtensionAttributes": {"RequestsOpenAccess": True}}}, fh)
    fw = os.path.join(app, "Frameworks", "AFNetworking.framework")
    os.makedirs(fw)
    with open(os.path.join(fw, "Info.plist"), "wb") as fh:
        plistlib.dump({"CFBundleIdentifier": "org.cocoapods.AFNetworking", "CFBundleShortVersionString": "2.5.1"}, fh)
    os.makedirs(os.path.join(app, "Settings.bundle"))
    with open(os.path.join(app, "Settings.bundle", "Root.plist"), "wb") as fh:
        plistlib.dump({"PreferenceSpecifiers": [{"Type": "PSTextFieldSpecifier", "Key": "password"}]}, fh)
    with open(os.path.join(app, "client.p12"), "wb") as fh:
        fh.write(b"\x30\x82\x01\x00fake")
    ipa = os.path.join(root, "TestApp.ipa")
    with zipfile.ZipFile(ipa, "w") as z:
        for dp, dn, fn in os.walk(os.path.join(root, "Payload")):
            for f in fn:
                p = os.path.join(dp, f)
                z.write(p, os.path.relpath(p, root))
        z.writestr("../../evil.txt", "zip slip")
    shutil.rmtree(os.path.join(root, "Payload"))
    return ipa


def binarycookies(cookies) -> bytes:
    page_cookies = []
    for domain, name, path, value, flags in cookies:
        strs = b""
        offs = []
        for s in (domain, name, path, value):
            offs.append(56 + len(strs))
            strs += s.encode() + b"\0"
        size = 56 + len(strs)
        page_cookies.append(struct.pack("<8I", size, 0, flags, 0, *offs) + b"\0" * 8 + struct.pack("<dd", 8e8, 7e8) + strs)
    n = len(page_cookies)
    hdr = b"\x00\x00\x01\x00" + struct.pack("<I", n)
    base = len(hdr) + 4 * n + 4
    offs, body = [], b""
    for c in page_cookies:
        offs.append(base + len(body))
        body += c
    page = hdr + b"".join(struct.pack("<I", o) for o in offs) + b"\0\0\0\0" + body
    return b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page + b"\0" * 8


def build_container(root: str) -> str:
    c = os.path.join(root, "container")
    for d in ("Documents", "Library/Preferences", f"Library/Caches/{BUNDLE}", "Library/Cookies", "Library/SplashBoard/Snapshots/main", "tmp"):
        os.makedirs(os.path.join(c, d))
    with open(os.path.join(c, "Library/Preferences", BUNDLE + ".plist"), "wb") as fh:
        plistlib.dump({"authToken": JWT, "userEmail": "tester@example.com", "lastLaunch": 123}, fh, fmt=plistlib.FMT_BINARY)
    db = os.path.join(c, "Documents", "app.sqlite")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE users(name TEXT, password TEXT, card TEXT, blob BLOB)")
    con.execute("INSERT INTO users VALUES ('bob', ?, '4111111111111111', NULL)", (MARKER,))
    con.executemany("INSERT INTO users VALUES ('x','y','z', ?)", [(b"\x00" * 600,) for _ in range(500)])
    con.commit()
    con.execute("DELETE FROM users WHERE name='x'")
    con.commit()
    con.close()
    cdb = sqlite3.connect(os.path.join(c, f"Library/Caches/{BUNDLE}/Cache.db"))
    cdb.execute("CREATE TABLE cfurl_cache_response(entry_ID INTEGER, request_key TEXT)")
    cdb.execute("INSERT INTO cfurl_cache_response VALUES (1, 'https://api.example.com/api/account?token=abc123456789')")
    cdb.commit()
    cdb.close()
    with open(os.path.join(c, "Library/Cookies/Cookies.binarycookies"), "wb") as fh:
        fh.write(binarycookies([(".example.com", "sessionid", "/", "abcdef123456", 0)]))
    with open(os.path.join(c, "Library/SplashBoard/Snapshots/main/snap.ktx"), "wb") as fh:
        fh.write(b"KTX fake")
    with open(os.path.join(c, "tmp", "upload.tmp"), "wb") as fh:
        fh.write(b"form=1&pw=" + MARKER.encode())
    with open(os.path.join(c, "Documents", "default.realm"), "wb") as fh:
        fh.write(b"\0" * 16 + b"T-DB" + b"\0" * 40)
    return c


def build_backup(root: str, container: str) -> str:
    b = os.path.join(root, "backup", "UDID")
    os.makedirs(b)
    with open(os.path.join(b, "Manifest.plist"), "wb") as fh:
        plistlib.dump({"IsEncrypted": False, "Version": "10.0"}, fh)
    con = sqlite3.connect(os.path.join(b, "Manifest.db"))
    con.execute("CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    rel = f"Library/Preferences/{BUNDLE}.plist"
    for domain, relp in ((f"AppDomain-{BUNDLE}", rel), (f"AppDomain-{BUNDLE}", "../../escape.plist"), ("HomeDomain", "Library/x")):
        fid = hashlib.sha1(f"{domain}-{relp}".encode()).hexdigest()
        os.makedirs(os.path.join(b, fid[:2]), exist_ok=True)
        shutil.copyfile(os.path.join(container, rel), os.path.join(b, fid[:2], fid))
        con.execute("INSERT INTO Files VALUES (?,?,?,1,NULL)", (fid, domain, relp))
    con.commit()
    con.close()
    return b


def run(args, env, expect_rc=0):
    p = subprocess.run([PY, "-I"] + args, capture_output=True, text=True, env=env, cwd=HERE)
    if p.returncode != expect_rc:
        print(p.stdout, p.stderr)
        raise SystemExit(f"FAILED rc={p.returncode}: {' '.join(args[:2])}")
    return p.stdout


def rules(path):
    with open(path, encoding="utf-8") as fh:
        rep = json.load(fh)
    return rep, {f["rule"] for f in rep["findings"]}


def check(name, got, want):
    missing = sorted(set(want) - got)
    print(f"{'ok  ' if not missing else 'FAIL'} {name}: {len(got)} rules" + (f"; missing {missing}" if missing else ""))
    return not missing


def main() -> int:
    keep = "--keep" in sys.argv
    root = tempfile.mkdtemp(prefix="ios-selftest-")
    env = dict(os.environ, IOS_AUDIT_ARTIFACTS=os.path.join(root, "artifacts"))
    ok = True
    try:
        ipa = build_ipa(root)
        out = os.path.join(root, "static.json")
        run(["ios_static.py", "--ipa", ipa, "--out", out, "--work", os.path.join(root, "work"), "--no-tools"], env)
        rep, got = rules(out)
        ok &= check("ios_static", got, [
            "ats-arbitrary-loads", "ats-exception-domain", "url-scheme-generic", "jb-url-scheme-detection", "background-mode-location",
            "itunes-file-sharing", "info-plist-secret-key", "settings-bundle-secret", "get-task-allow", "keychain-group-wildcard",
            "app-groups", "default-data-protection", "ent-critical-alerts", "unsafe-c-functions", "logging-apis", "insecure-random",
            "weak-hash", "commoncrypto", "keychain-accessible-always", "keychain-no-access-control", "biometric-boolean", "uiwebview",
            "webview-file-access", "js-bridge", "pasteboard", "file-protection-none", "nspredicate-format", "sqlite-no-sqlcipher",
            "sql-format-string", "custom-trust-eval", "afn-allow-invalid", "jailbreak-detection", "dylib-injection-detection",
            "no-screen-capture-detection", "third-party-keyboards-allowed", "url-handlers", "notifications", "receipt-validation-on-device",
            "privacy-missing-location", "idfa-without-att", "secret-aws-access-key", "secret-jwt", "secret-stripe-secret-key",
            "bundled-private-key", "firebase-config", "coredata-sensitive-attributes", "coredata-insecure-transformer", "sdk-inventory",
            "afnetworking-old", "cleartext-urls", "cleartext-websocket", "secrets-in-url", "share-truepredicate", "keyboard-extension",
            "extension-group-mismatch", "profile-type", "non-prod-hosts", "associated-domains"])
        main_bin = rep["binaries"]["main"]
        assert main_bin["pie"] and main_bin["stack_canary"] and main_bin["arc"] and main_bin["swift"], main_bin
        assert rep["entitlements"]["team_id"] == TEAM and rep["entitlements_source"] == "code signature"
        assert rep["extraction"]["skipped_unsafe"] == 1, rep["extraction"]
        assert "testapp://account/settings" in rep["deeplinks"]["routes"] and "redirect_url" in rep["deeplinks"]["params_seen"]
        assert all(f["checklist"] for f in rep["findings"] if f["severity"] in ("high", "critical")), "high finding without checklist IDs"
        print("ok   static report structure (fat slice, entitlements, zip-slip guard, routes, checklist IDs)")

        container = build_container(root)
        kc = os.path.join(root, "keychain.log")
        with open(kc, "w") as fh:
            fh.write("noise\nIOSAUDIT " + json.dumps({"type": "keychain", "class": "genp", "svce": "auth-token", "acct": "tester@example.com",
                                                      "pdmn": "dk", "accc": False, "sync": "1", "agrp": f"{TEAM}.shared", "tags": ["jwt"]}) + "\n")
        prot = os.path.join(root, "prot.log")
        base = "/var/mobile/Containers/Data/Application/U/Documents/app.sqlite"
        with open(prot, "w") as fh:
            for p, c in ((base, "NSFileProtectionCompleteUntilFirstUserAuthentication"), (base + "-wal", "NSFileProtectionNone")):
                fh.write("IOSAUDIT " + json.dumps({"type": "file", "path": p, "protection": c}) + "\n")
        backup = build_backup(root, container)
        cout = os.path.join(root, "container.json")
        run(["ios_container_audit.py", "--container", container, "--keychain-json", kc, "--protection-json", prot, "--backup", backup,
             "--bundle", BUNDLE, "--marker", MARKER, "--out", cout], env)
        crep, got = rules(cout)
        ok &= check("ios_container_audit", got, [
            "userdefaults-sensitive", "db-plaintext-sensitive", "db-freelist", "nsurlcache-responses", "cookie-not-secure",
            "persistent-session-cookies", "app-snapshots", "tmp-residue", "realm-unencrypted", "kc-always", "kc-synchronizable",
            "kc-no-access-control", "kc-shared-group", "fp-none", "fp-weak-sensitive", "fp-wal-mismatch", "backup-app-files", "marker-found"])
        assert crep["backup"]["app_files"] == 1, crep["backup"]
        print("ok   backup rebuild skipped the traversal entry")

        before = os.path.join(root, "snapA")
        shutil.copytree(container, before)
        dout = os.path.join(root, "diff.json")
        run(["ios_container_audit.py", "--diff", before, container, "--marker", MARKER, "--out", dout], env)
        ok &= check("residue diff", rules(dout)[1], ["residue-persisted", "marker-found"])

        # deep links: cases + AASA against a local server and a temp scope file
        site = os.path.join(root, "site", "links.example.com", ".well-known")
        os.makedirs(site)
        with open(os.path.join(site, "apple-app-site-association"), "w") as fh:
            json.dump({"applinks": {"details": [{"appIDs": ["OTHER.com.example.other"], "components": [{"/": "*"}]}]}}, fh)
        handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=os.path.join(root, "site"), **k)  # noqa: E731
        http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        ws = os.path.join(root, "ws")
        os.makedirs(os.path.join(ws, "testprog"))
        with open(os.path.join(ws, "testprog", "scope.txt"), "w") as fh:
            fh.write("authorized-by: selftest\ndate: 2026-01-01\nexample.com\n")
        env2 = dict(env, IOS_AASA_TEST_BASE=f"http://127.0.0.1:{srv.server_address[1]}")
        lout = os.path.join(root, "deeplinks.json")
        txt = run(["ios_deeplink.py", "--static", out, "--cases", "--aasa", "--workspace", ws, "--program", "testprog", "--out", lout], env2)
        srv.shutdown()
        lrep, got = rules(lout)
        cats = lrep["cases_by_category"]
        assert {"baseline", "auth", "param", "redirect", "javascript", "malformed", "universal"} <= set(cats), cats
        assert os.path.isfile(lrep["launcher"])
        if any("skipped" in a for a in lrep.get("aasa", [])):
            print("skip AASA check: scope_check.sh could not run here (" + lrep["aasa"][0]["skipped"][:80] + ")")
        else:
            ok &= check("ios_deeplink AASA", got, ["aasa-appid-mismatch", "aasa-wildcard", "aasa-content-type"])
        print(f"ok   ios_deeplink cases {sum(cats.values())} {cats}")

        run(["ios_checklist.py", "init", "--bundle", BUNDLE], env)
        run(["ios_checklist.py", "ingest", "--bundle", BUNDLE, out, cout, lout], env)
        run(["ios_checklist.py", "set", "--bundle", BUNDLE, "IOS-0001..IOS-0003", "passed", "--note", "selftest"], env)
        txt = run(["ios_checklist.py", "report", "--bundle", BUNDLE, "--md", os.path.join(root, "status.md")], env)
        assert "Static Analysis" in txt and "TOTAL" in txt
        status = json.load(open(os.path.join(root, "artifacts", BUNDLE, "ios-checklist-status.json")))
        flagged = sum(1 for r in status["rows"].values() if r["status"] == "flagged")
        print(f"ok   ios_checklist: {flagged} rows flagged; {txt.strip().splitlines()[-1]}")
        print(run(["ios_device.py", "--print-frida", BUNDLE], env).splitlines()[1][:90] + " ...")
    finally:
        if keep:
            print("fixtures kept in", root)
        else:
            shutil.rmtree(root, ignore_errors=True)
    print("SELFTEST " + ("PASSED" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
