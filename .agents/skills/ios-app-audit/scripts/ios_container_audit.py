#!/usr/bin/env python3
"""Offline audit of an iOS app's data: container, app groups, backup, keychain and protection dumps.

Inputs (any combination; all are files you pulled from your own test device):
  --container DIR          app data container (Documents/, Library/, tmp/) from `ios_device.py --pull-container`
  --group DIR              app group container (repeatable)
  --backup DIR --bundle ID unencrypted iTunes/Finder backup made with `ios_device.py --backup-approved`;
                           the app's AppDomain, AppDomainGroup and AppDomainPlugin files are rebuilt and scanned
  --keychain-json FILE     output of frida/keychain_dump.js (JSON array or IOSAUDIT log lines)
  --protection-json FILE   output of frida/file_protection.js
  --keyboard-dir DIR       copy of /var/mobile/Library/Keyboard (jailbroken test device; markers only)
  --logs DIR               syslog captures and crash reports (ios_device.py --syslog / --crashlogs)
  --diff BEFORE AFTER      compare two container snapshots (logout, clear data, uninstall and reinstall)
  --marker TEXT            known test value (password, card, token) to search for everywhere (repeatable)

Checks: plists and UserDefaults (sensitive keys and values), SQLite and CoreData (tables, sensitive
columns, plaintext values, WAL/SHM/journal, freelist pages, SQLCipher), NSURLCache Cache.db (cached
URLs and bodies), Cookies.binarycookies (flags, persistence), Realm encryption, snapshots, tmp
residue, POSIX permissions, backup inclusion, keychain accessibility classes, file protection classes.
Values are never written to the report: only redacted previews, lengths, and tags.

Usage:
  ios_container_audit.py --container artifacts/com.x/container --marker 'Pw!mark-7731' --out artifacts/com.x/container.json
  ios_container_audit.py --backup ~/backup/UDID --bundle com.x --out artifacts/com.x/backup.json
  ios_container_audit.py --diff snapA snapB --marker 'Pw!mark-7731' --out artifacts/com.x/residue.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import sys
import tempfile
import urllib.parse
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ios_common import (ARTIFACTS, Finding, SENSITIVE_NAME_RE, classify_value, find_secrets, ids, load_plist,  # noqa: E402
                        redact_value, snippet, sort_findings, write_json)

SQLITE_HEADER = b"SQLite format 3\x00"
TEXT_EXT = (".json", ".txt", ".log", ".xml", ".html", ".htm", ".js", ".csv", ".ips", ".crash", ".strings", ".yaml", ".yml")
PDMN = {"ak": "WhenUnlocked", "ck": "AfterFirstUnlock", "dk": "Always", "aku": "WhenUnlockedThisDeviceOnly",
        "cku": "AfterFirstUnlockThisDeviceOnly", "dku": "AlwaysThisDeviceOnly", "akpu": "WhenPasscodeSetThisDeviceOnly"}


class Ctx:
    def __init__(self, markers: list[str]):
        self.findings: list[dict] = []
        self.markers = [m for m in markers if m]
        self.marker_hits: list[dict] = []
        self.patterns = []
        for m in self.markers:
            b = m.encode()
            self.patterns += [(m, "utf8", b), (m, "utf16le", m.encode("utf-16-le")),
                              (m, "urlencoded", urllib.parse.quote(m, safe="").encode()),
                              (m, "base64", base64.b64encode(b).rstrip(b"="))]

    def add(self, rule, sev, title, where="", evidence="", *pats):
        self.findings.append(Finding(rule, sev, title, where, snippet(evidence, 300), ids(*pats) if pats else []).as_dict())

    def search_markers(self, data: bytes, where: str) -> list[str]:
        hit = []
        for m, enc, pat in self.patterns:
            if pat and pat in data:
                hit.append(f"{enc}")
                self.marker_hits.append({"marker": redact_value(m), "encoding": enc, "where": where})
        return hit


def area(rel: str) -> str:
    r = rel.replace("\\", "/")
    for key, name in (("Library/Preferences/", "UserDefaults/plist"), ("Library/Caches/Snapshots", "snapshot"),
                      ("Library/SplashBoard/Snapshots", "snapshot"), ("Library/Caches/", "cache"),
                      ("Library/Cookies/", "cookies"), ("Library/HTTPStorages/", "cookies"), ("Library/WebKit/", "webkit"),
                      ("Library/Application Support/", "application-support"), ("Documents/", "documents"),
                      ("tmp/", "tmp"), ("Library/Saved Application State", "saved-state"), ("Library/", "library")):
        if r.startswith(key) or f"/{key}" in r:
            return name
    return "other"


AREA_IDS = {
    "cache": [r"cache directories", r"Cache directory residue", r"cached data", r"URLSession cache"],
    "tmp": [r"tmp directories", r"temporary files", r"tmp directory residue"],
    "documents": [r"Documents/Library", r"Documents directory"],
    "UserDefaults/plist": [r"UserDefaults", r"plist files"],
    "cookies": [r"cookie"],
    "webkit": [r"WKWebView content retention", r"WebView"],
    "snapshot": [r"backgrounding behavior", r"screenshot prevention", r"snapshot"],
}


# --------------------------------------------------------------------------- plists
def walk_plist(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_plist(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:500]):
            yield from walk_plist(v, f"{path}[{i}]")
    else:
        yield path, obj


def audit_plist(ctx: Ctx, path: str, rel: str, report: dict) -> None:
    pl = load_plist(path)
    if pl is None:
        return
    is_defaults = "Library/Preferences/" in rel.replace("\\", "/")
    hits = []
    for kpath, val in walk_plist(pl):
        key = kpath.rsplit("/", 1)[-1]
        if isinstance(val, (bytes, bytearray)):
            sval = val[:4096].decode("utf-8", "ignore")
        else:
            sval = str(val)
        if not sval or sval in ("0", "1", "True", "False"):
            continue
        tags = classify_value(sval)
        sens = bool(SENSITIVE_NAME_RE.search(key)) and len(sval) >= 4 and not re.match(r"^(NS|Apple|AK|com\.apple)", key)
        if sens or tags:
            hits.append({"key": kpath[:120], "value": redact_value(sval), "tags": tags})
        ctx.search_markers(sval.encode("utf-8", "ignore"), f"{rel}:{kpath[:80]}")
    if hits:
        what = "UserDefaults" if is_defaults else "plist"
        sev = "high" if any("jwt" in h["tags"] or re.search(r"(?i)pass|secret|token|cvv|pin", h["key"]) for h in hits) else "medium"
        ctx.add(f"{'userdefaults' if is_defaults else 'plist'}-sensitive", sev,
                f"{what} holds {len(hits)} sensitive-looking values", rel,
                "; ".join(f"{h['key']}={h['value']} {h['tags'] or ''}" for h in hits[:6]),
                r"UserDefaults", r"plaintext credentials in plist", r"UserDefaults after uninstall")
    report.setdefault("plists", []).append({"file": rel, "userdefaults": is_defaults, "sensitive": hits[:50]})


# --------------------------------------------------------------------------- sqlite
def audit_sqlite(ctx: Ctx, path: str, rel: str, report: dict, in_backup: bool) -> None:
    with open(path, "rb") as fh:
        head = fh.read(100)
    rec = {"file": rel, "wal": os.path.exists(path + "-wal"), "shm": os.path.exists(path + "-shm"),
           "journal": os.path.exists(path + "-journal")}
    if not head.startswith(SQLITE_HEADER):
        rec["encrypted_or_not_sqlite"] = True
        report.setdefault("databases", []).append(rec)
        ctx.add("db-encrypted", "info", "database file without a SQLite header (SQLCipher or other encryption)", rel, "",
                r"SQLCipher", r"SQLite databases for sensitive data")
        return
    tmp = tempfile.mkdtemp(prefix="iosdb-")
    try:
        copy = os.path.join(tmp, "db.sqlite")
        shutil.copy2(path, copy)
        for sfx in ("-wal", "-shm"):
            if os.path.exists(path + sfx):
                shutil.copy2(path + sfx, copy + sfx)
        con = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        cur = con.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        rec["tables"] = len(tables)
        rec["coredata"] = "Z_METADATA" in tables or "Z_PRIMARYKEY" in tables
        rec["freelist_pages"] = cur.execute("PRAGMA freelist_count").fetchone()[0]
        rec["journal_mode"] = cur.execute("PRAGMA journal_mode").fetchone()[0]
        rec["secure_delete"] = cur.execute("PRAGMA secure_delete").fetchone()[0]
        sens_cols, value_hits = [], []
        is_cache = "cfurl_cache_response" in tables
        for t in tables[:200]:
            try:
                cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{t}")')]
            except sqlite3.DatabaseError:
                continue
            for c in cols:
                if SENSITIVE_NAME_RE.search(c):
                    sens_cols.append(f"{t}.{c}")
            try:
                rows = cur.execute(f'SELECT * FROM "{t}" LIMIT 300').fetchall()
            except sqlite3.DatabaseError:
                continue
            for row in rows:
                for c, v in zip(cols, row):
                    if v is None:
                        continue
                    if isinstance(v, (bytes, bytearray)):
                        b = bytes(v[:65536])
                        ctx.search_markers(b, f"{rel}:{t}.{c}")
                        sv = b.decode("utf-8", "ignore")
                    else:
                        sv = str(v)
                        ctx.search_markers(sv.encode(), f"{rel}:{t}.{c}")
                    tags = classify_value(sv)
                    if tags or (SENSITIVE_NAME_RE.search(c) and len(sv) >= 6):
                        value_hits.append({"column": f"{t}.{c}", "value": redact_value(sv), "tags": tags})
        rec["sensitive_columns"] = sens_cols[:50]
        rec["sensitive_values"] = value_hits[:30]
        if is_cache:
            urls = [r[0] for r in cur.execute("SELECT request_key FROM cfurl_cache_response LIMIT 500")]
            rec["cached_urls"] = len(urls)
            api = [u for u in urls if re.search(r"(?i)/api/|graphql|token|auth|account|user|profile", u or "")]
            red = [re.sub(r"=([^&]{4,})", lambda m: "=" + redact_value(m.group(1)), u) for u in api[:10]]
            if urls:
                ctx.add("nsurlcache-responses", "medium" if api else "low",
                        f"NSURLCache Cache.db holds {len(urls)} cached responses ({len(api)} API/account URLs)", rel, " | ".join(red),
                        r"cache directories", r"network response cache", r"URLSession cache", r"HTTP cache directory")
        con.close()
    except sqlite3.DatabaseError as e:
        rec["error"] = str(e)[:200]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    report.setdefault("databases", []).append(rec)
    kind = "CoreData store" if rec.get("coredata") else "SQLite database"
    if rec.get("sensitive_values"):
        ctx.add("db-plaintext-sensitive", "high", f"{kind} holds sensitive values in plaintext", rel,
                "; ".join(f"{h['column']}={h['value']} {h['tags'] or ''}" for h in rec["sensitive_values"][:5]),
                r"CoreData database for sensitive data" if rec.get("coredata") else r"SQLite databases for sensitive data",
                r"CoreData store files are encrypted", r"SQLite database residue")
    elif rec.get("sensitive_columns"):
        ctx.add("db-sensitive-columns", "medium", f"{kind} has sensitive column names (check contents)", rel,
                ", ".join(rec["sensitive_columns"][:8]), r"SQLite databases", r"CoreData database")
    if rec.get("freelist_pages"):
        ctx.add("db-freelist", "low", f"{rec['freelist_pages']} free pages: deleted records may be recoverable", rel,
                f"secure_delete={rec.get('secure_delete')}", r"deleted SQLite records", r"secure deletion", r"CoreData store compaction")
    if rec.get("wal"):
        ctx.add("db-wal", "info", "WAL file present next to the database (check its protection class)", rel + "-wal", "",
                r"WAL", r"SHM files", r"journal files")
    if in_backup:
        ctx.add("db-in-backup", "medium" if rec.get("sensitive_values") else "low", f"{kind} is included in the device backup", rel, "",
                r"backup inclusion", r"data protection on backup", r"CoreData store in backup exclusion")


# --------------------------------------------------------------------------- cookies, realm, generic
def parse_binarycookies(data: bytes) -> list[dict]:
    if data[:4] != b"cook":
        return []
    cookies = []
    n = struct.unpack(">I", data[4:8])[0]
    if n > 10000:
        return []
    sizes = struct.unpack(f">{n}I", data[8:8 + 4 * n])
    off = 8 + 4 * n
    for size in sizes:
        page = data[off:off + size]
        off += size
        if len(page) < 8:
            continue
        count = struct.unpack("<I", page[4:8])[0]
        offs = struct.unpack(f"<{count}I", page[8:8 + 4 * count]) if count < 10000 else ()
        for co in offs:
            c = page[co:]
            if len(c) < 56:
                continue
            csize, _u, flags, _u2, url_o, name_o, path_o, val_o = struct.unpack("<8I", c[:32])
            expiry, created = struct.unpack("<dd", c[40:56])

            def s(o):
                end = c.find(b"\x00", o)
                return c[o:end if end > 0 else o].decode("utf-8", "replace")
            cookies.append({"domain": s(url_o), "name": s(name_o), "path": s(path_o), "value": s(val_o),
                            "secure": bool(flags & 1), "httponly": bool(flags & 4), "expiry_epoch": expiry + 978307200})
    return cookies


def audit_cookies(ctx: Ctx, path: str, rel: str, report: dict) -> None:
    with open(path, "rb") as fh:
        data = fh.read()
    ctx.search_markers(data, rel)
    cookies = parse_binarycookies(data)
    out = []
    for c in cookies:
        sess = bool(SENSITIVE_NAME_RE.search(c["name"]) or re.search(r"(?i)sid|sess|auth|jwt", c["name"]))
        out.append({k: (redact_value(v) if k == "value" else v) for k, v in c.items()} | {"session_like": sess})
        if sess and not c["secure"]:
            ctx.add("cookie-not-secure", "medium", f"session-like cookie {c['name']} for {c['domain']} without Secure", rel, "",
                    r"cookie handling security", r"cookie storage")
        if sess and not c["httponly"]:
            ctx.add("cookie-not-httponly", "low", f"session-like cookie {c['name']} for {c['domain']} without HttpOnly", rel, "",
                    r"cookie handling")
    if any(o["session_like"] for o in out):
        ctx.add("persistent-session-cookies", "low", "session-like cookies persisted on disk (check they are cleared on logout)", rel,
                ", ".join(sorted({o["name"] for o in out if o["session_like"]}))[:200],
                r"cookie storage sensitive data persistence", r"cookie storage data")
    report.setdefault("cookies", []).append({"file": rel, "count": len(out), "cookies": out[:100]})


def audit_generic(ctx: Ctx, path: str, rel: str, size: int) -> None:
    with open(path, "rb") as fh:
        data = fh.read(min(size, 50 * 1024 * 1024))
    ctx.search_markers(data, rel)
    low = rel.lower()
    if low.endswith(".realm"):
        if len(data) > 24 and data[16:20] == b"T-DB":
            ctx.add("realm-unencrypted", "medium", "Realm file is not encrypted", rel, "", r"Realm database", r"encryption at rest")
        else:
            ctx.add("realm-encrypted", "info", "Realm file without plaintext header (encrypted)", rel, "", r"Realm")
        return
    if low.endswith(TEXT_EXT) or (size < 2 * 1024 * 1024 and data[:4096].count(b"\x00") == 0):
        text = data.decode("utf-8", "replace")
        for h in find_secrets(text, rel, limit=10):
            ctx.add(f"stored-{h['type']}", h["severity"], f"{h['type']} stored in a file", rel, h["value"],
                    r"plaintext credentials", r"sensitive data in cache", r"Documents/Library")
        tags = classify_value(text[:200000])
        if tags:
            ctx.add("stored-pii", "medium", f"file contains {', '.join(tags)}", rel, "", r"sensitive data in", r"Documents/Library")


# --------------------------------------------------------------------------- tree scan
def scan_tree(ctx: Ctx, root: str, label: str, report: dict, in_backup: bool = False) -> None:
    inv = Counter()
    posix = []
    snapshots, tmp_files, logs = [], [], []
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if not os.path.islink(os.path.join(dp, d))]
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.islink(p):
                ctx.add("symlink-in-container", "low", "symbolic link inside the container", os.path.relpath(p, root), os.readlink(p)[:200],
                        r"symbolic link", r"symlink")
                continue
            rel = f"{label}/{os.path.relpath(p, root)}".replace("\\", "/")
            try:
                st = os.stat(p)
            except OSError:
                continue
            a = area(rel)
            inv[a] += 1
            if os.name != "nt" and st.st_mode & stat.S_IWOTH:
                posix.append(rel)
            low = f.lower()
            if a == "snapshot" and low.endswith((".ktx", ".png", ".jpeg", ".jpg")):
                snapshots.append(rel)
            if a == "tmp":
                tmp_files.append(rel)
            if low.endswith((".log", ".ips", ".crash")) or "/Logs/" in rel:
                logs.append(rel)
            if low.endswith(("-wal", "-shm", "-journal")):
                with open(p, "rb") as fh:
                    ctx.search_markers(fh.read(50 * 1024 * 1024), rel)
                continue
            with open(p, "rb") as fh:
                head = fh.read(16)
            if head.startswith(SQLITE_HEADER) or low.endswith((".sqlite", ".sqlite3", ".db", ".store")):
                audit_sqlite(ctx, p, rel, report, in_backup)
            elif head.startswith(b"bplist") or low.endswith(".plist"):
                audit_plist(ctx, p, rel, report)
                with open(p, "rb") as fh:
                    ctx.search_markers(fh.read(), rel)
            elif head.startswith(b"cook") or low.endswith(".binarycookies"):
                audit_cookies(ctx, p, rel, report)
            else:
                audit_generic(ctx, p, rel, st.st_size)
    report.setdefault("inventory", {})[label] = dict(inv)
    if snapshots:
        ctx.add("app-snapshots", "medium", f"{len(snapshots)} app switcher snapshots on disk: open them and check for sensitive screens",
                label, ", ".join(snapshots[:5]), r"backgrounding behavior", r"screenshot prevention", r"UIImage cache retention",
                r"payment form screenshot")
    if tmp_files:
        ctx.add("tmp-residue", "low", f"{len(tmp_files)} files left in tmp/", label, ", ".join(tmp_files[:8]),
                r"tmp directories", r"temporary files", r"secure deletion of temporary")
    if logs:
        ctx.add("app-log-files", "low", f"{len(logs)} log or crash files in the container", label, ", ".join(logs[:8]),
                r"crash logs", r"logged without sanitization")
    if posix:
        ctx.add("world-writable", "medium", f"{len(posix)} world-writable files", label, ", ".join(posix[:8]), r"POSIX permissions")
    for a, pats in AREA_IDS.items():
        if inv.get(a) and in_backup:
            ctx.add(f"backup-includes-{a}", "info", f"backup includes {inv[a]} {a} files", label, "", r"backup", *pats)


# --------------------------------------------------------------------------- backup
def rebuild_backup(ctx: Ctx, backup: str, bundle: str, groups: list[str], work: str, report: dict) -> list[tuple[str, str]]:
    manifest = load_plist(os.path.join(backup, "Manifest.plist")) or {}
    info = {"encrypted": bool(manifest.get("IsEncrypted")), "version": manifest.get("Version"),
            "date": str(manifest.get("Date")), "product": (manifest.get("Lockdown") or {}).get("ProductVersion")}
    report["backup"] = info
    if info["encrypted"]:
        ctx.add("backup-encrypted", "info", "backup is encrypted: decrypt it yourself with the test device's backup password "
                "(for example iphone_backup_decrypt) and rerun on the decrypted copy", backup, "", r"backup")
        return []
    db = os.path.join(backup, "Manifest.db")
    if not os.path.isfile(db):
        ctx.add("backup-no-manifest", "info", "no Manifest.db (not a modern iTunes/Finder backup)", backup, "")
        return []
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    rows = con.execute("SELECT fileID, domain, relativePath, flags FROM Files").fetchall()
    con.close()
    want = {f"AppDomain-{bundle}"} | {f"AppDomainGroup-{g}" for g in groups}
    roots: dict[str, str] = {}
    out_root = os.path.join(work, "backup-rebuilt")
    count = 0
    for file_id, domain, relp, flags in rows:
        if not (domain in want or domain.startswith(f"AppDomainPlugin-{bundle}.")):
            continue
        if flags != 1 or not relp:
            continue
        if ".." in relp.split("/") or relp.startswith("/"):
            continue
        src = os.path.join(backup, file_id[:2], file_id)
        if not os.path.isfile(src):
            continue
        dest = os.path.join(out_root, domain, *relp.split("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(src, dest)
        roots[domain] = os.path.join(out_root, domain)
        count += 1
    report["backup"]["app_files"] = count
    report["backup"]["domains"] = sorted(roots)
    if count:
        ctx.add("backup-app-files", "info", f"{count} app files are included in the backup (domains: {', '.join(sorted(roots))})", backup, "",
                r"backup inclusion", r"iTunes/Finder backup", r"data protection on backup")
    keychain_backup = os.path.isfile(os.path.join(backup, "Keychain-backup.plist"))
    report["backup"]["keychain_backup_file"] = keychain_backup
    return [(d, r) for d, r in roots.items()]


# --------------------------------------------------------------------------- keychain and protection
def load_json_or_log(path: str) -> list:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else data.get("items", [])
    except json.JSONDecodeError:
        out = []
        for line in text.splitlines():
            if "IOSAUDIT " in line:
                try:
                    out.append(json.loads(line.split("IOSAUDIT ", 1)[1]))
                except json.JSONDecodeError:
                    pass
        return out


def audit_keychain(ctx: Ctx, path: str, bundle: str | None, report: dict) -> None:
    items = [i for i in load_json_or_log(path) if i.get("type", "keychain") == "keychain"]
    summary = Counter()
    out = []
    for it in items:
        pdmn = it.get("pdmn") or it.get("accessible") or ""
        acc = PDMN.get(pdmn, pdmn)
        summary[acc] += 1
        name = f"{it.get('class', '')}:{it.get('svce', '')}:{it.get('acct', '')}"
        sens = bool(SENSITIVE_NAME_RE.search(name) or it.get("tags"))
        where = f"keychain {name[:80]}"
        if acc in ("Always", "AlwaysThisDeviceOnly"):
            ctx.add("kc-always", "high", f"keychain item readable while locked ({acc})", where, "",
                    r"kSecAttrAccessibleAlways", r"kSecAttrAccessible always", r"protection level")
        elif acc == "AfterFirstUnlock" and sens:
            ctx.add("kc-afu-migrates", "low", "sensitive item with AfterFirstUnlock (not ThisDeviceOnly: restores to other devices)", where, "",
                    r"AfterFirstUnlock", r"migration between devices", r"backup")
        if not it.get("accc") and sens:
            ctx.add("kc-no-access-control", "low", "sensitive item without kSecAttrAccessControl (no user presence/biometry)", where, "",
                    r"without kSecAttrAccessControl", r"UserPresence", r"biometric")
        if it.get("sync") in (1, True, "1"):
            ctx.add("kc-synchronizable", "medium" if sens else "low", "item syncs to iCloud Keychain", where, "",
                    r"kSecAttrSynchronizable")
        agrp = it.get("agrp") or ""
        if bundle and agrp and not agrp.endswith("." + bundle) and agrp != bundle and "apple" not in agrp:
            ctx.add("kc-shared-group", "info", f"item in shared access group {agrp}", where, "", r"access group")
        if it.get("tags") and "jwt" in it.get("tags", []):
            summary["jwt"] += 1
        out.append({"class": it.get("class"), "service": it.get("svce"), "account": redact_value(it.get("acct", "")) if it.get("acct") else "",
                    "accessible": acc, "access_control": bool(it.get("accc")), "sync": it.get("sync"), "group": agrp,
                    "data_len": it.get("dataLen"), "tags": it.get("tags", [])})
    report["keychain"] = {"items": len(items), "accessibility": dict(summary), "detail": out[:300]}


def audit_protection(ctx: Ctx, path: str, report: dict) -> None:
    files = [i for i in load_json_or_log(path) if "protection" in i]
    by_class = Counter(i.get("protection") or "unknown" for i in files)
    weak = []
    db_prot = {}
    for i in files:
        p = i.get("path", "")
        prot = i.get("protection") or ""
        sensitive = bool(re.search(r"(?i)\.(sqlite|sqlite3|db|store|realm|plist|binarycookies)(-wal|-shm|-journal)?$|Cache\.db|Cookies|"
                                   r"Preferences/|keychain|token|session|cred", p))
        base = re.sub(r"-(wal|shm|journal)$", "", p)
        if re.search(r"\.(sqlite|sqlite3|db|store)(-wal|-shm|-journal)?$", p):
            db_prot.setdefault(base, {})[p[len(base):] or "main"] = prot
        if sensitive and prot in ("NSFileProtectionNone", "NSFileProtectionCompleteUntilFirstUserAuthentication", ""):
            weak.append(f"{p.split('/Containers/')[-1][-90:]}={prot or 'none'}")
        if not p.startswith(("/var/mobile/Containers/", "/private/var/mobile/Containers/")) and p:
            ctx.add("file-outside-container", "medium", "app file outside its container", p[-120:], "",
                    r"accesses files outside its designated container", r"isolates data within its sandbox")
    if by_class.get("NSFileProtectionNone"):
        ctx.add("fp-none", "high", f"{by_class['NSFileProtectionNone']} files with NSFileProtectionNone", "file protection", "",
                r"NSFileProtectionNone", r"Data Protection class verification")
    if weak:
        ctx.add("fp-weak-sensitive", "medium", f"{len(weak)} sensitive files readable after first unlock or unprotected", "file protection",
                "; ".join(weak[:6]), r"NSFileProtectionComplete on sensitive", r"file protection after device lock",
                r"protection on cached data", r"CoreData store files")
    for base, parts in db_prot.items():
        if len(set(parts.values())) > 1:
            ctx.add("fp-wal-mismatch", "medium", "database and its WAL/SHM/journal have different protection classes",
                    base[-100:], str(parts), r"WAL files", r"WAL and SHM", r"journal files")
    no_backup_excl = [i for i in files if i.get("excludedFromBackup") is False and re.search(r"(?i)\.(sqlite|db|realm)$", i.get("path", ""))]
    report["file_protection"] = {"files": len(files), "classes": dict(by_class), "weak_sensitive": weak[:100],
                                 "databases_in_backup": len(no_backup_excl)}


# --------------------------------------------------------------------------- diff and logs
def hash_tree(root: str) -> dict[str, str]:
    out = {}
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.islink(p):
                continue
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            out[os.path.relpath(p, root).replace("\\", "/")] = h.hexdigest()
    return out


def diff_trees(ctx: Ctx, before: str, after: str, report: dict) -> None:
    a, b = hash_tree(before), hash_tree(after)
    persisted = sorted(set(a) & set(b))
    unchanged = [p for p in persisted if a[p] == b[p]]
    report["diff"] = {"before_files": len(a), "after_files": len(b), "removed": sorted(set(a) - set(b))[:300],
                      "added": sorted(set(b) - set(a))[:300], "persisted": len(persisted), "persisted_unchanged": unchanged[:300]}
    sens = [p for p in unchanged if re.search(r"(?i)\.(sqlite|db|store|realm|plist|binarycookies)$|Cache\.db|Cookies|Preferences/", p)]
    if sens:
        ctx.add("residue-persisted", "medium", f"{len(sens)} data files unchanged after the action (logout/clear/reinstall)", after,
                ", ".join(sens[:8]), r"data persistence after app deletion", r"secure deletion", r"cleared on logout",
                r"properly deleted when user logs out", r"data recovery after")


def scan_logs(ctx: Ctx, root: str, report: dict) -> None:
    hits = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            with open(p, "rb") as fh:
                data = fh.read(100 * 1024 * 1024)
            rel = os.path.relpath(p, root)
            ctx.search_markers(data, f"logs/{rel}")
            text = data.decode("utf-8", "replace")
            for h in find_secrets(text, f"logs/{rel}", limit=10):
                hits.append(h)
            for m in re.finditer(r"(?i)(password|passwd|token|authorization|bearer|cookie|session|cvv|card)[\"']?\s*[:=]\s*\S{4,}", text):
                hits.append({"type": "sensitive-kv", "severity": "medium", "where": f"logs/{rel}", "value": snippet(m.group(0), 80)})
                if len(hits) > 200:
                    break
    for h in hits[:40]:
        ctx.add(f"log-{h['type']}", h["severity"], "sensitive data in logs or crash reports", h["where"], h["value"],
                r"crash logs", r"logged without sanitization", r"NSLog", r"system log entries", r"crash log residue")
    report["logs"] = {"hits": len(hits)}


def scan_keyboard(ctx: Ctx, root: str, report: dict) -> None:
    files = 0
    found = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            files += 1
            with open(os.path.join(dp, f), "rb") as fh:
                if ctx.search_markers(fh.read(), f"keyboard/{f}"):
                    found.append(f)
    report["keyboard_cache"] = {"files": files, "marker_files": found}
    if found:
        ctx.add("keyboard-cache-marker", "high", "test marker typed in the app appears in the keyboard cache", "keyboard cache",
                ", ".join(found), r"keyboard cache", r"autocorrection", r"Keyboard prediction", r"Keyboard learned words")
    elif ctx.markers:
        ctx.add("keyboard-cache-clean", "info", "test marker not found in the keyboard cache", "keyboard cache", "", r"keyboard cache")


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--container")
    ap.add_argument("--group", action="append", default=[])
    ap.add_argument("--backup")
    ap.add_argument("--bundle", help="bundle id (backup domain filter and keychain group checks)")
    ap.add_argument("--group-id", action="append", default=[], help="app group id to include from a backup (repeatable)")
    ap.add_argument("--keychain-json")
    ap.add_argument("--protection-json")
    ap.add_argument("--keyboard-dir")
    ap.add_argument("--logs")
    ap.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"))
    ap.add_argument("--marker", action="append", default=[], help="known test value to search for (repeatable)")
    ap.add_argument("--out")
    args = ap.parse_args()
    if not any([args.container, args.group, args.backup, args.keychain_json, args.protection_json, args.keyboard_dir, args.logs, args.diff]):
        ap.error("give at least one input")
    if args.backup and not args.bundle:
        ap.error("--backup needs --bundle")

    ctx = Ctx(args.marker)
    report: dict = {"inputs": {k: v for k, v in vars(args).items() if v and k != "marker"}, "markers": len(ctx.markers)}
    work = tempfile.mkdtemp(prefix="ios-container-", dir=ARTIFACTS if os.path.isdir(ARTIFACTS) else None)
    try:
        if args.container:
            scan_tree(ctx, args.container, "container", report)
        for g in args.group:
            scan_tree(ctx, g, "group:" + os.path.basename(g.rstrip("/\\")), report)
        if args.backup:
            for domain, root in rebuild_backup(ctx, args.backup, args.bundle, args.group_id, work, report):
                scan_tree(ctx, root, "backup:" + domain, report, in_backup=True)
        if args.keychain_json:
            audit_keychain(ctx, args.keychain_json, args.bundle, report)
        if args.protection_json:
            audit_protection(ctx, args.protection_json, report)
        if args.keyboard_dir:
            scan_keyboard(ctx, args.keyboard_dir, report)
        if args.logs:
            scan_logs(ctx, args.logs, report)
        if args.diff:
            diff_trees(ctx, args.diff[0], args.diff[1], report)
            scan_tree(ctx, args.diff[1], "after", report)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if ctx.marker_hits:
        where = sorted({h["where"] for h in ctx.marker_hits})
        ctx.add("marker-found", "high", f"test marker found in {len(where)} places", "", ", ".join(where[:10]),
                r"plaintext", r"sensitive data in", r"residue", r"persistence", r"cleared on logout")
    report["marker_hits"] = ctx.marker_hits[:500]
    seen, uniq = set(), []
    for f in ctx.findings:
        k = (f["rule"], f["where"], f["title"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    report["findings"] = sort_findings(uniq)
    out = args.out or os.path.join(ARTIFACTS, args.bundle or "ios-app", "ios-container.json")
    write_json(out, report)
    c = Counter(f["severity"] for f in report["findings"])
    print(f"findings: {len(report['findings'])} {dict(c)}  marker hits: {len(ctx.marker_hits)}  report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
