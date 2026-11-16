#!/usr/bin/env python3
"""Inventory object identifiers in HAR captures and URL lists (offline).

Usage:
  id_extract.py A.har [B.har ...] [--urls urls.txt ...] [--responses]
  id_extract.py --decode VALUE            # classify / decode a single identifier

Finds identifiers in URL path segments, query strings, form and JSON bodies
(with JSON paths), identity-looking headers and cookies, and optionally JSON
response bodies (--responses: IDs exposed to the caller, useful for ID-16).
Classifies each value: int, UUID (version, variant, v1/v6/v7 timestamp, nil/max/
repeated patterns), MongoDB ObjectId (timestamp), ULID, snowflake, hex, hash
(md5/sha1/sha256 length), base64 (decoded, JSON-aware).

Output TSV: source  location  key  type  value  decoded  request
"""
import argparse
import base64
import binascii
import json
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, unquote, urlsplit

ID_KEY = re.compile(r"(^|[_\-.])(id|ids|uid|uuid|guid|key|ref|no|num|number|token|cursor|slug)$|"
                    r"(id|Id|ID|Uuid|UUID|Guid)$|^(user|account|owner|org|tenant|customer|member|order|invoice|"
                    r"file|doc|document|project|team|group|message|conversation|thread|ticket|cursor|after|before|"
                    r"offset|page)", re.I)
HDR_ID = re.compile(r"^x-.*(id|user|account|tenant|org|customer|requester)", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")
OBJID_RE = re.compile(r"^[0-9a-fA-F]{24}$")
ULID_RE = re.compile(r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$")
HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]{8,}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_-]{8,}={0,2}$")
GREGORIAN = datetime(1582, 10, 15, tzinfo=timezone.utc)
NOW = datetime.now(timezone.utc)


def plausible(dt):
    return datetime(2000, 1, 1, tzinfo=timezone.utc) <= dt <= NOW + timedelta(days=365)


def classify(v):
    """Return (type, decoded-info) or (None, None) if not an identifier-looking value."""
    s = unquote(str(v)).strip()
    if not s or len(s) > 512:
        return None, None
    if re.fullmatch(r"-?\d{1,19}", s):
        n = int(s)
        info = ""
        if n >= 10 ** 17:  # snowflake-style
            for name, epoch in (("twitter", 1288834974657), ("discord", 1420070400000)):
                ms = (n >> 22) + epoch
                dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
                if plausible(dt):
                    info += f"snowflake({name}) ts={dt.isoformat()} "
        return "int", (info or f"{'sequential-looking' if 0 <= n < 10 ** 9 else 'large int'}").strip()
    if UUID_RE.match(s):
        u = uuid.UUID(s)
        h = u.hex
        if h == "0" * 32:
            return "uuid-nil", "NIL UUID - often a fixed/system/test identity"
        if h == "f" * 32:
            return "uuid-max", "MAX UUID"
        if len(set(h)) <= 2:
            return "uuid-fixed", "repeated-digit UUID - fixed identifier (check privileged accounts)"
        ver = int(h[12], 16)
        var = int(h[16], 16)
        variant = "RFC" if 8 <= var <= 0xb else ("MS" if var in (0xc, 0xd) else "NCS/other")
        info = f"v{ver} variant={variant}"
        if ver == 1:
            dt = GREGORIAN + timedelta(microseconds=u.time // 10)
            info += f" ts={dt.isoformat()} node={h[20:]} clock_seq={h[16:20]} -> time-ordered, predictable (sandwich)"
        elif ver == 6:
            t = (int(h[0:12], 16) << 12) | int(h[13:16], 16)
            dt = GREGORIAN + timedelta(microseconds=t // 10)
            info += f" ts={dt.isoformat()} -> time-ordered"
        elif ver == 7:
            dt = datetime.fromtimestamp(int(h[0:12], 16) / 1000, tz=timezone.utc)
            info += f" ts={dt.isoformat()} -> time-ordered (74 random bits)"
        elif ver in (3, 5):
            info += " name-based hash (MD5/SHA1 of namespace+name) - computable if the name is known"
        elif ver == 4:
            info += " random"
        return "uuid", info
    if OBJID_RE.match(s):
        ts = int(s[:8], 16)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        if plausible(dt):
            return "objectid", f"ts={dt.isoformat()} process={s[8:18]} counter={int(s[18:], 16)} -> neighbours predictable"
        return "hex96", "24 hex chars"
    if ULID_RE.match(s):
        alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        ms = 0
        for c in s[:10]:
            ms = ms * 32 + alphabet.index(c)
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        if plausible(dt):
            return "ulid", f"ts={dt.isoformat()} -> time-ordered"
    if HEX_RE.match(s):
        body = s[2:] if s.lower().startswith("0x") else s
        hashes = {32: "md5?", 40: "sha1?", 64: "sha256?"}
        if len(body) in hashes:
            return "hash", f"{hashes[len(body)]} - check md5/sha1 of known ids/emails"
        if len(body) <= 16:
            return "hex", f"= {int(body, 16)}"
        return "hex", f"{len(body)} hex chars"
    if B64_RE.match(s) and len(s) >= 8:
        try:
            raw = base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            raw = b""
        if raw and all(32 <= b < 127 for b in raw):
            txt = raw.decode()
            try:
                obj = json.loads(txt)
                return "base64-json", json.dumps(obj)[:200]
            except ValueError:
                pass
            if re.search(r"\d", txt) and len(txt) <= 120:
                return "base64", txt
    return None, None


def walk_json(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_json(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            yield from walk_json(v, f"{path}[{i}]")
    elif isinstance(obj, (str, int)) and not isinstance(obj, bool):
        yield path, obj


def consider(rows, seen, source, loc, key, value, req, require_key=False):
    t, info = classify(value)
    if not t:
        return
    last = re.split(r"[.\[]", key)[-1] if key else ""
    keyish = bool(ID_KEY.search(last)) if last else False
    if require_key and not keyish and t in ("int", "hex", "base64"):
        return
    if t == "int" and not keyish and loc not in ("path",):
        return
    sig = (loc, key, str(value))
    if sig in seen:
        return
    seen.add(sig)
    rows.append((source, loc, key, t, str(value), info, req))


def from_url(rows, seen, source, method, url, req_label):
    u = urlsplit(url)
    segs = [s for s in u.path.split("/") if s]
    for i, seg in enumerate(segs):
        prev = segs[i - 1] if i else ""
        t, _ = classify(seg)
        if t and not re.fullmatch(r"v\d+", seg):
            consider(rows, seen, source, "path", f"/{prev}/{{}}" if prev else "/{}", seg, req_label)
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        consider(rows, seen, source, "query", k, v, req_label)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("har", nargs="*")
    ap.add_argument("--urls", action="append", default=[])
    ap.add_argument("--responses", action="store_true", help="also scan JSON response bodies")
    ap.add_argument("--decode")
    a = ap.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if a.decode:
        t, info = classify(a.decode)
        print(f"type: {t or 'unrecognised'}\ninfo: {info or '-'}")
        return
    if not a.har and not a.urls:
        sys.exit(__doc__)

    rows, seen = [], set()
    for path in a.har:
        with open(path, encoding="utf-8", errors="replace") as fh:
            entries = json.load(fh).get("log", {}).get("entries", [])
        src = path.replace("\\", "/").split("/")[-1]
        for e in entries:
            req, res = e.get("request", {}), e.get("response", {})
            m, url = req.get("method", "GET"), req.get("url", "")
            if re.search(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|map)(\?|$)", url, re.I):
                continue
            label = f"{m} {urlsplit(url).path[:80]}"
            from_url(rows, seen, src, m, url, label)
            for h in req.get("headers", []):
                if HDR_ID.match(h.get("name", "")):
                    consider(rows, seen, src, "header", h["name"], h.get("value", ""), label)
            for c in req.get("cookies", []) or []:
                consider(rows, seen, src, "cookie", c.get("name", ""), c.get("value", ""), label, require_key=True)
            pd = req.get("postData") or {}
            text = pd.get("text") or ""
            if text:
                try:
                    obj = json.loads(text)
                    for p, v in walk_json(obj):
                        consider(rows, seen, src, "json", p, v, label)
                except ValueError:
                    for k, v in parse_qsl(text, keep_blank_values=True):
                        consider(rows, seen, src, "form", k, v, label)
            if a.responses:
                body = ((res.get("content") or {}).get("text") or "")[:500000]
                if body[:1] in "{[":
                    try:
                        for p, v in walk_json(json.loads(body)):
                            consider(rows, seen, src, "response", p, v, label, require_key=True)
                    except ValueError:
                        pass
    for upath in a.urls:
        with open(upath, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("http"):
                    from_url(rows, seen, upath.replace("\\", "/").split("/")[-1], "GET", line, line[:120])

    print("source\tlocation\tkey\ttype\tvalue\tdecoded\trequest")
    for r in rows:
        print("\t".join(x.replace("\t", " ") for x in r))
    types = {}
    for r in rows:
        types[r[3]] = types.get(r[3], 0) + 1
    print(f"# {len(rows)} identifiers: {types}", file=sys.stderr)


if __name__ == "__main__":
    main()
