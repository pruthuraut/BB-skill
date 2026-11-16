#!/usr/bin/env python3
"""Email DNS posture audit (EM rows) with optional, scope-gated SMTP checks.

DNS (passive, needs dnspython):
  SPF   EM-001/002/003  record count, all-qualifier, recursive DNS-lookup count (limit 10), void lookups
  DKIM  EM-004/005/006  selector sweep (built-in list or --selectors), key type/size, t=y, revoked keys
  DMARC EM-007..012     p, sp, pct, rua/ruf (+ external destination authorization), adkim/aspf, spoofability verdict
  CAA   EM-021, BIMI EM-023, MTA-STS / TLS-RPT (MAIL-007), MX + null MX, MX host resolution (EM-024)
  --subdomains FILE     per subdomain: MX, SPF, null MX, effective DMARC (sp=), spoofable?
SMTP (bounded, --smtp): for each MX host that passes the program's scope gate, one session:
  banner, EHLO extensions, STARTTLS, AUTH, VRFY postmaster vs a random name, EXPN support (EM-018).
  No mail is sent and no relay test is performed (EM-017 relay testing is authorized-only).

Example:
  email_dns_audit.py --domain example.com --subdomains subs.txt --out artifacts/example.com/email_dns.json
  email_dns_audit.py --domain example.com --smtp --target example.com
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import smtplib
import socket
import subprocess
import sys

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit("dnspython is required: pip install dnspython")

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
SCOPE = os.path.join(REPO, "scripts", "scope_check.sh")
SELECTORS = ["default", "dkim", "mail", "email", "selector1", "selector2", "google", "k1", "k2", "k3", "s1", "s2", "smtpapi",
             "mxvault", "mandrill", "mailjet", "pm", "zendesk1", "zendesk2", "amazonses", "ses", "sig1", "everlytickey1",
             "everlytickey2", "dkim1024", "20161025", "20210112", "20230601", "fm1", "fm2", "fm3", "protonmail", "protonmail2",
             "protonmail3", "mx", "smtp", "key1", "key2", "hs1", "hs2", "cm", "mailgun", "krs"]
R = dns.resolver.Resolver()
R.lifetime = 6.0


def txt(name):
    try:
        return ["".join(p.decode("utf-8", "replace") for p in r.strings) for r in R.resolve(name, "TXT")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def rr(name, rtype):
    try:
        return [r.to_text() for r in R.resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def tags(record):
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            out[k.strip().lower()] = v.strip()
    return out


def spf_record(domain):
    recs = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
    return recs


def spf_count(domain, depth=0, seen=None, voids=None):
    """Return (lookup_count, void_count, tree) following include/redirect."""
    seen = seen if seen is not None else set()
    voids = voids if voids is not None else [0]
    if domain in seen or depth > 10:
        return 0, voids[0], {"domain": domain, "loop_or_depth": True}
    seen.add(domain)
    recs = spf_record(domain)
    if not recs:
        voids[0] += 1
        return 0, voids[0], {"domain": domain, "record": None}
    rec = recs[0]
    count, children = 0, []
    for term in rec.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith("include:") or t.startswith("redirect="):
            target = t.split(":", 1)[1] if t.startswith("include:") else t.split("=", 1)[1]
            count += 1
            c, _, child = spf_count(target, depth + 1, seen, voids)
            count += c
            children.append(child)
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
    return count, voids[0], {"domain": domain, "record": rec, "children": children}


def dkim_key_bits(p):
    if not p:
        return None
    try:
        der = base64.b64decode(p + "=" * (-len(p) % 4))
    except Exception:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        k = load_der_public_key(der)
        return getattr(k, "key_size", None)
    except Exception:
        n = len(der)  # SubjectPublicKeyInfo length estimate for RSA keys
        return 512 if n < 100 else 1024 if n < 180 else 2048 if n < 310 else 4096


def dmarc_for(domain):
    recs = [t for t in txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    return (tags(recs[0]), recs) if recs else (None, [])


def org_domain(d):
    parts = d.split(".")
    return ".".join(parts[-3:]) if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") else ".".join(parts[-2:])


def audit_domain(domain, selectors, F):
    rep = {"domain": domain}
    spfs = spf_record(domain)
    rep["spf"] = spfs
    if not spfs:
        F.append(f"EM-001: {domain} has no SPF record")
    elif len(spfs) > 1:
        F.append(f"EM-001: {domain} publishes {len(spfs)} SPF records (permerror)")
    if spfs:
        rec = spfs[0]
        m = re.search(r"([+\-~?]?)all\b", rec)
        q = (m.group(1) or "+") if m else None
        rep["spf_all"] = q
        if q is None and "redirect=" not in rec:
            F.append(f"EM-002: {domain} SPF has no 'all' mechanism (neutral by default)")
        elif q in ("+", "?"):
            F.append(f"EM-002: {domain} SPF ends with '{q}all' (permissive)")
        elif q == "~":
            rep["spf_note"] = "~all (softfail) - acceptable only with enforced DMARC"
        count, voids, tree = spf_count(domain)
        rep["spf_lookups"], rep["spf_void_lookups"] = count, voids
        if count > 10:
            F.append(f"EM-003: {domain} SPF needs {count} DNS lookups (>10 = permerror)")
        if voids > 2:
            F.append(f"EM-003: {domain} SPF has {voids} void lookups (>2 = permerror on many receivers)")
    dk = []
    wild = txt(f"em{secrets.token_hex(6)}._domainkey.{domain}")
    if wild:
        wt = tags(wild[0])
        rep["dkim_wildcard"] = wild[0][:120]
        if wt.get("p", "x") == "":
            F.append(f"EM-004 info: {domain} publishes a wildcard null DKIM record (*._domainkey p=) - domain declares it sends no DKIM-signed mail")
        else:
            F.append(f"EM-006 info: {domain} answers every DKIM selector with the same wildcard key; selector enumeration is not meaningful")
        selectors = []
    for s in selectors:
        recs = txt(f"{s}._domainkey.{domain}")
        recs = [r for r in recs if "p=" in r or "v=DKIM1" in r.upper()]
        if not recs:
            cn = rr(f"{s}._domainkey.{domain}", "CNAME")
            if cn:
                dk.append({"selector": s, "cname": cn[0], "note": "CNAME to provider (resolved TXT checked)"})
            continue
        t = tags(recs[0])
        bits = dkim_key_bits(t.get("p", ""))
        info = {"selector": s, "k": t.get("k", "rsa"), "bits": bits, "testing": "y" in t.get("t", ""), "revoked": t.get("p", "x") == ""}
        dk.append(info)
        if info["revoked"]:
            continue
        if info["k"].lower() == "rsa" and bits and bits < 2048:
            F.append(f"EM-005: DKIM selector '{s}' uses a {bits}-bit RSA key")
        if info["testing"]:
            F.append(f"EM-005: DKIM selector '{s}' has t=y (testing mode)")
    rep["dkim"] = dk
    if not [d for d in dk if not d.get("revoked")] and not wild:
        F.append(f"EM-004: no DKIM key found for {domain} among {len(selectors)} selectors (check a received message's s= tag)")
    elif len(dk) > 1:
        F.append(f"EM-006 info: {len(dk)} DKIM selectors published for {domain}: {[d['selector'] for d in dk]}")
    dm, raw = dmarc_for(domain)
    rep["dmarc"] = raw
    if not dm:
        F.append(f"EM-007/EM-011: {domain} has no DMARC record (spoofable)")
    else:
        p, sp, pct = dm.get("p", "none").lower(), dm.get("sp"), int(re.sub(r"\D", "", dm.get("pct", "100")) or 100)
        if len(raw) > 1:
            F.append(f"EM-007: {domain} publishes multiple DMARC records (ignored by receivers)")
        if p == "none":
            F.append(f"EM-007/EM-011: {domain} DMARC p=none (monitoring only; spoofable)")
        if sp and sp.lower() == "none" and p != "none":
            F.append(f"EM-007/EM-024: {domain} DMARC sp=none (subdomains spoofable)")
        if pct < 100:
            F.append(f"EM-010: {domain} DMARC pct={pct} (only {pct}% of failing mail gets the policy)")
        for tag_, row in (("rua", "EM-008"), ("ruf", "EM-009")):
            if not dm.get(tag_):
                if tag_ == "rua":
                    F.append(f"EM-008: {domain} DMARC has no rua (no aggregate reporting)")
                continue
            for dest in dm[tag_].split(","):
                m = re.search(r"mailto:[^@]+@([^!,\s]+)", dest)
                if m and org_domain(m.group(1).lower()) != org_domain(domain):
                    auth = txt(f"{domain}._report._dmarc.{m.group(1)}")
                    if not any(a.lower().startswith("v=dmarc1") for a in auth):
                        F.append(f"{row}: {tag_} destination {m.group(1)} is external and not authorized via _report._dmarc (reports dropped)")
                    else:
                        rep.setdefault("external_reports", []).append(f"{tag_}:{m.group(1)}")
        if dm.get("ruf"):
            F.append(f"EM-009 info: {domain} requests forensic (ruf) reports to {dm['ruf']} (may contain message samples/PII)")
        if dm.get("adkim", "r") == "r" and dm.get("aspf", "r") == "r" and p != "none":
            rep["alignment"] = "relaxed"
            F.append(f"EM-012 info: {domain} uses relaxed DKIM/SPF alignment; any subdomain or third-party sender in SPF aligns")
    caa = rr(domain, "CAA")
    rep["caa"] = caa
    if not caa:
        F.append(f"EM-021: {domain} has no CAA record (any CA may issue)")
    elif not any("iodef" in c for c in caa):
        rep["caa_note"] = "no iodef contact"
    bimi = [t for t in txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
    rep["bimi"] = bimi
    if bimi and dm and dm.get("p", "none").lower() == "none":
        F.append(f"EM-023: BIMI published but DMARC is p=none (BIMI requires enforcement)")
    elif not bimi:
        rep["bimi_note"] = "no BIMI record (informational)"
    rep["mta_sts"] = txt(f"_mta-sts.{domain}")
    rep["tls_rpt"] = txt(f"_smtp._tls.{domain}")
    mx = rr(domain, "MX")
    rep["mx"] = mx
    nullmx = any(m.split()[-1] == "." for m in mx)
    rep["null_mx"] = nullmx
    for m in mx:
        host = m.split()[-1].rstrip(".")
        if host and host != "" and not rr(host, "A") and not rr(host, "AAAA"):
            F.append(f"EM-024: MX host {host} for {domain} does not resolve (dangling MX; check takeover)")
    return rep


def audit_subdomain(sub, parent_dmarc, F):
    mx, spf = rr(sub, "MX"), spf_record(sub)
    a = rr(sub, "A") or rr(sub, "AAAA") or rr(sub, "CNAME")
    own, _ = dmarc_for(sub)
    pol = (own.get("p") if own else None) or (parent_dmarc.get("sp") or parent_dmarc.get("p") if parent_dmarc else None)
    rec = {"subdomain": sub, "mx": mx, "spf": spf, "dmarc_effective": pol, "resolves": bool(a)}
    if (pol in (None, "none")) and not any(s.endswith("-all") for s in spf) and not any(m.split()[-1] == "." for m in mx):
        F.append(f"EM-024: {sub} can be spoofed (no SPF -all or null MX, effective DMARC {pol})")
    for m in mx:
        host = m.split()[-1].rstrip(".")
        if host and not rr(host, "A") and not rr(host, "AAAA"):
            F.append(f"EM-024: {sub} MX {host} does not resolve (dangling)")
    return rec


def scope_ok(host, workspace, program):
    res = subprocess.run(["bash", SCOPE, host, workspace or "", program], capture_output=True, text=True)
    return res.returncode == 0


def smtp_check(host, F, timeout):
    out = {"host": host}
    try:
        s = smtplib.SMTP(timeout=timeout)
        code, banner = s.connect(host, 25)
        out["banner"] = banner.decode(errors="replace")[:200]
        code, ehlo = s.ehlo("audit.invalid")
        feats = ehlo.decode(errors="replace").splitlines()
        out["ehlo"] = feats[:20]
        out["starttls"] = s.has_extn("starttls")
        out["auth"] = s.esmtp_features.get("auth", "")
        if not out["starttls"]:
            F.append(f"MAIL-013: {host} does not advertise STARTTLS")
        if re.search(r"\d+\.\d+", out["banner"]):
            F.append(f"EM-018 info: {host} banner reveals software/version: {out['banner'][:80]}")
        c1, m1 = s.verify("postmaster")
        c2, m2 = s.verify("em" + secrets.token_hex(5))
        out["vrfy"] = {"postmaster": c1, "random": c2}
        if c1 != c2 and c1 in (250, 251, 252) and c2 >= 500:
            F.append(f"EM-018: {host} VRFY distinguishes existing (code {c1}) from non-existing (code {c2}) users")
        c3, _ = s.docmd("EXPN", "postmaster")
        out["expn"] = c3
        if c3 in (250, 251):
            F.append(f"EM-018: {host} EXPN is enabled (list/alias expansion)")
        s.quit()
    except (OSError, smtplib.SMTPException) as e:
        out["error"] = str(e)[:150]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", required=True, action="append")
    ap.add_argument("--selectors", help="comma list of extra DKIM selectors (for example from received mail)")
    ap.add_argument("--subdomains", help="file of subdomains to check for mail spoofability and MX hygiene")
    ap.add_argument("--smtp", action="store_true", help="one SMTP session per in-scope MX host (banner/EHLO/STARTTLS/VRFY/EXPN)")
    ap.add_argument("--target", help="program name for the scope gate (required with --smtp)")
    ap.add_argument("--workspace")
    ap.add_argument("--resolver", help="DNS resolver IP (default: system)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.resolver:
        R.nameservers = [a.resolver]
    if a.smtp and not a.target:
        sys.exit("--smtp needs --target (program name for the scope gate)")
    selectors = SELECTORS + ([s.strip() for s in a.selectors.split(",")] if a.selectors else [])
    F: list[str] = []
    rep = {"domains": [], "subdomains": [], "smtp": []}
    for d in a.domain:
        d = d.lower().strip(".")
        r = audit_domain(d, list(dict.fromkeys(selectors)), F)
        rep["domains"].append(r)
        print(f"{d}: SPF={r['spf'][:1]} lookups={r.get('spf_lookups')} DKIM={[x['selector'] for x in r['dkim'] if not x.get('revoked')] or ('wildcard' if r.get('dkim_wildcard') else 'none found')} DMARC={r['dmarc'][:1]} MX={r['mx'][:3]}")
        if a.subdomains:
            parent, _ = dmarc_for(d)
            for sub in [l.strip().lower() for l in open(a.subdomains, encoding="utf-8") if l.strip()]:
                if sub.endswith("." + d):
                    rep["subdomains"].append(audit_subdomain(sub, parent, F))
        if a.smtp:
            for m in r["mx"]:
                host = m.split()[-1].rstrip(".")
                if not host:
                    continue
                if not scope_ok(host, a.workspace, a.target.lower()):
                    rep["smtp"].append({"host": host, "skipped": "not in scope (often a third-party provider)"})
                    print(f"  smtp {host}: skipped (not in scope)")
                    continue
                res = smtp_check(host, F, a.timeout)
                rep["smtp"].append(res)
                print(f"  smtp {host}: starttls={res.get('starttls')} vrfy={res.get('vrfy')} expn={res.get('expn')} {res.get('error', '')}")
    F = list(dict.fromkeys(F))
    rep["findings"] = F
    print("findings:")
    for f in F or ["none"]:
        print(f"  - {f}")
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump(rep, open(a.out, "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
