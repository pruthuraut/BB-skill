#!/usr/bin/env python3
"""Track the iOS checklist (IOS-0001..IOS-0955) for one app: 0/N to N/N per section.

  init    --bundle B                         create artifacts/B/ios-checklist-status.json (not-tested rows pre-marked)
  ingest  --bundle B REPORT.json [...]       attach findings from ios_static / ios_container_audit / ios_deeplink
                                             reports: low+ findings flag their rows, info findings add evidence
  set     --bundle B IDS STATUS [--note N]   IDS = IOS-0001,IOS-0002 or a range IOS-0001..IOS-0030
  report  --bundle B [--md FILE]             per-section progress and the flagged/failed rows

Statuses: not-started, in-progress, flagged (auto, needs manual confirmation), passed, failed,
not-applicable, not-tested. A row counts as complete when it is passed, failed, not-applicable or
not-tested. Automated findings never mark a row passed or failed: confirm by hand, then `set`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ios_common import ARTIFACTS, checklist_rows, write_json  # noqa: E402

STATUSES = ["not-started", "in-progress", "flagged", "passed", "failed", "not-applicable", "not-tested"]
DONE = {"passed", "failed", "not-applicable", "not-tested"}


def path_for(bundle: str) -> str:
    return os.path.join(ARTIFACTS, bundle, "ios-checklist-status.json")


def load(bundle: str) -> dict:
    p = path_for(bundle)
    if not os.path.isfile(p):
        sys.exit(f"no status file for {bundle}; run: ios_checklist.py init --bundle {bundle}")
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def save(bundle: str, data: dict) -> None:
    data["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    write_json(path_for(bundle), data)


def expand(spec: str, known: list[str]) -> list[str]:
    out = []
    for part in spec.split(","):
        part = part.strip().upper()
        m = re.match(r"^IOS-(\d{4})\.\.IOS-(\d{4})$", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            out += [f"IOS-{i:04d}" for i in range(a, b + 1)]
        elif part:
            out.append(part)
    bad = [x for x in out if x not in known]
    if bad:
        sys.exit(f"unknown IDs: {bad[:5]}")
    return out


def cmd_init(a) -> None:
    rows = checklist_rows()
    if not rows:
        sys.exit("checklist.json missing; run build_ios_checklists.py")
    p = path_for(a.bundle)
    if os.path.exists(p) and not a.force:
        sys.exit(f"{p} exists (use --force to reset)")
    data = {"bundle": a.bundle, "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "rows": {}}
    for r in rows:
        data["rows"][r["id"]] = {"status": "not-tested" if r["class"] == "not-tested" else "not-started",
                                 "evidence": [], "note": "OS or platform behaviour" if r["class"] == "not-tested" else ""}
    save(a.bundle, data)
    print(f"initialised {len(rows)} rows -> {p}")


def cmd_ingest(a) -> None:
    data = load(a.bundle)
    n_flag = n_ev = 0
    for rp in a.reports:
        with open(rp, encoding="utf-8") as fh:
            rep = json.load(fh)
        src = os.path.basename(rp)
        for f in rep.get("findings", []):
            for rid in f.get("checklist", []):
                row = data["rows"].get(rid)
                if not row:
                    continue
                ev = f"{src}: [{f['severity']}] {f['title']}" + (f" @ {f['where']}" if f.get("where") else "")
                if ev not in row["evidence"]:
                    row["evidence"].append(ev[:300])
                if row["status"] in DONE:
                    continue
                if f["severity"] in ("critical", "high", "medium", "low"):
                    if row["status"] != "flagged":
                        n_flag += 1
                    row["status"] = "flagged"
                elif row["status"] == "not-started":
                    row["status"] = "in-progress"
                    n_ev += 1
    save(a.bundle, data)
    print(f"flagged {n_flag} rows, {n_ev} rows moved to in-progress")


def cmd_set(a) -> None:
    if a.status not in STATUSES:
        sys.exit(f"status must be one of {STATUSES}")
    data = load(a.bundle)
    for rid in expand(a.ids, list(data["rows"])):
        data["rows"][rid]["status"] = a.status
        if a.note:
            data["rows"][rid]["note"] = a.note
    save(a.bundle, data)
    print(f"set {a.ids} -> {a.status}")


def cmd_report(a) -> None:
    data = load(a.bundle)
    rows = checklist_rows()
    sections: dict[str, list] = {}
    for r in rows:
        sections.setdefault(r["section"], []).append(r)
    lines = [f"# iOS checklist: {a.bundle}", "", f"Updated {data.get('updated')}", "",
             "| Section | Skill | Complete | Flagged | Failed | Passed |", "|---|---|---|---|---|---|"]
    tot = {"n": 0, "done": 0}
    for sec, items in sections.items():
        st = [data["rows"][r["id"]]["status"] for r in items]
        done = sum(1 for s in st if s in DONE)
        tot["n"] += len(st)
        tot["done"] += done
        lines.append(f"| {sec} | {items[0]['skill']} | {done}/{len(st)} | {st.count('flagged')} | {st.count('failed')} | {st.count('passed')} |")
        print(f"{sec:42s} {done:3d}/{len(st):<3d}  flagged {st.count('flagged'):3d}  failed {st.count('failed'):3d}")
    print(f"{'TOTAL':42s} {tot['done']:3d}/{tot['n']}")
    lines += ["", f"**Total: {tot['done']}/{tot['n']}**", "", "## Failed and flagged rows", "",
              "| ID | Status | Check | Evidence / note |", "|---|---|---|---|"]
    for r in rows:
        row = data["rows"][r["id"]]
        if row["status"] in ("failed", "flagged"):
            ev = "; ".join(row["evidence"][:2]) + (f" NOTE: {row['note']}" if row.get("note") else "")
            lines.append(f"| {r['id']} | {row['status']} | {r['check'].replace('|', '/')} | {ev.replace('|', '/')[:300]} |")
    if a.md:
        os.makedirs(os.path.dirname(os.path.abspath(a.md)), exist_ok=True)
        with open(a.md, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"markdown: {a.md}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("--bundle", required=True)
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("ingest")
    p.add_argument("--bundle", required=True)
    p.add_argument("reports", nargs="+")
    p = sub.add_parser("set")
    p.add_argument("--bundle", required=True)
    p.add_argument("ids")
    p.add_argument("status")
    p.add_argument("--note")
    p = sub.add_parser("report")
    p.add_argument("--bundle", required=True)
    p.add_argument("--md")
    a = ap.parse_args()
    {"init": cmd_init, "ingest": cmd_ingest, "set": cmd_set, "report": cmd_report}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
