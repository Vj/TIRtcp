#!/usr/bin/env python3
"""Post-scan automation: turns a TIRtcp JSON report into (1) a CI verdict, (2) a baseline diff,
(3) a ranked triage list and (4) a ready-to-run worklist for what is still manual.

  python scripts/triage_findings.py reports/tirtcp_App.json --baseline prev/tirtcp_App.json \
         --fail-on high --worklist-out manual_worklist.md

Exit codes: 0 ok | 2 new finding at/above --fail-on (only NEW findings fail when --baseline is given).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

SEV = ["info", "low", "medium", "high", "critical"]
CONF = {"Low": 0.5, "Medium": 0.75, "High": 1.0}
ACTIONABLE = {"Fail", "Evidence of Retention"}


def fingerprint(f: dict) -> str:
    asset = re.sub(r"[A-Za-z]:\\|/", "|", f["affected_asset"]).lower()
    return hashlib.sha256(f"{f['check_id']}|{f['title']}|{asset}".encode()).hexdigest()[:16]


def load(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["findings"]


def score(f: dict) -> float:
    return (SEV.index(f["severity"].lower()) + 1) * CONF.get(f["confidence"], 0.5)


def worklist(findings: list[dict]) -> str:
    """Concrete commands per Manual Required finding (run on an AUTHORIZED test host only)."""
    out = ["# Manual verification worklist (auto-generated)\n", "Run only on systems covered by the engagement authorization.\n"]
    groups = defaultdict(list)
    for f in findings:
        if f["status"] == "Manual Required":
            groups[f["check_id"]].append(f)
    for cid, fs in sorted(groups.items()):
        out.append(f"\n## {cid} ({len(fs)})")
        for f in fs:
            out.append(f"\n- **{f['title']}** — `{f['affected_asset']}`")
            ev = f.get("evidence", {})
            for p in (ev.get("named_pipes") or [])[:10]:
                name = p.get("pipe_name") or p.get("full_path", "")
                out.append(f"  - `accesschk.exe -accepteula -v \\\\.\\pipe\\{Path(name.replace(chr(92), '/')).name}`")
            for h in ([ev] if "scheme" in ev else []):
                out.append(f"  - `reg query HKCR\\{h['scheme']}\\shell\\open\\command`")
            if f["check_id"] == "TCP-HOST-002":
                out.append("  - Procmon filters: Process Name is <exe>; Result is NAME NOT FOUND; Path ends with .dll → export CSV → `--procmon-csv`")
            if f["check_id"] == "TCP-NET-001" and "Pinning" in f["title"]:
                out.append("  - Install proxy CA in the test VM trust store, route the app through the intercepting proxy, confirm connection is refused")
            pb = f.get("manual_playbook")
            if pb:
                out.append(f"  - Tool: {pb['tool']} — {pb['objective']}")
                out.extend(f"    {i}. {s}" for i, s in enumerate(pb["steps"], 1))
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--baseline", type=Path)
    ap.add_argument("--fail-on", choices=["none", *SEV[1:]], default="none")
    ap.add_argument("--worklist-out", type=Path)
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args()

    cur = load(a.report)
    actionable = [f for f in cur if f["status"] in ACTIONABLE]
    base_fp = {fingerprint(f) for f in load(a.baseline)} if a.baseline else set()
    new = [f for f in actionable if fingerprint(f) not in base_fp] if a.baseline else actionable
    fixed = []
    if a.baseline:
        cur_fp = {fingerprint(f) for f in cur}
        fixed = [f for f in load(a.baseline) if f["status"] in ACTIONABLE and fingerprint(f) not in cur_fp]

    gaps = [f for f in cur if f["status"] == "Tooling Gap"]
    manual = [f for f in cur if f["status"] == "Manual Required"]
    print(f"actionable={len(actionable)} new={len(new) if a.baseline else 'n/a'} fixed={len(fixed) if a.baseline else 'n/a'} "
          f"manual={len(manual)} tooling_gaps={len(gaps)}")
    if gaps:
        print("COVERAGE WARNING — these stages did not fully run (a 'pass' elsewhere does not cover them):")
        for g in gaps[:10]:
            print(f"  - {g['check_id']}: {g['title']}")
    print(f"\nTop {a.top} by severity x confidence:")
    for f in sorted(new, key=score, reverse=True)[: a.top]:
        print(f"  [{f['severity']:<8}/{f['confidence']:<6}] {f['check_id']} {f['title'][:80]}")
    if a.worklist_out:
        a.worklist_out.write_text(worklist(cur), encoding="utf-8"); print(f"\nworklist -> {a.worklist_out}")
    if a.fail_on != "none":
        gate = SEV.index(a.fail_on)
        if any(SEV.index(f["severity"].lower()) >= gate for f in new):
            print(f"\nCI GATE: new finding >= {a.fail_on}", file=sys.stderr); return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
