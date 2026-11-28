#!/usr/bin/env python3
"""
TIRtcp Manual Verification & Triage Worklist Processor
Applies manual verification decisions from a triage JSON file back into a TIRtcp JSON report,
and optionally recalculates risk scores and regenerates HTML + SARIF deliverables (--rerender).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _rerender_outputs(report_data: Dict[str, Any], json_dest: Path) -> Dict[str, Path]:
    from analyzer.core.schema import (
        ComplianceRef,
        ComplianceRelation,
        Confidence,
        Finding,
        FindingStatus,
        ScanReport,
        Severity,
    )

    rep = ScanReport(
        target_name=report_data.get("target_name", "UnknownTarget"),
        engagement_id=report_data.get("engagement_id", "TRIAGE-RERENDER"),
        compliance_profile=report_data.get("compliance_profile", "general"),
        authorized_runtime=bool(report_data.get("authorized_runtime", False)),
        compliance_last_verified=report_data.get("compliance_last_verified", ""),
    )

    status_by_val = {s.value: s for s in FindingStatus}
    sev_by_val = {s.value: s for s in Severity}
    conf_by_val = {c.value: c for c in Confidence}
    rel_by_val = {r.value: r for r in ComplianceRelation}

    for item in report_data.get("findings", []):
        refs: List[ComplianceRef] = []
        for c in item.get("compliance_support", []):
            refs.append(
                ComplianceRef(
                    framework=c.get("framework", ""),
                    control_id=c.get("control_id", ""),
                    title=c.get("title", ""),
                    relation=rel_by_val.get(c.get("relation", ""), ComplianceRelation.DIRECT_TECHNICAL_EVIDENCE),
                    rationale=c.get("rationale", ""),
                )
            )
        rep.add_finding(
            Finding(
                check_id=item.get("check_id", "TCP-TRIAGE"),
                title=item.get("title", ""),
                category=item.get("category", "General"),
                status=status_by_val.get(item.get("status", "Observation"), FindingStatus.OBSERVATION),
                severity=sev_by_val.get(item.get("severity", "Info"), Severity.INFO),
                confidence=conf_by_val.get(item.get("confidence", "Medium"), Confidence.MEDIUM),
                affected_asset=item.get("affected_asset", ""),
                summary=item.get("summary", ""),
                evidence=item.get("evidence") or {},
                remediation=item.get("remediation", ""),
                manual_playbook=item.get("manual_playbook", ""),
                compliance_support=refs,
            )
        )

    return rep.write_outputs(json_dest.parent, base_name=json_dest.stem)


def apply_triage_decisions(
    report_path: Path,
    decisions_path: Path,
    out_path: Path | None = None,
    rerender: bool = False,
) -> Dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    decisions: List[Dict[str, Any]] = json.loads(decisions_path.read_text(encoding="utf-8"))

    by_key = {
        (d.get("check_id", ""), d.get("title", ""), d.get("affected_asset", "")): d
        for d in decisions
    }

    updated = 0
    for f in report.get("findings", []):
        key = (f.get("check_id", ""), f.get("title", ""), f.get("affected_asset", ""))
        if key in by_key:
            dec = by_key[key]
            if dec.get("status"):
                f["status"] = dec["status"]
            if dec.get("severity"):
                f["severity"] = dec["severity"]
            ev = f.setdefault("evidence", {})
            ev["manual_triage"] = {
                "reviewer": dec.get("reviewer", "assessor"),
                "verdict": dec.get("verdict", "Verified"),
                "notes": dec.get("notes", ""),
            }
            updated += 1

    dest = out_path or report_path
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")

    artifacts: Dict[str, str] = {"json": str(dest)}
    if rerender:
        written = _rerender_outputs(report, dest)
        artifacts = {k: str(v) for k, v in written.items()}

    return {"updated_findings": updated, "output_path": str(dest), "artifacts": artifacts}


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply manual triage verdicts to a TIRtcp JSON report.")
    parser.add_argument("--report", type=Path, required=True, help="Path to tirtcp_*.json report.")
    parser.add_argument("--decisions", type=Path, required=True, help="Path to triage decisions JSON list.")
    parser.add_argument("--out", type=Path, default=None, help="Optional output JSON path (defaults to in-place).")
    parser.add_argument("--rerender", action="store_true", help="Recalculate risk score and regenerate HTML/SARIF reports.")
    args = parser.parse_args()

    res = apply_triage_decisions(args.report, args.decisions, args.out, rerender=args.rerender)
    print(f"[+] Updated {res['updated_findings']} finding(s) in {res['output_path']}")
    if args.rerender:
        print(f"[+] Regenerated deliverables: {res['artifacts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
