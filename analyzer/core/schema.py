"""
TIRtcp Canonical Finding Schema & Multi-Format Exporter (JSON, SARIF v2.1.0, HTML).
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class FindingStatus(str, Enum):
    FAIL = "Fail"
    VERIFIED_PASS = "Verified Pass"
    EVIDENCE_OF_RETENTION = "Evidence of Retention"  # Used for noisy runtime/memory artifacts
    TOOLING_GAP = "Tooling Gap"                      # External binary/permission unavailable
    MANUAL_REQUIRED = "Manual Required"              # Requires human GUI/playbook verification


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ComplianceRelation(str, Enum):
    DIRECT = "direct"                                # Technical control directly verified
    SUPPORTS = "supports"                            # Technical finding supports organizational control
    INFORMATIONAL_SUPPORT = "informational_support"  # Never Pass/Fail (e.g., CERT-In 6-hr reporting)


@dataclass
class ComplianceRef:
    framework: str
    version: str
    control_id: str
    control_title: str
    relation: ComplianceRelation = ComplianceRelation.SUPPORTS
    scope: str = "general"  # e.g., "general", "bfsi", "pci"


@dataclass
class PlaybookRef:
    tool: str               # e.g., "dnSpy", "Frida", "Procmon", "API Monitor", "Wireshark"
    objective: str
    steps: List[str] = field(default_factory=list)


@dataclass
class AuthorizationContext:
    gated: bool = False
    authorized_flag: bool = False
    engagement_id: Optional[str] = None
    operator: Optional[str] = None


@dataclass
class Finding:
    check_id: str
    title: str
    category: str           # e.g., "Binary Hardening", "Storage & DPDP", "Network & TLS"
    status: FindingStatus
    severity: Severity
    confidence: Confidence
    affected_asset: str
    summary: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    compliance_support: List[ComplianceRef] = field(default_factory=list)
    manual_playbook: Optional[PlaybookRef] = None
    auth_context: AuthorizationContext = field(default_factory=AuthorizationContext)
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding into a clean dictionary with Enum values resolved."""
        raw = asdict(self)
        raw["status"] = self.status.value
        raw["severity"] = self.severity.value
        raw["confidence"] = self.confidence.value
        for c in raw["compliance_support"]:
            if isinstance(c["relation"], Enum):
                c["relation"] = c["relation"].value
        return raw


@dataclass
class ScanReport:
    target_name: str
    engagement_id: str
    compliance_profile: str  # "general" or "bfsi"
    authorized_runtime: bool
    tool_version: str = "0.1.0-mvp"
    compliance_last_verified: str = "2026-11-24"
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings: List[Finding] = field(default_factory=list)

    DISCLAIMER = (
        "Regulatory Notice: TIRtcp findings support technical security gap analysis "
        "against referenced frameworks and do not constitute formal regulatory certification."
    )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary_counts(self) -> Dict[str, int]:
        counts = {status.value: 0 for status in FindingStatus}
        for f in self.findings:
            counts[f.status.value] = counts.get(f.status.value, 0) + 1
        return counts

    # -------------------------------------------------------------------------
    # 1. JSON Projection
    # -------------------------------------------------------------------------
    def to_json(self, indent: int = 2) -> str:
        payload = {
            "metadata": {
                "tool": "TIRtcp",
                "version": self.tool_version,
                "target": self.target_name,
                "engagement_id": self.engagement_id,
                "compliance_profile": self.compliance_profile,
                "compliance_last_verified": self.compliance_last_verified,
                "authorized_runtime_enabled": self.authorized_runtime,
                "generated_at_utc": self.generated_at_utc,
                "disclaimer": self.DISCLAIMER,
            },
            "summary": self.summary_counts(),
            "findings": [f.to_dict() for f in self.findings],
        }
        return json.dumps(payload, indent=indent)

    # -------------------------------------------------------------------------
    # 2. SARIF v2.1.0 Projection (for CI/CD & DevSecOps pipelines)
    # -------------------------------------------------------------------------
    def to_sarif(self) -> str:
        severity_to_sarif = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }

        rules_map: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in self.findings:
            # Skip pure passes in SARIF alerts while keeping Gaps/Manual/Fails/Retention
            if f.status == FindingStatus.VERIFIED_PASS:
                continue

            if f.check_id not in rules_map:
                rules_map[f.check_id] = {
                    "id": f.check_id,
                    "name": f.title.replace(" ", ""),
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.summary},
                    "help": {"text": f.remediation or "Review finding evidence."},
                    "properties": {
                        "category": f.category,
                        "compliance": [
                            f"{c.framework} ({c.version}): {c.control_id}"
                            for c in f.compliance_support
                        ],
                    },
                }

            level = (
                severity_to_sarif[f.severity]
                if f.status in (FindingStatus.FAIL, FindingStatus.EVIDENCE_OF_RETENTION)
                else "note"
            )

            results.append(
                {
                    "ruleId": f.check_id,
                    "level": level,
                    "message": {
                        "text": f"[{f.status.value} | Confidence: {f.confidence.value}] {f.summary}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.affected_asset}
                            }
                        }
                    ],
                    "properties": {
                        "status": f.status.value,
                        "severity": f.severity.value,
                        "confidence": f.confidence.value,
                        "evidence": f.evidence,
                    },
                }
            )

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TIRtcp",
                            "version": self.tool_version,
                            "informationUri": "https://internal.staarken/tirtcp",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": self.generated_at_utc,
                            "properties": {
                                "engagement_id": self.engagement_id,
                                "compliance_profile": self.compliance_profile,
                                "authorized_runtime": self.authorized_runtime,
                            },
                        }
                    ],
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif_doc, indent=2)

    # -------------------------------------------------------------------------
    # 3. Single-Format Standalone HTML Projection
    # -------------------------------------------------------------------------
    def to_html(self) -> str:
        counts = self.summary_counts()
        esc = html.escape

        def badge_class(status: FindingStatus) -> str:
            return {
                FindingStatus.FAIL: "badge-fail",
                FindingStatus.VERIFIED_PASS: "badge-pass",
                FindingStatus.EVIDENCE_OF_RETENTION: "badge-warn",
                FindingStatus.TOOLING_GAP: "badge-gap",
                FindingStatus.MANUAL_REQUIRED: "badge-manual",
            }[status]

        cards_html: List[str] = []
        for f in self.findings:
            comp_tags = "".join(
                f'<span class="tag">{esc(c.framework)} {esc(c.version)} · '
                f'{esc(c.control_id)} <em>({esc(c.relation.value)})</em></span>'
                for c in f.compliance_support
            )

            playbook_block = ""
            if f.manual_playbook:
                steps_li = "".join(f"<li>{esc(s)}</li>" for s in f.manual_playbook.steps)
                playbook_block = f"""
                <div class="playbook">
                    <strong>Manual Verification Playbook ({esc(f.manual_playbook.tool)}):</strong>
                    <span>{esc(f.manual_playbook.objective)}</span>
                    <ol>{steps_li}</ol>
                </div>
                """

            evidence_json = esc(json.dumps(f.evidence, indent=2))
            remediation_html = (
                f"<p><strong>Remediation:</strong> {esc(f.remediation)}</p>"
                if f.remediation
                else ""
            )

            cards_html.append(
                f"""
                <div class="card">
                    <div class="card-header">
                        <div>
                            <span class="check-id">{esc(f.check_id)}</span>
                            <span class="title">{esc(f.title)}</span>
                        </div>
                        <div class="badges">
                            <span class="badge {badge_class(f.status)}">{esc(f.status.value)}</span>
                            <span class="badge badge-sev">{esc(f.severity.value)}</span>
                            <span class="badge badge-conf">Conf: {esc(f.confidence.value)}</span>
                        </div>
                    </div>
                    <div class="meta"><strong>Asset:</strong> <code>{esc(f.affected_asset)}</code> | <strong>Category:</strong> {esc(f.category)}</div>
                    <p>{esc(f.summary)}</p>
                    <details>
                        <summary>Technical Evidence</summary>
                        <pre>{evidence_json}</pre>
                    </details>
                    {remediation_html}
                    {playbook_block}
                    <div class="tags">{comp_tags}</div>
                </div>
                """
            )

        auth_banner = (
            f"AUTHORIZED RUNTIME ENABLED (Engagement: {esc(self.engagement_id)})"
            if self.authorized_runtime
            else f"OFFLINE / STATIC MODE ONLY (Engagement: {esc(self.engagement_id)})"
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TIRtcp Security Assessment — {esc(self.target_name)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
  .container {{ max-width: 1120px; margin: 0 auto; }}
  header {{ background: #1e293b; padding: 20px 24px; border-radius: 8px; border-left: 4px solid #38bdf8; margin-bottom: 20px; }}
  h1 {{ margin: 0 0 8px 0; font-size: 22px; color: #f8fafc; }}
  .sub {{ font-size: 13px; color: #94a3b8; }}
  .disclaimer {{ margin-top: 12px; padding: 10px 12px; background: #0f172a; border-radius: 6px; font-size: 12px; color: #cbd5e1; }}
  .kpis {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }}
  .kpi {{ background: #1e293b; padding: 14px; border-radius: 8px; text-align: center; }}
  .kpi .num {{ font-size: 24px; font-weight: 700; color: #f8fafc; }}
  .kpi .lbl {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 18px 20px; margin-bottom: 14px; border: 1px solid #334155; }}
  .card-header {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 8px; }}
  .check-id {{ font-family: monospace; background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 12px; margin-right: 8px; }}
  .title {{ font-weight: 600; font-size: 16px; color: #f8fafc; }}
  .badges {{ display: flex; gap: 6px; flex-shrink: 0; }}
  .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-fail {{ background: #991b1b; color: #fecaca; }}
  .badge-pass {{ background: #166534; color: #bbf7d0; }}
  .badge-warn {{ background: #92400e; color: #fde68a; }}
  .badge-gap {{ background: #374151; color: #d1d5db; }}
  .badge-manual {{ background: #1e40af; color: #bfdbfe; }}
  .badge-sev, .badge-conf {{ background: #0f172a; color: #cbd5e1; border: 1px solid #334155; }}
  .meta {{ font-size: 12px; color: #94a3b8; margin-bottom: 10px; }}
  pre {{ background: #0f172a; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #38bdf8; }}
  .playbook {{ background: #0f172a; border-left: 3px solid #3b82f6; padding: 10px 14px; margin: 10px 0; border-radius: 4px; font-size: 13px; }}
  .tags {{ margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px; }}
  .tag {{ background: #0f172a; border: 1px solid #334155; padding: 3px 8px; border-radius: 4px; font-size: 11px; color: #94a3b8; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>TIRtcp Thick-Client Security Assessment: {esc(self.target_name)}</h1>
    <div class="sub">
      Profile: <strong>{esc(self.compliance_profile.upper())}</strong> |
      Mode: <strong>{auth_banner}</strong> |
      Generated: {esc(self.generated_at_utc)} |
      Compliance Map Verified: {esc(self.compliance_last_verified)}
    </div>
    <div class="disclaimer">{esc(self.DISCLAIMER)}</div>
  </header>

  <div class="kpis">
    <div class="kpi"><div class="num">{counts['Fail']}</div><div class="lbl">Fail</div></div>
    <div class="kpi"><div class="num">{counts['Verified Pass']}</div><div class="lbl">Verified Pass</div></div>
    <div class="kpi"><div class="num">{counts['Evidence of Retention']}</div><div class="lbl">Retention Evidence</div></div>
    <div class="kpi"><div class="num">{counts['Manual Required']}</div><div class="lbl">Manual Required</div></div>
    <div class="kpi"><div class="num">{counts['Tooling Gap']}</div><div class="lbl">Tooling Gap</div></div>
  </div>

  {''.join(cards_html)}
</div>
</body>
</html>
"""

    def write_outputs(self, output_dir: Path, base_name: str = "tirtcp_report") -> Dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        paths = {
            "json": output_dir / f"{base_name}.json",
            "sarif": output_dir / f"{base_name}.sarif",
            "html": output_dir / f"{base_name}.html",
        }
        paths["json"].write_text(self.to_json(), encoding="utf-8")
        paths["sarif"].write_text(self.to_sarif(), encoding="utf-8")
        paths["html"].write_text(self.to_html(), encoding="utf-8")
        return paths