"""
TIRtcp Canonical Finding Schema & Multi-Format Exporter (JSON, SARIF v2.1.0, HTML).
"""

from __future__ import annotations

import hashlib
import re
import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple


class FindingStatus(str, Enum):
    FAIL = "Fail"
    VERIFIED_PASS = "Verified Pass"
    NOT_ASSESSED = "Not Assessed"                    # Partial coverage / files skipped / tool failed
    EVIDENCE_OF_RETENTION = "Evidence of Retention"  # Used for noisy runtime/memory artifacts
    TOOLING_GAP = "Tooling Gap"                      # External binary/permission unavailable
    MANUAL_REQUIRED = "Manual Required"              # Requires human GUI/playbook verification
    OBSERVATION = "Observation"                      # Informational intelligence / test lead (not a defect)


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
    grouped_assets: List[str] = field(default_factory=list)
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def fingerprint(self) -> str:
        """Stable SHA-256 fingerprint matching scripts/triage_findings.py and SARIF partialFingerprints."""
        norm_asset = re.sub(r"[A-Za-z]:\\|/", "|", self.affected_asset).lower()
        raw = f"{self.check_id}|{self.title}|{norm_asset}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        raw = asdict(self)
        raw["fingerprint"] = self.fingerprint
        raw["status"] = self.status.value
        raw["severity"] = self.severity.value
        raw["confidence"] = self.confidence.value
        for c in raw["compliance_support"]:
            if isinstance(c["relation"], Enum):
                c["relation"] = c["relation"].value
        return raw

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding into a clean dictionary with Enum values resolved."""
        raw = asdict(self)
        raw["fingerprint"] = self.fingerprint
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
    ROOT_CAUSE_PATTERNS: ClassVar[Dict[str, Tuple[str, ...]]] = {
        "uac_elevation": ("uac", "elevated execution", "requireadministrator", "highestavailable"),
        "unsigned_binary": ("not authenticode-signed", "unsigned binary"),
        "tls_bypass": (
            "servercertificatevalidationcallback",
            "ignore-certificate-errors",
            "x509trustmanager",
            "servercertificatecustomvalidationcallback",
        ),
        "weak_crypto": ("weak cryptographic", "sha-1 digest", "ecb"),
    }
    
    DISCLAIMER = (
        "Regulatory Notice: TIRtcp findings support technical security gap analysis "
        "against referenced frameworks and do not constitute formal regulatory certification."
    )

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    # Add inside ScanReport in analyzer/core/schema.py:
    def compute_risk_score(self) -> Dict[str, Any]:
        """Compute a deterministic 0-100 risk score weighted by actionable Fail / Retention findings."""
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 12,
            Severity.MEDIUM: 5,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        raw_points = 0
        for f in self.findings:
            if f.status in (FindingStatus.FAIL, FindingStatus.EVIDENCE_OF_RETENTION):
                raw_points += weights.get(f.severity, 0)

        score = min(100, raw_points)
        if score >= 75:
            rating = "Critical Risk"
        elif score >= 45:
            rating = "High Risk"
        elif score >= 20:
            rating = "Moderate Risk"
        else:
            rating = "Low Risk"

        return {
            "risk_score": score,
            "risk_rating": rating,
            "raw_weighted_points": raw_points,
        }

    # Add inside ScanReport in analyzer/core/schema.py:
    ROOT_CAUSE_PATTERNS = {
        "uac_elevation": ("uac", "elevated execution", "requireadministrator", "highestavailable"),
        "unsigned_binary": ("not authenticode-signed", "unsigned binary"),
        "tls_bypass": ("servercertificatevalidationcallback", "ignore-certificate-errors", "x509trustmanager"),
        "weak_crypto": ("weak cryptographic", "sha-1 digest", "ecb"),
    }

    def correlate_root_causes(self) -> None:
        """Merge duplicate cross-module findings on the same asset sharing a root cause."""
        seen_cause: Dict[tuple[str, str], Finding] = {}
        kept: List[Finding] = []

        for f in self.findings:
            low_title = f.title.lower()
            matched_cause = None
            for cause, tokens in self.ROOT_CAUSE_PATTERNS.items():
                if any(tok in low_title for tok in tokens):
                    matched_cause = cause
                    break

            if not matched_cause:
                kept.append(f)
                continue

            key = (f.affected_asset.lower(), matched_cause)
            if key not in seen_cause:
                seen_cause[key] = f
                kept.append(f)
            else:
                primary = seen_cause[key]
                corrob = primary.evidence.setdefault("corroborated_by", [])
                corrob.append({"check_id": f.check_id, "title": f.title, "status": f.status.value})

        self.findings = kept
    
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
            if f.status in (FindingStatus.VERIFIED_PASS, FindingStatus.OBSERVATION):
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
                    "partialFingerprints": {
                        "primaryLocationLineHash": f.fingerprint,
                    },
                    "message": {
                        "text": f"[{f.status.value} | Confidence: {f.confidence.value}] {f.summary}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.affected_asset.replace("\\", "/")
                                                     }
                            }
                        }
                    ],
                    "properties": {
                        "fingerprint": f.fingerprint,
                        "status": f.status.value,
                        "severity": f.severity.value,
                        "confidence": f.confidence.value,
                        "grouped_assets": f.grouped_assets,
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
    def deduplicate_findings(self) -> None:
        """
        Group repeated findings with identical (check_id, title, status) into a single
        consolidated finding with an aggregated grouped_assets list so large installs
        do not generate hundreds of duplicate cards.
        """
        sev_rank = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        grouped: Dict[tuple[str, str, str], Finding] = {}
        order: List[tuple[str, str, str]] = []

        for f in self.findings:
            key = (f.check_id, f.title, f.status.value)
            if key not in grouped:
                if f.affected_asset and f.affected_asset not in f.grouped_assets:
                    f.grouped_assets.append(f.affected_asset)
                grouped[key] = f
                order.append(key)
            else:
                existing = grouped[key]
                if f.affected_asset and f.affected_asset not in existing.grouped_assets:
                    existing.grouped_assets.append(f.affected_asset)
                if sev_rank[f.severity] > sev_rank[existing.severity]:
                    existing.severity = f.severity
                existing.affected_asset = (
                    f"{existing.grouped_assets[0]} (+{len(existing.grouped_assets) - 1} more)"
                )
                existing.evidence["grouped_asset_count"] = len(existing.grouped_assets)
                existing.evidence["grouped_assets"] = existing.grouped_assets[:50]

        self.findings = [grouped[k] for k in order]

    # -------------------------------------------------------------------------
    ROOT_CAUSE_PATTERNS: ClassVar[Dict[str, Tuple[str, ...]]] = {
        "uac_elevation": ("uac", "elevated execution", "requireadministrator", "highestavailable"),
        "unsigned_binary": ("not authenticode-signed", "unsigned binary"),
        "tls_bypass": (
            "servercertificatevalidationcallback",
            "ignore-certificate-errors",
            "x509trustmanager",
            "servercertificatecustomvalidationcallback",
        ),
        "weak_crypto": ("weak cryptographic", "sha-1 digest", "ecb"),
    }

    def correlate_root_causes(self) -> None:
        """Merge duplicate cross-module findings on the same asset sharing a root cause."""
        seen_cause: Dict[Tuple[str, str], Finding] = {}
        kept: List[Finding] = []

        for f in self.findings:
            low_title = f.title.lower()
            matched_cause: Optional[str] = None
            for cause, tokens in self.ROOT_CAUSE_PATTERNS.items():
                if any(tok in low_title for tok in tokens):
                    matched_cause = cause
                    break

            if not matched_cause:
                kept.append(f)
                continue

            key = (f.affected_asset.lower(), matched_cause)
            if key not in seen_cause:
                seen_cause[key] = f
                kept.append(f)
            else:
                primary = seen_cause[key]
                corrob = primary.evidence.setdefault("corroborated_by", [])
                corrob.append(
                    {
                        "check_id": f.check_id,
                        "title": f.title,
                        "status": f.status.value,
                    }
                )

        self.findings = kept

    # -------------------------------------------------------------------------
    # Add inside ScanReport in analyzer/core/schema.py:
    def apply_baseline_diff(self, baseline_json_path: Path) -> Dict[str, int]:
        """Compare current findings against a prior TIRtcp JSON report using SHA-256 fingerprints."""
        prior = json.loads(baseline_json_path.read_text(encoding="utf-8"))
        prior_fps = {
            item["fingerprint"]: item
            for item in prior.get("findings", [])
            if item.get("fingerprint") and item.get("status") in ("Fail", "Evidence of Retention")
        }

        current_fps: set[str] = set()
        new_count = 0
        persistent_count = 0

        for f in self.findings:
            fp = f.fingerprint
            if f.status in (FindingStatus.FAIL, FindingStatus.EVIDENCE_OF_RETENTION):
                current_fps.add(fp)
                if fp in prior_fps:
                    f.evidence["retest_status"] = "PERSISTENT"
                    persistent_count += 1
                else:
                    f.evidence["retest_status"] = "NEW"
                    new_count += 1
            else:
                f.evidence["retest_status"] = "BASELINE_NON_DEFECT"

        fixed_items = [
            {"check_id": item.get("check_id"), "title": item.get("title"), "affected_asset": item.get("affected_asset")}
            for fp, item in prior_fps.items()
            if fp not in current_fps
        ]

        return {
            "new_actionable": new_count,
            "persistent_actionable": persistent_count,
            "fixed_since_baseline": len(fixed_items),
            "fixed_findings": fixed_items,
        }

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
                FindingStatus.OBSERVATION: "badge-obs",
                FindingStatus.NOT_ASSESSED: "badge-gap",
            }.get(status, "badge-gap")

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
  .badge-obs {{ background: #0e7490; color: #cffafe; }}
  .kpis {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 24px; }}
  .kpi {{ background: #1e293b; padding: 14px; border-radius: 8px; text-align: center; }}
  .kpi .num {{ font-size: 24px; font-weight: 700; color: #f8fafc; }}
  .kpi .lbl {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
  <div class="filters" style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px;">
    <button class="fbtn active" onclick="filterCards('ALL', this)">All Findings</button>
    <button class="fbtn" onclick="filterCards('Fail', this)">Failures</button>
    <button class="fbtn" onclick="filterCards('Evidence of Retention', this)">Retention</button>
    <button class="fbtn" onclick="filterCards('Manual Required', this)">Manual Required</button>
    <button class="fbtn" onclick="filterCards('Observation', this)">Observations</button>
    <button class="fbtn" onclick="filterCards('Tooling Gap', this)">Tooling Gaps</button>
    <button class="fbtn" onclick="filterCards('Verified Pass', this)">Verified Pass</button>
  </div>
  <script>
    function filterCards(status, btn) {{
      document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.card').forEach(c => {{
        c.style.display = (status === 'ALL' || c.dataset.status === status) ? 'block' : 'none';
      }});
    }}
  </script>
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
    <div class="kpi"><div class="num">{counts['Observation']}</div><div class="lbl">Observations</div></div>
  </div>

  {''.join(cards_html)}
</div>
</body>
</html>
"""


    def to_dict(self) -> Dict[str, Any]:
        """Serialize full scan report to a JSON-ready dictionary."""
        return {
            "tool": "TIRtcp",
            "tool_version": self.tool_version,
            "target_name": self.target_name,
            "engagement_id": self.engagement_id,
            "compliance_profile": self.compliance_profile,
            "authorized_runtime": self.authorized_runtime,
            "compliance_last_verified": self.compliance_last_verified,
            "generated_at_utc": self.generated_at_utc,
            "summary": self.summary_counts(),
            "risk_summary": self.compute_risk_score() if hasattr(self, "compute_risk_score") else {},
            "findings": [f.to_dict() for f in self.findings],
        }

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