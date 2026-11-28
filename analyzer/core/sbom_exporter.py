"""
TIRtcp CycloneDX 1.5 SBOM Exporter
Generates a standards-compliant CycloneDX 1.5 JSON Software Bill of Materials
from findings and ScanContext inventory (native DLLs, npm, NuGet, PyPI, and container packages).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def export_cyclonedx_sbom(report_dict: Dict[str, Any], out_path: Path) -> Path:
    """Build and write a CycloneDX 1.5 JSON SBOM from a serialized ScanReport dictionary."""
    components: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for f in report_dict.get("findings", []):
        ev = f.get("evidence") or {}
        # Extract from SCA / DLL / Container package evidence
        for pkg in ev.get("packages_sample") or ev.get("matched_packages") or []:
            if isinstance(pkg, dict):
                name = str(pkg.get("name") or pkg.get("package") or "")
                ver = str(pkg.get("version") or "unknown")
                eco = str(pkg.get("ecosystem") or "generic").lower()
                if name and (name, ver) not in seen:
                    seen.add((name, ver))
                    components.append(
                        {
                            "type": "library",
                            "name": name,
                            "version": ver,
                            "purl": f"pkg:{eco}/{name}@{ver}",
                        }
                    )

        # Extract native DLL / binary assets
        asset = str(f.get("affected_asset") or "")
        if asset.lower().endswith((".exe", ".dll", ".apk", ".jar")):
            fname = Path(asset).name
            if fname and (fname, "detected") not in seen:
                seen.add((fname, "detected"))
                components.append(
                    {
                        "type": "application" if fname.lower().endswith(".exe") else "library",
                        "name": fname,
                        "version": "detected",
                    }
                )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "TIRtcp", "name": "TIRtcp Analyzer", "version": report_dict.get("tool_version", "1.1.0")}],
            "component": {
                "type": "application",
                "name": report_dict.get("target_name", "TargetApplication"),
            },
        },
        "components": components,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return out_path
