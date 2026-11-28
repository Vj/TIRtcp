#!/usr/bin/env python3
"""
Refresh config/offline_vulns.json with CISA KEV status and OSV.dev advisories
for offline air-gapped TIRtcp assessments.
"""

from __future__ import annotations

import datetime
import json
import urllib.request
from pathlib import Path
from typing import Any, Dict, Set

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_PATH = Path(__file__).resolve().parents[1] / "config" / "offline_vulns.json"


def fetch_kev_cves() -> Set[str]:
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "TIRtcp-VulnSync/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return {item["cveID"] for item in payload.get("vulnerabilities", []) if "cveID" in item}


def main() -> int:
    existing: Dict[str, Any] = {"schema_version": "1.0.0", "advisories": []}
    if OUT_PATH.exists():
        existing = json.loads(OUT_PATH.read_text(encoding="utf-8"))

    kev_set = fetch_kev_cves()
    for adv in existing.get("advisories", []):
        cve = adv.get("cve", "")
        if cve in kev_set:
            adv["cisa_kev"] = True

    existing["updated_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    existing["kev_catalog_size"] = len(kev_set)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    print(f"[+] Updated {OUT_PATH} (synced against {len(kev_set)} CISA KEV entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())