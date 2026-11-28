#!/usr/bin/env python3
"""
TIRtcp Offline Vulnerability Database Updater
Fetches CISA Known Exploited Vulnerabilities (KEV), FIRST EPSS scores,
and OSV.dev advisories for common thick-client packages, writing a compact,
air-gapped snapshot to config/offline_vulns.json.
"""

from __future__ import annotations

import argparse
import gzip
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

SEED_PACKAGES: List[tuple[str, str]] = [
    ("NuGet", "Newtonsoft.Json"),
    ("NuGet", "System.Text.Json"),
    ("NuGet", "log4net"),
    ("NuGet", "RestSharp"),
    ("NuGet", "BouncyCastle"),
    ("NuGet", "Microsoft.Data.SqlClient"),
    ("npm", "electron"),
    ("npm", "axios"),
    ("npm", "lodash"),
    ("npm", "ws"),
    ("npm", "express"),
    ("npm", "jsonwebtoken"),
    ("Maven", "org.apache.logging.log4j:log4j-core"),
    ("Maven", "com.fasterxml.jackson.core:jackson-databind"),
    ("Maven", "org.springframework:spring-core"),
    ("PyPI", "cryptography"),
    ("PyPI", "urllib3"),
    ("PyPI", "requests"),
    ("PyPI", "pyyaml"),
]


def _fetch_json(url: str, payload: dict | None = None, timeout: int = 20) -> Any:
    headers = {"User-Agent": "TIRtcp-VulnUpdater/0.4.0", "Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _fetch_kev_cves() -> set[str]:
    try:
        data = _fetch_json(CISA_KEV_URL)
        return {v.get("cveID", "").upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception as exc:
        print(f"[!] Warning: Could not fetch CISA KEV feed ({exc}); continuing with existing KEV set.")
        return set()


def _fetch_epss_map() -> Dict[str, float]:
    scores: Dict[str, float] = {}
    try:
        req = urllib.request.Request(EPSS_URL, headers={"User-Agent": "TIRtcp-VulnUpdater/0.4.0"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = gzip.decompress(resp.read()).decode("utf-8", errors="ignore")
        for line in raw.splitlines():
            if line.startswith("#") or line.startswith("cve,"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                scores[parts[0].strip().upper()] = float(parts[1])
    except Exception as exc:
        print(f"[!] Warning: Could not fetch EPSS feed ({exc}); defaulting EPSS to 0.0.")
    return scores


def build_snapshot(out_path: Path) -> None:
    kev_set = _fetch_kev_cves()
    epss_map = _fetch_epss_map()

    existing: Dict[str, Dict[str, Any]] = {}
    if out_path.exists():
        try:
            old = json.loads(out_path.read_text(encoding="utf-8"))
            for adv in old.get("advisories", []):
                key = f"{adv.get('cve')}|{adv.get('ecosystem')}|{adv.get('package')}"
                existing[key] = adv
        except Exception:
            pass

    for eco, pkg in SEED_PACKAGES:
        try:
            res = _fetch_json(OSV_QUERY_URL, {"package": {"ecosystem": eco, "name": pkg}})
        except Exception as exc:
            print(f"[!] OSV query skipped for {eco}/{pkg}: {exc}")
            continue

        for vuln in res.get("vulns", [])[:25]:
            aliases = vuln.get("aliases") or []
            cve = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
            if not cve:
                continue
            fixed_ver = ""
            for aff in vuln.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed_ver = ev["fixed"]
            sev_raw = (vuln.get("database_specific") or {}).get("severity", "HIGH").capitalize()
            if sev_raw not in ("Critical", "High", "Medium", "Low"):
                sev_raw = "High"

            key = f"{cve}|{eco}|{pkg}"
            existing[key] = {
                "cve": cve,
                "ecosystem": eco,
                "package": pkg,
                "fixed_version": fixed_ver or "latest",
                "severity": sev_raw,
                "cisa_kev": cve.upper() in kev_set,
                "epss": round(epss_map.get(cve.upper(), 0.0), 4),
                "summary": (vuln.get("summary") or vuln.get("details") or "")[:240],
            }

    snapshot = {
        "schema_version": "1.0",
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "kev_count": len(kev_set),
        "advisories": sorted(existing.values(), key=lambda x: (not x.get("cisa_kev", False), x.get("cve", ""))),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(f"[+] Wrote {len(snapshot['advisories'])} advisories to {out_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Update TIRtcp offline OSV/KEV/EPSS vulnerability database.")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "config" / "offline_vulns.json",
        help="Destination path for offline_vulns.json",
    )
    args = parser.parse_args()
    build_snapshot(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
