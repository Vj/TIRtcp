#!/usr/bin/env bash
# One-command regression: unit tests + end-to-end on the synthetic fixture + CI-gate check.
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pytest -q tests
python scripts/create_demo_target.py --out .demo
python -m analyzer.tirtcp --target .demo/DemoClient --evidence .demo/host_evidence.json --pcap .demo/capture.pcap \
  --procmon-csv .demo/procmon.csv --memory-dump .demo/post_logout.dmp --canary-markers 'CanaryPass#2026' \
  --authorized --engagement-id ENG-SELFTEST --no-active-probe --compliance-map tests/fixtures/compliance_map.test.yaml \
  --output .demo/reports || true
python scripts/triage_findings.py .demo/reports/*.json --fail-on high --worklist-out .demo/manual_worklist.md || test $? -eq 2
