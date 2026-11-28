<#
.SYNOPSIS
    End-to-end automated verification harness for TIRtcp (unit tests, AI-browser self-test,
    synthetic 4-phase CLI fixture check, and YAML compliance map validation).
#>
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "[1/4] Validating config/compliance_map.yaml & config/offline_vulns.json..." -ForegroundColor Cyan
python -c "import yaml, json; yaml.safe_load(open('config/compliance_map.yaml', encoding='utf-8')); json.load(open('config/offline_vulns.json', encoding='utf-8')); print('Config schemas valid.')"

Write-Host "[2/4] Running full pytest unit & integration suite..." -ForegroundColor Cyan
python -m pytest -v tests\

Write-Host "[3/4] Running AI-browser / Chromium profile self-test..." -ForegroundColor Cyan
python .\scripts\test_browser_files.py --self-test

Write-Host "[4/4] Running synthetic 4-phase CLI end-to-end check..." -ForegroundColor Cyan
$TmpDir = Join-Path $RepoRoot ".tmp_selftest"
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
try {
    python .\scripts\create_demo_target.py --out $TmpDir
    python -m analyzer.tirtcp `
      --target "$TmpDir\DemoClient" `
      --evidence "$TmpDir\host_evidence.json" `
      --pcap "$TmpDir\capture.pcap" `
      --procmon-csv "$TmpDir\procmon.csv" `
      --memory-dump "$TmpDir\post_logout.dmp" `
      --canary-markers "CanaryPass#2026" `
      --authorized `
      --engagement-id SELFTEST-001 `
      --no-active-probe `
      --compliance-map .\tests\fixtures\compliance_map.test.yaml `
      --output "$TmpDir\reports"

    if (-not (Test-Path "$TmpDir\reports\tirtcp_DemoClient.html")) {
        throw "Expected HTML report was not generated."
    }
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}

Write-Host "`n[+] ALL TIRtcp SELF-TESTS PASSED!" -ForegroundColor Green