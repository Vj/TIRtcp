<#
.SYNOPSIS
    Build standalone single-file Windows executables for TIRtcp and collect_host.py via PyInstaller.
#>
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$ReleaseDir = Join-Path $RepoRoot "dist\TIRtcp_win64"
Remove-Item -Recurse -Force $ReleaseDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null

Write-Host "[1/3] Building standalone collect_host.exe..." -ForegroundColor Cyan
pyinstaller --onefile --clean --name collect_host --distpath $ReleaseDir .\collector\collect_host.py

Write-Host "[2/3] Building standalone tirtcp.exe (bundling config/)..." -ForegroundColor Cyan
pyinstaller --onefile --clean --name tirtcp `
  --add-data "config;config" `
  --hidden-import "yaml" `
  --hidden-import "pefile" `
  --hidden-import "asn1crypto" `
  --hidden-import "dnfile" `
  --distpath $ReleaseDir `
  .\analyzer\tirtcp.py

Copy-Item -Recurse -Force .\config (Join-Path $ReleaseDir "config")

Write-Host "[3/3] Generating SHA256SUMS.txt..." -ForegroundColor Cyan
Get-ChildItem -Path $ReleaseDir -File | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)"
} | Set-Content -Path (Join-Path $ReleaseDir "SHA256SUMS.txt") -Encoding ASCII

Write-Host "`n[+] Portable release bundle ready at: $ReleaseDir" -ForegroundColor Green