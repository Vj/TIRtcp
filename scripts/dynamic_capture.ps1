<#
.SYNOPSIS
    Automated Windows Runtime Capture Harness for TIRtcp (Procmon + pktmon + Host Evidence + State Diff).

.DESCRIPTION
    Orchestrates dynamic evidence collection around a target thick-client executable:
      1. Captures pre-execution filesystem (%APPDATA%, %LOCALAPPDATA%, %PROGRAMDATA%, %TEMP%, install dir)
         and registry (HKCU/HKLM Run) baselines.
      2. Starts Windows built-in packet capture (pktmon.exe) if running as Administrator.
      3. Starts Sysinternals Process Monitor (Procmon64.exe / Procmon.exe) silently if available.
      4. Launches the target application for a configurable duration (or until user closes it).
      5. Stops captures, converts PktMon.etl -> capture.pcapng and trace.pml -> procmon.csv.
      6. Computes post-run filesystem/registry state diff (state_diff.json).
      7. Runs collector/collect_host.py to produce host_evidence.json.
      8. Prints the exact TIRtcp command referencing all collected artifacts.

.EXAMPLE
    .\scripts\dynamic_capture.ps1 `
      -TargetExe "C:\Users\ADMIN\Downloads\vpro_secret\ModernPaint.exe" `
      -DurationSeconds 25 `
      -EngagementId "ENG-2026-014" `
      -OutDir ".\evidence\ModernPaint"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetExe,

    [Parameter(Mandatory = $false)]
    [string[]]$TargetArgs = @(),

    [Parameter(Mandatory = $false)]
    [int]$DurationSeconds = 30,

    [Parameter(Mandatory = $false)]
    [string]$OutDir = ".\evidence_capture",

    [Parameter(Mandatory = $false)]
    [string]$ProcmonPath = "",

    [Parameter(Mandatory = $false)]
    [string]$EngagementId = "ENG-DYNAMIC-001",

    [Parameter(Mandatory = $false)]
    [ValidateSet("general", "bfsi")]
    [string]$Compliance = "general",

    [Parameter(Mandatory = $false)]
    [switch]$WaitForExit
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-ProcmonBinary {
    param([string]$ExplicitPath)
    if ($ExplicitPath -and (Test-Path $ExplicitPath)) {
        return (Resolve-Path $ExplicitPath).Path
    }
    foreach ($name in @("Procmon64.exe", "Procmon.exe")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    $commonPaths = @(
        "$env:ProgramFiles\Sysinternals\Procmon64.exe",
        "$env:ProgramFiles\Sysinternals\Procmon.exe",
        "C:\Tools\Sysinternals\Procmon64.exe",
        "C:\Tools\Sysinternals\Procmon.exe",
        "$env:USERPROFILE\Downloads\Procmon64.exe",
        "$env:USERPROFILE\Downloads\Procmon.exe"
    )
    foreach ($p in $commonPaths) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-FileSnapshot {
    param([string[]]$Roots)
    $snap = @{}
    foreach ($root in $Roots) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $snap[$_.FullName] = @{
                size = $_.Length
                mtime = $_.LastWriteTimeUtc.ToString("o")
            }
        }
    }
    return $snap
}

function Get-RunKeySnapshot {
    $regSnap = @{}
    $keys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $regSnap["$k\$($_.Name)"] = [string]$_.Value
            }
        }
    }
    return $regSnap
}

# 1. Validate Target & Prepare Workspace
if (-not (Test-Path $TargetExe)) {
    throw "Target executable not found: $TargetExe"
}
$ResolvedExe = (Resolve-Path $TargetExe).Path
$AppDir = Split-Path -Parent $ResolvedExe
$ProcessBaseName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedExe)

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$ResolvedOutDir = (Resolve-Path $OutDir).Path

$IsAdmin = Test-IsAdmin
$ProcmonBin = Resolve-ProcmonBinary -ExplicitPath $ProcmonPath
$PktmonBin = (Get-Command "pktmon.exe" -ErrorAction SilentlyContinue).Source

$PmlFile = Join-Path $ResolvedOutDir "trace.pml"
$CsvFile = Join-Path $ResolvedOutDir "procmon.csv"
$EtlFile = Join-Path $ResolvedOutDir "PktMon.etl"
$PcapngFile = Join-Path $ResolvedOutDir "capture.pcapng"
$EvidenceFile = Join-Path $ResolvedOutDir "host_evidence.json"
$DiffFile = Join-Path $ResolvedOutDir "state_diff.json"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "TIRtcp Automated Windows Runtime Capture Harness" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Target Executable  : $ResolvedExe"
Write-Host "Install Directory  : $AppDir"
Write-Host "Output Directory   : $ResolvedOutDir"
Write-Host "Elevated Admin     : $IsAdmin"
Write-Host "Procmon Available  : $([bool]$ProcmonBin) $(if ($ProcmonBin) { "($ProcmonBin)" })"
Write-Host "pktmon Available   : $([bool]$PktmonBin -and $IsAdmin)"
Write-Host "========================================================================" -ForegroundColor Cyan

# 2. Capture Pre-Execution Filesystem & Registry Baseline
Write-Host "[1/6] Taking pre-execution filesystem and registry baseline..." -ForegroundColor Yellow
$MonitoredRoots = @(
    $AppDir,
    "$env:LOCALAPPDATA\$ProcessBaseName",
    "$env:APPDATA\$ProcessBaseName",
    "$env:PROGRAMDATA\$ProcessBaseName"
) | Select-Object -Unique

$PreFiles = Get-FileSnapshot -Roots $MonitoredRoots
$PreReg = Get-RunKeySnapshot

# 3. Start pktmon Network Capture (requires Administrator)
$PktmonStarted = $false
if ($PktmonBin -and $IsAdmin) {
    Write-Host "[2/6] Starting Windows pktmon network capture..." -ForegroundColor Yellow
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $PktmonBin stop 2>&1 | Out-Null
    & $PktmonBin filter remove 2>&1 | Out-Null
    & $PktmonBin start --capture --pkt-size 0 --file-name $EtlFile 2>&1 | Out-Null
    $pktExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if ($pktExit -eq 0) {
        $PktmonStarted = $true
    }
} else {
    Write-Host "[2/6] Skipping pktmon capture (requires Administrator shell)." -ForegroundColor DarkGray
}

# 4. Start Sysinternals Procmon Capture
$ProcmonStarted = $false
if ($ProcmonBin) {
    Write-Host "[3/6] Starting Sysinternals Procmon trace -> $PmlFile..." -ForegroundColor Yellow
    Remove-Item -Path $PmlFile, $CsvFile -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $ProcmonBin -ArgumentList @(
        "/AcceptEula",
        "/Quiet",
        "/Minimized",
        "/BackingFile", $PmlFile
    )
    Start-Sleep -Seconds 2
    $ProcmonStarted = $true
} else {
    Write-Host "[3/6] Skipping Procmon (Procmon64.exe/Procmon.exe not found on PATH or -ProcmonPath)." -ForegroundColor DarkGray
}

# 5. Launch Target Thick Client
Write-Host "[4/6] Launching target application ($ProcessBaseName)..." -ForegroundColor Green
$StartParams = @{
    FilePath = $ResolvedExe
    WorkingDirectory = $AppDir
    PassThru = $true
}
if ($TargetArgs.Count -gt 0) {
    $StartParams["ArgumentList"] = $TargetArgs
}
$AppProc = Start-Process @StartParams

if ($WaitForExit) {
    Write-Host "      Interact with the application (login, sync, settings, logout), then close it..." -ForegroundColor Cyan
    $AppProc.WaitForExit()
} else {
    Write-Host "      Capturing runtime activity for $DurationSeconds second(s)... Interact with the app now!" -ForegroundColor Cyan
    Start-Sleep -Seconds $DurationSeconds
    if (-not $AppProc.HasExited) {
        Write-Host "      Stopping target process (PID $($AppProc.Id))..." -ForegroundColor DarkYellow
        Stop-Process -Id $AppProc.Id -Force -ErrorAction SilentlyContinue
    }
}

# 6. Stop Captures & Convert Artifacts
Write-Host "[5/6] Stopping captures and converting artifacts..." -ForegroundColor Yellow

if ($ProcmonStarted) {
    & $ProcmonBin /Terminate | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Path $PmlFile) {
        Write-Host "      Exporting Procmon PML -> CSV ($CsvFile)..."
        & $ProcmonBin /AcceptEula /Quiet /Minimized /OpenLog $PmlFile /SaveAs $CsvFile | Out-Null
        Start-Sleep -Seconds 2
    }
}

if ($PktmonStarted) {
    & $PktmonBin stop | Out-Null
    if (Test-Path $EtlFile) {
        Write-Host "      Converting PktMon.etl -> PCAPNG ($PcapngFile)..."
        & $PktmonBin etl2pcap $EtlFile --out $PcapngFile | Out-Null
    }
}

# Compute Post-Execution State Diff
$PostFiles = Get-FileSnapshot -Roots $MonitoredRoots
$PostReg = Get-RunKeySnapshot

$CreatedFiles = @()
$ModifiedFiles = @()
foreach ($k in $PostFiles.Keys) {
    if (-not $PreFiles.ContainsKey($k)) {
        $CreatedFiles += $k
    } elseif ($PostFiles[$k].size -ne $PreFiles[$k].size -or $PostFiles[$k].mtime -ne $PreFiles[$k].mtime) {
        $ModifiedFiles += $k
    }
}
$AddedRegKeys = @{}
foreach ($rk in $PostReg.Keys) {
    if (-not $PreReg.ContainsKey($rk) -or $PreReg[$rk] -ne $PostReg[$rk]) {
        $AddedRegKeys[$rk] = $PostReg[$rk]
    }
}

$StateDiff = @{
    target_exe = $ResolvedExe
    captured_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    created_files = $CreatedFiles
    modified_files = $ModifiedFiles
    run_key_changes = $AddedRegKeys
}
$StateDiff | ConvertTo-Json -Depth 5 | Set-Content -Path $DiffFile -Encoding UTF8

# 7. Run Host Evidence & SDDL Collector
Write-Host "[6/6] Collecting host ACLs, SDDL descriptors, pipes, COM & KnownDLLs..." -ForegroundColor Yellow
$RepoRoot = Split-Path -Parent $PSScriptRoot
$CollectorScript = Join-Path $RepoRoot "collector\collect_host.py"
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

if (Test-Path $CollectorScript) {
    & $PythonExe $CollectorScript --app-dir $AppDir --filter $ProcessBaseName --output $EvidenceFile
}

# 8. Emit Ready-to-Run TIRtcp Command
Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "Capture Complete! Run TIRtcp with the collected evidence:" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green

$CmdParts = @(
    "tirtcp",
    "--target `"$AppDir`""
)
if (Test-Path $EvidenceFile) { $CmdParts += "--evidence `"$EvidenceFile`"" }
if (Test-Path $PcapngFile)   { $CmdParts += "--pcap `"$PcapngFile`"" }
if (Test-Path $CsvFile)      { $CmdParts += "--procmon-csv `"$CsvFile`"" }
$CmdParts += @(
    "--compliance $Compliance",
    "--engagement-id $EngagementId",
    "--no-active-probe",
    "--output `"$ResolvedOutDir\reports`""
)

Write-Host ($CmdParts -join " `` `n  ") -ForegroundColor White
Write-Host "========================================================================`n" -ForegroundColor Green