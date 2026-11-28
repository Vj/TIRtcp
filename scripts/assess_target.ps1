<#
.SYNOPSIS
    One-command TIRtcp end-to-end assessment wrapper for Windows thick clients.
    Orchestrates static scan + optional dynamic capture + optional Frida hooks + unified report.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [string]$EngagementId = "ENG-2026-001",

    [ValidateSet("general", "bfsi")]
    [string]$Compliance = "general",

    [switch]$DynamicCapture,
    [switch]$FridaHook,
    [int]$CaptureSeconds = 20,

    [switch]$Authorized,
    [string]$BaselineReport = "",
    [string]$OutputDir = ".\reports"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$ExeRunner = Join-Path $RepoRoot "dist\TIRtcp_win64\tirtcp.exe"
$UseBinary = Test-Path $ExeRunner

$CaptureDir = Join-Path $OutputDir "capture_$EngagementId"
$StateDiffArg = @()
$RuntimeHookArg = @()

if ($DynamicCapture -and (Test-Path $Target -PathType Leaf)) {
    if (-not $Authorized) {
        throw "Dynamic capture launches the target binary and requires -Authorized."
    }
    New-Item -ItemType Directory -Path $CaptureDir -Force | Out-Null
    Write-Host "[1/2] Running dynamic runtime capture for ${CaptureSeconds}s..." -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot "dynamic_capture.ps1") -TargetExe $Target -DurationSeconds $CaptureSeconds -OutDir $CaptureDir
    $DiffJson = Join-Path $CaptureDir "state_diff.json"
    if (Test-Path $DiffJson) {
        $StateDiffArg = @("--state-diff", $DiffJson)
    }
}


if ($FridaHook -and (Test-Path $Target -PathType Leaf)) {
    if (-not $Authorized) {
        throw "Frida runtime instrumentation requires -Authorized."
    }
    New-Item -ItemType Directory -Path $CaptureDir -Force | Out-Null
    $HookOut = Join-Path $CaptureDir "runtime_hooks.json"
    $FridaScript = Join-Path $PSScriptRoot "frida_hook_harness.py"
    if (Test-Path $FridaScript) {
        Write-Host "[*] Running Frida runtime API hook harness..." -ForegroundColor Cyan
        python $FridaScript --target $Target --duration $CaptureSeconds --out $HookOut
        if (Test-Path $HookOut) {
            $RuntimeHookArg = @("--runtime-hooks", $HookOut)
        }
    }
}

$CliArgs = @(
    "--target", $Target,
    "--compliance", $Compliance,
    "--engagement-id", $EngagementId,
    "--no-active-probe",
    "--output", $OutputDir
) + $StateDiffArg + $RuntimeHookArg

if ($Authorized) {
    $CliArgs += "--authorized"
}
if ($BaselineReport -and (Test-Path $BaselineReport)) {
    $CliArgs += @("--baseline-report", $BaselineReport)
}

Write-Host "[2/2] Running TIRtcp unified assessment..." -ForegroundColor Cyan
if ($UseBinary) {
    & $ExeRunner @CliArgs
} else {
    python -m analyzer.tirtcp @CliArgs
}
