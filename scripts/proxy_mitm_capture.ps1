<#
.SYNOPSIS
    Starts an isolated local MITM HTTP/HTTPS capture proxy (mitmdump if available, or Python
    HTTP CONNECT logger) scoped to the target thick-client process, restoring system/env proxy
    settings cleanly on exit.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetExe,

    [int]$ProxyPort = 8080,
    [int]$DurationSeconds = 30,
    [string]$OutDir = ".\reports\mitm_capture"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $TargetExe -PathType Leaf)) {
    throw "Target executable not found: $TargetExe"
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$FlowFile = Join-Path $OutDir "mitm_flows.mitm"
$LogFile = Join-Path $OutDir "mitm_requests.jsonl"

$MitmBin = Get-Command mitmdump -ErrorAction SilentlyContinue
$ProxyProc = $null
$TargetProc = $null

$OrigHttpProxy = $env:HTTP_PROXY
$OrigHttpsProxy = $env:HTTPS_PROXY

try {
    if ($MitmBin) {
        Write-Host "[*] Starting mitmdump on 127.0.0.1:$ProxyPort -> $FlowFile" -ForegroundColor Cyan
        $ProxyProc = Start-Process -FilePath $MitmBin.Source `
            -ArgumentList @("--listen-host", "127.0.0.1", "--listen-port", "$ProxyPort", "-w", $FlowFile, "--set", "termlog_verbosity=error") `
            -PassThru -WindowStyle Hidden
    } else {
        Write-Host "[!] mitmdump not found on PATH; starting lightweight Python CONNECT/HTTP logger on 127.0.0.1:$ProxyPort" -ForegroundColor Yellow
        $PyLogger = @"
import json, socket, threading, time
from pathlib import Path
log_path = Path(r'$LogFile')
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', $ProxyPort))
srv.listen(32)
def handle(c):
    try:
        head = c.recv(4096).decode('utf-8', errors='ignore')
        first = head.splitlines()[0] if head else ''
        if first:
            with log_path.open('a', encoding='utf-8') as f:
                f.write(json.dumps({'ts': time.time(), 'request_line': first}) + '\n')
        c.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
    except Exception:
        pass
    finally:
        c.close()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"@
        $HelperPy = Join-Path $OutDir "_connect_logger.py"
        $PyLogger | Set-Content -Path $HelperPy -Encoding UTF8
        $ProxyProc = Start-Process -FilePath "python" -ArgumentList @($HelperPy) -PassThru -WindowStyle Hidden
    }

    Start-Sleep -Seconds 2
    $env:HTTP_PROXY = "http://127.0.0.1:$ProxyPort"
    $env:HTTPS_PROXY = "http://127.0.0.1:$ProxyPort"

    Write-Host "[*] Launching target with scoped proxy for ${DurationSeconds}s: $TargetExe" -ForegroundColor Cyan
    $TargetProc = Start-Process -FilePath $TargetExe -PassThru
    Start-Sleep -Seconds $DurationSeconds
}
finally {
    $env:HTTP_PROXY = $OrigHttpProxy
    $env:HTTPS_PROXY = $OrigHttpsProxy

    if ($TargetProc -and -not $TargetProc.HasExited) {
        Stop-Process -Id $TargetProc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($ProxyProc -and -not $ProxyProc.HasExited) {
        Stop-Process -Id $ProxyProc.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] Proxy settings restored and capture saved under: $OutDir" -ForegroundColor Green
}
