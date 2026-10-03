# install_scorer.ps1 — autostart the APT-CTI scoring service for the current
# user (Startup folder; no admin rights required).
#
#   powershell -ExecutionPolicy Bypass -File deploy\install_scorer.ps1
#   powershell -ExecutionPolicy Bypass -File deploy\install_scorer.ps1 -StartNow
#   powershell -ExecutionPolicy Bypass -File deploy\install_scorer.ps1 -Uninstall
#
# Runs hidden via pythonw; stdout/stderr append to deploy\scorer.log.

param([switch]$Uninstall, [switch]$StartNow)

$root = Split-Path -Parent $PSScriptRoot
$entry = Join-Path $env:APPDATA `
    'Microsoft\Windows\Start Menu\Programs\Startup\apt-cti-scorer.cmd'
$py = Join-Path $root '.venv\Scripts\pythonw.exe'
$svc = Join-Path $root 'deploy\service.py'
$cfg = Join-Path $root 'deploy\config.yaml'

function Stop-Scorer {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*deploy\service.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

if ($Uninstall) {
    Stop-Scorer
    Remove-Item $entry -Force -ErrorAction SilentlyContinue
    Write-Host "removed: $entry (and any running service instance)"
    exit 0
}

if (-not (Test-Path $py))  { throw "venv pythonw not found: $py" }
if (-not (Test-Path $svc)) { throw "service not found: $svc" }

$cmd = @"
@echo off
cd /d "$root"
start "" /b "$py" "$svc" --config "$cfg" >> "$root\deploy\scorer.log" 2>&1
"@
Set-Content -Path $entry -Value $cmd -Encoding ASCII
Write-Host "installed autostart: $entry"

if ($StartNow) {
    Stop-Scorer
    Start-Process -FilePath $py `
        -ArgumentList "`"$svc`"", "--config", "`"$cfg`"" `
        -WorkingDirectory $root -WindowStyle Hidden
    Write-Host "service started (web: http://127.0.0.1:8099/)"
}
