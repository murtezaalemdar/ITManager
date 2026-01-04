Param(
  [string]$Server = "root@192.168.0.6",
  [string]$KeyPath = "$(Join-Path $env:USERPROFILE '.ssh\itmanager_root_192_168_0_6')",
  [string]$RemoteRoot = "/opt/itmanager/itmanager-server"
)

$ErrorActionPreference = 'Stop'

function Require-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command not found in PATH: $Name"
  }
}

Require-Command ssh
Require-Command scp

if (-not (Test-Path -LiteralPath $KeyPath)) {
  throw "SSH key not found: $KeyPath"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$localServerDir = Join-Path $repoRoot 'itmanager-server'

$files = @(
  @{ Local = (Join-Path $localServerDir 'app\main.py'); Remote = "$RemoteRoot/app/main.py" },
  @{ Local = (Join-Path $localServerDir 'app\templates\device_detail.html'); Remote = "$RemoteRoot/app/templates/device_detail.html" }
)

foreach ($f in $files) {
  if (-not (Test-Path -LiteralPath $f.Local)) {
    throw "Local file missing: $($f.Local)"
  }
}

Write-Host "[deploy] Uploading files to $Server" -ForegroundColor Cyan

foreach ($f in $files) {
  $remoteDir = Split-Path -Parent $f.Remote
  ssh -i $KeyPath $Server "mkdir -p '$remoteDir'" | Out-Null
  scp -i $KeyPath $f.Local "${Server}:$($f.Remote)" | Out-Null
  Write-Host "[deploy] Updated $($f.Remote)" -ForegroundColor Green
}

Write-Host "[deploy] Restarting service itmanager-server" -ForegroundColor Cyan
ssh -i $KeyPath $Server "systemctl restart itmanager-server; systemctl status itmanager-server --no-pager -l" 

Write-Host "[deploy] Waiting for upstream health (127.0.0.1:8000)" -ForegroundColor Cyan
ssh -i $KeyPath $Server "bash -lc 'for i in {1..30}; do curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 && break; sleep 1; done; curl -fsS http://127.0.0.1:8000/health; echo'"

Write-Host "[deploy] Verifying template contains expected text" -ForegroundColor Cyan
ssh -i $KeyPath $Server "grep -R 'Online sayılır: son' -n $RemoteRoot/app/templates/device_detail.html || true"

Write-Host "[deploy] Health check" -ForegroundColor Cyan
ssh -i $KeyPath $Server "bash -lc 'for i in {1..30}; do curl -kfsS https://127.0.0.1/health >/dev/null 2>&1 && break; sleep 1; done; curl -kfsS https://127.0.0.1/health; echo'" 

Write-Host "[deploy] Done" -ForegroundColor Green
