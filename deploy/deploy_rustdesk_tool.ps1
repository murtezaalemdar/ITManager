Param(
  [string]$Server = "root@192.168.0.6",
  [string]$KeyPath = "$(Join-Path $env:USERPROFILE '.ssh\itmanager_root_192_168_0_6')",
  [string]$RemoteToolsDir = "/opt/itmanager/itmanager-server/agent-releases/tools/windows"
)

Set-StrictMode -Version Latest
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
$localToolsDir = Join-Path $repoRoot 'itmanager-server\agent-releases\tools\windows'

if (-not (Test-Path -LiteralPath $localToolsDir)) {
  throw "Local tools directory not found: $localToolsDir"
}

$msi = Get-ChildItem -LiteralPath $localToolsDir -Filter 'rustdesk*.msi' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $msi) {
  throw "No RustDesk MSI found in $localToolsDir. Put rustdesk-*-x86_64.msi here first."
}

Write-Host "[deploy-rustdesk] Uploading $($msi.Name) to $Server" -ForegroundColor Cyan
ssh -i $KeyPath $Server "mkdir -p '$RemoteToolsDir'" | Out-Null
scp -i $KeyPath $msi.FullName "${Server}:$RemoteToolsDir/$($msi.Name)" | Out-Null
Write-Host "[deploy-rustdesk] Uploaded: $RemoteToolsDir/$($msi.Name)" -ForegroundColor Green

Write-Host "[deploy-rustdesk] Done" -ForegroundColor Green
