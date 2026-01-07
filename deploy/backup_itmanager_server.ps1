Param(
  [string]$Server = "root@192.168.0.6",
  [string]$KeyPath = "$(Join-Path $env:USERPROFILE '.ssh\itmanager_root_192_168_0_6')",
  [string]$RemoteRoot = "/opt/itmanager/itmanager-server",
  [string]$RemoteBackupDir = "/opt/itmanager/_backups",
  [switch]$IncludeEnv
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
$localBackupDir = Join-Path $repoRoot 'backups'
New-Item -ItemType Directory -Force -Path $localBackupDir | Out-Null

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$envPart = if ($IncludeEnv) { 'withenv' } else { 'noenv' }
$remoteFile = "$RemoteBackupDir/itmanager-server_${ts}_${envPart}.tar.gz"
$localFile = Join-Path $localBackupDir (Split-Path -Leaf $remoteFile)

Write-Host "[backup] Creating remote backup at $remoteFile" -ForegroundColor Cyan

$inc = if ($IncludeEnv) { 1 } else { 0 }

$tarCmd = if ($inc -eq 1) {
  "sudo tar -czf '$remoteFile' app agent-releases .env"
} else {
  "sudo tar -czf '$remoteFile' app agent-releases"
}

# Create archive on server (avoid heredoc to prevent CRLF/quoting issues)
$remoteBash = @(
  "set -euo pipefail",
  "mkdir -p '$RemoteBackupDir'",
  "cd '$RemoteRoot'",
  $tarCmd,
  "ls -lh '$remoteFile'"
) -join '; '

ssh -i $KeyPath $Server "bash -lc \"$remoteBash\""

Write-Host "[backup] Downloading to $localFile" -ForegroundColor Cyan
scp -i $KeyPath "${Server}:$remoteFile" "$localFile" | Out-Null

Write-Host "[backup] Local file:" -ForegroundColor Cyan
Get-Item -LiteralPath $localFile | Format-List FullName,Length,LastWriteTime

Write-Host "[backup] Done" -ForegroundColor Green
