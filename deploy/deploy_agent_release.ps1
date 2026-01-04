Param(
  [string]$Server = "root@192.168.0.6",
  [string]$KeyPath = "$(Join-Path $env:USERPROFILE '.ssh\itmanager_root_192_168_0_6')",
  [string]$RemoteReleaseDir = "/opt/itmanager/itmanager-server/agent-releases/windows",
  [switch]$NoBuild,
  [switch]$NoRestartServer
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
$agentDir = Join-Path $repoRoot 'itmanager-agent'
$buildScript = Join-Path $agentDir 'build_agent_exe.ps1'

if (-not (Test-Path -LiteralPath $buildScript)) {
  throw "Build script not found: $buildScript"
}

if (-not $NoBuild) {
  Write-Host "[deploy-agent] Building agent (auto version bump)" -ForegroundColor Cyan
  Push-Location $agentDir
  try {
    # build_agent_exe.ps1 now bumps patch by default.
    & $buildScript
  } finally {
    Pop-Location
  }
}

# Determine current version from version.py (source of truth).
$version = ''
try {
  $version = (Get-Content (Join-Path $agentDir 'version.py') -Raw) -replace '\r',''
  if ($version -match '__version__\s*=\s*\"(?<v>[^\"]+)\"') {
    $version = $Matches['v']
  } else {
    throw "version.py parse failed"
  }
} catch {
  throw "Unable to read agent version from version.py: $($_.Exception.Message)"
}

if ($version -notmatch '^\d+\.\d+\.\d+$') {
  throw "Invalid SemVer in version.py: $version"
}

$zipName = "itmanager-agent-windows-$version.zip"
$zipPath = Join-Path $agentDir $zipName
$shaPath = "$zipPath.sha256"

if (-not (Test-Path -LiteralPath $zipPath)) {
  throw "Release ZIP not found: $zipPath (build was skipped or failed?)"
}
if (-not (Test-Path -LiteralPath $shaPath)) {
  throw "SHA256 file not found: $shaPath"
}

Write-Host "[deploy-agent] Uploading $zipName to $Server" -ForegroundColor Cyan
ssh -i $KeyPath $Server "mkdir -p '$RemoteReleaseDir'" | Out-Null
scp -i $KeyPath $zipPath "${Server}:$RemoteReleaseDir/$zipName" | Out-Null
scp -i $KeyPath $shaPath "${Server}:$RemoteReleaseDir/$zipName.sha256" | Out-Null
Write-Host "[deploy-agent] Uploaded: $RemoteReleaseDir/$zipName (+ .sha256)" -ForegroundColor Green

if (-not $NoRestartServer) {
  Write-Host "[deploy-agent] Restarting itmanager-server (to pick up new release)" -ForegroundColor Cyan
  ssh -i $KeyPath $Server "systemctl restart itmanager-server; systemctl status itmanager-server --no-pager -l" 

  Write-Host "[deploy-agent] Waiting for server health" -ForegroundColor Cyan
  ssh -i $KeyPath $Server "bash -lc 'for i in {1..30}; do curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 && break; sleep 1; done; curl -fsS http://127.0.0.1:8000/health; echo'"
}

Write-Host "[deploy-agent] Done (version=$version)" -ForegroundColor Green
