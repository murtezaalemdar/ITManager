Param(
  [string]$Server = "root@192.168.0.6",
  [string]$KeyPath = "$(Join-Path $env:USERPROFILE '.ssh\itmanager_root_192_168_0_6')",
  [string]$RemoteEnvFile = "/opt/itmanager/itmanager-server/.env",
  [string]$ConfigString = "",
  [switch]$NoRestart,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Require-Command([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command not found in PATH: $Name"
  }
}

Require-Command ssh

if (-not (Test-Path -LiteralPath $KeyPath)) {
  throw "SSH key not found: $KeyPath"
}

# Prefer clipboard to avoid pasting into terminal history.
if (-not $ConfigString) {
  try {
    $ConfigString = (Get-Clipboard -Raw)
  } catch {
    $ConfigString = ""
  }
}

$ConfigString = ($ConfigString + "") -replace "\r", ""
$ConfigString = $ConfigString.Trim()
if ($ConfigString -match "\n") {
  $ConfigString = ($ConfigString -split "\n")[0].Trim()
}

if (-not $ConfigString) {
  Write-Host "[rustdesk-config] Clipboard boş. RustDesk -> Settings -> Network -> Export Server Config ile string'i kopyalayıp tekrar çalıştırın." -ForegroundColor Yellow
  throw "Clipboard empty. Copy the Export Server Config string and rerun, or pass -ConfigString explicitly."
}

if (-not $ConfigString) {
  throw "RUSTDESK_CONFIG_STRING empty"
}

# Basic sanity check: exported config is typically a long single-line token.
$suspicious = $false
if ($ConfigString.Length -lt 30) { $suspicious = $true }
if ($ConfigString -match "\n") { $suspicious = $true }

if ($suspicious -and -not $Force) {
  Write-Host ("[rustdesk-config] UYARI: Clipboard içeriği şüpheli görünüyor (len=" + $ConfigString.Length + ").") -ForegroundColor Yellow
  Write-Host "[rustdesk-config] Doğru string'i kopyaladığınızdan emin olun (RustDesk -> Settings -> Network -> Export Server Config)." -ForegroundColor Yellow
  Write-Host "[rustdesk-config] Devam etmek için: .\\deploy\\set_rustdesk_config.ps1 -Force" -ForegroundColor Yellow
  throw "Suspicious clipboard content; aborting without changes."
}

# Base64 to avoid shell escaping issues.
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ConfigString))

Write-Host "[rustdesk-config] Setting RUSTDESK_CONFIG_STRING in $RemoteEnvFile on $Server" -ForegroundColor Cyan

# Build a small bash script locally, then ship it as base64 to avoid quoting issues.
# NOTE: Do not print the secret value.
$remoteScript = @'
set -e
ENVFILE="__ENVFILE__"
mkdir -p "$(dirname "$ENVFILE")"
touch "$ENVFILE"

val=$(printf %s '__B64__' | base64 -d | tr -d '\r\n')

tmp=$(mktemp)
(grep -v '^RUSTDESK_CONFIG_STRING=' "$ENVFILE" > "$tmp" || true)
printf 'RUSTDESK_CONFIG_STRING=%s\n' "$val" >> "$tmp"
chmod 600 "$tmp" || true
mv "$tmp" "$ENVFILE"

grep -q '^RUSTDESK_CONFIG_STRING=' "$ENVFILE"
echo OK
'@

$remoteScript = $remoteScript.Replace('__ENVFILE__', $RemoteEnvFile).Replace('__B64__', $b64)
$remoteScript = $remoteScript -replace "\r", ""
$remoteScriptB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remoteScript))

$sshCmd = "bash -lc 'printf %s ""$remoteScriptB64"" | base64 -d | bash'"
ssh -i $KeyPath $Server $sshCmd
if ($LASTEXITCODE -ne 0) {
  throw "Remote apply failed (ssh exit=$LASTEXITCODE)"
}

if (-not $NoRestart) {
  Write-Host "[rustdesk-config] Restarting itmanager-server" -ForegroundColor Cyan
  ssh -i $KeyPath $Server "systemctl restart itmanager-server"
  ssh -i $KeyPath $Server "bash -lc 'for i in {1..30}; do curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 && break; sleep 1; done; curl -fsS http://127.0.0.1:8000/health; echo'"
}

Write-Host "[rustdesk-config] Done" -ForegroundColor Green
