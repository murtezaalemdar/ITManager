param(
  [Parameter(Mandatory=$true)][string]$ServerBaseUrl,
  [Parameter(Mandatory=$true)][string]$EnrollmentToken,
  [string]$Platform = 'windows',
  [switch]$VerifyTls
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  Write-Host 'Yönetici yetkisi gerekiyor, UAC açılıyor...'
  $args = @(
    '-NoProfile','-ExecutionPolicy','Bypass','-File',"$PSCommandPath",
    '-ServerBaseUrl',"$ServerBaseUrl",
    '-EnrollmentToken',"$EnrollmentToken",
    '-Platform',"$Platform"
  )
  if ($VerifyTls) { $args += '-VerifyTls' }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args | Out-Null
  exit 0
}

$base = ($ServerBaseUrl.TrimEnd('/'))
$pd = Join-Path $env:ProgramData 'ITManagerAgent'
New-Item -ItemType Directory -Force -Path $pd | Out-Null
$log = Join-Path $pd 'bootstrap_install.log'

function Log([string]$m) {
  $line = "$(Get-Date -Format s) $m"
  try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch {}
  Write-Host $line
}

# TLS validation bypass for Windows PowerShell 5.1 if VerifyTls is not set
$oldCallback = $null
if (-not $VerifyTls) {
  try {
    $oldCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  } catch {}
}

try {
  Log "bootstrap start server=$base platform=$Platform verify_tls=$VerifyTls"

  $latestUrl = "$base/api/agent/releases/enroll/latest?platform=$Platform&enrollment_token=$([uri]::EscapeDataString($EnrollmentToken))"
  Log "fetch latest -> $latestUrl"
  $info = Invoke-RestMethod -Method Get -Uri $latestUrl -TimeoutSec 30

  if (-not $info -or -not $info.version -or -not $info.download_url) {
    throw 'latest response invalid'
  }

  $ver = [string]$info.version
  $shaExpected = ''
  if ($info.sha256) { $shaExpected = ([string]$info.sha256).ToUpper() }

  $downloadUrl = [string]$info.download_url
  if ($downloadUrl.StartsWith('/')) { $downloadUrl = "$base$downloadUrl" }

  $tmpDir = Join-Path $pd 'bootstrap'
  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  $zipPath = Join-Path $tmpDir "itmanager-agent-$Platform-$ver.zip"

  Log "download -> $downloadUrl"
  Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 180 | Out-Null

  if ($shaExpected) {
    $sha = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToUpper()
    if ($sha -ne $shaExpected) {
      throw "SHA256 mismatch expected=$shaExpected actual=$sha"
    }
    Log "sha256 ok $sha"
  }

  $releaseRoot = Join-Path $pd 'releases'
  New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null
  $releaseDir = Join-Path $releaseRoot "$Platform-$ver"
  if (Test-Path $releaseDir) { Remove-Item -Recurse -Force $releaseDir }
  New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

  Log "extract -> $releaseDir"
  Expand-Archive -Path $zipPath -DestinationPath $releaseDir -Force

  # Find service exe (zip may include a top-level folder)
  $svcExe = Join-Path $releaseDir 'ITManagerAgentService.exe'
  if (-not (Test-Path $svcExe)) {
    $found = Get-ChildItem -Path $releaseDir -Recurse -Filter 'ITManagerAgentService.exe' | Select-Object -First 1
    if (-not $found) { throw 'ITManagerAgentService.exe not found in extracted zip' }
    $svcExe = $found.FullName
  }

  # Ensure ProgramData config exists (merge-friendly)
  $cfgPath = Join-Path $pd 'config.json'
  if (-not (Test-Path $cfgPath)) {
    Log "write config -> $cfgPath"
    $cfg = @{
      server_base_url = $base
      enrollment_token = $EnrollmentToken
      verify_tls = [bool]$VerifyTls
      poll_seconds = 10
      state_dir = $pd
      auto_update = $true
      update_check_interval_seconds = 3600
      update_notify_user = $true
    }
    $cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $cfgPath -Encoding UTF8
  }

  $svcName = 'ITManagerAgent'
  Log "stop service (best-effort)"
  try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch {}
  Start-Sleep -Seconds 2

  Log "set binPath -> $svcExe"
  & sc.exe config $svcName binPath= "\"$svcExe\"" | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Log "service not configured yet; installing"
    & "$svcExe" install | Out-Null
  }

  Log "start service"
  try { Start-Service -Name $svcName -ErrorAction Stop } catch { & "$svcExe" start | Out-Null }

  Log "bootstrap done version=$ver"
  exit 0
}
finally {
  if (-not $VerifyTls) {
    try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $oldCallback } catch {}
  }
}
