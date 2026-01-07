param(
  [switch]$ServiceOnly,
  [switch]$TrayOnly,
  [switch]$NoStart,
  [switch]$Delayed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  $argList = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', "`"$PSCommandPath`""
  ) + $MyInvocation.UnboundArguments

  $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -Wait -PassThru
  if ($null -ne $p -and $null -ne $p.ExitCode) { exit [int]$p.ExitCode }
  exit 1
}

Set-Location -LiteralPath (Split-Path -Parent $PSCommandPath)

# Stop running instances (prevents locked binaries during update)
$svcName = 'ITManagerAgent'
try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch { }
Start-Sleep -Seconds 1
foreach ($p in @('ITManagerAgentService', 'ITManagerAgentTray', 'ITManagerAgent')) {
  try { Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch { }
  try { & taskkill.exe /F /T /IM ($p + '.exe') 2>$null | Out-Null } catch { }
}
Start-Sleep -Seconds 1

$pd = Join-Path $env:ProgramData 'ITManagerAgent'
New-Item -ItemType Directory -Force -Path $pd | Out-Null

# Remove legacy Quick Assist desktop shortcut if present
try {
  $publicDesktop = Join-Path $env:Public 'Desktop'
  $qaShortcut = Join-Path $publicDesktop 'Hızlı Yardım.url'
  if (Test-Path -LiteralPath $qaShortcut) {
    Remove-Item -Force -LiteralPath $qaShortcut -ErrorAction SilentlyContinue
  }
} catch {
  # Non-fatal
}

# Ensure config.json exists (first install UX)
$cfgJson = Join-Path (Get-Location) 'config.json'
$cfgExample = Join-Path (Get-Location) 'config.example.json'
if (-not (Test-Path -LiteralPath $cfgJson)) {
  if (Test-Path -LiteralPath $cfgExample) {
    Copy-Item -Force -LiteralPath $cfgExample -Destination $cfgJson
    Write-Host "[!] config.json bulunamadı; config.example.json -> config.json kopyalandı." -ForegroundColor Yellow
    Write-Host "    Lütfen config.json içindeki server_url/api_key gibi alanları düzenleyin." -ForegroundColor Yellow
  } else {
    throw "config.json bulunamadı ve config.example.json da yok. Kurulum yapılamadı."
  }
}

# Copy config.json to stable location too (service/tray will read it there)
Copy-Item -Force -LiteralPath $cfgJson -Destination (Join-Path $pd 'config.json')
try { Unblock-File -Path (Join-Path $pd 'config.json') -ErrorAction SilentlyContinue } catch { }

$doService = -not $TrayOnly
$doTray = -not $ServiceOnly

# Copy all binaries to ProgramData (stable install dir) so the folder is fully populated
# and updates are not "half-copied" depending on which helper script ran.
$srcDir = Get-Location
$required = @()
if ($doService) { $required += 'ITManagerAgentService.exe' }
if ($doTray) { $required += 'ITManagerAgentTray.exe' }
# Keep console exe too (used for manual runs / diagnostics)
$required += 'ITManagerAgent.exe'

foreach ($name in ($required | Select-Object -Unique)) {
  $p = Join-Path $srcDir $name
  if (-not (Test-Path -LiteralPath $p)) {
    if ($name -eq 'ITManagerAgent.exe') {
      Write-Host "[WARN] $name bulunamadı; atlanıyor: $p" -ForegroundColor Yellow
      continue
    }
    throw "$name bulunamadı: $p"
  }
}

$stage = Join-Path $pd ("_stage_setup_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
  foreach ($name in @('ITManagerAgentService.exe','ITManagerAgentTray.exe','ITManagerAgent.exe')) {
    $src = Join-Path $srcDir $name
    if (-not (Test-Path -LiteralPath $src)) { continue }
    $tmp = Join-Path $stage $name
    Copy-Item -Force -LiteralPath $src -Destination $tmp
    try { Unblock-File -Path $tmp -ErrorAction SilentlyContinue } catch { }
  }

  foreach ($name in @('ITManagerAgentService.exe','ITManagerAgentTray.exe','ITManagerAgent.exe')) {
    $tmp = Join-Path $stage $name
    if (-not (Test-Path -LiteralPath $tmp)) { continue }
    Copy-Item -Force -LiteralPath $tmp -Destination (Join-Path $pd $name)
    try { Unblock-File -Path (Join-Path $pd $name) -ErrorAction SilentlyContinue } catch { }
  }
} finally {
  try { Remove-Item -Recurse -Force -LiteralPath $stage -ErrorAction SilentlyContinue } catch { }
}

if ($doService) {
  $args = @()
  if ($Delayed) { $args += '-Delayed' }
  if ($NoStart) { $args += '-NoStart' }
  $args += '-Reinstall'

  & (Join-Path (Get-Location) 'install_service_admin.ps1') @args
}

if ($doTray) {
  & (Join-Path (Get-Location) 'install_tray_startup.ps1') -TrayExePath (Join-Path (Get-Location) 'ITManagerAgentTray.exe')
}

if (-not $NoStart) {
  try {
    for ($i = 1; $i -le 10; $i++) {
      $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if ($null -eq $svc) { throw "Servis bulunamadı: $svcName" }
      if ($svc.Status -eq 'Running') { break }

      Write-Host "[INFO] Servis start denemesi $i/10: $svcName (mevcut=$($svc.Status))" -ForegroundColor Yellow
      try { Start-Service -Name $svcName -ErrorAction SilentlyContinue } catch { }
      try { sc.exe start $svcName | Out-Null } catch { }
      Start-Sleep -Seconds 2
      $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if ($null -ne $svc -and $svc.Status -eq 'Running') { break }
      if ($i -lt 10) { Start-Sleep -Seconds 3 }
    }

    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($null -eq $svc -or $svc.Status -ne 'Running') {
      sc.exe query $svcName | Out-Host
      throw "Servis RUNNING durumuna gelemedi: $svcName"
    }
  } catch {
    Write-Host "[ERROR] Servis doğrulama/başlatma başarısız: $($_)" -ForegroundColor Red
    exit 1
  }
}

Write-Host "[OK] Kurulum/Update tamamlandı." -ForegroundColor Green
Write-Host "- Dosyalar: $pd" 
Write-Host "- Servis: ITManagerAgent (auto/delayed-auto)" 
Write-Host "- Tray: Startup'a eklendi (login sonrası açılır)" 
