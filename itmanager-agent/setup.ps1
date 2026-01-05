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

  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList | Out-Null
  exit 0
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

Write-Host "[OK] Kurulum/Update tamamlandı." -ForegroundColor Green
Write-Host "- Dosyalar: $pd" 
Write-Host "- Servis: ITManagerAgent (auto/delayed-auto)" 
Write-Host "- Tray: Startup'a eklendi (login sonrası açılır)" 
