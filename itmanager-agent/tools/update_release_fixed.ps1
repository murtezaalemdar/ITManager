param(
  [string]$Root = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
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

$agentDir = $Root
$src = Join-Path $agentDir 'build-dist'
$dst = Join-Path $agentDir 'release-fixed'

if (-not (Test-Path $src)) { throw "Kaynak yok: $src" }
if (-not (Test-Path $dst)) { throw "Hedef yok: $dst" }

Write-Host "[+] Stopping service..." -ForegroundColor Cyan
try { sc.exe stop ITManagerAgent | Out-Host } catch { }

Write-Host "[+] Stopping tray/agent processes..." -ForegroundColor Cyan
@('ITManagerAgentTray','ITManagerAgent') | ForEach-Object {
  try {
    Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  } catch { }
}
Start-Sleep -Milliseconds 500

$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
  try {
    $q = sc.exe query ITManagerAgent | Out-String
    if ($q -match 'STATE\s*:\s*\d+\s+STOPPED') { break }
  } catch { }
  Start-Sleep -Seconds 1
}

Write-Host "[+] Copying EXEs to release-fixed..." -ForegroundColor Cyan
Copy-Item -Force (Join-Path $src 'ITManagerAgentService.exe') (Join-Path $dst 'ITManagerAgentService.exe')
Copy-Item -Force (Join-Path $src 'ITManagerAgentTray.exe') (Join-Path $dst 'ITManagerAgentTray.exe')
Copy-Item -Force (Join-Path $src 'ITManagerAgent.exe') (Join-Path $dst 'ITManagerAgent.exe')

Write-Host "[+] Reinstalling service..." -ForegroundColor Cyan
Push-Location $dst
try {
  .\install_service_admin.ps1 -Reinstall
} finally {
  Pop-Location
}

Write-Host "[+] Starting service..." -ForegroundColor Cyan
try { sc.exe start ITManagerAgent | Out-Host } catch { }

Write-Host "[OK] Updated release-fixed and reinstalled service." -ForegroundColor Green
