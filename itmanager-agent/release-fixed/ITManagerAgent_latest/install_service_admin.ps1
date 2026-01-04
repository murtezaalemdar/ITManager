param(
  [switch]$Reinstall,
  [switch]$Delayed,
  [switch]$NoStart
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

$exe = Join-Path (Get-Location) 'ITManagerAgentService.exe'
if (-not (Test-Path $exe)) {
  throw "ITManagerAgentService.exe bulunamadı: $exe"
}

if ($Reinstall) {
  try { & $exe --wait 20 stop | Out-Host } catch { }
  try { & $exe remove | Out-Host } catch { }
}

$startup = if ($Delayed) { 'delayed' } else { 'auto' }

& $exe --startup $startup install | Out-Host

# Also set startup type via sc.exe for reliability after reboot
$startupSc = if ($Delayed) { 'delayed-auto' } else { 'auto' }
sc.exe config ITManagerAgent start= $startupSc | Out-Null

# Crash/recovery: fail -> restart
sc.exe failure ITManagerAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag ITManagerAgent 1 | Out-Null

if (-not $NoStart) {
  & $exe --wait 30 start | Out-Host
}

sc.exe query ITManagerAgent | Out-Host
Write-Host "[OK] Kurulum tamamlandı. (startup=$startup)"