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

function Ensure-ServiceRunning([string]$ServiceName, [int]$Attempts = 10, [int]$SleepSeconds = 3) {
  for ($i = 1; $i -le $Attempts; $i++) {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
      throw "Service not found: $ServiceName"
    }
    if ($svc.Status -eq 'Running') {
      return
    }

    Write-Host "[INFO] Servis start denemesi $i/$($Attempts): $ServiceName (mevcut=$($svc.Status))" -ForegroundColor Yellow
    try { Start-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
    try { sc.exe start $ServiceName | Out-Null } catch { }

    # Wait a bit for transition to RUNNING
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.Status -eq 'Running') {
      return
    }

    if ($i -lt $Attempts) {
      Start-Sleep -Seconds $SleepSeconds
    }
  }

  sc.exe query $ServiceName | Out-Host
  throw "Service did not reach RUNNING after $Attempts attempts: $ServiceName"
}

$srcExe = Join-Path (Get-Location) 'ITManagerAgentService.exe'
if (-not (Test-Path $srcExe)) {
  throw "ITManagerAgentService.exe bulunamadı: $srcExe"
}

# Install from a stable location so the service keeps working after reboot
# even if the extracted ZIP folder is moved or deleted.
$pd = Join-Path $env:ProgramData 'ITManagerAgent'
New-Item -ItemType Directory -Force -Path $pd | Out-Null
$exe = Join-Path $pd 'ITManagerAgentService.exe'
Copy-Item -Force $srcExe $exe

# Remove Mark-of-the-Web if present
try { Unblock-File -Path $exe -ErrorAction SilentlyContinue } catch { }

if ($Reinstall) {
  try { sc.exe stop ITManagerAgent | Out-Null } catch { }
  Start-Sleep -Seconds 2
  try { sc.exe delete ITManagerAgent | Out-Null } catch { }
  Start-Sleep -Seconds 2
}

$startup = if ($Delayed) { 'delayed' } else { 'auto' }

& $exe --startup $startup install | Out-Host
if ($LASTEXITCODE -ne 0) {
  throw "Service install failed (exit=$LASTEXITCODE)"
}

# Also set startup type via sc.exe for reliability after reboot
$startupSc = if ($Delayed) { 'delayed-auto' } else { 'auto' }
sc.exe config ITManagerAgent start= $startupSc | Out-Null

# Crash/recovery: fail -> restart
sc.exe failure ITManagerAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag ITManagerAgent 1 | Out-Null

if (-not $NoStart) {
  & $exe --wait 30 start | Out-Host
  if ($LASTEXITCODE -ne 0) {
    throw "Service start command failed (exit=$LASTEXITCODE)"
  }

  # Verify service is actually running; retry a few times (some machines need extra time).
  Ensure-ServiceRunning -ServiceName 'ITManagerAgent' -Attempts 10 -SleepSeconds 3
}

sc.exe query ITManagerAgent | Out-Host
Write-Host "[OK] Kurulum tamamlandı. (startup=$startup)"