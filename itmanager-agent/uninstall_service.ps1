param(
  [string]$AgentDir = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  throw "Bu script Administrator olarak çalıştırılmalı. PowerShell'i 'Run as administrator' aç."
}

Push-Location $AgentDir

$venvPy = Join-Path $AgentDir ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  throw "Venv python bulunamadı: $venvPy"
}

Write-Host "Servis durduruluyor (varsa)..."
try { & $venvPy .\service.py stop } catch { }

Write-Host "Servis kaldırılıyor..."
try { & $venvPy .\service.py remove } catch { }

Pop-Location
Write-Host "OK: ITManagerAgent servisi kaldırıldı."