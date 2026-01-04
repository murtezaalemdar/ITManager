param(
  [string]$AgentDir = (Split-Path -Parent $MyInvocation.MyCommand.Path),
  [string]$ServerBaseUrl,
  [string]$EnrollmentToken,
  $VerifyTls = $false,
  [int]$PollSeconds = 10,
  [string]$StateDir = "C:/ProgramData/ITManagerAgent",
  [string]$PythonExe = "python"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Convert-ToBool($value, [bool]$default = $false) {
  if ($null -eq $value) { return $default }
  if ($value -is [bool]) { return $value }
  $s = "$value".Trim().ToLowerInvariant()
  if ($s -in @("true","1","yes","y","on")) { return $true }
  if ($s -in @("false","0","no","n","off")) { return $false }
  return $default
}

if (-not (Test-IsAdmin)) {
  throw "Bu script Administrator olarak çalıştırılmalı. PowerShell'i 'Run as administrator' aç." 
}

Write-Host "AgentDir: $AgentDir"
Push-Location $AgentDir

$venvDir = Join-Path $AgentDir ".venv"
if (-not (Test-Path $venvDir)) {
  Write-Host "Venv oluşturuluyor..."
  & $PythonExe -m venv $venvDir
}

$venvPy = Join-Path $venvDir "Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
  throw "Venv python bulunamadı: $venvPy"
}

Write-Host "Paketler kuruluyor..."
& $venvPy -m pip install -r .\requirements.txt

$configPath = Join-Path $AgentDir "config.json"
if (-not (Test-Path $configPath)) {
  Write-Host "config.json yok. config.example.json'dan kopyalanıyor..."
  Copy-Item .\config.example.json .\config.json
}

# Parametre verilmişse config.json'ı güncelle
if ($ServerBaseUrl -or $EnrollmentToken) {
  $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
  if ($ServerBaseUrl) { $cfg.server_base_url = $ServerBaseUrl.TrimEnd('/') }
  if ($EnrollmentToken) { $cfg.enrollment_token = $EnrollmentToken }
  $cfg.verify_tls = (Convert-ToBool $VerifyTls $false)
  $cfg.poll_seconds = [int]$PollSeconds
  $cfg.state_dir = $StateDir
  $cfg | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8
  Write-Host "config.json güncellendi."
} else {
  Write-Host "Not: ServerBaseUrl/EnrollmentToken verilmedi; mevcut config.json kullanılacak."
}

Write-Host "Servis kuruluyor..."
& $venvPy .\service.py install

Write-Host "Servis startup tipi ayarlanıyor (Automatic)..."
sc.exe config ITManagerAgent start= auto | Out-Null

Write-Host "Servis recovery ayarlanıyor (fail->restart)..."
sc.exe failure ITManagerAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
sc.exe failureflag ITManagerAgent 1 | Out-Null

Write-Host "Servis başlatılıyor..."
& $venvPy .\service.py start

Pop-Location
Write-Host "OK: ITManagerAgent servisi kuruldu ve başlatıldı."