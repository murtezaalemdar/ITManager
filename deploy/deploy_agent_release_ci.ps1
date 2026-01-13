<#
.SYNOPSIS
  GitHub Actions ile üretilen multi-platform agent ZIP'lerini sunucuya yükler.

.DESCRIPTION
  Local'de indirilen ZIP + .sha256 dosyalarını platform klasörlerine kopyalar:
    windows, windows-32, windows7, windows7-32

  Varsayılan kaynak klasör:
    agent-releases/downloaded/v<version>/

.EXAMPLE
  .\deploy\deploy_agent_release_ci.ps1 -Version 0.2.63

.EXAMPLE
  .\deploy\deploy_agent_release_ci.ps1 -Version 0.2.63 -NoRestart

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [string]$SourceDir = "",

  [string]$ServerHost = "192.168.0.6",

  [string]$ServerUser = "root",

  [string]$IdentityFile = "",

  [string]$RemoteBaseDir = "/opt/itmanager/itmanager-server/agent-releases",

  [switch]$NoRestart,

  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Info([string]$m) { Write-Host "[i] $m" -ForegroundColor DarkGray }
function Write-Ok([string]$m) { Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Fail([string]$m) { Write-Host "[HATA] $m" -ForegroundColor Red }

function Require-Command([string]$name) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "Komut bulunamadı: $name (Windows OpenSSH Client gerekli)"
  }
}

function Normalize-Version([string]$v) {
  $s = $v
  if ($null -eq $s) { $s = "" }
  $s = ([string]$s).Trim()
  if ($s.StartsWith("v")) { $s = $s.Substring(1) }
  if ($s -notmatch '^\d+\.\d+\.\d+$') {
    throw "Sürüm SemVer olmalı (X.Y.Z): $v"
  }
  return $s
}

function Resolve-Platform([string]$fileName) {
  # En uzun prefix önce (çakışmayı önler)
  if ($fileName -match '^itmanager-agent-windows7-32-') { return "windows7-32" }
  if ($fileName -match '^itmanager-agent-windows7-') { return "windows7" }
  if ($fileName -match '^itmanager-agent-windows-32-') { return "windows-32" }
  if ($fileName -match '^itmanager-agent-windows-') { return "windows" }
  return $null
}

function Read-ExpectedSha([string]$shaPath) {
  $raw = (Get-Content -LiteralPath $shaPath -Raw).Trim()
  if (-not $raw) { return "" }
  return $raw.Split()[0].ToUpperInvariant()
}

function Verify-Sha([string]$zipPath) {
  $shaPath = $zipPath + '.sha256'
  if (-not (Test-Path -LiteralPath $shaPath)) {
    throw "SHA256 dosyası eksik: $shaPath"
  }
  $expected = Read-ExpectedSha $shaPath
  if (-not $expected) { throw "SHA256 dosyası boş/okunamadı: $shaPath" }
  $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToUpperInvariant()
  if ($expected -ne $got) {
    throw "SHA256 uyumsuz: $([IO.Path]::GetFileName($zipPath)) expected=$expected got=$got"
  }
}

$ver = Normalize-Version $Version

if (-not $SourceDir) {
  $SourceDir = Join-Path $PSScriptRoot ("..\agent-releases\downloaded\v" + $ver)
}
$SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path

if (-not $IdentityFile) {
  $IdentityFile = Join-Path $env:USERPROFILE ".ssh\itmanager_root_192_168_0_6"
}

Require-Command ssh
Require-Command scp

Write-Info "Version: $ver"
Write-Info "SourceDir: $SourceDir"
Write-Info "Server: $ServerUser@$ServerHost"
Write-Info "RemoteBaseDir: $RemoteBaseDir"
Write-Info "IdentityFile: $IdentityFile"

if (-not (Test-Path -LiteralPath $IdentityFile)) {
  throw "SSH key bulunamadı: $IdentityFile"
}

$zips = Get-ChildItem -LiteralPath $SourceDir -Filter '*.zip' -File
if (-not $zips -or $zips.Count -eq 0) {
  throw "ZIP bulunamadı: $SourceDir"
}

# Sadece bu sürüme ait zip'leri seç
$zips = $zips | Where-Object { $_.Name -match ("-" + [regex]::Escape($ver) + "\.zip$") }
if (-not $zips -or $zips.Count -eq 0) {
  throw "Bu sürüme ait ZIP bulunamadı (v$ver): $SourceDir"
}

# Dosyaları platformlara ayır
$items = @()
foreach ($z in $zips) {
  $plat = Resolve-Platform $z.Name
  if (-not $plat) {
    Write-Warn "Platform çözümlenemedi, atlandı: $($z.Name)"
    continue
  }
  $sha = $z.FullName + '.sha256'
  if (-not (Test-Path -LiteralPath $sha)) {
    throw "Eksik sha256 dosyası: $sha"
  }
  $items += [PSCustomObject]@{
    Platform = $plat
    ZipPath  = $z.FullName
    ShaPath  = $sha
  }
}

if ($items.Count -eq 0) {
  throw "Yüklenecek dosya bulunamadı (platform çözümleme başarısız)"
}

Write-Info "SHA256 doğrulaması..."
foreach ($it in $items) {
  Verify-Sha $it.ZipPath
}
Write-Ok "SHA256 doğrulaması OK"

# Remote klasörleri oluştur
$platforms = ($items | Select-Object -ExpandProperty Platform | Sort-Object -Unique)
$remoteDirs = $platforms | ForEach-Object { "$RemoteBaseDir/$_" }
$mk = "mkdir -p " + ($remoteDirs -join ' ')

Write-Info "Remote klasörleri hazırlanıyor: $($platforms -join ', ')"
$sshArgs = @('-i', $IdentityFile, "$ServerUser@$ServerHost", $mk)
if ($DryRun) {
  Write-Info "DRYRUN ssh $($sshArgs -join ' ')"
} else {
  & ssh @sshArgs
}

# Upload
foreach ($it in $items) {
  $remoteDir = "$RemoteBaseDir/$($it.Platform)/"

  $scpZipArgs = @('-i', $IdentityFile, $it.ZipPath, "$ServerUser@${ServerHost}:$remoteDir")
  $scpShaArgs = @('-i', $IdentityFile, $it.ShaPath, "$ServerUser@${ServerHost}:$remoteDir")

  Write-Info "Upload: $([IO.Path]::GetFileName($it.ZipPath)) -> $($it.Platform)"
  if ($DryRun) {
    Write-Info "DRYRUN scp $($scpZipArgs -join ' ')"
    Write-Info "DRYRUN scp $($scpShaArgs -join ' ')"
  } else {
    & scp @scpZipArgs
    & scp @scpShaArgs
  }
}

Write-Ok "Upload tamamlandı"

if (-not $NoRestart) {
  Write-Info "Sunucu servisi restart ediliyor: itmanager-server"
  $restartCmd = "sudo systemctl restart itmanager-server; sudo systemctl status itmanager-server --no-pager -l"
  $sshRestartArgs = @('-i', $IdentityFile, "$ServerUser@$ServerHost", $restartCmd)
  if ($DryRun) {
    Write-Info "DRYRUN ssh $($sshRestartArgs -join ' ')"
  } else {
    & ssh @sshRestartArgs
  }
  Write-Ok "Restart tamam"
} else {
  Write-Info "NoRestart seçildi, servis restart edilmedi"
}

Write-Ok "Bitti"
