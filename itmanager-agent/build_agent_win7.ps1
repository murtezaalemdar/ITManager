<#
.SYNOPSIS
  Windows 7 için ITManager Agent build scripti (offline).
  
.DESCRIPTION
  Bu script Win7'de SSL/TLS sorunlarını bypass etmek için
  wheels-win7 klasöründeki offline paketleri kullanır.
  
.EXAMPLE
  .\build_agent_win7.ps1
  .\build_agent_win7.ps1 -SetVersion 0.2.63
#>

param(
  [string]$OutputDir = "release",
  [string]$Name = "ITManagerAgentService",
  [string]$TrayName = "ITManagerAgentTray",
  [string]$AgentName = "ITManagerAgent",
  [string]$SetVersion = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here

$Platform = "windows7"
$venvDir = Join-Path $here ".venv-build-$Platform"
$wheelsDir = Join-Path $here "wheels-win7"

# Check wheels directory
if (-not (Test-Path $wheelsDir)) {
  throw @"
wheels-win7 klasörü bulunamadı!

Lütfen Win10/11 makinede şu komutu çalıştırıp oluşan klasörü buraya kopyalayın:
  pip download -d wheels-win7 --python-version 3.7 --only-binary=:all: --platform win_amd64 `
    requests==2.28.2 psutil==5.9.8 pywin32==306 pystray==0.19.5 Pillow==9.5.0 `
    cryptography==40.0.2 pyinstaller==5.13.2
"@
}

# Create venv if not exists
if (-not (Test-Path $venvDir)) {
  Write-Host "[+] Build venv oluşturuluyor (windows7, Python 3.7): $venvDir" -ForegroundColor Cyan
  
  # Try py launcher first, then python directly
  $pyCmd = $null
  if (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py"
    & py -3.7 -m venv $venvDir
  } elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
    & python -m venv $venvDir
  } else {
    throw "Python bulunamadı. Python 3.7'yi kurun."
  }
}

$py = Join-Path $venvDir "Scripts\python.exe"
if (-not (Test-Path $py)) {
  throw "Python bulunamadı: $py"
}

# Version functions
function Get-AgentVersion {
  try {
    $v = (& $py -c "import version; print(getattr(version,'__version__','unknown'))" 2>$null | Select-Object -First 1)
    if ($v) { return $v.Trim() }
    return "unknown"
  } catch {
    return "unknown"
  }
}

function Set-AgentVersion([string]$NewVersion) {
  if (-not $NewVersion) { throw "NewVersion boş olamaz" }
  if ($NewVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "Sürüm SemVer olmalı (X.Y.Z): $NewVersion"
  }
  $verPath = Join-Path $here 'version.py'
  $verLine = "__version__ = `"$NewVersion`""
  Set-Content -Path $verPath -Value $verLine -Encoding UTF8
  
  $cfgPath = Join-Path $here 'config.example.json'
  if (Test-Path $cfgPath) {
    try {
      $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
      $cfg.agent_version = $NewVersion
      $cfg | ConvertTo-Json -Depth 20 | Set-Content -Path $cfgPath -Encoding UTF8
    } catch {
      Write-Host "[!] config.example.json güncellenemedi" -ForegroundColor Yellow
    }
  }
}

# Set version if provided
$currentVersion = Get-AgentVersion
if ($SetVersion) {
  Write-Host "[+] Sürüm set ediliyor: $currentVersion -> $SetVersion" -ForegroundColor Cyan
  Set-AgentVersion $SetVersion
  $currentVersion = Get-AgentVersion
} else {
  Write-Host "[i] Sürüm korunuyor: $currentVersion" -ForegroundColor DarkGray
}

# Install packages from offline wheels
Write-Host "[+] Paketler kuruluyor (offline wheels)..." -ForegroundColor Cyan

# pip upgrade - skip if fails (already installed is fine)
try {
  & $py -m pip install --upgrade pip --no-index --find-links $wheelsDir 2>&1 | Out-Null
} catch {
  Write-Host "[!] pip upgrade atlandı, devam ediliyor..." -ForegroundColor Yellow
}

# Install all wheels from directory - ignore exit code, check if pyinstaller works later
& $py -m pip install --no-index --find-links $wheelsDir `
  requests psutil pywin32 pystray Pillow cryptography pyinstaller 2>&1 | ForEach-Object { Write-Host $_ }

# Verify pyinstaller is available
try {
  $pyi = & $py -c "import PyInstaller; print('OK')" 2>&1
  if ($pyi -notmatch "OK") {
    throw "PyInstaller import edilemedi"
  }
  Write-Host "[OK] Paketler kuruldu" -ForegroundColor Green
} catch {
  throw "PyInstaller kurulumu başarısız! Hata: $_"
}

# Build paths
$pyiWork = Join-Path $here "build-work"
$pyiDist = Join-Path $here "build-dist"

if (Test-Path $pyiWork) { Remove-Item -Recurse -Force $pyiWork }
if (Test-Path $pyiDist) { Remove-Item -Recurse -Force $pyiDist }

Write-Host "[+] EXE build ediliyor..." -ForegroundColor Cyan

# Common PyInstaller args
$pyiCommon = @(
  "--noconfirm",
  "--onefile",
  "--workpath", $pyiWork,
  "--distpath", $pyiDist,
  "--hidden-import", "agent",
  "--hidden-import", "commands",
  "--hidden-import", "version"
)

# Build Service EXE
Write-Host "[+] Service EXE build ediliyor..." -ForegroundColor Cyan
$svcArgs = $pyiCommon + @(
  "--name", $Name,
  "--hidden-import", "servicemanager",
  "--hidden-import", "win32serviceutil",
  "--hidden-import", "win32service",
  "--hidden-import", "win32event",
  "--hidden-import", "win32api",
  "service.py"
)
& $py -m PyInstaller @svcArgs
if ($LASTEXITCODE -ne 0) { throw "Service EXE build başarısız!" }

# Build Tray EXE
Write-Host "[+] Tray EXE build ediliyor..." -ForegroundColor Cyan
$trayArgs = $pyiCommon + @(
  "--name", $TrayName,
  "--windowed",
  "--hidden-import", "pystray",
  "--hidden-import", "PIL",
  "tray.py"
)
& $py -m PyInstaller @trayArgs
if ($LASTEXITCODE -ne 0) { throw "Tray EXE build başarısız!" }

# Build Agent EXE
Write-Host "[+] Agent EXE build ediliyor..." -ForegroundColor Cyan
$agentArgs = $pyiCommon + @(
  "--name", $AgentName,
  "agent.py"
)
& $py -m PyInstaller @agentArgs
if ($LASTEXITCODE -ne 0) { throw "Agent EXE build başarısız!" }

# Copy to release folder
$outPath = Join-Path $here $OutputDir
if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath | Out-Null }

Copy-Item -Force (Join-Path $pyiDist "$Name.exe") $outPath
Copy-Item -Force (Join-Path $pyiDist "$TrayName.exe") $outPath
Copy-Item -Force (Join-Path $pyiDist "$AgentName.exe") $outPath

# Copy support files
$supportFiles = @(
  "config.example.json",
  "config.json",
  "install_service_admin.ps1",
  "install_tray_startup.ps1",
  "setup.ps1",
  "Setup.cmd"
)
foreach ($f in $supportFiles) {
  $src = Join-Path $here $f
  if (Test-Path $src) {
    Copy-Item -Force $src $outPath
  }
}

Write-Host ""
Write-Host "[OK] Build tamamlandı: $outPath" -ForegroundColor Green
Write-Host "     - $Name.exe"
Write-Host "     - $TrayName.exe"
Write-Host "     - $AgentName.exe"

# Create ZIP
$version = Get-AgentVersion
if ($version -and $version -ne "unknown") {
  $zipName = "itmanager-agent-windows7-$version.zip"
  $zipPath = Join-Path $here $zipName
  if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
  
  Write-Host "[+] Release ZIP oluşturuluyor: $zipName" -ForegroundColor Cyan
  
  $zipItems = @(
    (Join-Path $outPath "$Name.exe"),
    (Join-Path $outPath "$TrayName.exe"),
    (Join-Path $outPath "$AgentName.exe"),
    (Join-Path $outPath "config.example.json")
  )
  
  # Add optional files
  @("config.json", "install_service_admin.ps1", "install_tray_startup.ps1", "setup.ps1", "Setup.cmd") | ForEach-Object {
    $p = Join-Path $outPath $_
    if (Test-Path $p) { $zipItems += $p }
  }
  
  Compress-Archive -Path $zipItems -DestinationPath $zipPath -Force
  
  $hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
  Set-Content -Path ("$zipPath.sha256") -Value $hash -Encoding ASCII
  
  Write-Host "[OK] ZIP: $zipPath" -ForegroundColor Green
  Write-Host "[OK] SHA256: $hash" -ForegroundColor Green
  Write-Host ""
  Write-Host "Sunucuya kopyala: /opt/itmanager/itmanager-server/agent-releases/windows7/$zipName" -ForegroundColor Yellow
} else {
  Write-Host "[!] Sürüm okunamadı; ZIP üretilmedi." -ForegroundColor Red
}

Pop-Location
