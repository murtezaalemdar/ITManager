param(
  [string]$OutputDir = "release",
  [string]$Name = "ITManagerAgentService",
  [string]$TrayName = "ITManagerAgentTray",
  [string]$AgentName = "ITManagerAgent",
  [switch]$AutoVersion,
  [string]$SetVersion = "",
  [string]$PyVersion = "3.13",    # Windows 10/11 için 3.13, Win7 için 3.7 kullan
  [string]$Platform = "windows"   # "windows" veya "windows7"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here

$venvDir = Join-Path $here ".venv-build-$Platform"
if (-not (Test-Path $venvDir)) {
  Write-Host "[+] Build venv oluşturuluyor ($Platform, Python $PyVersion): $venvDir"
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    py -$PyVersion -m venv $venvDir
  } else {
    throw "Python launcher 'py' bulunamadı. Win7/Win10 için Python'u 'py launcher' ile kurun veya py'yi PATH'e ekleyin."
  }
}

$py = Join-Path $venvDir "Scripts\python.exe"
if (-not (Test-Path $py)) {
  throw "Python bulunamadı: $py"
}

function Get-AgentVersion {
  try {
    $v = (& $py -c "import version; print(getattr(version,'__version__','unknown'))" | Select-Object -First 1).Trim()
    if (-not $v) { return "unknown" }
    return $v
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

  # Dokümantasyon/kurulum için örnek config'i de senkron tut.
  $cfgPath = Join-Path $here 'config.example.json'
  if (Test-Path $cfgPath) {
    try {
      $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
      $cfg.agent_version = $NewVersion
      $cfg | ConvertTo-Json -Depth 20 | Set-Content -Path $cfgPath -Encoding UTF8
    } catch {
      Write-Host "[!] config.example.json güncellenemedi: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }
}

function Bump-Patch([string]$Current) {
  if ($Current -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
    throw "Mevcut sürüm SemVer değil: $Current"
  }
  $major = [int]$Matches[1]
  $minor = [int]$Matches[2]
  $patch = [int]$Matches[3]
  return "{0}.{1}.{2}" -f $major, $minor, ($patch + 1)
}

$currentVersion = Get-AgentVersion
if ($SetVersion) {
  Write-Host "[+] Sürüm set ediliyor: $currentVersion -> $SetVersion" -ForegroundColor Cyan
  Set-AgentVersion $SetVersion
  $currentVersion = Get-AgentVersion
} elseif ($AutoVersion) {
  if ($currentVersion -eq 'unknown') {
    throw "version.py okunamadı; AutoVersion uygulanamadı"
  }
  $nextVersion = Bump-Patch $currentVersion
  Write-Host "[+] AutoVersion: $currentVersion -> $nextVersion" -ForegroundColor Cyan
  Set-AgentVersion $nextVersion
  $currentVersion = Get-AgentVersion
} else {
  # Default behavior:
  # - windows: bump patch
  # - non-windows (e.g. windows7): keep the same version unless explicitly requested
  if ($currentVersion -eq 'unknown') {
    throw "version.py okunamadı"
  }
  if ($Platform -eq 'windows') {
    $nextVersion = Bump-Patch $currentVersion
    Write-Host "[+] AutoVersion (default): $currentVersion -> $nextVersion" -ForegroundColor Cyan
    Set-AgentVersion $nextVersion
    $currentVersion = Get-AgentVersion
  } else {
    Write-Host "[i] Platform '$Platform' için default sürüm artırma kapalı; sürüm korunuyor: $currentVersion" -ForegroundColor DarkGray
  }
}

Write-Host "[+] Paketler kuruluyor (agent requirements + pyinstaller)..."
try {
  $pyVer = (& $py -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" | Select-Object -First 1).Trim()
} catch {
  $pyVer = ""
}

# Win7 SSL/TLS sorunları için trusted-host ekle
$pipTrust = @("--trusted-host", "pypi.org", "--trusted-host", "files.pythonhosted.org")

# Python 3.7: pip>=23.2 and PyInstaller>=6 drop support.
if ($pyVer -eq '3.7') {
  & $py -m pip install @pipTrust --upgrade "pip==23.1.2"
} else {
  & $py -m pip install @pipTrust --upgrade pip
}
& $py -m pip install @pipTrust -r .\requirements.txt
if ($pyVer -eq '3.7') {
  & $py -m pip install @pipTrust "pyinstaller==5.13.2"
} else {
  & $py -m pip install @pipTrust pyinstaller
}

$pyiWork = Join-Path $here "build-work"
$pyiDist = Join-Path $here "build-dist"

if (Test-Path $pyiWork) { Remove-Item -Recurse -Force $pyiWork }
if (Test-Path $pyiDist) { Remove-Item -Recurse -Force $pyiDist }

Write-Host "[+] EXE build ediliyor..."
$pyiArgs = @(
  "--noconfirm",
  "--onefile",
  "--name", $Name,
  "--workpath", $pyiWork,
  "--distpath", $pyiDist,
  # Force-bundle local agent modules used by the service at runtime.
  "--hidden-import", "agent",
  "--hidden-import", "commands",
  "--hidden-import", "version",
  "--hidden-import", "servicemanager",
  "--hidden-import", "win32serviceutil",
  "--hidden-import", "win32service",
  "--hidden-import", "win32event",
  "--hidden-import", "win32timezone",
  ".\\service.py"
)
& $py -m PyInstaller @pyiArgs

Write-Host "[+] Tray EXE build ediliyor..."
$pyiTrayArgs = @(
  "--noconfirm",
  "--onefile",
  "--noconsole",
  "--name", $TrayName,
  "--workpath", $pyiWork,
  "--distpath", $pyiDist,
  ".\\tray.py"
)
& $py -m PyInstaller @pyiTrayArgs

Write-Host "[+] Agent EXE build ediliyor..."
$pyiAgentArgs = @(
  "--noconfirm",
  "--onefile",
  "--name", $AgentName,
  "--workpath", $pyiWork,
  "--distpath", $pyiDist,
  "--hidden-import", "psutil",
  ".\\agent.py"
)
& $py -m PyInstaller @pyiAgentArgs

if (Test-Path $OutputDir) {
  # OutputDir daha önceki release artıkları (eski zip/klasör) bırakabiliyor; zip'i şişirmesin.
  Remove-Item -Recurse -Force -Path (Join-Path $OutputDir "*") -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Copy-Item -Force (Join-Path $pyiDist ("$Name.exe")) (Join-Path $OutputDir ("$Name.exe"))
Copy-Item -Force (Join-Path $pyiDist ("$TrayName.exe")) (Join-Path $OutputDir ("$TrayName.exe"))
Copy-Item -Force (Join-Path $pyiDist ("$AgentName.exe")) (Join-Path $OutputDir ("$AgentName.exe"))
Copy-Item -Force .\config.example.json (Join-Path $OutputDir "config.example.json")
if (Test-Path .\config.json) {
  Copy-Item -Force .\config.json (Join-Path $OutputDir "config.json")
}
if (Test-Path .\install_service_admin.ps1) {
  Copy-Item -Force .\install_service_admin.ps1 (Join-Path $OutputDir "install_service_admin.ps1")
}
if (Test-Path .\install_tray_startup.ps1) {
  Copy-Item -Force .\install_tray_startup.ps1 (Join-Path $OutputDir "install_tray_startup.ps1")
}
if (Test-Path .\setup.ps1) {
  Copy-Item -Force .\setup.ps1 (Join-Path $OutputDir "setup.ps1")
}
if (Test-Path .\Setup.cmd) {
  Copy-Item -Force .\Setup.cmd (Join-Path $OutputDir "Setup.cmd")
}

Write-Host "[OK] Çıktı: $(Resolve-Path $OutputDir)"
Write-Host "     - $OutputDir\\$Name.exe"
Write-Host "     - $OutputDir\\$TrayName.exe"
Write-Host "     - $OutputDir\\$AgentName.exe"
Write-Host "     - $OutputDir\\install_service_admin.ps1"
Write-Host "     - $OutputDir\\install_tray_startup.ps1"
Write-Host "     - $OutputDir\\setup.ps1"
Write-Host "     - $OutputDir\\Setup.cmd"
Write-Host "     - $OutputDir\\config.example.json"
if (Test-Path .\config.json) { Write-Host "     - $OutputDir\\config.json" }
Write-Host "\nKurulum (hedef PC - Admin PowerShell):"
Write-Host "  1) $Name.exe ve config.json aynı klasörde olacak"
Write-Host "  2) .\\$Name.exe install"
Write-Host "  3) .\\$Name.exe start"
Write-Host "  Alternatif: .\\install_service_admin.ps1 -Reinstall"
Write-Host "Kaldırma: .\\$Name.exe stop ; .\\$Name.exe remove"
Write-Host "\nTray (saat yanında ikon):"
Write-Host "  - $TrayName.exe ve config.json aynı klasörde olacak"
Write-Host "  - .\\$TrayName.exe (kullanıcı oturumunda çalışır)"

Write-Host "\nAgent (konsol - test/manuel):"
Write-Host "  - $AgentName.exe ve config.json aynı klasörde olacak"
Write-Host "  - .\\$AgentName.exe --once"

# --- Release ZIP (versioned) ---
try {
  $version = (& $py -c "import version; print(getattr(version,'__version__','unknown'))" | Select-Object -First 1).Trim()
} catch {
  $version = "unknown"
}

if ($version -and $version -ne "unknown") {
  $zipName = "itmanager-agent-$Platform-$version.zip"
  $zipPath = Join-Path $here $zipName
  if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
  Write-Host "[+] Release ZIP oluşturuluyor: $zipName"
  $zipItems = @(
    (Join-Path $OutputDir "$Name.exe"),
    (Join-Path $OutputDir "$TrayName.exe"),
    (Join-Path $OutputDir "$AgentName.exe"),
    (Join-Path $OutputDir "config.example.json")
  )
  if (Test-Path (Join-Path $OutputDir "config.json")) { $zipItems += (Join-Path $OutputDir "config.json") }
  if (Test-Path (Join-Path $OutputDir "install_service_admin.ps1")) { $zipItems += (Join-Path $OutputDir "install_service_admin.ps1") }
  if (Test-Path (Join-Path $OutputDir "install_tray_startup.ps1")) { $zipItems += (Join-Path $OutputDir "install_tray_startup.ps1") }
  if (Test-Path (Join-Path $OutputDir "setup.ps1")) { $zipItems += (Join-Path $OutputDir "setup.ps1") }
  if (Test-Path (Join-Path $OutputDir "Setup.cmd")) { $zipItems += (Join-Path $OutputDir "Setup.cmd") }
  Compress-Archive -Path $zipItems -DestinationPath $zipPath -Force
  $hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
  Set-Content -Path ("$zipPath.sha256") -Value $hash -Encoding ascii
  Write-Host "[OK] ZIP: $zipPath"
  Write-Host "[OK] SHA256: $hash"
  Write-Host "Sunucuya kopyala: itmanager-server\\agent-releases\\$Platform\\$zipName"
} else {
  Write-Host "[!] Sürüm okunamadı; ZIP üretilmedi. version.py kontrol et."
}

Pop-Location
