param(
  [string]$OutputDir = "release",
  [string]$Name = "ITManagerAgentService",
  [string]$TrayName = "ITManagerAgentTray",
  [string]$AgentName = "ITManagerAgent",
  [switch]$AutoVersion,
  [string]$SetVersion = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $here

$venvDir = Join-Path $here ".venv-build"
if (-not (Test-Path $venvDir)) {
  Write-Host "[+] Build venv oluşturuluyor: $venvDir"
  py -3.13 -m venv $venvDir
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
  # Default behavior: always bump patch unless user explicitly set a version.
  if ($currentVersion -eq 'unknown') {
    throw "version.py okunamadı; otomatik sürüm artırma uygulanamadı"
  }
  $nextVersion = Bump-Patch $currentVersion
  Write-Host "[+] AutoVersion (default): $currentVersion -> $nextVersion" -ForegroundColor Cyan
  Set-AgentVersion $nextVersion
  $currentVersion = Get-AgentVersion
}

Write-Host "[+] Paketler kuruluyor (agent requirements + pyinstaller)..."
& $py -m pip install --upgrade pip
& $py -m pip install -r .\requirements.txt
& $py -m pip install pyinstaller

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

Write-Host "[OK] Çıktı: $(Resolve-Path $OutputDir)"
Write-Host "     - $OutputDir\\$Name.exe"
Write-Host "     - $OutputDir\\$TrayName.exe"
Write-Host "     - $OutputDir\\$AgentName.exe"
Write-Host "     - $OutputDir\\install_service_admin.ps1"
Write-Host "     - $OutputDir\\install_tray_startup.ps1"
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
  $zipName = "itmanager-agent-windows-$version.zip"
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
  Compress-Archive -Path $zipItems -DestinationPath $zipPath -Force
  $hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash
  Set-Content -Path ("$zipPath.sha256") -Value $hash -Encoding ascii
  Write-Host "[OK] ZIP: $zipPath"
  Write-Host "[OK] SHA256: $hash"
  Write-Host "Sunucuya kopyala: itmanager-server\\agent-releases\\windows\\$zipName"
} else {
  Write-Host "[!] Sürüm okunamadı; ZIP üretilmedi. version.py kontrol et."
}

Pop-Location
