param(
  [string]$TrayExePath = ".\ITManagerAgentTray.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$srcTrayExe = (Resolve-Path $TrayExePath).Path

$pdDir = Join-Path $env:ProgramData 'ITManagerAgent'
New-Item -ItemType Directory -Force -Path $pdDir | Out-Null
$dstTrayExe = Join-Path $pdDir 'ITManagerAgentTray.exe'

# Copy to a stable location (ProgramData) so Startup keeps working
# even if the extracted ZIP folder is moved/deleted.
try {
  Copy-Item -Force $srcTrayExe $dstTrayExe
} catch {
  # If copy fails (locked/no permission), fallback to source path.
  $dstTrayExe = $srcTrayExe
}

$startup = [Environment]::GetFolderPath('Startup')
$lnkPath = Join-Path $startup "ITManagerAgentTray.lnk"

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($lnkPath)
$lnk.TargetPath = $dstTrayExe
$lnk.WorkingDirectory = Split-Path -Parent $dstTrayExe
$lnk.Save()

Write-Host "[OK] Startup kısayolu eklendi: $lnkPath"
Write-Host "Giriş-çıkış yapınca tray otomatik açılır."