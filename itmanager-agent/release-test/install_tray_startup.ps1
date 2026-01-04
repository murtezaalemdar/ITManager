param(
  [string]$TrayExePath = ".\release\ITManagerAgentTray.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TrayExePath = (Resolve-Path $TrayExePath).Path

$startup = [Environment]::GetFolderPath('Startup')
$lnkPath = Join-Path $startup "ITManagerAgentTray.lnk"

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($lnkPath)
$lnk.TargetPath = $TrayExePath
$lnk.WorkingDirectory = Split-Path -Parent $TrayExePath
$lnk.Save()

Write-Host "[OK] Startup kısayolu eklendi: $lnkPath"
Write-Host "Giriş-çıkış yapınca tray otomatik açılır."