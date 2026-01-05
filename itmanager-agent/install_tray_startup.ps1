param(
  [string]$TrayExePath = ".\ITManagerAgentTray.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

$srcTrayExe = (Resolve-Path $TrayExePath).Path

$pdDir = Join-Path $env:ProgramData 'ITManagerAgent'
New-Item -ItemType Directory -Force -Path $pdDir | Out-Null
$dstTrayExe = Join-Path $pdDir 'ITManagerAgentTray.exe'

# Copy to a stable location (ProgramData) so Startup keeps working
# even if the extracted ZIP folder is moved/deleted.
Copy-Item -Force $srcTrayExe $dstTrayExe

# Remove Mark-of-the-Web if present (prevents security prompts)
try { Unblock-File -Path $dstTrayExe -ErrorAction SilentlyContinue } catch { }

# Remove any existing shortcuts (user + common)
try {
  $userStartup = [Environment]::GetFolderPath('Startup')
  $userLnk = Join-Path $userStartup 'ITManagerAgentTray.lnk'
  if (Test-Path -LiteralPath $userLnk) { Remove-Item -Force -LiteralPath $userLnk -ErrorAction SilentlyContinue }
} catch { }

try {
  $commonStartup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
  $commonLnk = Join-Path $commonStartup 'ITManagerAgentTray.lnk'
  if (Test-Path -LiteralPath $commonLnk) { Remove-Item -Force -LiteralPath $commonLnk -ErrorAction SilentlyContinue }
} catch { }

$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
New-Item -ItemType Directory -Force -Path $startup | Out-Null
$lnkPath = Join-Path $startup "ITManagerAgentTray.lnk"

$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut($lnkPath)
$lnk.TargetPath = $dstTrayExe
$lnk.WorkingDirectory = Split-Path -Parent $dstTrayExe
$lnk.Save()

Write-Host "[OK] Startup kısayolu eklendi: $lnkPath"
Write-Host "Giriş-çıkış yapınca tray otomatik açılır."