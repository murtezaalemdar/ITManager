# Push local RustDesk2.toml to server .env as RUSTDESK_CONFIG_STRING
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$localToml = Join-Path $repoRoot 'itmanager-server\agent-releases\tools\windows\RustDesk2.toml'
if (-not (Test-Path -LiteralPath $localToml)) {
    Write-Host "Local RustDesk2.toml not found: $localToml" -ForegroundColor Red
    exit 1
}
$toml = Get-Content -Raw -Path $localToml
$single = $toml -replace "`r`n","\\n"
$single = $single -replace "`n","\\n"
Write-Host "Pushing config string to server (hidden)" -ForegroundColor Cyan
& "$PSScriptRoot\set_rustdesk_config.ps1" -ConfigString $single -Force
