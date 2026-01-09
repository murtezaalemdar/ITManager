param()
$svc = 'ITManagerAgentService'
if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
    try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 2
    try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {}
    Get-Service -Name $svc | Select-Object Status,Name,DisplayName
} else {
    Write-Output 'Service not found'
}
