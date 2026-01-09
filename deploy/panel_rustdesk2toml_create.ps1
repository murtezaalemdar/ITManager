# RustDesk2.toml otomatik oluşturma scripti
$configDir = "$env:APPDATA\RustDesk\config"
$configFile = Join-Path $configDir "RustDesk2.toml"

if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force
}

$tomlContent = @"
rendezvous_server = '192.168.0.6:21116'
nat_type = 1
serial = 0
unlock_pin = ''
trusted_devices = ''

[options]
avi1-test = 'Y'
relay-server = '192.168.0.6'
api-server = 'http://192.168.0.6'
key = 'XpzXX98VWqJlMrvAQdwnGCkjeHInP5dwIx1CsE6jOqQ='
custom-rendezvous-server = '192.168.0.6'
local-ip-addr = ''
"@

$tomlContent | Set-Content -Path $configFile -Encoding UTF8

Write-Host "RustDesk2.toml başarıyla oluşturuldu: $configFile"
