# ITManager Agent (Windows)

## Kurulum (Service)

PowerShell'i **Run as administrator** açıp agent klasöründe çalıştır:

- Kur:
  - `./install_service.ps1 -ServerBaseUrl "https://192.168.0.6" -EnrollmentToken "KARAKOC_ENROLL_CHANGE_ME" -VerifyTls:$false`

- Kaldır:
  - `./uninstall_service.ps1`

## Manuel test

- Tek tur çalıştır (register/heartbeat/pull):
  - `./.venv/Scripts/python.exe ./agent.py --once`

## Tray (ikon) - otomatik başlatma

- Startup'a ekle (kullanıcı login olunca ikon çıkar):
  - `./release/ITManagerAgentTray.exe --install-startup`

- Startup'tan kaldır:
  - `./release/ITManagerAgentTray.exe --uninstall-startup`

## Notlar

- `config.json` içinde `state_dir` varsayılanı `C:/ProgramData/ITManagerAgent`.
- Panelde `Enrollment Token` rotate edilirse agent `EnrollmentToken` değeri güncellenmelidir.

## Otomatik güncelleme (self-update)

- Agent, register olduktan sonra belirli aralıklarla sunucudan en güncel sürümü kontrol eder.
- Sunucu tarafında paketler `itmanager-server/app/settings.py` içindeki `agent_releases_dir` altında tutulur.
  - Örn: `itmanager-server/agent-releases/windows/itmanager-agent-windows-0.2.0.zip`
  - Dosya adının sonunda `X.Y.Z.zip` formatında sürüm olmalı (server bunu buradan okur).
  - İstersen aynı klasöre `*.zip.sha256` dosyası koyabilirsin (ilk token SHA256 olmalı).

Agent config (ProgramData'daki `config.json`) için ilgili ayarlar:
- `auto_update`: `true/false` (varsayılan `true`)
- `update_check_interval_seconds`: kontrol aralığı (varsayılan `3600`)
- `update_notify_user`: best-effort kullanıcıya mesaj (varsayılan `true`)
