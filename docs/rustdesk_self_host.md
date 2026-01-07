# RustDesk Self-host (ITManager)

Bu doküman, ITManager panelinden `RustDesk Deploy` komutunu kullanarak RustDesk'i **self-host** sunucunuzu kullanacak şekilde otomatik kurulum/konfigüre etmek içindir.

## 1) Sunucu tarafı (hbbs/hbbr)

RustDesk self-host yapısında iki servis vardır:

- `hbbs` (ID/Rendezvous)
- `hbbr` (Relay)

Gerekli portlar (minimum):

- TCP `21115-21117`
- UDP `21116`

(İhtiyaca göre Web Client için TCP `21118-21119`.)

Kurulum için resmi dokümantasyon:
- https://rustdesk.com/docs/en/self-host/
- https://rustdesk.com/docs/en/self-host/rustdesk-server-oss/

## 2) RustDesk client config string

RustDesk client'ta (örnek bir makinede) aşağıdan export alıp tek satır string olarak elde edin:

- RustDesk -> Settings -> Network -> (Unlock) -> `Export Server Config`

Bu çıktı, RustDesk'in `--config <config-string>` parametresiyle uygulanabilen config string'idir.

## 3) ITManager server ayarları (.env)

ITManager server'ın `.env` dosyasına aşağıdakileri ekleyin:

- `RUSTDESK_CONFIG_STRING=<export ettiğiniz config string>`
- (opsiyonel) `RUSTDESK_PASSWORD=<kalıcı parola>`

Not:
- `RUSTDESK_PASSWORD` **DB'ye yazılmaz**; sadece agent'a deploy sırasında iletilir ve agent tarafında `rustdesk.exe --password` ile ayarlanır.

## 4) RustDesk MSI dosyası (server'a kopyalama)

Sunucu dosya sistemi altında bu klasöre RustDesk MSI'yı koyun:

- `agent-releases/tools/windows/`

Dosya adı seçiminde sunucu şu önceliği uygular:

- `.msi` (tercih) -> `.exe` -> `.zip`
- ayrıca isminde `x64`, `x86_64` veya `amd64` geçen dosyalar önceliklidir

Örnek:
- `rustdesk-<versiyon>-x86_64.msi`

## 5) Panelden deploy

- Cihaz detayından `RustDesk Deploy` butonuna basın.
- Agent 0.2.43+ olmalıdır.

Beklenen çıktı:
- Kurulum tamamlanır
- Config uygulanır
- RustDesk ID (varsa) komut çıktısında görünür

## 6) MSI silent install notu

RustDesk MSI silent kurulum parametreleri için:
- https://rustdesk.com/docs/en/client/windows/msi/

