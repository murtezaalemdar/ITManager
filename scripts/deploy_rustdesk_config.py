#!/usr/bin/env python3
import re
import os
import sys
from pathlib import Path

def main():
    env_path = Path("itmanager-server") / ".env"
    if not env_path.exists():
        print(f"HATA: {env_path} bulunamadı", file=sys.stderr)
        return 2

    s = env_path.read_text(encoding="utf-8")

    m = re.search(r"RUSTDESK_CONFIG_STRING\s*=\s*(?P<q>[\"\'])(?P<v>.*?)(?P=q)", s, flags=re.S)
    if m:
        val = m.group("v")
    else:
        m2 = re.search(r"RUSTDESK_CONFIG_STRING\s*=\s*(.+)", s)
        if m2:
            val = m2.group(1).strip().strip('"\'')
        else:
            print("HATA: RUSTDESK_CONFIG_STRING bulunamadı", file=sys.stderr)
            return 3

    # Replace escaped newlines (\n) with real newlines
    toml = val.replace('\\n', '\n')

    # Destination in Windows AppData Roaming
    userprofile = os.environ.get('USERPROFILE') or os.path.expanduser('~')
    dest = Path(userprofile) / 'AppData' / 'Roaming' / 'RustDesk' / 'config' / 'RustDesk2.toml'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(toml, encoding='utf-8')

    print(f"Yazıldı: {dest}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
