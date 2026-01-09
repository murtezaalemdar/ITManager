#!/usr/bin/env python3
import os
from pathlib import Path

content = """rendezvous_server = '192.168.0.6:21116'
nat_type = 1
serial = 0
unlock_pin = ''
trusted_devices = ''

[options]
direct-server = 'Y'
allow-remote-config-modification = 'Y'
relay-server = '192.168.0.6'
av1-test = 'Y'
api-server = 'http://192.168.0.6'
key = 'XpzXX98VWqJlMrvAQdwnGCkjeHInP5dwIx1CsE6jOqQ='
local-ip-addr = ''
custom-rendezvous-server = '192.168.0.6'
"""

def write_to(path: Path):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
        print(f'WROTE: {path}')
    except Exception as e:
        print(f'ERROR writing {path}: {e}')

def main():
    # Current user AppData
    up = Path(os.environ.get('USERPROFILE') or Path.home())
    dest = up / 'AppData' / 'Roaming' / 'RustDesk' / 'config' / 'RustDesk2.toml'
    write_to(dest)

    # Also attempt to write to all user profiles (requires admin)
    drive = Path(os.environ.get('SYSTEMDRIVE', 'C:'))
    users_root = drive / 'Users'
    if users_root.exists():
        for p in users_root.iterdir():
            if not p.is_dir():
                continue
            name = p.name.lower()
            if name in ('public', 'default', 'all users', 'default user', 'defaultuser0'):
                continue
            write_to(Path(p) / 'AppData' / 'Roaming' / 'RustDesk' / 'config' / 'RustDesk2.toml')

    # Also update workspace build copy
    ws_dest = Path(__file__).resolve().parent.parent / 'build' / 'RustDesk2.toml'
    write_to(ws_dest)

if __name__ == '__main__':
    main()
