#!/usr/bin/env python3
import os
import sys
from pathlib import Path

# Canonical RustDesk2.toml content
CONTENT = """rendezvous_server = '192.168.0.6:21116'
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

def write_dest(path: Path):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CONTENT, encoding='utf-8')
        print(f'WROTE: {path}')
    except Exception as e:
        print(f'ERROR writing {path}: {e}', file=sys.stderr)

def main():
    userprofile = Path(os.environ.get('USERPROFILE') or Path.home())
    dest = userprofile / 'AppData' / 'Roaming' / 'RustDesk' / 'config' / 'RustDesk2.toml'
    write_dest(dest)

    # Also write a workspace copy (build folder)
    ws_dest = Path(__file__).resolve().parent.parent / 'build' / 'RustDesk2.toml'
    write_dest(ws_dest)

    return 0

if __name__ == '__main__':
    sys.exit(main())
