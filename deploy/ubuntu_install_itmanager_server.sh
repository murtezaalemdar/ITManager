#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="/opt/itmanager"
SERVER_DIR="$APP_ROOT/itmanager-server"
CERT_DIR="$APP_ROOT/certs"

PANEL_DNS="panel.karakoc.local"
PANEL_IP="192.168.0.6"

log() { echo "[itmanager] $*"; }

log "Installing OS packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-venv python3-pip nginx curl gnupg2 unixodbc-dev ca-certificates openssl

# Install MS ODBC Driver 18 for SQL Server
if ! dpkg -s msodbcsql18 >/dev/null 2>&1; then
  log "Installing msodbcsql18"
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

  if command -v lsb_release >/dev/null 2>&1; then
    UBUNTU_VER="$(lsb_release -rs)"
  else
    UBUNTU_VER="$(. /etc/os-release; echo ${VERSION_ID})"
  fi

  curl -fsSL "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VER}/prod.list" > /etc/apt/sources.list.d/mssql-release.list
  apt-get update -y
  ACCEPT_EULA=Y apt-get install -y msodbcsql18
else
  log "msodbcsql18 already installed"
fi

log "Preparing directories"
mkdir -p "$APP_ROOT" "$CERT_DIR"

if [ ! -d "$SERVER_DIR" ]; then
  log "ERROR: $SERVER_DIR not found. Copy itmanager-server to $APP_ROOT first."
  exit 2
fi

log "Setting up python venv + deps"
cd "$SERVER_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f "$SERVER_DIR/.env" ]; then
  log "Creating .env from .env.example (edit as needed)"
  cp "$SERVER_DIR/.env.example" "$SERVER_DIR/.env"
fi

log "Writing systemd unit"
cat > /etc/systemd/system/itmanager-server.service <<EOF
[Unit]
Description=ITManager Server (FastAPI)
After=network.target

[Service]
WorkingDirectory=$SERVER_DIR
EnvironmentFile=$SERVER_DIR/.env
ExecStart=$SERVER_DIR/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now itmanager-server

log "Generating CA + server cert (SAN: $PANEL_DNS, $PANEL_IP)"
cd "$CERT_DIR"

if [ ! -f "$CERT_DIR/ca.crt" ]; then
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=ITManager-CA"
fi

cat > server.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = $PANEL_DNS

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $PANEL_DNS
IP.1 = $PANEL_IP
EOF

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256 -extensions req_ext -extfile server.cnf

log "Configuring nginx"
cat > /etc/nginx/sites-available/itmanager.conf <<'EOF'
server {
  listen 80;
  server_name panel.karakoc.local 192.168.0.6;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl;
  server_name panel.karakoc.local 192.168.0.6;

  ssl_certificate     /opt/itmanager/certs/server.crt;
  ssl_certificate_key /opt/itmanager/certs/server.key;

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $remote_addr;
  }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/itmanager.conf /etc/nginx/sites-enabled/itmanager.conf
nginx -t
systemctl restart nginx

log "Done"
echo "CA cert: $CERT_DIR/ca.crt"
echo "Test: curl -k https://$PANEL_IP/health"
