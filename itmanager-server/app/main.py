from __future__ import annotations

import base64
import json
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, select
from sqlalchemy import text
from sqlalchemy.orm import selectinload

from .auth import ensure_default_admin, generate_device_token, get_sso_user, hash_password, verify_password
from .db import Base, SessionLocal, engine
from .models import Command, Device, Group, ServerConfig, User, device_groups
from .settings import settings

app = FastAPI(title=settings.app_name)
templates = Jinja2Templates(directory="app/templates")


_TR_MONTHS = [
    "Ocak",
    "Şubat",
    "Mart",
    "Nisan",
    "Mayıs",
    "Haziran",
    "Temmuz",
    "Ağustos",
    "Eylül",
    "Ekim",
    "Kasım",
    "Aralık",
]

_TR_WEEKDAYS = [
    "Pazartesi",
    "Salı",
    "Çarşamba",
    "Perşembe",
    "Cuma",
    "Cumartesi",
    "Pazar",
]

_ISO_DT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
)


def _try_pretty_tr_datetime_from_iso(s: str) -> str | None:
    s = (s or "").strip()
    if not s or not _ISO_DT_RE.match(s):
        return None

    try:
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s

        # Python's datetime.fromisoformat supports up to 6 fractional digits.
        # Some sources (e.g., .NET) emit 7 digits (ticks). Truncate for parsing.
        m = re.match(
            r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?(?P<tz>(?:Z|[+-]\d{2}:\d{2}))?$",
            iso,
        )
        if m:
            base = m.group("base")
            frac = m.group("frac")
            tz = m.group("tz")
            if tz == "Z":
                tz = "+00:00"
            if frac and len(frac) > 6:
                frac = frac[:6]
            iso = base + (("." + frac) if frac else "") + (tz or "")

        dt = datetime.fromisoformat(iso)
        month = _TR_MONTHS[dt.month - 1]
        weekday = _TR_WEEKDAYS[dt.weekday()]
        return f"{dt.day} {month} {dt.year} {weekday} {dt:%H:%M:%S}"
    except Exception:
        return None


def _fmt_dt(value: Any) -> str:
    if not value:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%d.%m.%Y %H:%M:%S")
    return str(value)


def _rel_time(value: Any) -> str:
    if not value:
        return "-"

    if isinstance(value, datetime):
        dt = value
    else:
        return str(value)

    delta = datetime.utcnow() - dt
    seconds = int(delta.total_seconds())
    if seconds < 0:
        seconds = 0

    if seconds < 60:
        return "şimdi"
    if seconds < 3600:
        minutes = max(1, seconds // 60)
        return f"{minutes} dk önce"
    if seconds < 86400:
        hours = max(1, seconds // 3600)
        return f"{hours} saat önce"

    days = max(1, seconds // 86400)
    return f"{days} gün önce"


templates.env.filters["fmt_dt"] = _fmt_dt
templates.env.filters["rel_time"] = _rel_time


def db_session():
    with SessionLocal() as db:
        yield db


def _ensure_groups_schema() -> None:
    """Best-effort schema patching for existing MSSQL installs.

    SQLAlchemy create_all() does not add columns to existing tables.
    """

    try:
        with engine.begin() as conn:
            # Create groups table if missing
            conn.execute(
                text(
                    """
IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'groups')
BEGIN
    CREATE TABLE groups (
        id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
        name NVARCHAR(128) NOT NULL UNIQUE,
        created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
    );
END
"""
                )
            )

            # Add devices.group_id if missing
            conn.execute(
                text(
                    """
IF COL_LENGTH('devices', 'group_id') IS NULL
BEGIN
    ALTER TABLE devices ADD group_id INT NULL;
END
"""
                )
            )

            # Index (best-effort)
            conn.execute(
                text(
                    """
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes WHERE name = 'IX_devices_group_id' AND object_id = OBJECT_ID('devices')
)
BEGIN
    CREATE INDEX IX_devices_group_id ON devices(group_id);
END
"""
                )
            )

            # FK (best-effort)
            conn.execute(
                text(
                    """
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_devices_groups_group_id')
BEGIN
    ALTER TABLE devices
    ADD CONSTRAINT FK_devices_groups_group_id
    FOREIGN KEY (group_id) REFERENCES groups(id);
END
"""
                )
            )

            # Create device_groups join table if missing
            conn.execute(
                text(
                    """
IF NOT EXISTS (SELECT 1 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'device_groups')
BEGIN
    CREATE TABLE device_groups (
        device_id INT NOT NULL,
        group_id INT NOT NULL,
        CONSTRAINT PK_device_groups PRIMARY KEY (device_id, group_id)
    );
END
"""
                )
            )

            # Index (best-effort)
            conn.execute(
                text(
                    """
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes WHERE name = 'IX_device_groups_group_id' AND object_id = OBJECT_ID('device_groups')
)
BEGIN
    CREATE INDEX IX_device_groups_group_id ON device_groups(group_id);
END
"""
                )
            )

            # FKs (best-effort)
            conn.execute(
                text(
                    """
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_device_groups_devices_device_id')
BEGIN
    ALTER TABLE device_groups
    ADD CONSTRAINT FK_device_groups_devices_device_id
    FOREIGN KEY (device_id) REFERENCES devices(id)
    ON DELETE CASCADE;
END
"""
                )
            )
            conn.execute(
                text(
                    """
IF NOT EXISTS (SELECT 1 FROM sys.foreign_keys WHERE name = 'FK_device_groups_groups_group_id')
BEGIN
    ALTER TABLE device_groups
    ADD CONSTRAINT FK_device_groups_groups_group_id
    FOREIGN KEY (group_id) REFERENCES groups(id)
    ON DELETE CASCADE;
END
"""
                )
            )

            # Backfill device_groups from legacy devices.group_id
            conn.execute(
                text(
                    """
IF COL_LENGTH('devices', 'group_id') IS NOT NULL
BEGIN
    INSERT INTO device_groups (device_id, group_id)
    SELECT d.id, d.group_id
    FROM devices d
    WHERE d.group_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM device_groups dg
          WHERE dg.device_id = d.id AND dg.group_id = d.group_id
      );
END
"""
                )
            )
    except Exception as e:
        # Keep server booting even if migration fails.
        print("WARN: groups schema migration failed:", e)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_groups_schema()
    ensure_default_admin()


def require_panel_user(request: Request) -> str:
    sso_user = get_sso_user(request)
    if sso_user:
        return sso_user

    cookie_user = request.cookies.get("itmanager_user")
    if not cookie_user:
        raise HTTPException(status_code=401)
    return cookie_user


def require_admin_user(request: Request, db) -> str:
    username = require_panel_user(request)
    user = db.scalar(select(User).where(User.username == username))
    if not user or not user.is_admin:
        raise HTTPException(status_code=403)
    return username


def get_or_init_server_config(db) -> ServerConfig:
    cfg = db.scalar(select(ServerConfig).order_by(ServerConfig.id))
    if cfg:
        return cfg
    cfg = ServerConfig(agent_enrollment_token=settings.agent_enrollment_token)
    db.add(cfg)
    db.commit()
    db.refresh(cfg)
    return cfg


@app.get("/health")
def health():
    return {"ok": True, "ts": datetime.utcnow().isoformat()}


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    try:
        require_panel_user(request)
        return RedirectResponse("/dashboard", status_code=302)
    except Exception:
        return RedirectResponse("/login", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db=Depends(db_session)):
    user = require_panel_user(request)

    is_admin = False
    try:
        u = db.scalar(select(User).where(User.username == user))
        is_admin = bool(u and u.is_admin)
    except Exception:
        is_admin = False

    def _pct(part: int, whole: int) -> int:
        if whole <= 0:
            return 0
        return int(round((part * 100.0) / whole))

    # Devices
    devices = db.scalars(select(Device).order_by(Device.hostname)).all()
    total_devices = len(devices)

    online_cutoff = datetime.utcnow() - timedelta(seconds=settings.panel_online_cutoff_seconds)
    online_devices = sum(1 for d in devices if d.last_seen_at and d.last_seen_at >= online_cutoff)
    offline_devices = total_devices - online_devices

    devices_online_pct = _pct(online_devices, total_devices)

    online_window_label = (
        f"{settings.panel_online_cutoff_seconds} sn"
        if settings.panel_online_cutoff_seconds < 60
        else f"{max(1, int(round(settings.panel_online_cutoff_seconds / 60)))} dk"
    )

    # Commands
    status_counts = dict(db.execute(select(Command.status, func.count()).group_by(Command.status)).all())
    queued_commands = int(status_counts.get("queued", 0) or 0)
    running_commands = int(status_counts.get("running", 0) or 0)
    failed_commands = int(status_counts.get("failed", 0) or 0)
    success_commands = int(status_counts.get("success", 0) or 0)
    total_commands = int(sum(int(v or 0) for v in status_counts.values()))

    queued_pct = _pct(queued_commands, total_commands)
    running_pct = _pct(running_commands, total_commands)
    failed_pct = _pct(failed_commands, total_commands)
    success_pct = _pct(success_commands, total_commands)

    resp = templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "is_admin": is_admin,
            "total_devices": total_devices,
            "online_devices": online_devices,
            "offline_devices": offline_devices,
            "devices_online_pct": devices_online_pct,
            "online_window_label": online_window_label,
            "queued_commands": queued_commands,
            "running_commands": running_commands,
            "failed_commands": failed_commands,
            "success_commands": success_commands,
            "total_commands": total_commands,
            "queued_pct": queued_pct,
            "running_pct": running_pct,
            "failed_pct": failed_pct,
            "success_pct": success_pct,
        },
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, err: str | None = None):
    resp = templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "err": bool(err),
        },
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db=Depends(db_session)):
    user = db.scalar(select(User).where(User.username == username))
    if not user or not verify_password(password, user.password_hash):
        return RedirectResponse("/login?err=1", status_code=302)

    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("itmanager_user", username, httponly=True, samesite="lax")
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("itmanager_user")
    return resp


@app.get("/devices", response_class=HTMLResponse)
def devices(request: Request, db=Depends(db_session)):
    user = require_panel_user(request)
    err = request.query_params.get("err")
    ok = request.query_params.get("ok")
    preselect_cmd = request.query_params.get("cmd")
    group_id_param = (request.query_params.get("group_id") or "").strip()
    status_filter = (request.query_params.get("status") or "").strip().lower()
    selected_group_id: int | None = None
    if group_id_param.isdigit():
        selected_group_id = int(group_id_param)
    cfg = get_or_init_server_config(db)
    online_cutoff = datetime.utcnow() - timedelta(seconds=settings.panel_online_cutoff_seconds)
    online_window_minutes = max(1, int(round(settings.panel_online_cutoff_seconds / 60)))
    is_admin = False
    try:
        u = db.scalar(select(User).where(User.username == user))
        is_admin = bool(u and u.is_admin)
    except Exception:
        is_admin = False
    groups = db.scalars(select(Group).order_by(Group.name)).all()

    selected_group = None
    if selected_group_id is not None:
        try:
            selected_group = db.get(Group, selected_group_id)
        except Exception:
            selected_group = None

    q = select(Device).options(selectinload(Device.groups)).order_by(Device.hostname)
    if selected_group_id is not None:
        q = q.where(Device.groups.any(Group.id == selected_group_id))
    rows_all = db.scalars(q).all()

    total_devices = len(rows_all)
    online_devices = sum(1 for d in rows_all if d.last_seen_at and d.last_seen_at >= online_cutoff)
    offline_devices = total_devices - online_devices
    devices_online_pct = int(round((online_devices * 100.0) / total_devices)) if total_devices > 0 else 0

    rows = rows_all
    if status_filter == "online":
        rows = [d for d in rows_all if d.last_seen_at and d.last_seen_at >= online_cutoff]
    elif status_filter == "offline":
        rows = [d for d in rows_all if not d.last_seen_at or d.last_seen_at < online_cutoff]
    else:
        status_filter = ""

    # UI hints (capability detection by agent version)
    for d in rows:
        try:
            d.ui_supports_notify = _require_min_agent_version(d, "0.2.0")
        except Exception:
            d.ui_supports_notify = False

        try:
            d.ui_supports_exit_password = _require_min_agent_version(d, "0.2.13")
        except Exception:
            d.ui_supports_exit_password = False

        try:
            d.ui_supports_agent_update = _require_min_agent_version(d, "0.2.28")
        except Exception:
            d.ui_supports_agent_update = False

    resp = templates.TemplateResponse(
        "devices.html",
        {
            "request": request,
            "user": user,
            "is_admin": is_admin,
            "err": err,
            "ok": ok,
            "preselect_cmd": preselect_cmd,
            "enrollment_token": cfg.agent_enrollment_token,
            "groups": groups,
            "selected_group_id": selected_group_id,
            "selected_group": selected_group,
            "status_filter": status_filter,
            "devices": rows,
            "online_cutoff": online_cutoff,
            "online_window_minutes": online_window_minutes,
            "total_devices": total_devices,
            "online_devices": online_devices,
            "offline_devices": offline_devices,
            "devices_online_pct": devices_online_pct,
        },
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(device_id: int, request: Request, db=Depends(db_session)):
    user = require_panel_user(request)
    err = request.query_params.get("err")
    ok = request.query_params.get("ok")
    preselect_cmd = request.query_params.get("cmd")

    dev = db.scalar(select(Device).options(selectinload(Device.groups)).where(Device.id == device_id))
    if not dev:
        raise HTTPException(status_code=404)
    groups = db.scalars(select(Group).order_by(Group.name)).all()

    online_cutoff = datetime.utcnow() - timedelta(seconds=settings.panel_online_cutoff_seconds)
    online_window_minutes = max(1, int(round(settings.panel_online_cutoff_seconds / 60)))

    is_admin = False
    try:
        u = db.scalar(select(User).where(User.username == user))
        is_admin = bool(u and u.is_admin)
    except Exception:
        is_admin = False

    try:
        dev.ui_supports_notify = _require_min_agent_version(dev, "0.2.0")
    except Exception:
        dev.ui_supports_notify = False

    try:
        dev.ui_supports_exit_password = _require_min_agent_version(dev, "0.2.13")
    except Exception:
        dev.ui_supports_exit_password = False

    try:
        dev.ui_supports_agent_update = _require_min_agent_version(dev, "0.2.28")
    except Exception:
        dev.ui_supports_agent_update = False

    recent_commands = db.scalars(
        select(Command)
        .where(Command.device_id == device_id)
        .order_by(Command.created_at.desc())
        .limit(10)
    ).all()
    for c in recent_commands:
        _decorate_command_for_ui(c)

    last_command = db.scalar(
        select(Command)
        .where(Command.device_id == device_id)
        .order_by(Command.created_at.desc())
        .limit(1)
    )
    if last_command:
        _decorate_command_for_ui(last_command)

    last_executed = db.scalar(
        select(Command)
        .where(Command.device_id == device_id)
        .where(Command.status.in_(["success", "failed"]))
        .order_by(Command.finished_at.desc(), Command.created_at.desc())
        .limit(1)
    )
    if last_executed:
        _decorate_command_for_ui(last_executed)

    inventory_by_device = _build_inventory_by_device({device_id: recent_commands})
    inventory = inventory_by_device.get(device_id)

    resp = templates.TemplateResponse(
        "device_detail.html",
        {
            "request": request,
            "user": user,
            "is_admin": is_admin,
            "err": err,
            "ok": ok,
            "preselect_cmd": preselect_cmd,
            "device": dev,
            "groups": groups,
            "online_cutoff": online_cutoff,
            "online_window_minutes": online_window_minutes,
            "recent_commands": recent_commands,
            "last_command": last_command,
            "last_executed": last_executed,
            "inventory": inventory,
        },
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


def _try_parse_json(text: str) -> Any | None:
    s = (text or "").strip()
    if not s:
        return None
    if not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        t = line.strip()
        if t:
            return t
    return ""


def _parse_semver(v: str) -> tuple[int, int, int]:
    """Parse 'X.Y.Z' (extras ignored) into a comparable tuple."""
    s = (v or "").strip()
    if not s:
        return (0, 0, 0)

    # Keep only leading numeric-dot parts: '0.2.0+abc' -> '0.2.0'
    core = s.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (max(0, major), max(0, minor), max(0, patch))
    except Exception:
        return (0, 0, 0)


def _require_min_agent_version(dev: Device, min_version: str) -> bool:
    return _parse_semver(getattr(dev, "agent_version", "")) >= _parse_semver(min_version)


def _ps_single_quote(value: object) -> str:
    # PowerShell single-quoted string escape
    return str(value).replace("'", "''")


def _build_agent_update_fallback_ps(target_version: str = "") -> str:
    # Old agents execute PowerShell via cmd.exe (shell=True) and some implementations pass the script
    # to `powershell -Command` without quoting. In that case cmd.exe metacharacters (| & < > ^) inside
    # the script break execution.
    # Keep bootstrap tiny AND avoid cmd metacharacters entirely.
    # NOTE: For maximum compatibility we do not include the optional version query parameter here
    # (it would require '&' in the URL). Old agents will update to latest.
    return (
        "$ErrorActionPreference='Stop';"
        "try{"
        "$pd=Join-Path $env:ProgramData 'ITManagerAgent';"
        "$cfgPath=Join-Path $pd 'config.json';"
        "$cfg=ConvertFrom-Json (Get-Content -LiteralPath $cfgPath -Raw);"
        "$b=([string]$cfg.server_base_url).TrimEnd('/');"
        "$t=[string]$cfg.enrollment_token;"
        "if(-not $b -or -not $t){throw 'missing config'};"
        # Best-effort TLS1.2 enablement for older Windows/.NET defaults
        "try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls}catch{};"
        "$vt=$true;try{$vt=[bool]$cfg.verify_tls}catch{$vt=$true};"
        "if(-not $vt){try{[Net.ServicePointManager]::ServerCertificateValidationCallback={ $true }}catch{}};"
        "$url=$b+'/api/agent/tools/agent_update.ps1?enrollment_token='+[uri]::EscapeDataString($t);"
        "$ps1=Join-Path $pd 'agent_update.ps1';"
        "$wc=New-Object System.Net.WebClient;"
        "$wc.DownloadFile($url,$ps1);"
        "Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',$ps1 -WorkingDirectory $pd -WindowStyle Hidden;"
        "Write-Output 'update-started';"
        "exit 0;"
        "}catch{"
        "try{Write-Output ('update-failed: ' + $_.Exception.Message)}catch{Write-Output 'update-failed'};"
        "exit 1;"
        "}"
    )


def _agent_update_tool_ps1(target_version: str = "") -> str:
        tv = (target_version or "").strip()
        tv_ps = _ps_single_quote(tv)
        # This script runs detached on Windows clients.
        # It uses the enrollment-token bootstrap endpoints to download a release ZIP.
        return f"""$ErrorActionPreference = 'Stop'

$pd = Join-Path $env:ProgramData 'ITManagerAgent'
$log = Join-Path $pd 'update_apply.log'
function Log([string]$m) {{ try {{ Add-Content -Path $log -Value ("$(Get-Date -Format s) " + $m) }} catch {{ }} }}

try {{
    $cfg = Get-Content -LiteralPath (Join-Path $pd 'config.json') -Raw | ConvertFrom-Json
    $base = ([string]$cfg.server_base_url).TrimEnd('/')
    $enroll = [string]$cfg.enrollment_token
    if (-not $base -or -not $enroll) {{ throw 'missing config' }}

    $verifyTls = $true
    try {{ $verifyTls = [bool]$cfg.verify_tls }} catch {{ $verifyTls = $true }}
    if (-not $verifyTls) {{
        try {{ [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }} }} catch {{ }}
    }}

    # WebClient is more compatible than Invoke-WebRequest/Invoke-RestMethod on some older Windows builds.
    $wc = New-Object System.Net.WebClient
    $wc.Headers['Accept'] = 'application/json'

    $plat = 'windows'
    $tv = '{tv_ps}'
    $relUrl = $base + '/api/agent/releases/enroll/latest?platform=' + $plat + '&enrollment_token=' + [uri]::EscapeDataString($enroll)
    if ($tv) {{ $relUrl = $relUrl + '&version=' + [uri]::EscapeDataString($tv) }}

    $relJson = $wc.DownloadString($relUrl)
    $rel = ConvertFrom-Json $relJson
    $ver = [string]$rel.version
    $sha = (([string]$rel.sha256) + '').ToUpperInvariant()
    $dl = [string]$rel.download_url
    if (-not $ver -or -not $dl) {{ throw 'invalid release info' }}
    if (-not ($dl -match '^https?://')) {{ $dl = $base + $dl }}

    $tmp = Join-Path $pd 'update_tmp'
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $zip = Join-Path $tmp ('release_' + $ver + '.zip')
    $stage = Join-Path $tmp ('stage_' + $ver)
    Remove-Item -Recurse -Force -LiteralPath $stage -ErrorAction SilentlyContinue

    Log ('download start version=' + $ver)
    $wc.DownloadFile($dl, $zip)
    if ($sha) {{
        $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToUpperInvariant()
        if ($h -ne $sha) {{ throw ('sha256 mismatch expected=' + $sha + ' got=' + $h) }}
    }}

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $stage)

    $svc = Get-ChildItem -Path $stage -Recurse -Filter 'ITManagerAgentService.exe' | Select-Object -First 1
    $tray = Get-ChildItem -Path $stage -Recurse -Filter 'ITManagerAgentTray.exe' | Select-Object -First 1
    $agent = Get-ChildItem -Path $stage -Recurse -Filter 'ITManagerAgent.exe' | Select-Object -First 1
    if (-not $svc -or -not $tray -or -not $agent) {{ throw 'release missing required exe(s)' }}

    $svcName = 'ITManagerAgent'
    Log 'stopping service'
    try {{ Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue }} catch {{ }}
    Start-Sleep -Seconds 2
    try {{ & taskkill.exe /F /T /IM 'ITManagerAgentService.exe' 2>$null | Out-Null }} catch {{ }}
    try {{ & taskkill.exe /F /T /IM 'ITManagerAgentTray.exe' 2>$null | Out-Null }} catch {{ }}
    try {{ & taskkill.exe /F /T /IM 'ITManagerAgent.exe' 2>$null | Out-Null }} catch {{ }}
    Start-Sleep -Seconds 1

    Log 'copy binaries'
    Copy-Item -Force -LiteralPath $svc.FullName -Destination (Join-Path $pd 'ITManagerAgentService.exe')
    Copy-Item -Force -LiteralPath $tray.FullName -Destination (Join-Path $pd 'ITManagerAgentTray.exe')
    Copy-Item -Force -LiteralPath $agent.FullName -Destination (Join-Path $pd 'ITManagerAgent.exe')

    $exe = Join-Path $pd 'ITManagerAgentService.exe'
    $q = & sc.exe query $svcName 2>&1
    if ($LASTEXITCODE -ne 0) {{
        Log 'installing service'
        & $exe install | Out-Null
    }}

    Log 'config service start=auto'
    $bin = "`"$exe`""
    & sc.exe config $svcName binPath= $bin start= auto | Out-Null
    try {{
        & sc.exe failure $svcName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        & sc.exe failureflag $svcName 1 | Out-Null
    }} catch {{ }}

    Log 'starting service'
    try {{ Start-Service -Name $svcName -ErrorAction Stop }} catch {{ & $exe start | Out-Null }}

    try {{ Remove-Item -Recurse -Force -LiteralPath $stage -ErrorAction SilentlyContinue }} catch {{ }}

    Log ('update done version=' + $ver)
}} catch {{
    Log ('update failed: ' + $_)
    throw
}}
"""


def _server_root_dir() -> Path:
    # itmanager-server/
    return Path(__file__).resolve().parent.parent


def _agent_releases_dir() -> Path:
    base = Path(settings.agent_releases_dir)
    if not base.is_absolute():
        base = _server_root_dir() / base
    return base


_RELEASE_VERSION_RE = re.compile(r"(?P<version>\d+\.\d+\.\d+)(?:[^\\/]*?)\.zip$", re.IGNORECASE)


def _parse_version_from_filename(path: Path) -> str | None:
    m = _RELEASE_VERSION_RE.search(path.name)
    return m.group("version") if m else None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _fmt_tr_int(n: int) -> str:
    # Turkish-friendly thousands separator (.)
    return f"{int(n):,}".replace(",", ".")


def _fmt_tr_float(x: float, decimals: int = 1) -> str:
    s = f"{float(x):.{decimals}f}"
    return s.replace(".", ",")


def _fmt_bytes_tr(n: Any) -> str:
    try:
        b = float(n)
    except Exception:
        return str(n)
    if b < 0:
        return str(n)

    units = [
        (1024.0**4, "TB", 1),
        (1024.0**3, "GB", 1),
        (1024.0**2, "MB", 0),
        (1024.0, "KB", 0),
    ]
    for div, unit, dec in units:
        if b >= div:
            return f"{_fmt_tr_float(b / div, dec)} {unit}"
    return f"{_fmt_tr_int(int(b))} B"


def _format_inventory_for_ui(inv: dict[str, Any]) -> dict[str, Any]:
    # Build an ordered mapping for nicer UI rendering.
    ordered_keys = [
        "ts",
        "hostname",
        "platform",
        "machine",
        "processor",
        "python",
        "ram_total",
        "ram_available",
        "cpu_count",
        "disks",
    ]

    out: dict[str, Any] = {}

    # Copy known keys in a stable order.
    for k in ordered_keys:
        if k in inv:
            out[k] = inv.get(k)

    # Append any remaining keys (rare/new fields).
    for k, v in inv.items():
        if k not in out:
            out[k] = v

    # Pretty conversions
    ts = out.get("ts")
    if isinstance(ts, str):
        pretty = _try_pretty_tr_datetime_from_iso(ts)
        if pretty:
            out["ts"] = pretty

    for k in ("ram_total", "ram_available"):
        if k in out:
            try:
                raw = int(float(out.get(k) or 0))
                out[k] = f"{_fmt_bytes_tr(raw)} ({_fmt_tr_int(raw)} B)"
            except Exception:
                pass

    if "cpu_count" in out:
        try:
            out["cpu_count"] = int(out.get("cpu_count") or 0)
        except Exception:
            pass

    # Disks: replace long raw list with a compact table-friendly structure.
    disks = inv.get("disks")
    if isinstance(disks, list) and disks and all(isinstance(d, dict) for d in disks):
        rows: list[dict[str, Any]] = []
        for d in disks:
            try:
                total = int(float(d.get("total") or 0))
                used = int(float(d.get("used") or 0))
                free = int(float(d.get("free") or 0))
            except Exception:
                total = used = free = 0

            pct = "-"
            try:
                if total > 0:
                    pct = f"{_fmt_tr_float((used / total) * 100.0, 1)}%"
            except Exception:
                pct = "-"

            drive = (d.get("mount") or d.get("device") or "")
            rows.append(
                {
                    "Sürücü": str(drive),
                    "FS": str(d.get("fstype") or ""),
                    "Toplam": _fmt_bytes_tr(total),
                    "Kullanılan": _fmt_bytes_tr(used),
                    "Boş": _fmt_bytes_tr(free),
                    "Doluluk": pct,
                }
            )

        out["disks"] = rows
    elif "disks" in out:
        # At least show a short summary.
        try:
            out["disks"] = f"{len(disks) if isinstance(disks, list) else 0} disk"
        except Exception:
            pass

    return out


def _get_latest_release(platform: str) -> dict[str, Any] | None:
    plat = (platform or "").strip().lower()
    if plat not in {"windows"}:
        return None

    base = _agent_releases_dir() / plat
    if not base.exists():
        return None

    zips = [p for p in base.glob("*.zip") if p.is_file()]
    candidates: list[tuple[tuple[int, int, int], str, Path]] = []
    for p in zips:
        v = _parse_version_from_filename(p)
        if not v:
            continue
        candidates.append((_parse_semver(v), v, p))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    _, version, path = candidates[0]

    sha_path = Path(str(path) + ".sha256")
    sha = ""
    if sha_path.exists():
        try:
            sha = sha_path.read_text(encoding="utf-8").strip().split()[0].upper()
        except Exception:
            sha = ""
    if not sha:
        sha = _sha256_file(path)

    return {
        "platform": plat,
        "version": version,
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha,
        "download_url": f"/api/agent/releases/download?platform={plat}&version={version}",
    }


def _get_release_by_version(platform: str, version: str) -> dict[str, Any] | None:
    plat = (platform or "").strip().lower()
    ver = (version or "").strip()
    if plat not in {"windows"}:
        return None
    if not ver:
        return None

    base = _agent_releases_dir() / plat
    if not base.exists():
        return None

    # Accept any file that contains the exact version and ends with .zip
    candidates = [p for p in base.glob(f"*{ver}*.zip") if p.is_file() and _parse_version_from_filename(p) == ver]
    if not candidates:
        return None

    path = sorted(candidates, key=lambda p: p.name)[-1]
    sha_path = Path(str(path) + ".sha256")
    sha = ""
    if sha_path.exists():
        try:
            sha = sha_path.read_text(encoding="utf-8").strip().split()[0].upper()
        except Exception:
            sha = ""
    if not sha:
        sha = _sha256_file(path)

    return {
        "platform": plat,
        "version": ver,
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha,
        "download_url": f"/api/agent/releases/download?platform={plat}&version={ver}",
    }


def _decorate_command_for_ui(c: Command) -> None:
    """Attach UI-friendly attributes onto a Command instance for templates."""

    type_map = {
        "inventory": "Envanter",
        "get_inventory": "Envanter",
        "services_list": "Servisler",
        "service_control": "Servis İşlemi",
        "processes_list": "Process List",
        "process_kill": "Process Kill",
        "eventlog_recent": "Event Log",
        "task_list": "Scheduled Tasks",
        "task_run": "Scheduled Task Çalıştır",
        "restart": "Restart",
        "shutdown": "Shutdown",
        "w32time_resync": "W32Time Resync",
        "w32time_restart": "W32Time Restart",
        "w32time_status": "W32Time Status",
        "time_get": "Saat/Tarih Oku",
        "time_set": "Saat/Tarih Ayarla",
        "notify": "Mesaj Gönder",
        "cmd_exec": "CMD (Admin)",
        "powershell_exec": "PowerShell (Admin)",
        "exit_password_set": "Çıkış Parolası Güncelle",
    }

    cmd_type = (c.type or "").strip().lower()
    c.ui_title = type_map.get(cmd_type, c.type or "")
    c.ui_summary = ""
    c.ui_request = ""
    c.ui_stdout_json = None
    c.ui_table_cols = []
    c.ui_table_rows = []
    c.ui_table_total = None

    # Extract a compact "what was requested" line from payload_json.
    try:
        payload = _try_parse_json(c.payload_json or "")
        if isinstance(payload, dict):
            if cmd_type == "cmd_exec":
                c.ui_request = str(payload.get("command") or "").strip()
            elif cmd_type == "powershell_exec":
                c.ui_request = str(payload.get("script") or "").strip()
            elif cmd_type == "notify":
                msg = str(payload.get("text") or payload.get("message") or "").strip()
                t = payload.get("timeout_seconds")
                if msg and t is not None:
                    c.ui_request = f"{msg} (süre={t}s)"
                else:
                    c.ui_request = msg
            elif cmd_type == "service_control":
                name = str(payload.get("name") or "").strip()
                action = str(payload.get("action") or "").strip()
                c.ui_request = (f"{name} {action}").strip()
            elif cmd_type == "process_kill":
                pid = payload.get("pid")
                c.ui_request = f"pid={pid}" if pid is not None else ""
            elif cmd_type == "task_run":
                tn = str(payload.get("tn") or "").strip()
                c.ui_request = tn
            elif cmd_type == "time_set":
                iso = str(payload.get("iso") or "").strip()
                c.ui_request = iso
            elif cmd_type == "exit_password_set":
                c.ui_request = "(gizli)"
    except Exception:
        c.ui_request = ""

    # For failed commands, show a short hint from stderr/stdout.
    try:
        if (c.status or "") == "failed" and not getattr(c, "ui_summary", None):
            hint = _first_line(c.stderr or "") or _first_line(c.stdout or "")
            if hint:
                c.ui_summary = hint[:220]
    except Exception:
        pass

    if not c.stdout:
        return

    parsed = _try_parse_json(c.stdout)
    if parsed is not None:
        c.ui_stdout_json = parsed

    # Inventory summary (also helpful in recent commands)
    if cmd_type in ("inventory", "get_inventory") and isinstance(parsed, dict):
        # Make inventory output readable (bytes -> GB, disks -> table).
        try:
            c.ui_stdout_json = _format_inventory_for_ui(parsed)
        except Exception:
            pass
        try:
            ram_gb = round(float(parsed.get("ram_total", 0)) / 1024 / 1024 / 1024, 1)
        except Exception:
            ram_gb = 0
        cpu = parsed.get("cpu_count")
        disks = parsed.get("disks")
        disk_n = len(disks) if isinstance(disks, list) else 0
        c.ui_summary = f"RAM {ram_gb} GB • CPU {cpu} • Disk {disk_n}"
        return

    # List-like JSON -> render a compact table
    if isinstance(parsed, list) and parsed and all(isinstance(x, dict) for x in parsed):
        def _pretty_cell(v: Any) -> Any:
            if isinstance(v, str):
                pretty = _try_pretty_tr_datetime_from_iso(v)
                return pretty or v
            return v

        rows = parsed
        c.ui_table_total = len(rows)
        if cmd_type == "services_list":
            cols = ["DisplayName", "Name", "State", "StartMode"]
        elif cmd_type == "processes_list":
            cols = ["Id", "ProcessName", "CPU", "WorkingSetMB", "StartTime"]
        elif cmd_type == "eventlog_recent":
            cols = ["TimeCreated", "Id", "LevelDisplayName", "ProviderName", "Message"]
        elif cmd_type == "task_list":
            cols = ["TaskName", "State", "Author"]
        else:
            cols = list(rows[0].keys())[:6]

        c.ui_table_cols = cols
        c.ui_table_rows = [{k: _pretty_cell(r.get(k)) for k in cols} for r in rows]
        c.ui_summary = f"Toplam {len(rows)} kayıt"
        return

    # Dict-like JSON -> short summary
    if isinstance(parsed, dict):
        line = _first_line(json.dumps(parsed, ensure_ascii=False))
        c.ui_summary = line[:160]
        return

    # Plain text fallback
    first = _first_line(c.stdout)
    pretty_dt = _try_pretty_tr_datetime_from_iso(first) if first else None
    c.ui_summary = (pretty_dt or first)[:160] if (pretty_dt or first) else "Çıktı mevcut"


def _build_inventory_by_device(recent_commands_by_device: dict[int, list[Command]]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for device_id, cmds in recent_commands_by_device.items():
        inv_cmd = next(
            (
                c
                for c in cmds
                if (c.type or "").lower() in ("inventory", "get_inventory")
                and (c.status or "") == "success"
                and c.stdout
            ),
            None,
        )
        if not inv_cmd:
            continue

        try:
            inv = json.loads(inv_cmd.stdout)
            if isinstance(inv, dict):
                inv["_command_id"] = inv_cmd.id
                try:
                    out[device_id] = _format_inventory_for_ui(inv)
                except Exception:
                    out[device_id] = inv
        except Exception:
            continue
    return out


@app.post("/devices/{device_id}/command")
def send_command(
    device_id: int,
    request: Request,
    type: str = Form(...),
    payload: str = Form("{}"),
    db=Depends(db_session),
):
    require_panel_user(request)

    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(status_code=404)

    allowed_types = {
        "inventory",
        "notify",
        "restart",
        "shutdown",
        "agent_update",
        "w32time_resync",
        "w32time_restart",
        "w32time_status",
        "time_get",
        "time_set",
        "services_list",
        "service_control",
        "processes_list",
        "process_kill",
        "eventlog_recent",
        "task_list",
        "task_run",
        "cmd_exec",
        "powershell_exec",
        "exit_password_set",
    }
    if (type or "").strip() not in allowed_types:
        raise HTTPException(status_code=400, detail="invalid command type")

    # Feature gating by agent version (prevents confusing 'unknown command type').
    # notify/cmd_exec/powershell_exec require agent v0.2.0+
    if (type or "").strip() in {"notify", "cmd_exec", "powershell_exec"}:
        if not _require_min_agent_version(dev, "0.2.0"):
            msg = f"Bu komut için agent güncel değil (min 0.2.0). Cihaz: {dev.hostname} sürüm={dev.agent_version or 'unknown'}"
            return RedirectResponse(f"/devices/{device_id}?err={quote(msg)}", status_code=302)

    # agent_update is best-effort: old agents may respond with 'unknown command type'.

    # High-risk commands are admin-only.
    if (type or "").strip() in {"cmd_exec", "powershell_exec", "exit_password_set"}:
        require_admin_user(request, db)

    # validate payload is JSON
    try:
        parsed_payload = json.loads(payload or "{}")
    except Exception:
        parsed_payload = {}

    cmd_type = (type or "").strip()
    # Never store plaintext passwords in DB. Convert to a salted hash payload.
    if cmd_type == "exit_password_set":
        try:
            if not isinstance(parsed_payload, dict):
                raise ValueError("payload must be an object")
            pw = str(parsed_payload.get("password") or "").strip()
            if not pw:
                raise ValueError("password is required")
            salt = secrets.token_bytes(16)
            iters = 150_000
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)
            parsed_payload = {
                "algo": "pbkdf2_sha256",
                "salt_b64": base64.b64encode(salt).decode("ascii"),
                "hash_b64": base64.b64encode(dk).decode("ascii"),
                "iters": iters,
            }
        except Exception:
            msg = "Parola güncelleme: geçersiz payload (password gerekli)"
            return RedirectResponse(f"/devices/{device_id}?err={quote(msg)}", status_code=302)

    cmd = Command(device_id=device_id, type=cmd_type, payload_json=json.dumps(parsed_payload), status="queued")
    db.add(cmd)
    db.commit()

    return RedirectResponse(f"/devices/{device_id}?cmd={quote((type or '').strip())}&sent=1", status_code=302)


@app.post("/devices/{device_id}/group")
def set_device_group(
    device_id: int,
    request: Request,
    group_ids: list[str] = Form([]),
    group_id: str = Form(""),
    db=Depends(db_session),
):
    require_admin_user(request, db)

    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(status_code=404)

    raw_ids = [str(x).strip() for x in (group_ids or []) if str(x).strip()]
    if not raw_ids:
        legacy_raw = (group_id or "").strip()
        raw_ids = [legacy_raw] if legacy_raw else []

    if not raw_ids:
        dev.groups = []
        dev.group_id = None
        db.commit()
        return RedirectResponse(f"/devices/{device_id}?ok=group_cleared", status_code=302)

    if any((not s.isdigit()) for s in raw_ids):
        msg = "Geçersiz grup"
        return RedirectResponse(f"/devices/{device_id}?err={quote(msg)}", status_code=302)

    ids = sorted({int(s) for s in raw_ids})
    groups = db.scalars(select(Group).where(Group.id.in_(ids))).all()
    found = {g.id for g in groups}
    missing = [gid for gid in ids if gid not in found]
    if missing:
        msg = "Grup bulunamadı"
        return RedirectResponse(f"/devices/{device_id}?err={quote(msg)}", status_code=302)

    dev.groups = groups
    # Keep legacy column in sync with a deterministic "primary" group.
    dev.group_id = ids[0] if ids else None
    db.commit()
    return RedirectResponse(f"/devices/{device_id}?ok=group_saved", status_code=302)


@app.post("/groups/create")
def create_group(
    request: Request,
    name: str = Form(""),
    db=Depends(db_session),
):
    require_admin_user(request, db)

    n = (name or "").strip()
    if not n:
        msg = "Grup adı boş olamaz"
        return RedirectResponse(f"/devices?err={quote(msg)}", status_code=302)
    if len(n) > 128:
        msg = "Grup adı çok uzun"
        return RedirectResponse(f"/devices?err={quote(msg)}", status_code=302)

    existing = db.scalar(select(Group).where(Group.name == n))
    if existing:
        return RedirectResponse(f"/devices?group_id={existing.id}", status_code=302)

    g = Group(name=n)
    db.add(g)
    db.commit()
    db.refresh(g)
    return RedirectResponse(f"/devices?group_id={g.id}", status_code=302)


@app.post("/groups/{group_id}/rename")
def rename_group(
    group_id: int,
    request: Request,
    name: str = Form(""),
    db=Depends(db_session),
):
    require_admin_user(request, db)

    grp = db.get(Group, group_id)
    if not grp:
        raise HTTPException(status_code=404)

    n = (name or "").strip()
    if not n:
        msg = "Grup adı boş olamaz"
        return RedirectResponse(f"/devices?group_id={group_id}&err={quote(msg)}", status_code=302)
    if len(n) > 128:
        msg = "Grup adı çok uzun"
        return RedirectResponse(f"/devices?group_id={group_id}&err={quote(msg)}", status_code=302)

    existing = db.scalar(select(Group).where(Group.name == n))
    if existing and existing.id != group_id:
        msg = "Bu isimde bir grup zaten var"
        return RedirectResponse(f"/devices?group_id={group_id}&err={quote(msg)}", status_code=302)

    grp.name = n
    db.commit()
    msg = "Grup adı güncellendi"
    return RedirectResponse(f"/devices?group_id={group_id}&ok={quote(msg)}", status_code=302)


@app.post("/groups/{group_id}/command")
def send_group_command(
    group_id: int,
    request: Request,
    type: str = Form(...),
    payload: str = Form("{}"),
    db=Depends(db_session),
):
    require_panel_user(request)

    grp = db.get(Group, group_id)
    if not grp:
        raise HTTPException(status_code=404)

    allowed_types = {
        "inventory",
        "notify",
        "restart",
        "shutdown",
        "agent_update",
        "w32time_resync",
        "w32time_restart",
        "w32time_status",
        "time_get",
        "time_set",
        "services_list",
        "service_control",
        "processes_list",
        "process_kill",
        "eventlog_recent",
        "task_list",
        "task_run",
        "cmd_exec",
        "powershell_exec",
        "exit_password_set",
    }
    cmd_type = (type or "").strip()
    if cmd_type not in allowed_types:
        raise HTTPException(status_code=400, detail="invalid command type")

    # High-risk commands are admin-only.
    if cmd_type in {"cmd_exec", "powershell_exec", "exit_password_set"}:
        require_admin_user(request, db)

    # validate payload is JSON
    try:
        parsed_payload = json.loads(payload or "{}")
    except Exception:
        parsed_payload = {}

    # Never store plaintext passwords in DB. Convert to a salted hash payload.
    if cmd_type == "exit_password_set":
        try:
            if not isinstance(parsed_payload, dict):
                raise ValueError("payload must be an object")
            pw = str(parsed_payload.get("password") or "").strip()
            if not pw:
                raise ValueError("password is required")
            salt = secrets.token_bytes(16)
            iters = 150_000
            dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)
            parsed_payload = {
                "algo": "pbkdf2_sha256",
                "salt_b64": base64.b64encode(salt).decode("ascii"),
                "hash_b64": base64.b64encode(dk).decode("ascii"),
                "iters": iters,
            }
        except Exception:
            msg = "Parola güncelleme: geçersiz payload (password gerekli)"
            return RedirectResponse(f"/devices?group_id={group_id}&err={quote(msg)}", status_code=302)

    devices = db.scalars(select(Device).where(Device.groups.any(Group.id == group_id))).all()
    if not devices:
        msg = f"Grup '{grp.name}': cihaz yok"
        return RedirectResponse(f"/devices?group_id={group_id}&err={quote(msg)}", status_code=302)

    queued = 0
    skipped = 0
    for dev in devices:
        # Feature gating by agent version (prevents confusing 'unknown command type').
        if cmd_type in {"notify", "cmd_exec", "powershell_exec"}:
            try:
                if not _require_min_agent_version(dev, "0.2.0"):
                    skipped += 1
                    continue
            except Exception:
                skipped += 1
                continue

        if cmd_type == "exit_password_set":
            try:
                if not _require_min_agent_version(dev, "0.2.13"):
                    skipped += 1
                    continue
            except Exception:
                skipped += 1
                continue

        db.add(
            Command(
                device_id=dev.id,
                type=cmd_type,
                payload_json=json.dumps(parsed_payload),
                status="queued",
            )
        )
        queued += 1

    db.commit()

    msg = f"Grup '{grp.name}': {queued} cihaz için '{cmd_type}' kuyruğa alındı"
    if skipped:
        msg += f" (skip: {skipped})"
    return RedirectResponse(f"/devices?group_id={group_id}&ok={quote(msg)}", status_code=302)


@app.post("/devices/{device_id}/exit_password")
def update_exit_password(
    device_id: int,
    request: Request,
    password: str = Form(""),
    db=Depends(db_session),
):
    require_admin_user(request, db)

    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(status_code=404)

    pw = (password or "").strip()
    if not pw:
        msg = "Parola boş olamaz"
        return RedirectResponse(f"/devices/{device_id}?err={quote(msg)}", status_code=302)

    # Feature gating: requires agent v0.2.13+
    if not _require_min_agent_version(dev, "0.2.13"):
        msg = f"Bu özellik için agent güncel değil (min 0.2.13). Cihaz: {dev.hostname} sürüm={dev.agent_version or 'unknown'}"
        return RedirectResponse(f"/devices/{device_id}?err={quote(msg)}", status_code=302)

    salt = secrets.token_bytes(16)
    iters = 150_000
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters)
    payload = {
        "algo": "pbkdf2_sha256",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "hash_b64": base64.b64encode(dk).decode("ascii"),
        "iters": iters,
    }

    cmd = Command(device_id=device_id, type="exit_password_set", payload_json=json.dumps(payload), status="queued")
    db.add(cmd)
    db.commit()

    return RedirectResponse(f"/devices/{device_id}?cmd=exit_password_set&sent=1", status_code=302)


@app.post("/devices/{device_id}/token/rotate")
def rotate_device_token(device_id: int, request: Request, db=Depends(db_session)):
    require_admin_user(request, db)
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(status_code=404)

    dev.token = generate_device_token()
    db.commit()
    return RedirectResponse(f"/devices/{device_id}", status_code=302)


@app.post("/devices/{device_id}/delete")
def delete_device(device_id: int, request: Request, db=Depends(db_session)):
    require_admin_user(request, db)
    dev = db.get(Device, device_id)
    if not dev:
        raise HTTPException(status_code=404)

    # Ensure related commands are removed first (FK constraint).
    db.execute(sa_delete(Command).where(Command.device_id == device_id))
    db.delete(dev)
    db.commit()
    return RedirectResponse("/devices", status_code=302)


@app.post("/admin/enrollment/rotate")
def rotate_enrollment_token(request: Request, db=Depends(db_session)):
    require_admin_user(request, db)
    cfg = get_or_init_server_config(db)
    cfg.agent_enrollment_token = secrets.token_urlsafe(24)
    cfg.updated_at = datetime.utcnow()
    db.commit()
    return RedirectResponse("/devices", status_code=302)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db=Depends(db_session)):
    user = require_admin_user(request, db)
    err = request.query_params.get("err")
    ok = request.query_params.get("ok")

    users = db.scalars(select(User).order_by(User.username)).all()

    resp = templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "user": user,
            "is_admin": True,
            "users": users,
            "err": err,
            "ok": ok,
        },
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    is_admin: str | None = Form(None),
    db=Depends(db_session),
):
    require_admin_user(request, db)

    u = (username or "").strip()
    if not u:
        msg = "Kullanıcı adı boş olamaz"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)
    if len(u) > 64:
        msg = "Kullanıcı adı çok uzun"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)
    if any(ch.isspace() for ch in u):
        msg = "Kullanıcı adında boşluk olamaz"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)

    existing = db.scalar(select(User).where(User.username == u))
    if existing:
        msg = "Bu kullanıcı zaten var"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)

    pw = (password or "").strip()
    if len(pw) < 8:
        msg = "Parola en az 8 karakter olmalı"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)
    if len(pw) > 256:
        msg = "Parola çok uzun"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)

    admin_flag = bool(is_admin)
    new_user = User(username=u, password_hash=hash_password(pw), is_admin=admin_flag)
    db.add(new_user)
    db.commit()

    msg = "Kullanıcı oluşturuldu"
    return RedirectResponse(f"/admin/users?ok={quote(msg)}", status_code=302)


@app.post("/admin/password")
def admin_change_own_password(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    db=Depends(db_session),
):
    username = require_admin_user(request, db)
    user = db.scalar(select(User).where(User.username == username))
    if not user:
        raise HTTPException(status_code=403)

    cp = (current_password or "").strip()
    if not cp:
        msg = "Mevcut parola boş olamaz"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)
    if not verify_password(cp, user.password_hash):
        msg = "Mevcut parola hatalı"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)

    np = (new_password or "").strip()
    if len(np) < 8:
        msg = "Yeni parola en az 8 karakter olmalı"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)
    if len(np) > 256:
        msg = "Yeni parola çok uzun"
        return RedirectResponse(f"/admin/users?err={quote(msg)}", status_code=302)

    user.password_hash = hash_password(np)
    db.commit()

    msg = "Parola güncellendi"
    return RedirectResponse(f"/admin/users?ok={quote(msg)}", status_code=302)


# -------- Agent API --------

def require_agent_token(request: Request, db) -> Device:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)

    token = auth.removeprefix("Bearer ").strip()
    dev = db.scalar(select(Device).where(Device.token == token))
    if not dev:
        raise HTTPException(status_code=401)

    # Keep agent version fresh even if heartbeat is flaky.
    hdr_ver = (request.headers.get("X-Agent-Version") or "").strip()
    if hdr_ver and hdr_ver != (dev.agent_version or ""):
        dev.agent_version = hdr_ver
        db.commit()
    return dev


def require_enrollment_token(enrollment_token: str, db) -> None:
    cfg = get_or_init_server_config(db)
    if not enrollment_token or str(enrollment_token) != str(cfg.agent_enrollment_token):
        raise HTTPException(status_code=403, detail="Forbidden")


@app.post("/api/agent/register")
async def agent_register(request: Request, db=Depends(db_session)):
    data = await request.json()
    cfg = get_or_init_server_config(db)
    if data.get("enrollment_token") != cfg.agent_enrollment_token:
        raise HTTPException(status_code=403)

    hostname = data.get("hostname") or "unknown"
    agent_version = data.get("agent_version") or "unknown"

    # Avoid duplicate rows for the same machine: reuse the latest record by hostname.
    # This also covers re-installs where the agent needs a fresh token.
    existing = db.scalar(select(Device).where(Device.hostname == hostname).order_by(Device.id.desc()))
    token = generate_device_token()
    now = datetime.utcnow()
    if existing:
        existing.token = token
        existing.agent_version = agent_version
        existing.last_seen_at = now
        db.commit()
        return {"device_id": existing.id, "token": token}

    dev = Device(hostname=hostname, agent_version=agent_version, token=token, last_seen_at=now)
    db.add(dev)
    db.commit()
    db.refresh(dev)
    return {"device_id": dev.id, "token": token}


@app.post("/api/agent/heartbeat")
async def agent_heartbeat(request: Request, db=Depends(db_session)):
    dev = require_agent_token(request, db)
    data = await request.json()

    dev.last_seen_at = datetime.utcnow()
    dev.ip = data.get("ip")
    dev.os = data.get("os")
    if data.get("agent_version"):
        dev.agent_version = str(data.get("agent_version"))
    db.commit()

    return {"ok": True}


@app.get("/api/agent/commands/pull")
def agent_pull(request: Request, db=Depends(db_session)):
    dev = require_agent_token(request, db)

    # Agent talks to the server frequently (poll); use this as a reliable online signal.
    dev.last_seen_at = datetime.utcnow()
    db.commit()

    cmd = db.scalar(
        select(Command)
        .where(Command.device_id == dev.id, Command.status == "queued")
        .order_by(Command.created_at)
    )
    if not cmd:
        return {"command": None}

    cmd.status = "running"
    cmd.started_at = datetime.utcnow()
    db.commit()

    out_type = cmd.type
    try:
        out_payload = json.loads(cmd.payload_json or "{}")
    except Exception:
        out_payload = {}

    # Backward-compatible agent_update:
    # - New agents (>=0.2.28) handle `agent_update` natively.
    # - Old agents don't know `agent_update`, so we send a `powershell_exec` command
    #   that stages + launches the updater detached (so the service can be stopped safely).
    if (cmd.type or "").strip().lower() == "agent_update" and not _require_min_agent_version(dev, "0.2.28"):
        tv = ""
        if isinstance(out_payload, dict):
            tv = str(out_payload.get("version") or "").strip()
        out_type = "powershell_exec"
        out_payload = {
            "script": _build_agent_update_fallback_ps(tv),
            "timeout": 900,
        }

    return {
        "command": {
            "id": cmd.id,
            "type": out_type,
            "payload": out_payload,
        }
    }


@app.post("/api/agent/commands/{command_id}/result")
async def agent_result(command_id: int, request: Request, db=Depends(db_session)):
    dev = require_agent_token(request, db)
    cmd = db.get(Command, command_id)
    if not cmd or cmd.device_id != dev.id:
        raise HTTPException(status_code=404)

    data = await request.json()
    cmd.exit_code = int(data.get("exit_code", 1))
    cmd.stdout = data.get("stdout")
    cmd.stderr = data.get("stderr")
    cmd.finished_at = datetime.utcnow()

    cmd.status = "success" if cmd.exit_code == 0 else "failed"
    dev.last_seen_at = datetime.utcnow()
    db.commit()

    return {"ok": True}


@app.get("/api/agent/releases/latest")
def agent_latest_release(request: Request, platform: str = "windows", version: str = "", db=Depends(db_session)):
    # Only enrolled agents can see/download releases.
    require_agent_token(request, db)
    info = _get_release_by_version(platform, version) if (version or "").strip() else _get_latest_release(platform)
    if not info:
        raise HTTPException(status_code=404, detail="no releases")
    return info


@app.get("/api/agent/releases/enroll/latest")
def agent_latest_release_enroll(platform: str = "windows", version: str = "", enrollment_token: str = "", db=Depends(db_session)):
    # Bootstrap path (no device token yet): allow access with enrollment token.
    require_enrollment_token(enrollment_token, db)
    info = _get_release_by_version(platform, version) if (version or "").strip() else _get_latest_release(platform)
    if not info:
        raise HTTPException(status_code=404, detail="no releases")
    # Include an enrollment-protected download URL for the bootstrap script.
    info = dict(info)
    info["download_url"] = (
        f"/api/agent/releases/enroll/download?platform={info['platform']}&version={info['version']}&enrollment_token={quote(enrollment_token)}"
    )
    return info


@app.get("/api/agent/tools/agent_update.ps1")
def agent_update_tool_ps1(enrollment_token: str = "", version: str = "", db=Depends(db_session)):
    # Enrollment-token protected helper script for very old agents.
    require_enrollment_token(enrollment_token, db)
    return PlainTextResponse(_agent_update_tool_ps1(version), media_type="text/plain; charset=utf-8")


@app.get("/api/agent/releases/download")
def agent_download_release(request: Request, platform: str, version: str, db=Depends(db_session)):
    require_agent_token(request, db)
    plat = (platform or "").strip().lower()
    ver = (version or "").strip()
    if plat not in {"windows"}:
        raise HTTPException(status_code=400, detail="invalid platform")
    if not ver:
        raise HTTPException(status_code=400, detail="version required")

    base = _agent_releases_dir() / plat
    if not base.exists():
        raise HTTPException(status_code=404, detail="no releases")

    # Accept any file that contains the exact version and ends with .zip
    candidates = [p for p in base.glob(f"*{ver}*.zip") if p.is_file() and _parse_version_from_filename(p) == ver]
    if not candidates:
        raise HTTPException(status_code=404, detail="release not found")

    path = sorted(candidates, key=lambda p: p.name)[-1]
    return FileResponse(
        path=str(path),
        media_type="application/zip",
        filename=path.name,
    )


@app.get("/api/agent/releases/enroll/download")
def agent_download_release_enroll(platform: str, version: str, enrollment_token: str = "", db=Depends(db_session)):
    require_enrollment_token(enrollment_token, db)
    plat = (platform or "").strip().lower()
    ver = (version or "").strip()
    if plat not in {"windows"}:
        raise HTTPException(status_code=400, detail="invalid platform")
    if not ver:
        raise HTTPException(status_code=400, detail="version required")

    base = _agent_releases_dir() / plat
    if not base.exists():
        raise HTTPException(status_code=404, detail="no releases")

    candidates = [p for p in base.glob(f"*{ver}*.zip") if p.is_file() and _parse_version_from_filename(p) == ver]
    if not candidates:
        raise HTTPException(status_code=404, detail="release not found")

    path = sorted(candidates, key=lambda p: p.name)[-1]
    return FileResponse(
        path=str(path),
        media_type="application/zip",
        filename=path.name,
    )
