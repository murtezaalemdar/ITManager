from __future__ import annotations

import json
import os
import socket
import sys
import time
import logging
import traceback
import hashlib
import zipfile
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from commands import execute_command, get_supported_command_types
from version import __version__ as AGENT_VERSION


@dataclass(frozen=True)
class AgentConfig:
    server_base_url: str
    enrollment_token: str
    verify_tls: bool
    poll_seconds: int
    agent_version: str
    state_dir: Path
    auto_update: bool
    update_check_interval_seconds: int
    update_notify_user: bool
    update_notify_timeout_seconds: int


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception:
        return None


def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_config(config_path: Path) -> AgentConfig:
    cfg = _read_json(config_path)
    if not cfg:
        raise RuntimeError(f"Config not found or invalid JSON: {config_path}")

    server_base_url = str(cfg.get("server_base_url") or "").rstrip("/")
    enrollment_token = str(cfg.get("enrollment_token") or "")
    verify_tls = bool(cfg.get("verify_tls", False))
    poll_seconds = int(cfg.get("poll_seconds", 10))
    # IMPORTANT: Agent version must reflect the running binary, not the config file.
    # Config can be persisted under ProgramData and may not be updated on upgrades.
    agent_version = str(AGENT_VERSION or "unknown")
    state_dir = Path(str(cfg.get("state_dir") or "C:/ProgramData/ITManagerAgent"))

    auto_update = bool(cfg.get("auto_update", True))
    update_check_interval_seconds = int(cfg.get("update_check_interval_seconds", 3600))
    update_notify_user = bool(cfg.get("update_notify_user", True))
    update_notify_timeout_seconds = int(cfg.get("update_notify_timeout_seconds", 10))

    if not server_base_url:
        raise RuntimeError("server_base_url is required")
    if not enrollment_token:
        raise RuntimeError("enrollment_token is required")

    return AgentConfig(
        server_base_url=server_base_url,
        enrollment_token=enrollment_token,
        verify_tls=verify_tls,
        poll_seconds=max(3, poll_seconds),
        agent_version=agent_version,
        state_dir=state_dir,
        auto_update=auto_update,
        update_check_interval_seconds=max(300, update_check_interval_seconds),
        update_notify_user=update_notify_user,
        update_notify_timeout_seconds=max(5, min(600, update_notify_timeout_seconds)),
    )


def _parse_semver(v: str) -> Tuple[int, int, int]:
    s = (v or "").strip()
    if not s:
        return (0, 0, 0)
    core = s.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (max(0, major), max(0, minor), max(0, patch))
    except Exception:
        return (0, 0, 0)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _platform_name() -> str:
    if os.name == "nt":
        import struct
        is_32bit = struct.calcsize("P") * 8 == 32
        try:
            import sys
            v = sys.getwindowsversion()
            # Windows 7 / Server 2008 R2 = major 6, minor 1
            # Windows Vista / Server 2008 = major 6, minor 0
            if v.major < 6 or (v.major == 6 and v.minor <= 1):
                return "windows7-32" if is_32bit else "windows7"
        except Exception:
            pass
        # Windows 10/11 için 32-bit kontrolü
        return "windows-32" if is_32bit else "windows"
    return "unknown"


def _tail_text_file(path: Path, max_chars: int = 4000) -> str:
    try:
        if not path.exists():
            return ""
        data = path.read_text(encoding="utf-8", errors="ignore")
        if len(data) <= max_chars:
            return data
        return data[-max_chars:]
    except Exception:
        return ""


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def get_primary_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
        finally:
            s.close()
    except Exception:
        return None


def get_os_string() -> str:
    try:
        import platform

        return platform.platform()
    except Exception:
        return "unknown"


class ITManagerAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.session = requests.Session()
        if not self.config.verify_tls:
            try:
                import urllib3

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        self.state_path = self.config.state_dir / "state.json"
        self.health_path = self.config.state_dir / "health.json"
        self.log_path = self.config.state_dir / "agent.log"
        self.log = self._init_logger()
        self._device_id: Optional[int] = None
        self._token: Optional[str] = None
        self._last_update_check_ts: float = 0.0

        self.log.info("agent init version=%s server=%s verify_tls=%s poll=%ss state_dir=%s", self.config.agent_version, self.config.server_base_url, self.config.verify_tls, self.config.poll_seconds, str(self.config.state_dir))

        # Write an initial health snapshot immediately so field troubleshooting
        # can confirm which EXE is running (path/version/capabilities).
        self._write_health(
            {
                "status": "starting",
                "server_base_url": self.config.server_base_url,
                "agent_version": self.config.agent_version,
                "exe": sys.executable,
                "supported_command_types": get_supported_command_types(),
                "auto_update": bool(self.config.auto_update),
                "http_status": None,
                "http_body": "",
                "last_http_error": None,
            }
        )

    def _maybe_notify_user_update(self, text: str) -> None:
        if not self.config.update_notify_user:
            return
        if os.name != "nt":
            return
        # Best-effort: message currently logged-on users via msg.exe.
        # This can fail depending on session/policy; log only.
        try:
            timeout = int(getattr(self.config, "update_notify_timeout_seconds", 10) or 10)
            timeout = max(5, min(600, timeout))
            subprocess.Popen(
                ["msg.exe", "*", f"/TIME:{timeout}", text],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass

    def _update_check_due(self) -> bool:
        now = time.time()
        return (now - self._last_update_check_ts) >= float(self.config.update_check_interval_seconds)

    def check_for_update(self, target_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if not self._token:
            return None
        plat = _platform_name()
        if plat == "unknown":
            return None

        url = f"{self.config.server_base_url}/api/agent/releases/latest"
        try:
            params: Dict[str, Any] = {"platform": plat}
            tv = (target_version or "").strip()
            if tv:
                params["version"] = tv
            r = self.session.get(
                url,
                params=params,
                headers=self.auth_headers,
                timeout=20,
                verify=self.config.verify_tls,
            )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            info = r.json() if r.text else None
            if not isinstance(info, dict):
                return None
        except Exception as e:
            self.log.warning("update_check_failed %r", e)
            self._write_health({"update_check_failed": True, "update_check_error": repr(e)[:240]})
            return None

        latest = str(info.get("version") or "")
        if not latest:
            return None
        if _parse_semver(latest) <= _parse_semver(self.config.agent_version):
            # up-to-date
            self._write_health({"update_available": False, "latest_version": latest})
            return None

        # Update available
        self.log.warning("update_available current=%s latest=%s", self.config.agent_version, latest)
        self._write_health(
            {
                "update_available": True,
                "latest_version": latest,
                "latest_sha256": info.get("sha256"),
                "latest_download_url": info.get("download_url"),
            }
        )
        self._maybe_notify_user_update(f"ITManager Agent güncelleme var: {latest}.")
        return info

    def _download_release_zip(self, info: Dict[str, Any]) -> Path:
        plat = str(info.get("platform") or _platform_name())
        ver = str(info.get("version") or "").strip()
        if not ver:
            raise RuntimeError("release version missing")
        rel_url = str(info.get("download_url") or "").strip()
        if not rel_url:
            raise RuntimeError("download_url missing")

        if rel_url.startswith("http://") or rel_url.startswith("https://"):
            url = rel_url
        else:
            url = f"{self.config.server_base_url}{rel_url}"

        out_dir = self.config.state_dir / "updates" / f"{plat}-{ver}"
        out_dir.mkdir(parents=True, exist_ok=True)
        zip_path = out_dir / f"itmanager-agent-{plat}-{ver}.zip"

        self.log.info("update_download -> %s", url)
        r = self.session.get(url, headers=self.auth_headers, timeout=120, verify=self.config.verify_tls, stream=True)
        r.raise_for_status()
        with zip_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)

        expected = str(info.get("sha256") or "").strip().upper()
        if expected:
            actual = _sha256_file(zip_path)
            if actual != expected:
                raise RuntimeError(f"sha256 mismatch expected={expected} actual={actual}")

        return zip_path

    def _download_tool_file(self, url: str, out_path: Path, expected_sha256: str = "") -> Path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self.log.info("tool_download -> %s", url)
        r = self.session.get(url, headers=self.auth_headers, timeout=180, verify=self.config.verify_tls, stream=True)
        r.raise_for_status()
        with out_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)

        exp = (expected_sha256 or "").strip().upper()
        if exp:
            actual = _sha256_file(out_path)
            if actual != exp:
                raise RuntimeError(f"sha256 mismatch expected={exp} actual={actual}")
        return out_path

    def _rustdesk_deploy(self) -> tuple[int, str, str]:
        if not self._token:
            return 2, "", "not enrolled"

        try:
            info_url = f"{self.config.server_base_url}/api/agent/tools/rustdesk/latest"
            r = self.session.get(info_url, headers=self.auth_headers, timeout=30, verify=self.config.verify_tls)
            if r.status_code == 404:
                return 2, "", "rustdesk tool not found on server"
            r.raise_for_status()
            info = r.json() if r.text else None
            if not isinstance(info, dict):
                return 2, "", "invalid tool info"

            filename = str(info.get("filename") or "").strip()
            sha = str(info.get("sha256") or "").strip().upper()
            dl = str(info.get("download_url") or "").strip()
            cfg = str(info.get("config_string") or "").strip()
            pw = str(info.get("password") or "").strip()
            if not filename or not dl:
                return 2, "", "invalid tool info (filename/download_url missing)"
            if not cfg:
                return 2, "", "rustdesk self-host config not set on server"

            if dl.startswith("http://") or dl.startswith("https://"):
                dl_url = dl
            else:
                dl_url = f"{self.config.server_base_url}{dl}"

            tools_dir = self.config.state_dir / "tools" / "rustdesk"
            download_path = tools_dir / filename
            self._download_tool_file(dl_url, download_path, expected_sha256=sha)

            # Deploy/install best-effort.
            ext = download_path.suffix.lower()

            # Common install location (keeps files stable across updates)
            pd = Path(os.environ.get("ProgramData") or r"C:\ProgramData")
            install_root = pd / "ITManager" / "tools" / "rustdesk"
            install_root.mkdir(parents=True, exist_ok=True)

            def _run_no_window(args: List[str], timeout: int = 600) -> subprocess.CompletedProcess:
                kwargs = {
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.PIPE,
                    "text": True,
                    "timeout": timeout,
                    "shell": False,
                }
                if os.name == "nt":
                    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                return subprocess.run(args, **kwargs)

            def _find_rustdesk_exe() -> Optional[Path]:
                if os.name != "nt":
                    return None
                pf = Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
                pf86 = Path(os.environ.get("ProgramFiles(x86)") or r"C:\Program Files (x86)")
                candidates = [
                    pf / "RustDesk" / "rustdesk.exe",
                    pf / "RustDesk" / "RustDesk.exe",
                    pf86 / "RustDesk" / "rustdesk.exe",
                    pf86 / "RustDesk" / "RustDesk.exe",
                ]
                for p in candidates:
                    try:
                        if p.exists() and p.is_file():
                            return p
                    except Exception:
                        continue
                return None

            def _apply_rustdesk_config(rustdesk_exe: Path) -> tuple[Optional[str], str]:
                # Apply config string and optionally set permanent password.
                # IMPORTANT: do not return the password to avoid storing plaintext in server DB.
                err_msgs: List[str] = []
                try:
                    cp = _run_no_window([str(rustdesk_exe), "--config", cfg], timeout=60)
                    if cp.returncode != 0:
                        err_msgs.append((cp.stderr or cp.stdout or "").strip() or "rustdesk --config failed")
                except Exception as e:
                    err_msgs.append(f"rustdesk --config exception: {e}")

                if pw:
                    try:
                        cp = _run_no_window([str(rustdesk_exe), "--password", pw], timeout=30)
                        if cp.returncode != 0:
                            err_msgs.append((cp.stderr or cp.stdout or "").strip() or "rustdesk --password failed")
                    except Exception as e:
                        err_msgs.append(f"rustdesk --password exception: {e}")

                rustdesk_id: Optional[str] = None
                try:
                    cp = _run_no_window([str(rustdesk_exe), "--get-id"], timeout=30)
                    if cp.returncode == 0:
                        cand = (cp.stdout or "").strip()
                        if cand:
                            # Sometimes prints extra lines; keep last non-empty line.
                            lines = [ln.strip() for ln in cand.splitlines() if ln.strip()]
                            if lines:
                                rustdesk_id = lines[-1]
                except Exception as e:
                    err_msgs.append(f"rustdesk --get-id exception: {e}")

                # Also write the config string into per-user AppData Roaming locations (RustDesk2.toml).
                try:
                    if os.name == "nt":
                        users_root = Path(os.environ.get("SYSTEMDRIVE", "C:") ) / "Users"
                        if users_root.exists():
                            for prof in users_root.iterdir():
                                try:
                                    if not prof.is_dir():
                                        continue
                                    name = prof.name.lower()
                                    # Skip known non-user profiles
                                    if name in ("public", "default", "default user", "defaultuser0", "all users", "desktop.ini"):
                                        continue
                                    dest_dir = prof / "AppData" / "Roaming" / "RustDesk" / "config"
                                    dest_dir.mkdir(parents=True, exist_ok=True)
                                    (dest_dir / "RustDesk2.toml").write_text(cfg, encoding="utf-8")
                                except Exception as e:
                                    err_msgs.append(f"appdata write {prof.name} error: {e}")
                except Exception as e:
                    err_msgs.append(f"appdata write root error: {e}")

                return rustdesk_id, "\n".join([m for m in err_msgs if m])

            if ext == ".msi":
                # Silent MSI install.
                cp = _run_no_window(["msiexec.exe", "/i", str(download_path), "/qn", "/norestart"], timeout=900)
                out = (cp.stdout or "").strip()
                err = (cp.stderr or "").strip()
                if cp.returncode != 0:
                    return int(cp.returncode), out, (err or "msiexec failed")
                rustdesk_exe = _find_rustdesk_exe()
                if rustdesk_exe:
                    rid, cfg_err = _apply_rustdesk_config(rustdesk_exe)
                    msg = f"rustdesk msi installed ({filename}); config applied"
                    if rid:
                        msg += f"; id={rid}"
                    if pw:
                        msg += "; password set"
                    return 0, msg, cfg_err
                return 0, f"rustdesk msi installed ({filename}); rustdesk.exe not found to apply config", ""

            if ext == ".zip":
                # Extract to ProgramData tool dir.
                target_dir = install_root / download_path.stem
                if target_dir.exists():
                    shutil.rmtree(target_dir, ignore_errors=True)
                target_dir.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(download_path, "r") as z:
                    z.extractall(target_dir)
                return 0, f"rustdesk zip extracted to {target_dir}", ""

            if ext == ".exe":
                # Copy exe into stable location.
                target_exe = install_root / filename
                try:
                    shutil.copy2(download_path, target_exe)
                except Exception:
                    target_exe = download_path

                # Best-effort silent install (many installers accept /S). If it fails, still consider deploy ok.
                try:
                    cp = _run_no_window([str(target_exe), "/S"], timeout=900)
                    if cp.returncode == 0:
                        rustdesk_exe = _find_rustdesk_exe() or target_exe
                        if rustdesk_exe and rustdesk_exe.exists():
                            rid, cfg_err = _apply_rustdesk_config(rustdesk_exe)
                            msg = f"rustdesk exe installed (silent) ({filename}); config applied"
                            if rid:
                                msg += f"; id={rid}"
                            if pw:
                                msg += "; password set"
                            return 0, msg, cfg_err
                        return 0, f"rustdesk exe installed (silent) ({filename}); rustdesk.exe not found to apply config", ""
                except Exception:
                    pass

                # If install didn't run, at least apply config to the deployed binary if it supports it.
                try:
                    rid, cfg_err = _apply_rustdesk_config(target_exe)
                    msg = f"rustdesk exe deployed to {target_exe}; config applied"
                    if rid:
                        msg += f"; id={rid}"
                    if pw:
                        msg += "; password set"
                    return 0, msg, cfg_err
                except Exception:
                    return 0, f"rustdesk exe deployed to {target_exe}", ""

            return 2, "", f"unsupported rustdesk tool file extension: {ext or '-'}"
        except Exception:
            return 1, "", traceback.format_exc()[-2000:]

    def _extract_release(self, zip_path: Path, info: Dict[str, Any]) -> Path:
        plat = str(info.get("platform") or _platform_name())
        ver = str(info.get("version") or "").strip()
        if not ver:
            raise RuntimeError("release version missing")

        # Stage only required executables; avoid extracting every file from the zip.
        stage_dir = self.config.state_dir / "releases" / f"{plat}-{ver}"
        stage_dir.mkdir(parents=True, exist_ok=True)

        required: Dict[str, Optional[str]] = {
            "ITManagerAgentService.exe": None,
            "ITManagerAgentTray.exe": None,
            "ITManagerAgent.exe": None,
        }

        with zipfile.ZipFile(zip_path, "r") as z:
            for name in z.namelist():
                base = name.replace("\\", "/").split("/")[-1]
                if base in required and required[base] is None:
                    required[base] = name

            missing = [k for k, v in required.items() if v is None]
            if missing:
                raise RuntimeError(f"release missing required files: {', '.join(missing)}")

            for base, member in required.items():
                assert member is not None
                with z.open(member, "r") as src, (stage_dir / base).open("wb") as dst:
                    shutil.copyfileobj(src, dst)

        return stage_dir

    def _write_update_script(self, release_dir: Path, version: str) -> Path:
        pd_dir = self.config.state_dir
        log_path = pd_dir / "update_apply.log"
        script_path = pd_dir / "apply_update.ps1"
        install_dir = pd_dir
        stage_svc_exe = (release_dir / "ITManagerAgentService.exe").resolve()
        stage_tray_exe = (release_dir / "ITManagerAgentTray.exe").resolve()
        stage_agent_exe = (release_dir / "ITManagerAgent.exe").resolve()

        target_svc_exe = (install_dir / "ITManagerAgentService.exe").resolve()
        target_tray_exe = (install_dir / "ITManagerAgentTray.exe").resolve()
        target_agent_exe = (install_dir / "ITManagerAgent.exe").resolve()

        # Note: sc.exe config syntax requires a space after '='.
        def _ps_single_quote(value: object) -> str:
            return str(value).replace("'", "''")

        script = r"""
$ErrorActionPreference = 'Stop'
$log = '__LOG__'
function Log([string]$m) {
  try { Add-Content -Path $log -Value ("$(Get-Date -Format s) " + $m) } catch { }
}

function Wait-ProcessExit([string]$name, [int]$timeoutSeconds = 15) {
    $start = Get-Date
    while ($true) {
        try {
            $p = Get-Process -Name $name -ErrorAction SilentlyContinue
        } catch {
            $p = $null
        }
        if (-not $p) { return $true }
        if (((Get-Date) - $start).TotalSeconds -ge $timeoutSeconds) { return $false }
        Start-Sleep -Milliseconds 300
    }
}

function Kill-ProcessByName([string]$name) {
    try {
        # Stop-Process is fast; taskkill helps across sessions.
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch { }
    try {
        & taskkill.exe /F /T /IM "$name.exe" 2>$null | Out-Null
    } catch { }
}

function Copy-WithRetry([string]$src, [string]$dst, [int]$retries = 10) {
    for ($i = 1; $i -le $retries; $i++) {
        try {
            Copy-Item -Force -Path $src -Destination $dst
            return
        } catch {
            Log ("copy failed attempt=$i src=$src dst=$dst err=" + $_)
            Start-Sleep -Seconds 1
        }
    }
    throw "copy failed after $retries attempts: $src -> $dst"
}

function Wait-ServiceState([string]$svcName, [string]$contains, [int]$timeoutSeconds = 30) {
    $start = Get-Date
    $want = ($contains | ForEach-Object { $_.ToUpperInvariant() })
    while ($true) {
        try {
            $q = & sc.exe query $svcName 2>&1
            $txt = ($q | Out-String)
        } catch {
            $txt = ""
        }
        if ($txt -and $want -and ($txt.ToUpperInvariant().Contains($want))) { return $true }
        if (((Get-Date) - $start).TotalSeconds -ge $timeoutSeconds) { return $false }
        Start-Sleep -Milliseconds 500
    }
}

$svcName = 'ITManagerAgent'
$stageSvc = '__STAGE_SVC__'
$stageTray = '__STAGE_TRAY__'
$stageAgent = '__STAGE_AGENT__'
$installDir = '__INSTALL_DIR__'
$exe = '__TARGET_SVC__'
$targetTray = '__TARGET_TRAY__'
$targetAgent = '__TARGET_AGENT__'

try {
  Log "update start target=__VERSION__ exe=$exe"

    New-Item -ItemType Directory -Force -Path $installDir | Out-Null

    # Stop service before replacing binaries (binary can be locked while running)
    $q = & sc.exe query $svcName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Log "stopping service"
        try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch { }
        [void](Wait-ServiceState $svcName 'STOPPED' 20)

        # If the service process is still alive (hung/slow stop), force-kill it to release file locks.
        if (-not (Wait-ProcessExit 'ITManagerAgentService' 5)) {
            Log "service process still running, force kill"
            Kill-ProcessByName 'ITManagerAgentService'
            [void](Wait-ProcessExit 'ITManagerAgentService' 15)
        }

        # One more check: service can report stop-pending even if process is killed.
        [void](Wait-ServiceState $svcName 'STOPPED' 10)
    } else {
        Log "service not installed (yet)"
    }

    # Also stop/kill tray + agent processes so EXEs can be overwritten.
    # Service runs in session 0, tray runs in user session; taskkill covers both.
    Log "killing running processes (tray/agent)"
    Kill-ProcessByName 'ITManagerAgentTray'
    Kill-ProcessByName 'ITManagerAgent'
    # Wait a bit for file locks to be released.
    [void](Wait-ProcessExit 'ITManagerAgentTray' 15)
    [void](Wait-ProcessExit 'ITManagerAgent' 15)

    Log "copy binaries to ProgramData"
    Copy-WithRetry $stageSvc $exe 12
    Copy-WithRetry $stageTray $targetTray 12
    Copy-WithRetry $stageAgent $targetAgent 12

    # Remove Mark-of-the-Web if present (prevents security prompts on logon/startup).
    try { Unblock-File -Path $exe -ErrorAction SilentlyContinue } catch { }
    try { Unblock-File -Path $targetTray -ErrorAction SilentlyContinue } catch { }
    try { Unblock-File -Path $targetAgent -ErrorAction SilentlyContinue } catch { }

    Log "ensure service installed"
    $q2 = & sc.exe query $svcName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Log "installing service"
        & $exe install | Out-Null
    }

    Log "config binPath + start=auto"
    $bin = "`"$exe`""
    & sc.exe config $svcName binPath= $bin start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc config failed" }

    # Best-effort recovery settings so the service comes back after crashes/reboots.
    try {
        & sc.exe failure $svcName reset= 0 actions= restart/5000/restart/5000/restart/5000 | Out-Null
        & sc.exe failureflag $svcName 1 | Out-Null
        Log "service recovery configured"
    } catch {
        Log ("service recovery config failed: " + $_)
    }

    Start-Sleep -Seconds 1

    Log "starting service"
    try { Start-Service -Name $svcName -ErrorAction Stop } catch {
        # Fallback: use exe start
        & $exe start | Out-Null
    }

    # Ensure it actually reached RUNNING; if not, try once more via sc.
    if (-not (Wait-ServiceState $svcName 'RUNNING' 25)) {
        Log "service did not reach RUNNING, retry start via sc"
        try { & sc.exe start $svcName | Out-Null } catch { }
        [void](Wait-ServiceState $svcName 'RUNNING' 25)
    }

    # Ensure tray auto-starts for users by maintaining a Common Startup shortcut.
    # This runs at user logon (tray is a user-session process).
    try {
        $commonStartup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'
        New-Item -ItemType Directory -Force -Path $commonStartup | Out-Null
        $lnk = Join-Path $commonStartup 'ITManagerAgentTray.lnk'
        $wsh = New-Object -ComObject WScript.Shell
        $scut = $wsh.CreateShortcut($lnk)
        $scut.TargetPath = $targetTray
        $scut.WorkingDirectory = $installDir
        $scut.WindowStyle = 7
        $scut.Description = 'ITManager Agent Tray'
        $scut.Save()
        Log "tray startup shortcut ok: $lnk -> $targetTray"
    } catch {
        Log ("tray startup shortcut failed: " + $_)
    }

    # Cleanup stage folder to avoid accumulating old releases
    try {
        $stageDir = Split-Path -Parent $stageSvc
        if ($stageDir -and (Test-Path $stageDir)) {
            Remove-Item -Recurse -Force -Path $stageDir -ErrorAction SilentlyContinue
        }
    } catch { }

  Log "update done"
  exit 0
} catch {
  Log ("update failed: " + $_)
  exit 1
}

    """

        script = (
            script.replace("__LOG__", _ps_single_quote(log_path))
            .replace("__STAGE_SVC__", _ps_single_quote(stage_svc_exe))
            .replace("__STAGE_TRAY__", _ps_single_quote(stage_tray_exe))
            .replace("__STAGE_AGENT__", _ps_single_quote(stage_agent_exe))
            .replace("__INSTALL_DIR__", _ps_single_quote(install_dir))
            .replace("__TARGET_SVC__", _ps_single_quote(target_svc_exe))
            .replace("__TARGET_TRAY__", _ps_single_quote(target_tray_exe))
            .replace("__TARGET_AGENT__", _ps_single_quote(target_agent_exe))
            .replace("__VERSION__", str(version))
        )

        script_path.write_text(script, encoding="utf-8")
        return script_path

    def apply_update_if_needed(
        self,
        info: Dict[str, Any],
        force: bool = False,
        *,
        raise_on_error: bool = False,
        wait_for_log_seconds: int = 0,
    ) -> Tuple[bool, str, str]:
        if os.name != "nt":
            return False, "", "unsupported-os"
        if not force and not self.config.auto_update:
            return False, "", "auto-update-disabled"

        ver = str(info.get("version") or "").strip()
        if not ver:
            return False, "", "release-version-missing"

        script_path: Optional[Path] = None
        try:
            self._write_health({"update_in_progress": True, "update_target_version": ver})
            zip_path = self._download_release_zip(info)
            release_dir = self._extract_release(zip_path, info)
            script_path = self._write_update_script(release_dir, ver)

            self.log.warning("applying_update version=%s script=%s", ver, str(script_path))
            self._maybe_notify_user_update(f"ITManager Agent güncelleniyor: {ver}.")

            # Run updater detached; it will stop this service process.
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
            subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                cwd=str(self.config.state_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=True,
            )

            # Best-effort: confirm the updater actually started by waiting for log output.
            if wait_for_log_seconds > 0 and script_path is not None:
                log_path = self.config.state_dir / "update_apply.log"
                started = False
                deadline = time.time() + max(1, int(wait_for_log_seconds))
                while time.time() < deadline:
                    tail = _tail_text_file(log_path, max_chars=2000)
                    if tail and "update start" in tail:
                        started = True
                        break
                    time.sleep(0.25)
                if started:
                    return True, f"update-started:{ver}", ""
                # If log didn't show up, still report started but include hint.
                tail2 = _tail_text_file(log_path, max_chars=2000)
                hint = "updater launched but no log yet; check ProgramData/update_apply.log"
                if tail2.strip():
                    hint = hint + "\n\n" + tail2.strip()[-2000:]
                return True, f"update-started:{ver}", hint

            return True, f"update-started:{ver}", ""
        except Exception as e:
            self.log.error("apply_update_failed %r", e)
            self._write_health({"update_in_progress": False, "update_failed": True, "update_error": repr(e)[:500]})
            if raise_on_error:
                raise
            return False, "", repr(e)[:800]

    def _write_health(self, patch: Dict[str, Any]) -> None:
        try:
            now = datetime.now(timezone.utc).isoformat()
            base: Dict[str, Any] = _read_json(self.health_path) or {}
            base.update(patch)
            base.setdefault("created_at", now)
            base["updated_at"] = now
            _write_json(self.health_path, base)
        except Exception:
            pass

    def _init_logger(self) -> logging.Logger:
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger("itmanager-agent")
        if logger.handlers:
            return logger
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(self.log_path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        return logger

    def load_state(self) -> None:
        state = _read_json(self.state_path) or {}
        self._device_id = state.get("device_id")
        self._token = state.get("token")

    def save_state(self) -> None:
        _write_json(
            self.state_path,
            {
                "device_id": self._device_id,
                "token": self._token,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    @property
    def auth_headers(self) -> Dict[str, str]:
        if not self._token:
            return {}
        return {
            "Authorization": f"Bearer {self._token}",
            "X-Agent-Version": str(self.config.agent_version or ""),
        }

    def register_if_needed(self) -> None:
        if self._token:
            return

        url = f"{self.config.server_base_url}/api/agent/register"
        payload = {
            "enrollment_token": self.config.enrollment_token,
            "hostname": get_hostname(),
            "agent_version": self.config.agent_version,
        }

        self.log.info("register -> %s host=%s", url, payload.get("hostname"))
        r = self.session.post(url, json=payload, timeout=15, verify=self.config.verify_tls)
        r.raise_for_status()
        data = r.json()

        self._device_id = int(data["device_id"])
        self._token = str(data["token"])
        self.save_state()
        self.log.info("registered device_id=%s", self._device_id)
        self._write_health(
            {
                "status": "registered",
                "server_base_url": self.config.server_base_url,
                "device_id": self._device_id,
                "agent_version": self.config.agent_version,
                "exe": sys.executable,
                "supported_command_types": get_supported_command_types(),
                "http_status": None,
                "http_body": "",
                "last_http_error": None,
                "last_register_ok": datetime.now(timezone.utc).isoformat(),
            }
        )

    def heartbeat(self) -> None:
        url = f"{self.config.server_base_url}/api/agent/heartbeat"
        payload = {
            "ip": get_primary_ip(),
            "os": get_os_string(),
            "agent_version": self.config.agent_version,
        }
        self.log.info("heartbeat -> %s", url)
        r = self.session.post(
            url,
            json=payload,
            headers=self.auth_headers,
            timeout=15,
            verify=self.config.verify_tls,
        )
        r.raise_for_status()
        self._write_health(
            {
                "status": "heartbeat_ok",
                "device_id": self._device_id,
                "agent_version": self.config.agent_version,
                "exe": sys.executable,
                "supported_command_types": get_supported_command_types(),
                "http_status": None,
                "http_body": "",
                "last_http_error": None,
                "last_heartbeat_ok": datetime.now(timezone.utc).isoformat(),
            }
        )

    def pull_command(self) -> Optional[Dict[str, Any]]:
        url = f"{self.config.server_base_url}/api/agent/commands/pull"
        self.log.info("pull -> %s", url)
        r = self.session.get(url, headers=self.auth_headers, timeout=30, verify=self.config.verify_tls)
        r.raise_for_status()
        data = r.json()
        return data.get("command")

    def post_result(self, command_id: int, exit_code: int, stdout: str, stderr: str) -> None:
        url = f"{self.config.server_base_url}/api/agent/commands/{command_id}/result"
        self.log.info("result -> %s id=%s exit=%s", url, command_id, exit_code)
        payload = {
            "exit_code": int(exit_code),
            "stdout": stdout,
            "stderr": stderr,
        }
        r = self.session.post(
            url,
            json=payload,
            headers=self.auth_headers,
            timeout=60,
            verify=self.config.verify_tls,
        )
        r.raise_for_status()

    def run_forever(self, stop_flag: Optional["StopFlag"] = None) -> None:
        self.load_state()

        self.log.info("run_forever starting")

        backoff_seconds = 2
        while True:
            if stop_flag and stop_flag.is_set():
                return

            try:
                self.register_if_needed()
                self.heartbeat()

                # Periodic update check (best effort).
                if self._update_check_due():
                    self._last_update_check_ts = time.time()
                    info = self.check_for_update()
                    if info:
                        # best-effort auto update
                        self.apply_update_if_needed(info)

                cmd = self.pull_command()
                if cmd:
                    cmd_id = int(cmd["id"])
                    cmd_type = str(cmd.get("type") or "")
                    cmd_payload = cmd.get("payload") or {}

                    # Some commands require access to the device token for local decryption.
                    # Keep it in-memory only (never logged / never posted back).
                    try:
                        if isinstance(cmd_payload, dict) and self._token:
                            # If server sent an encrypted secret payload, inject token in-memory.
                            # This is required for client-side decrypt (AES-GCM key derived from token).
                            sv = cmd_payload.get("secret_v")
                            if int(sv or 0) == 1 and "_device_token" not in cmd_payload:
                                cmd_payload["_device_token"] = self._token
                    except Exception:
                        pass

                    self.log.info("execute id=%s type=%s", cmd_id, cmd_type)
                    ct_norm = (cmd_type or "").strip().lower()
                    if ct_norm == "agent_update":
                        try:
                            tv = ""
                            if isinstance(cmd_payload, dict):
                                tv = str(cmd_payload.get("version") or "").strip()
                            info = self.check_for_update(target_version=tv or None)
                            if not info:
                                exit_code, out, err = 0, "no-update", ""
                            else:
                                ver = str(info.get("version") or "").strip()
                                started, out2, err2 = self.apply_update_if_needed(
                                    info,
                                    force=True,
                                    raise_on_error=True,
                                    wait_for_log_seconds=8,
                                )
                                exit_code = 0 if started else 1
                                out = out2 or f"update-started:{ver or '?'}"
                                err = err2 or ""
                        except Exception:
                            exit_code, out, err = 1, "", traceback.format_exc()[-2000:]
                    elif ct_norm == "rustdesk_deploy":
                        exit_code, out, err = self._rustdesk_deploy()
                    else:
                        exit_code, out, err = execute_command(cmd_type, cmd_payload)
                    self.post_result(cmd_id, exit_code=exit_code, stdout=out, stderr=err)

                backoff_seconds = 2
                sleep_seconds = self.config.poll_seconds
            except requests.HTTPError as e:
                # auth token revoked? clear state and re-enroll.
                if e.response is not None and e.response.status_code in (401, 403):
                    self._device_id = None
                    self._token = None
                    self.save_state()
                try:
                    status = e.response.status_code if e.response is not None else "?"
                    body = ""
                    if e.response is not None:
                        body = (e.response.text or "")[:500]
                    self.log.warning("http_error status=%s body=%s", status, body)
                    self._write_health(
                        {
                            "status": "http_error",
                            "http_status": status,
                            "http_body": (body or "")[:500],
                            "last_http_error": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                except Exception:
                    self.log.warning("http_error")
                sleep_seconds = min(60, backoff_seconds)
                backoff_seconds = min(60, backoff_seconds * 2)
            except Exception:
                err = traceback.format_exc()
                self.log.error("loop_error\n%s", err)
                self._write_health(
                    {
                        "status": "error",
                        "last_error": datetime.now(timezone.utc).isoformat(),
                        "error": err[-2000:],
                    }
                )
                sleep_seconds = min(60, backoff_seconds)
                backoff_seconds = min(60, backoff_seconds * 2)

            for _ in range(sleep_seconds * 10):
                if stop_flag and stop_flag.is_set():
                    return
                time.sleep(0.1)

    def run_once(self) -> Tuple[int, str]:
        """Single iteration for manual testing."""
        self.load_state()
        self.register_if_needed()
        self.heartbeat()

        cmd = self.pull_command()
        if not cmd:
            return 0, "no-command"

        cmd_id = int(cmd["id"])
        cmd_type = str(cmd.get("type") or "")
        cmd_payload = cmd.get("payload") or {}

        ct_norm = (cmd_type or "").strip().lower()
        if ct_norm == "agent_update":
            try:
                tv = ""
                if isinstance(cmd_payload, dict):
                    tv = str(cmd_payload.get("version") or "").strip()
                info = self.check_for_update(target_version=tv or None)
                if not info:
                    exit_code, out, err = 0, "no-update", ""
                else:
                    ver = str(info.get("version") or "").strip()
                    started, out2, err2 = self.apply_update_if_needed(
                        info,
                        force=True,
                        raise_on_error=True,
                        wait_for_log_seconds=8,
                    )
                    exit_code = 0 if started else 1
                    out = out2 or f"update-started:{ver or '?'}"
                    err = err2 or ""
            except Exception:
                exit_code, out, err = 1, "", traceback.format_exc()[-2000:]
        elif ct_norm == "rustdesk_deploy":
            exit_code, out, err = self._rustdesk_deploy()
        else:
            exit_code, out, err = execute_command(cmd_type, cmd_payload)
        self.post_result(cmd_id, exit_code=exit_code, stdout=out, stderr=err)
        return 0, f"executed:{cmd_type}"


class StopFlag:
    def __init__(self) -> None:
        import threading

        self._evt = threading.Event()

    def set(self) -> None:
        self._evt.set()

    def is_set(self) -> bool:
        return self._evt.is_set()


def main() -> int:
    args = sys.argv[1:]
    if getattr(sys, "frozen", False):
        # PyInstaller onefile/onedir: prefer config next to the exe
        config_path = Path(sys.executable).with_name("config.json")
    else:
        config_path = Path(__file__).with_name("config.json")
    once = False

    # Usage:
    #   python agent.py [config.json] [--once]
    for a in list(args):
        if a == "--once":
            once = True
            args.remove(a)

    if args:
        config_path = Path(args[0])

    cfg = load_config(config_path)
    agent = ITManagerAgent(cfg)
    if once:
        code, msg = agent.run_once()
        print(msg)
        return code

    agent.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
