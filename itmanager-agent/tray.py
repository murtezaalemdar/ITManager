from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import webbrowser
import tempfile
import uuid
import ctypes
import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List

import requests

try:
    from version import __version__ as AGENT_VERSION
except Exception:
    AGENT_VERSION = "unknown"


try:
    # Reuse the agent's existing update logic (download/sha256/apply_update.ps1).
    from agent import ITManagerAgent, load_config as load_agent_config  # type: ignore
except Exception:
    ITManagerAgent = None  # type: ignore
    load_agent_config = None  # type: ignore


def _exit_password_path() -> Path:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(base) / "ITManagerAgent" / "exit_password.json"


def _load_exit_password_record() -> dict | None:
    try:
        p = _exit_password_path()
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        return data
    except Exception:
        return None


def _verify_exit_password(password: str, record: dict) -> bool:
    try:
        algo = str(record.get("algo") or "").strip().lower()
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(str(record.get("salt_b64") or ""))
        expected = base64.b64decode(str(record.get("hash_b64") or ""))
        iters = int(record.get("iters") or 0)
        if not salt or not expected or iters <= 0:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def _prompt_exit_password() -> str | None:
    try:
        import tkinter as tk
        from tkinter import simpledialog

        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        pw = simpledialog.askstring("ITManager", "Çıkış parolası:", show="*")
        try:
            root.destroy()
        except Exception:
            pass
        if pw is None:
            return None
        return str(pw)
    except Exception:
        return None


def _get_startup_folder() -> Path:
    """Per-user Startup folder (shell:startup)."""
    # Prefer Known Folder API for correctness across locales.
    try:
        import ctypes
        from ctypes import wintypes

        # FOLDERID_Startup
        folder_id = ctypes.c_wchar_p("{B97D20BB-F46A-4C97-BA10-5E3608430854}")
        ppath = ctypes.c_void_p()

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        SHGetKnownFolderPath = shell32.SHGetKnownFolderPath
        SHGetKnownFolderPath.argtypes = [ctypes.c_wchar_p, wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)]
        SHGetKnownFolderPath.restype = wintypes.HRESULT

        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        CoTaskMemFree = ole32.CoTaskMemFree
        CoTaskMemFree.argtypes = [ctypes.c_void_p]
        CoTaskMemFree.restype = None

        hr = SHGetKnownFolderPath(folder_id, 0, None, ctypes.byref(ppath))
        if hr == 0 and ppath.value:
            try:
                startup = Path(ctypes.wstring_at(ppath.value))
                return startup
            finally:
                try:
                    CoTaskMemFree(ppath)
                except Exception:
                    pass
    except Exception:
        pass

    # Fallback: APPDATA-based path
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    return Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def _get_common_startup_folder() -> Path:
    """All-users Startup folder (Common Startup)."""
    pd = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    return Path(pd) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def _user_startup_shortcut_path() -> Path:
    return _get_startup_folder() / "ITManagerAgentTray.lnk"


def _common_startup_shortcut_path() -> Path:
    return _get_common_startup_folder() / "ITManagerAgentTray.lnk"


def _install_startup_shortcut() -> Tuple[int, str]:
    """Create/overwrite Startup shortcut for tray."""
    try:
        try:
            import win32com.client  # type: ignore
        except Exception as e:
            return 1, f"pywin32/win32com missing: {e!r}"

        # Prefer Common Startup (matches installer) when available/admin;
        # otherwise fall back to per-user Startup.
        lnk_path = _common_startup_shortcut_path()
        startup_dir = lnk_path.parent
        try:
            startup_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            lnk_path = _user_startup_shortcut_path()
            startup_dir = lnk_path.parent
            startup_dir.mkdir(parents=True, exist_ok=True)

        # Target depends on whether we're frozen.
        if getattr(sys, "frozen", False):
            target_path = str(Path(sys.executable).resolve())
            args = ""
            workdir = str(Path(sys.executable).resolve().parent)
        else:
            target_path = sys.executable
            args = str(Path(__file__).resolve())
            workdir = str(Path(__file__).resolve().parent)

        wsh = win32com.client.Dispatch("WScript.Shell")
        shortcut = wsh.CreateShortcut(str(lnk_path))
        shortcut.TargetPath = target_path
        shortcut.Arguments = args
        shortcut.WorkingDirectory = workdir
        shortcut.Description = "ITManager Agent Tray"
        try:
            shortcut.IconLocation = target_path
        except Exception:
            pass
        shortcut.Save()

        return 0, f"Startup kısayolu eklendi: {lnk_path}"
    except Exception as e:
        return 1, f"Startup kısayolu eklenemedi: {e!r}"


def _uninstall_startup_shortcut() -> Tuple[int, str]:
    try:
        removed = []
        errors = []

        for p in (_user_startup_shortcut_path(), _common_startup_shortcut_path()):
            try:
                if p.exists():
                    p.unlink()
                    removed.append(str(p))
            except Exception as e:
                errors.append(f"{p}: {e!r}")

        if errors and not removed:
            return 1, "Startup kısayolu silinemedi: " + "; ".join(errors)
        if removed:
            return 0, "Startup kısayolu silindi: " + ", ".join(removed)
        return 0, "Startup kısayolu zaten yok"
    except Exception as e:
        return 1, f"Startup kısayolu silinemedi: {e!r}"


def _is_startup_enabled() -> bool:
    try:
        # Consider both per-user and common Startup shortcuts.
        return _user_startup_shortcut_path().exists() or _common_startup_shortcut_path().exists()
    except Exception:
        return False


def _log_line(msg: str) -> None:
    try:
        p = Path(tempfile.gettempdir()) / "itmanager_tray_actions.log"
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with p.open("a", encoding="utf-8", newline="") as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        pass


def _runtime_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _programdata_dir() -> Path:
    try:
        import os
        # PROGRAMDATA = C:\ProgramData (Vista+)
        # ALLUSERSPROFILE = C:\ProgramData (Vista+) veya C:\Documents and Settings\All Users (XP)
        pd = os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE") or r"C:\ProgramData"
        return Path(pd) / "ITManagerAgent"
    except Exception:
        return Path(r"C:\ProgramData\ITManagerAgent")


def _programdata_config_path() -> Path:
    return _programdata_dir() / "config.json"


def _single_instance_lock_path() -> Path:
    # Per-user lock (avoids requiring admin rights).
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
    return Path(base) / "ITManagerAgent" / "tray.lock"


def _acquire_single_instance_lock() -> Optional[object]:
    # Use a file lock to guarantee single instance even if WinAPI mutex
    # behaves unexpectedly across different tokens/integrity levels.
    try:
        import msvcrt

        lp = _single_instance_lock_path()
        lp.parent.mkdir(parents=True, exist_ok=True)

        f = lp.open("a+b")
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            try:
                f.close()
            except Exception:
                pass
            return None

        try:
            f.seek(0)
            f.truncate(0)
            f.write(str(os.getpid()).encode("ascii", errors="ignore"))
            f.flush()
        except Exception:
            pass
        return f
    except Exception:
        return None


@dataclass(frozen=True)
class TrayConfig:
    server_base_url: str
    state_dir: Path
    config_path: Path


def load_tray_config() -> TrayConfig:
    # Prefer ProgramData config (stable across upgrades), fallback to EXE dir.
    cfg_path = _programdata_config_path()
    if not cfg_path.exists():
        cfg_path = _runtime_dir() / "config.json"
    cfg = _read_json(cfg_path) or {}
    server_base_url = str(cfg.get("server_base_url") or "").rstrip("/")
    state_dir = Path(str(cfg.get("state_dir") or "C:/ProgramData/ITManagerAgent"))
    return TrayConfig(server_base_url=server_base_url, state_dir=state_dir, config_path=cfg_path)


def _ensure_programdata_config() -> Path:
    pd_cfg = _programdata_config_path()
    if pd_cfg.exists():
        return pd_cfg
    try:
        src = _runtime_dir() / "config.json"
        if src.exists():
            pd_cfg.parent.mkdir(parents=True, exist_ok=True)
            pd_cfg.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            return pd_cfg
    except Exception:
        pass
    return pd_cfg


def _run_sc(args: list[str]) -> Tuple[int, str]:
    try:
        run_kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": 20,
        }

        # When running as a windowed (no-console) app (PyInstaller --noconsole),
        # launching console utilities like sc.exe can momentarily flash a console window.
        # Force a hidden/no-window subprocess on Windows.
        if os.name == "nt":
            try:
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0  # SW_HIDE
                run_kwargs["startupinfo"] = si
            except Exception:
                pass
            run_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        p = subprocess.run(["sc.exe"] + args, **run_kwargs)
        out = (p.stdout or "") + (p.stderr or "")
        return int(p.returncode), out.strip()
    except Exception as e:
        return 1, repr(e)


def _is_access_denied(text: str) -> bool:
    t = (text or "").lower()
    return (
        "openservice failed 5" in t
        or "error 5" in t
        or "access is denied" in t
        or "erişim engellendi" in t
    )


def _is_service_missing(code: int, text: str) -> bool:
    t = (text or "").lower()
    return code == 1060 or "openservice failed 1060" in t or "error 1060" in t or "1060" in t and "yok" in t


def _is_already_running(code: int, text: str) -> bool:
    # Windows error 1056: "An instance of the service is already running."
    t = (text or "").lower()
    return code == 1056 or "1056" in t or "already running" in t or "already been started" in t


def _is_already_stopped(code: int, text: str) -> bool:
    # Windows error 1062: "The service has not been started."
    t = (text or "").lower()
    return (
        code == 1062
        or "1062" in t
        or "has not been started" in t
        or "not been started" in t
        or "başlatılmad" in t
    )


def _is_uac_canceled(text: str) -> bool:
    t = (text or "").lower()
    return (
        "canceled by the user" in t
        or "cancelled by the user" in t
        or "kullanıcı tarafından iptal" in t
        or "işlem iptal edildi" in t
        or "1223" in t  # ERROR_CANCELLED
    )


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _self_path() -> str:
    try:
        if getattr(sys, "frozen", False):
            return str(Path(sys.executable).resolve())
        return str(Path(__file__).resolve())
    except Exception:
        return "-"


def _run_sc_elevated(args: list[str]) -> Tuple[int, str]:
    # Triggers a UAC prompt.
    # NOTE: On Windows PowerShell 5.1, Start-Process -Verb RunAs cannot be combined with
    # RedirectStandardOutput/RedirectStandardError (different parameter set). We instead
    # run an elevated PowerShell that writes sc.exe output to a temp file.
    run_id = uuid.uuid4().hex
    out_file = Path(tempfile.gettempdir()) / f"itmanager_sc_{run_id}.out.txt"

    try:
        # Build inner (elevated) script and pass via -EncodedCommand (UTF-16LE base64).
        def _esc(s):
            return "'" + s.replace("'", "''") + "'"
        arg_list = ",".join([_esc(a) for a in args])
        out_esc = str(out_file).replace("'", "''")
        inner = (
            "$ErrorActionPreference='Stop'\n"
            "$out='" + out_esc + "'\n"
            "try {\n"
            "  & sc.exe @(" + arg_list + ") *>&1 | Out-File -FilePath $out -Encoding utf8\n"
            "  exit $LASTEXITCODE\n"
            "} catch {\n"
            "  ($_ | Out-String) | Out-File -FilePath $out -Encoding utf8\n"
            "  exit 1\n"
            "}\n"
        )
        encoded = base64.b64encode(inner.encode("utf-16le")).decode("ascii")

        outer = (
            "$ErrorActionPreference='Stop'; "
            f"$enc='{encoded}'; "
            "try { "
            "  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$enc) -Verb RunAs -PassThru -Wait; "
            "  exit $p.ExitCode "
            "} catch { "
            "  ($_ | Out-String) | Write-Output; "
            "  exit 1 "
            "}"
        )
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", outer],
            capture_output=True,
            text=True,
            timeout=120,
        )

        captured = ""
        try:
            if out_file.exists():
                captured = out_file.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            captured = ""

        # If we couldn't read the file (or UAC was canceled), fall back to PowerShell output.
        if not captured:
            captured = ((p.stdout or "") + (p.stderr or "")).strip()
        return int(p.returncode), captured
    except Exception as e:
        return 1, repr(e)
    finally:
        try:
            if out_file.exists():
                out_file.unlink(missing_ok=True)
        except Exception:
            pass


def _run_sc_maybe_elevated(args: list[str]) -> Tuple[int, str]:
    code, out = _run_sc(args)
    if code != 0 and _is_access_denied(out):
        code2, out2 = _run_sc_elevated(args)
        if code2 == 0:
            return code2, out2
        # Keep both outputs for troubleshooting.
        combined = "(non-elevated)\n" + out
        if out2:
            combined = (combined + "\n\n" + "(elevated attempt)\n" + out2).strip()
        return code2, combined
    return code, out


def _run_exe_elevated(exe_path: Path, exe_args: list[str]) -> Tuple[int, str]:
    run_id = uuid.uuid4().hex
    out_file = Path(tempfile.gettempdir()) / f"itmanager_exe_{run_id}.out.txt"

    try:
        exe_str = str(exe_path)
        exe_str = exe_str.replace("'", "''")
        def _esc(s):
            return "'" + s.replace("'", "''") + "'"
        arg_list = ",".join([_esc(a) for a in exe_args])
        out_esc = str(out_file).replace("'", "''")
        inner = (
            "$ErrorActionPreference='Stop'\n"
            "$out='" + out_esc + "'\n"
            "try {\n"
            "  & '" + exe_str + "' @(" + arg_list + ") *>&1 | Out-File -FilePath $out -Encoding utf8\n"
            "  exit $LASTEXITCODE\n"
            "} catch {\n"
            "  ($_ | Out-String) | Out-File -FilePath $out -Encoding utf8\n"
            "  exit 1\n"
            "}\n"
        )
        encoded = base64.b64encode(inner.encode("utf-16le")).decode("ascii")

        outer = (
            "$ErrorActionPreference='Stop'; "
            f"$enc='{encoded}'; "
            "try { "
            "  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$enc) -Verb RunAs -PassThru -Wait; "
            "  exit $p.ExitCode "
            "} catch { "
            "  ($_ | Out-String) | Write-Output; "
            "  exit 1 "
            "}"
        )
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", outer],
            capture_output=True,
            text=True,
            timeout=180,
        )

        captured = ""
        try:
            if out_file.exists():
                captured = out_file.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            captured = ""

        if not captured:
            captured = ((p.stdout or "") + (p.stderr or "")).strip()
        return int(p.returncode), captured
    except Exception as e:
        return 1, repr(e)
    finally:
        try:
            if out_file.exists():
                out_file.unlink(missing_ok=True)
        except Exception:
            pass


def _run_ps_file_elevated(script_path: Path, script_args: Optional[List[str]] = None) -> Tuple[int, str]:
    """Run a PowerShell script elevated (UAC) and capture its output."""
    run_id = uuid.uuid4().hex
    out_file = Path(tempfile.gettempdir()) / f"itmanager_ps_{run_id}.out.txt"
    script_args = script_args or []

    try:
        sp = str(script_path).replace("'", "''")
        def _esc(s):
            return "'" + s.replace("'", "''") + "'"
        arg_list = ",".join([_esc(a) for a in script_args])
        out_esc = str(out_file).replace("'", "''")
        inner = (
            "$ErrorActionPreference='Stop'\n"
            "$out='" + out_esc + "'\n"
            "try {\n"
            "  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File '" + sp + "' @(" + arg_list + ") *>&1 | Out-File -FilePath $out -Encoding utf8\n"
            "  exit $LASTEXITCODE\n"
            "} catch {\n"
            "  ($_ | Out-String) | Out-File -FilePath $out -Encoding utf8\n"
            "  exit 1\n"
            "}\n"
        )
        encoded = base64.b64encode(inner.encode("utf-16le")).decode("ascii")

        outer = (
            "$ErrorActionPreference='Stop'; "
            f"$enc='{encoded}'; "
            "try { "
            "  $p = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$enc) -Verb RunAs -PassThru -Wait; "
            "  exit $p.ExitCode "
            "} catch { "
            "  ($_ | Out-String) | Write-Output; "
            "  exit 1 "
            "}"
        )
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", outer],
            capture_output=True,
            text=True,
            timeout=180,
        )

        captured = ""
        try:
            if out_file.exists():
                captured = out_file.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            captured = ""

        if not captured:
            captured = ((p.stdout or "") + (p.stderr or "")).strip()
        return int(p.returncode), captured
    except Exception as e:
        return 1, repr(e)
    finally:
        try:
            if out_file.exists():
                out_file.unlink(missing_ok=True)
        except Exception:
            pass


def _get_service_state() -> str:
    code, out = _run_sc(["query", "ITManagerAgent"])
    if code != 0:
        if _is_service_missing(code, out):
            return "not installed"
        if _is_access_denied(out):
            return "access denied"
        return "unknown"
    # Look for line: STATE              : 4  RUNNING
    for line in out.splitlines():
        if "STATE" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                return parts[1].strip()
    return "unknown"


def _wait_service_state_contains(token: str, timeout_seconds: int = 30) -> bool:
    """Poll `sc query` until service state contains the given token."""
    end = time.time() + max(1, int(timeout_seconds))
    want = (token or "").upper()
    while time.time() < end:
        st = (_get_service_state() or "").upper()
        if "NOT INSTALLED" in st:
            return True
        if want and want in st:
            return True
        time.sleep(0.5)
    return False


def _taskkill_image_maybe_elevated(image_name: str) -> Tuple[int, str]:
    """Force-kill a process image, best-effort with UAC fallback."""
    img = (image_name or "").strip()
    if not img:
        return 1, "empty image name"

    # Non-elevated attempt first
    try:
        p = subprocess.run(
            ["taskkill.exe", "/F", "/T", "/IM", img],
            capture_output=True,
            text=True,
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = ((p.stdout or "") + "\n" + (p.stderr or "")).strip()
        if int(p.returncode) == 0:
            return 0, out
        # Access denied or other failure => try elevated
        if _is_access_denied(out):
            code2, out2 = _run_exe_elevated(Path("taskkill.exe"), ["/F", "/T", "/IM", img])
            return int(code2), (out2 or "")
        return int(p.returncode), out
    except Exception as e:
        return 1, repr(e)


def _get_service_start_type() -> Optional[str]:
    """Returns start type token like AUTO_START, DEMAND_START, DISABLED, DELAYED_AUTO_START."""
    code, out = _run_sc(["qc", "ITManagerAgent"])
    if code != 0:
        return None

    for line in out.splitlines():
        # Example: START_TYPE         : 2   AUTO_START
        if "START_TYPE" in line:
            # Normalize spaces
            parts = line.split(":", 1)
            if len(parts) != 2:
                continue
            rhs = parts[1].strip()
            # pick the last token (AUTO_START etc.)
            tokens = [t for t in rhs.replace("\t", " ").split(" ") if t]
            if tokens:
                return tokens[-1].strip()
    return None


def _is_service_autostart_enabled() -> bool:
    st = (_get_service_start_type() or "").upper()
    return st in {"AUTO_START", "DELAYED_AUTO_START"}


def _read_last_saved_at(state_dir: Path) -> Optional[str]:
    state_path = state_dir / "state.json"
    st = _read_json(state_path) or {}
    v = st.get("saved_at")
    if isinstance(v, str) and v:
        return v
    return None


def _read_health_summary(state_dir: Path) -> Tuple[str, str]:
    """Returns (status_line, last_ts_19) for tray display."""
    hp = state_dir / "health.json"
    h = _read_json(hp) or {}
    status = str(h.get("status") or "-")

    # Prefer last_heartbeat_ok, then last_register_ok, then updated_at
    ts = (
        h.get("last_heartbeat_ok")
        or h.get("last_register_ok")
        or h.get("updated_at")
        or h.get("created_at")
        or "-"
    )
    ts_s = str(ts) if ts is not None else "-"
    ts_19 = ts_s[:19] if ts_s else "-"

    http_status = h.get("http_status")
    if status == "http_error" and http_status is not None:
        status = f"http_{http_status}"
    return status, ts_19


def main() -> int:
    import argparse

    import pystray
    from PIL import Image, ImageDraw

    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--install-startup", action="store_true", help="Tray'i kullanıcı Startup klasörüne ekler")
    parser.add_argument("--uninstall-startup", action="store_true", help="Tray Startup kısayolunu kaldırır")
    args, _unknown = parser.parse_known_args()

    if args.install_startup or args.uninstall_startup:
        if args.install_startup:
            code, msg = _install_startup_shortcut()
            _log_line(f"startup install: rc={code} msg={msg}")
            if msg:
                print(msg)
            return code
        code, msg = _uninstall_startup_shortcut()
        _log_line(f"startup uninstall: rc={code} msg={msg}")
        if msg:
            print(msg)
        return code

    # Prevent multiple tray instances in the same session.
    # Multiple instances can cause confusing UI state (menu enable/disable)
    # and make it look like the agent is running twice.
    instance_lock = _acquire_single_instance_lock()
    if not instance_lock:
        _log_line("single-instance: lock busy, exiting")
        return 0

    mutex_handle = None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        CreateMutexW = kernel32.CreateMutexW
        CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        CreateMutexW.restype = ctypes.c_void_p
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [ctypes.c_void_p]
        CloseHandle.restype = ctypes.c_bool

        ctypes.set_last_error(0)
        mutex_handle = CreateMutexW(None, False, "Local\\ITManagerAgentTray")
        if not mutex_handle:
            mutex_handle = None
        else:
            last_err = ctypes.get_last_error()
            # 183 = ERROR_ALREADY_EXISTS
            if last_err == 183:
                try:
                    CloseHandle(mutex_handle)
                except Exception:
                    pass
                _log_line("single-instance: mutex already exists, exiting")
                return 0
    except Exception:
        mutex_handle = None

    cfg = load_tray_config()

    ui_lock = threading.Lock()
    ui_state = {
        "service_state": "unknown",
        "busy": False,
        "busy_label": "",
    }

    # Guard to prevent opening multiple password dialogs at the same time.
    exit_prompt_in_progress = threading.Event()

    def make_image(fill: tuple[int, int, int, int]) -> Image.Image:
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((4, 4, 60, 60), fill=fill)
        d.text((18, 18), "IT", fill=(255, 255, 255, 255))
        return img

    ICON_GREEN = make_image((34, 197, 94, 255))   # green
    ICON_RED = make_image((239, 68, 68, 255))     # red
    ICON_YELLOW = make_image((234, 179, 8, 255))  # yellow

    def notify(msg: str) -> None:
        try:
            safe_msg = (msg or "").replace("\r", " ").strip()
            if len(safe_msg) > 240:
                safe_msg = safe_msg[:240]
            _log_line(f"notify: {safe_msg!r}")
            # Windows balloon: title max 64, message max 256.
            icon.notify(safe_msg, title="ITManager")
        except Exception as e:
            _log_line(f"notify failed: {e!r}")

    def run_async(label: str, fn) -> None:
        def _worker():
            with ui_lock:
                ui_state["busy"] = True
                ui_state["busy_label"] = label
            try:
                _log_line(f"{label}: begin admin={_is_admin()} self={_self_path()}")
                fn()
                _log_line(f"{label}: end")
            except Exception as e:
                _log_line(f"{label}: exception {e!r}")
                notify(f"{label}: hata (detay: %TEMP%\\itmanager_tray_actions.log)")
            finally:
                with ui_lock:
                    ui_state["busy"] = False
                    ui_state["busy_label"] = ""

        threading.Thread(target=_worker, daemon=True).start()

    def _get_cached_state() -> tuple[str, bool, str]:
        with ui_lock:
            return (
                str(ui_state.get("service_state") or "unknown"),
                bool(ui_state.get("busy")),
                str(ui_state.get("busy_label") or ""),
            )

    def _can_start() -> bool:
        state, busy, _ = _get_cached_state()
        if busy:
            return False
        s = (state or "").upper()
        if "PENDING" in s:
            return False
        # Start should be clickable in almost all states.
        # If already running, the start action will simply report "zaten çalışıyor".
        # This avoids false-disabled behavior on some machines/backends.
        return True

    def _can_stop() -> bool:
        state, busy, _ = _get_cached_state()
        if busy:
            return False
        s = (state or "").upper()
        if "PENDING" in s:
            return False
        # If we cannot reliably detect state (e.g., access denied/unknown),
        # keep stop clickable so the action can trigger UAC and attempt the operation.
        if "NOT INSTALLED" in s:
            return False
        return ("RUNNING" in s) or ("ACCESS DENIED" in s) or ("UNKNOWN" in s)

    def _can_restart() -> bool:
        state, busy, _ = _get_cached_state()
        if busy:
            return False
        s = (state or "").upper()
        if "PENDING" in s:
            return False
        if "NOT INSTALLED" in s:
            return False
        # Restart can be used as a start when service is stopped.
        return ("RUNNING" in s) or ("STOPPED" in s) or ("ACCESS DENIED" in s) or ("UNKNOWN" in s)

    def open_dashboard(_icon, _item):
        if cfg.server_base_url:
            webbrowser.open(cfg.server_base_url + "/dashboard")
        else:
            notify("config.json içinde server_base_url yok")

    def open_devices(_icon, _item):
        if cfg.server_base_url:
            webbrowser.open(cfg.server_base_url + "/devices")
        else:
            notify("config.json içinde server_base_url yok")

    def open_config(_icon, _item):
        try:
            p = _ensure_programdata_config()
            subprocess.Popen(["notepad.exe", str(p)])
        except Exception as e:
            _log_line(f"open_config failed: {e!r}")
            notify("config açılamadı")

    def _defer_menu_action(fn) -> None:
        def _work():
            try:
                time.sleep(0.25)
                fn()
            except Exception as e:
                _log_line(f"defer_menu_action failed: {e!r}")

        threading.Thread(target=_work, daemon=True).start()

    def _prompt_update_version() -> str:
        """Ask user for a target version (blank => latest)."""
        if os.name != "nt":
            return ""
        try:
            # Use a simple InputBox via PowerShell; Cancel returns empty string.
            # Keep it minimal to avoid extra UI dependencies.
            ps = (
                "Add-Type -AssemblyName Microsoft.VisualBasic; "
                "[Microsoft.VisualBasic.Interaction]::InputBox('Hedef sürüm (boş bırak = latest):', 'Agent Update', '')"
            )
            run_kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 60,
            }
            if os.name == "nt":
                run_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            p = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps], **run_kwargs)
            v = (p.stdout or "").strip()
            return v
        except Exception as e:
            _log_line(f"prompt_update_version failed: {e!r}")
            return ""

    def agent_update(_icon, _item):
        notify("agent update: hazırlanıyor...")

        def work():
            if ITManagerAgent is None or load_agent_config is None:
                notify("agent update: bu build içinde aktif değil")
                return

            cfg_path = _ensure_programdata_config()
            try:
                agent_cfg = load_agent_config(cfg_path)
            except Exception as e:
                _log_line(f"agent_update load_config failed: {e!r}")
                notify("agent update: config okunamadı (config.json kontrol edin)")
                return

            target = _prompt_update_version()
            target_s = (target or "").strip()

            a = ITManagerAgent(agent_cfg)
            a.load_state()

            # Prefer token-based path (gives exact version selection), but don't block updates
            # if registration/token fails (common in field machines).
            info = None
            try:
                a.register_if_needed()
                a.load_state()
                notify("agent update: kontrol ediliyor...")
                info = a.check_for_update(target_version=target_s or None)
            except Exception as e:
                detail = repr(e)
                _log_line(f"agent_update register/check failed: {detail}")
                # Fallback to enrollment-based latest/version endpoint (no device token needed).
                try:
                    notify("agent update: enroll ile kontrol...")
                    params = {
                        "platform": "windows",
                        "enrollment_token": str(agent_cfg.enrollment_token or ""),
                    }
                    if target_s:
                        params["version"] = target_s
                    url = f"{agent_cfg.server_base_url}/api/agent/releases/enroll/latest"
                    r = requests.get(url, params=params, timeout=20, verify=agent_cfg.verify_tls)
                    if r.status_code == 404:
                        info = None
                    else:
                        r.raise_for_status()
                        info = r.json() if r.text else None
                except Exception as e2:
                    detail2 = repr(e2)
                    _log_line(f"agent_update enroll fallback failed: {detail2}")
                    notify(f"agent update: bağlantı/kayıt hatası\n{(detail2 or detail)[:120]}")
                    return

            if not info:
                if target_s:
                    notify("agent update: sürüm bulunamadı veya zaten güncel")
                else:
                    notify("agent update: güncelleme yok")
                return

            ver = str(info.get("version") or "").strip()
            if ver:
                notify(f"agent update: uygulanıyor (hedef {ver})")
            else:
                notify("agent update: uygulanıyor")

            # Interactive update from tray typically needs admin rights to reconfigure the service.
            # We prepare the update script using the agent's logic, then run it elevated (UAC).
            try:
                zip_path = a._download_release_zip(info)  # type: ignore[attr-defined]
                release_dir = a._extract_release(zip_path, info)  # type: ignore[attr-defined]
                script_path = a._write_update_script(release_dir, ver or "unknown")  # type: ignore[attr-defined]
            except Exception as e:
                _log_line(f"agent_update prepare failed: {e!r}")
                notify("agent update: hazırlık başarısız (indir/çıkart)")
                return

            if os.name == "nt" and not _is_admin():
                notify("agent update: admin izni isteniyor (UAC)...")

            code, out = _run_ps_file_elevated(script_path)
            detail = (out or "").strip()
            _log_line(f"agent_update apply elevated exit={code} out={detail[:800]!r}")
            if code != 0:
                if _is_uac_canceled(detail):
                    notify("agent update: UAC iptal edildi")
                    return
                # Try to show last log line from ProgramData for quick diagnosis.
                try:
                    logp = _programdata_dir() / "update_apply.log"
                    last_line = ""
                    if logp.exists():
                        lines = logp.read_text(encoding="utf-8", errors="replace").splitlines()
                        last_line = (lines[-1] if lines else "")
                    msg = (last_line or detail[:200] or "hata")
                    notify(f"agent update: failed ({code})\n{msg[:200]}")
                except Exception:
                    notify(f"agent update: failed ({code})")
                return

            # Ensure service is up after update (field expectation: new agent works immediately).
            try:
                _run_sc_maybe_elevated(["start", "ITManagerAgent"])
                _wait_service_state_contains("RUNNING", 25)
            except Exception:
                pass

            notify("agent update: ok (servis güncellendi)")

        run_async("agent_update", work)

    def start_service(_icon, _item):
        notify("start: çalışıyor...")

        def work():
            code, out = _run_sc(["start", "ITManagerAgent"])
            detail = (out or "").strip()
            _log_line(f"start non-elevated exit={code} out={detail[:500]!r}")
            if code == 0:
                notify("start: ok")
                return

            if _is_already_running(code, detail):
                notify("start: zaten çalışıyor")
                return

            if _is_service_missing(code, detail):
                notify("start: servis yok, kuruluyor...")
                svc_exe = _runtime_dir() / "ITManagerAgentService.exe"
                if not svc_exe.exists():
                    notify("start: servis exe yok (ITManagerAgentService.exe)\nZIP içeriği aynı klasörde olmalı")
                    return
                # NOTE: win32serviceutil expects options BEFORE the command verb.
                # Usage: <exe> [options] install|update|...
                codei, outi = _run_exe_elevated(svc_exe, ["--startup", "auto", "install"])
                deti = (outi or "").strip()
                _log_line(f"install elevated exit={codei} out={deti[:800]!r}")
                if codei != 0:
                    if _is_uac_canceled(deti):
                        notify("install: UAC iptal edildi")
                        return
                    notify(f"install: failed (exit={codei})\n{deti[:250]}")
                    return

                codes, outs = _run_exe_elevated(svc_exe, ["--wait", "30", "start"])
                dets = (outs or "").strip()
                _log_line(f"start-exe elevated exit={codes} out={dets[:800]!r}")
                if codes == 0:
                    notify("start: ok")
                    return
                if _is_already_running(codes, dets):
                    notify("start: zaten çalışıyor")
                    return
                if _is_uac_canceled(dets):
                    notify("start: UAC iptal edildi")
                    return
                notify(f"start: failed (exit={codes})\n{dets[:250]}")
                return

            if _is_access_denied(detail):
                notify("start: UAC isteniyor...")
                code2, out2 = _run_sc_elevated(["start", "ITManagerAgent"])
                detail2 = (out2 or "").strip()
                _log_line(f"start elevated exit={code2} out={detail2[:500]!r}")
                if code2 == 0:
                    notify("start: ok")
                    return
                if _is_already_running(code2, detail2):
                    notify("start: zaten çalışıyor")
                    return
                if _is_uac_canceled(detail2):
                    notify("start: UAC iptal edildi")
                    return
                if _is_access_denied(detail2):
                    notify("start: yetki yok (Admin gerekli)")
                    return
                notify(f"start: failed (exit={code2})\n{detail2[:250]}")
                return

            if _is_uac_canceled(detail):
                notify("start: UAC iptal edildi")
                return

            notify(f"start: failed (exit={code})\n{detail[:250]}")

        run_async("start", work)

    def stop_service(_icon, _item):
        notify("stop: çalışıyor...")

        def work():
            code, out = _run_sc(["stop", "ITManagerAgent"])
            detail = (out or "").strip()
            _log_line(f"stop non-elevated exit={code} out={detail[:500]!r}")
            if code == 0:
                if not _wait_service_state_contains("STOPPED", 30):
                    _log_line("stop: still not STOPPED, force-killing ITManagerAgentService.exe")
                    _taskkill_image_maybe_elevated("ITManagerAgentService.exe")
                    _wait_service_state_contains("STOPPED", 20)
                notify("stop: ok")
                return

            if _is_service_missing(code, detail):
                notify("stop: servis kurulu değil")
                return

            if _is_already_stopped(code, detail):
                notify("stop: zaten durmuş")
                return

            if _is_access_denied(detail):
                notify("stop: UAC isteniyor...")
                code2, out2 = _run_sc_elevated(["stop", "ITManagerAgent"])
                detail2 = (out2 or "").strip()
                _log_line(f"stop elevated exit={code2} out={detail2[:500]!r}")
                if code2 == 0:
                    if not _wait_service_state_contains("STOPPED", 30):
                        _log_line("stop(elevated): still not STOPPED, force-killing ITManagerAgentService.exe")
                        _taskkill_image_maybe_elevated("ITManagerAgentService.exe")
                        _wait_service_state_contains("STOPPED", 20)
                    notify("stop: ok")
                    return
                if _is_already_stopped(code2, detail2):
                    notify("stop: zaten durmuş")
                    return
                if _is_uac_canceled(detail2):
                    notify("stop: UAC iptal edildi")
                    return
                if _is_access_denied(detail2):
                    notify("stop: yetki yok (Admin gerekli)")
                    return
                notify(f"stop: failed (exit={code2})\n{detail2[:250]}")
                return

            if _is_uac_canceled(detail):
                notify("stop: UAC iptal edildi")
                return

            notify(f"stop: failed (exit={code})\n{detail[:250]}")

        run_async("stop", work)

    def restart_service(_icon, _item):
        notify("restart: çalışıyor...")

        def work():
            _run_sc_maybe_elevated(["stop", "ITManagerAgent"])
            # Wait for a clean stop; if hung, kill service process.
            if not _wait_service_state_contains("STOPPED", 30):
                _log_line("restart: stop timeout, force-killing ITManagerAgentService.exe")
                _taskkill_image_maybe_elevated("ITManagerAgentService.exe")
                _wait_service_state_contains("STOPPED", 20)

            # Start again
            code, out = _run_sc(["start", "ITManagerAgent"])
            detail = (out or "").strip()
            _log_line(f"restart start non-elevated exit={code} out={detail[:500]!r}")
            if code == 0:
                _wait_service_state_contains("RUNNING", 25)
                notify("restart: ok")
                return
            if _is_service_missing(code, detail):
                notify("restart: servis kurulu değil")
                return
            if _is_access_denied(detail):
                notify("restart: UAC isteniyor...")
                code2, out2 = _run_sc_elevated(["start", "ITManagerAgent"])
                detail2 = (out2 or "").strip()
                _log_line(f"restart start elevated exit={code2} out={detail2[:500]!r}")
                if code2 == 0:
                    _wait_service_state_contains("RUNNING", 25)
                    notify("restart: ok")
                    return
                if _is_uac_canceled(detail2):
                    notify("restart: UAC iptal edildi")
                    return
                if _is_access_denied(detail2):
                    notify("restart: yetki yok (Admin gerekli)")
                    return
                notify(f"restart: failed (exit={code2})\n{detail2[:250]}")
                return
            if _is_uac_canceled(detail):
                notify("restart: UAC iptal edildi")
                return
            notify(f"restart: failed (exit={code})\n{detail[:250]}")

        run_async("restart", work)

    def show_status(_icon, _item):
        state = _get_service_state()
        health_status, health_ts = _read_health_summary(cfg.state_dir)
        admin = "evet" if _is_admin() else "hayır"

        st_l = (state or "").strip().lower()
        if "not installed" in st_l:
            svc = "kurulu değil"
        elif "access denied" in st_l:
            svc = "yetki yok"
        elif st_l in {"unknown", ""}:
            svc = "bilinmiyor"
        else:
            svc = state

        # Keep it short for Windows balloon limits (title<=64, msg<=256).
        notify(f"Servis: {svc} | Admin: {admin} | Agent: {health_status} | Son: {health_ts}")

    def toggle_tray_autostart(_icon, _item):
        def work():
            if _is_startup_enabled():
                code, msg = _uninstall_startup_shortcut()
                _log_line(f"tray autostart disable: rc={code} msg={msg}")
                if code == 0:
                    notify("oto start: kapatıldı")
                else:
                    notify(f"oto start: hata\n{msg[:200]}")
                return

            code, msg = _install_startup_shortcut()
            _log_line(f"tray autostart enable: rc={code} msg={msg}")
            if code == 0:
                notify("oto start: açıldı (login sonrası)")
            else:
                notify(f"oto start: hata\n{msg[:200]}")

        notify("oto start: uygulanıyor...")
        run_async("tray_autostart", work)

    def toggle_service_autostart(_icon, _item):
        def work():
            # If service not installed, inform.
            state = _get_service_state().lower()
            if "not installed" in state:
                notify("servis oto start: servis kurulu değil")
                return

            if _is_service_autostart_enabled():
                # Set to manual (demand) start.
                code, out = _run_sc(["config", "ITManagerAgent", "start=", "demand"])
                detail = (out or "").strip()
                if code != 0 and _is_access_denied(detail):
                    code, out = _run_sc_elevated(["config", "ITManagerAgent", "start=", "demand"])
                    detail = (out or "").strip()

                _log_line(f"service autostart disable: exit={code} out={detail[:300]!r}")
                if code == 0:
                    notify("servis oto start: kapatıldı")
                else:
                    notify(f"servis oto start: hata (exit={code})\n{detail[:220]}")
                return

            # Enable auto start and recovery (requires admin on most machines)
            code, out = _run_sc(["config", "ITManagerAgent", "start=", "auto"])
            detail = (out or "").strip()
            if code != 0 and _is_access_denied(detail):
                notify("servis oto start: UAC isteniyor...")
                code, out = _run_sc_elevated(["config", "ITManagerAgent", "start=", "auto"])
                detail = (out or "").strip()

            if code != 0:
                if _is_uac_canceled(detail):
                    notify("servis oto start: UAC iptal edildi")
                    return
                notify(f"servis oto start: hata (exit={code})\n{detail[:220]}")
                return

            # Best-effort recovery settings (doesn't hurt if already set)
            # restart service on failures; reset counter never.
            code2, out2 = _run_sc(["failure", "ITManagerAgent", "reset=", "0", "actions=", "restart/5000/restart/5000/restart/5000"])
            detail2 = (out2 or "").strip()
            if code2 != 0 and _is_access_denied(detail2):
                code2, out2 = _run_sc_elevated(["failure", "ITManagerAgent", "reset=", "0", "actions=", "restart/5000/restart/5000/restart/5000"])
                detail2 = (out2 or "").strip()
            _log_line(f"service recovery set: exit={code2} out={detail2[:300]!r}")

            code3, out3 = _run_sc(["failureflag", "ITManagerAgent", "1"])
            detail3 = (out3 or "").strip()
            if code3 != 0 and _is_access_denied(detail3):
                code3, out3 = _run_sc_elevated(["failureflag", "ITManagerAgent", "1"])
                detail3 = (out3 or "").strip()
            _log_line(f"service failureflag set: exit={code3} out={detail3[:300]!r}")

            notify("servis oto start: açıldı")

        notify("servis oto start: uygulanıyor...")
        run_async("service_autostart", work)

    def _confirm_exit_password() -> bool:
        record = _load_exit_password_record()
        if not record:
            try:
                notify("Çıkış parolası ayarlı değil. Panelden 'Çıkış Parolası Güncelle' ile ayarlayın.")
            except Exception:
                pass
            return False

        pw = _prompt_exit_password()
        if pw is None:
            return False
        if _verify_exit_password(pw, record):
            return True

        try:
            notify("Hatalı parola")
        except Exception:
            pass
        return False

    def quit_app(_icon, _item):
        # Important: Showing a modal dialog directly inside a tray menu callback
        # can result in a window that appears but does not accept mouse/keyboard
        # input (the tray menu keeps input capture). Defer the prompt slightly.
        if exit_prompt_in_progress.is_set():
            return
        exit_prompt_in_progress.set()

        def _do_quit():
            try:
                time.sleep(0.25)
                if not _confirm_exit_password():
                    return

                # User requested a full exit; stop the service too so the agent
                # fully shuts down and binaries are not left locked.
                try:
                    notify("çıkış: servis durduruluyor...")
                except Exception:
                    pass
                try:
                    code, out = _run_sc(["stop", "ITManagerAgent"])
                    detail = (out or "").strip()
                    _log_line(f"quit stop non-elevated exit={code} out={detail[:500]!r}")
                    if code != 0 and _is_access_denied(detail):
                        code2, out2 = _run_sc_elevated(["stop", "ITManagerAgent"])
                        detail2 = (out2 or "").strip()
                        _log_line(f"quit stop elevated exit={code2} out={detail2[:500]!r}")
                except Exception as e:
                    _log_line(f"quit stop service failed: {e!r}")

                # Ensure the service isn't left hung in Task Manager. If it does not stop
                # within a reasonable window, force-kill the service process.
                try:
                    if not _wait_service_state_contains("STOPPED", 30):
                        _log_line("quit: stop timeout, force-killing ITManagerAgentService.exe")
                        _taskkill_image_maybe_elevated("ITManagerAgentService.exe")
                        _wait_service_state_contains("STOPPED", 20)
                except Exception as e:
                    _log_line(f"quit wait/kill failed: {e!r}")

                # pystray shutdown can occasionally hang depending on backend/state.
                # Request a clean stop, then force-exit after a short grace period
                # only if the main loop does not return.
                try:
                    quit_requested.set()
                except Exception:
                    pass

                try:
                    icon.stop()
                except Exception:
                    pass
                try:
                    def _force_exit_watchdog():
                        time.sleep(4)
                        if not clean_exit.is_set():
                            _log_line("quit watchdog: forcing exit")
                            os._exit(0)

                    threading.Thread(target=_force_exit_watchdog, daemon=True).start()
                except Exception:
                    pass
            finally:
                # If we did not exit, allow retry.
                if not quit_requested.is_set():
                    exit_prompt_in_progress.clear()

        threading.Thread(target=_do_quit, daemon=True).start()

    def _noop(_icon=None, _item=None):
        return

    icon = pystray.Icon(
        "ITManager",
        icon=ICON_YELLOW,
        title="ITManager Agent",
        menu=pystray.Menu(
            pystray.MenuItem("Dashboard aç", open_dashboard),
            pystray.MenuItem("Cihazlar aç", open_devices),
            pystray.MenuItem("Config aç", open_config),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Status", show_status),
            pystray.MenuItem(
                "Oto start (Windows açılışında)",
                toggle_tray_autostart,
                checked=lambda *_args: _is_startup_enabled(),
            ),
            pystray.MenuItem(
                "Servis oto start (reboot sonrası)",
                toggle_service_autostart,
                checked=lambda *_args: _is_service_autostart_enabled(),
            ),
            pystray.MenuItem("Servisi başlat", start_service, enabled=lambda *_args: _can_start()),
            pystray.MenuItem("Servisi durdur", stop_service, enabled=lambda *_args: _can_stop()),
            pystray.MenuItem("Servisi restart", restart_service, enabled=lambda *_args: _can_restart()),
            pystray.Menu.SEPARATOR,
            # Show version in the right-side column (Windows accelerator area) on a separate line.
            pystray.MenuItem("Agent Update...", agent_update, enabled=lambda *_args: not _get_cached_state()[1]),
            pystray.MenuItem(f"Agent Sürümü\tv{AGENT_VERSION}", _noop, enabled=False),
            pystray.MenuItem("Çıkış", quit_app),
        ),
    )

    def updater():
        while not quit_requested.is_set():
            try:
                state = _get_service_state()
                with ui_lock:
                    ui_state["service_state"] = state
                cached_state, busy, busy_label = _get_cached_state()

                # Icon color logic:
                # - busy (start/stop/restart/install): yellow
                # - running: green
                # - stopped: red
                # - otherwise: yellow
                s = (cached_state or "").upper()
                if busy or ("PENDING" in s):
                    icon.icon = ICON_YELLOW
                elif "RUNNING" in s:
                    icon.icon = ICON_GREEN
                elif "STOPPED" in s:
                    icon.icon = ICON_RED
                else:
                    icon.icon = ICON_YELLOW

                saved = _read_last_saved_at(cfg.state_dir)
                admin = "admin" if _is_admin() else "user"
                # Keep title <= 63 chars to avoid Windows notify title limit.
                short_state = (state or "unknown").replace("\n", " ")
                extra = f" {busy_label}" if busy_label else ""
                icon.title = f"ITManager {admin} {short_state}{extra}"[:63]
                # last timestamp is available via Status menu (and logs), not in title.
            except Exception:
                pass
            time.sleep(3)

    quit_requested = threading.Event()
    clean_exit = threading.Event()

    t = threading.Thread(target=updater, daemon=True)
    t.start()

    # If tray is started manually while the service is stopped, bring it up.
    # This matches field expectation: "tray açıldıysa agent çalışsın".
    def _autostart_on_tray_launch():
        try:
            st = (_get_service_state() or "").upper()
            if "STOPPED" in st:
                _log_line("startup: service stopped, attempting start")
                _run_sc_maybe_elevated(["start", "ITManagerAgent"])
                _wait_service_state_contains("RUNNING", 25)
        except Exception as e:
            _log_line(f"startup autostart failed: {e!r}")

    threading.Thread(target=_autostart_on_tray_launch, daemon=True).start()

    icon.run()
    clean_exit.set()

    try:
        if mutex_handle:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(mutex_handle)
    except Exception:
        pass

    try:
        if instance_lock:
            import msvcrt

            try:
                instance_lock.seek(0)
                msvcrt.locking(instance_lock.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
            try:
                instance_lock.close()
            except Exception:
                pass
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
