from __future__ import annotations

import json
import subprocess
import os
import base64
import hashlib
import hmac
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _wts_send_message_to_sessions(title: str, message: str, timeout: int = 15) -> Tuple[int, str, str]:
    """Send a modal message box to active/connected user sessions.

    This works from a Windows service context and allows a custom title, unlike msg.exe.
    """
    if os.name != "nt":
        return 2, "", "WTSSendMessage is only available on Windows"

    try:
        import ctypes
        from ctypes import wintypes
    except Exception as e:
        return 2, "", f"ctypes unavailable: {e}"

    # WTS constants
    WTS_CURRENT_SERVER_HANDLE = wintypes.HANDLE(0)
    WTSActive = 0
    WTSConnected = 1

    class WTS_SESSION_INFO(ctypes.Structure):
        _fields_ = [
            ("SessionId", wintypes.DWORD),
            ("pWinStationName", wintypes.LPWSTR),
            ("State", wintypes.DWORD),
        ]

    wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    WTSEnumerateSessionsW = wtsapi32.WTSEnumerateSessionsW
    WTSEnumerateSessionsW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(WTS_SESSION_INFO)),
        ctypes.POINTER(wintypes.DWORD),
    ]
    WTSEnumerateSessionsW.restype = wintypes.BOOL

    WTSFreeMemory = wtsapi32.WTSFreeMemory
    WTSFreeMemory.argtypes = [wintypes.LPVOID]
    WTSFreeMemory.restype = None

    WTSSendMessageW = wtsapi32.WTSSendMessageW
    WTSSendMessageW.argtypes = [
        wintypes.HANDLE,  # hServer
        wintypes.DWORD,  # SessionId
        wintypes.LPWSTR,  # pTitle
        wintypes.DWORD,  # TitleLength (bytes)
        wintypes.LPWSTR,  # pMessage
        wintypes.DWORD,  # MessageLength (bytes)
        wintypes.DWORD,  # Style
        wintypes.DWORD,  # Timeout
        ctypes.POINTER(wintypes.DWORD),  # pResponse
        wintypes.BOOL,  # bWait
    ]
    WTSSendMessageW.restype = wintypes.BOOL

    # Fallback helper
    WTSGetActiveConsoleSessionId = kernel32.WTSGetActiveConsoleSessionId
    WTSGetActiveConsoleSessionId.argtypes = []
    WTSGetActiveConsoleSessionId.restype = wintypes.DWORD

    title = str(title or "")
    message = str(message or "")

    # WTSSendMessage expects byte lengths for UTF-16 strings.
    title_len = len(title.encode("utf-16le"))
    msg_len = len(message.encode("utf-16le"))

    # MB_ICONINFORMATION | MB_OK
    style = 0x00000040
    sent = 0
    last_err = ""

    # Enumerate sessions; if it fails, try the active console session.
    p_sessions = ctypes.POINTER(WTS_SESSION_INFO)()
    count = wintypes.DWORD(0)
    ok_enum = WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, ctypes.byref(p_sessions), ctypes.byref(count))
    session_ids: List[int] = []
    try:
        if ok_enum and count.value:
            for i in range(int(count.value)):
                si = p_sessions[i]
                if int(si.State) in (WTSActive, WTSConnected):
                    session_ids.append(int(si.SessionId))
    finally:
        if ok_enum and p_sessions:
            try:
                WTSFreeMemory(p_sessions)
            except Exception:
                pass

    if not session_ids:
        try:
            sid = int(WTSGetActiveConsoleSessionId())
            if sid >= 0:
                session_ids = [sid]
        except Exception:
            session_ids = []

    for sid in session_ids:
        try:
            response = wintypes.DWORD(0)
            ok_send = WTSSendMessageW(
                WTS_CURRENT_SERVER_HANDLE,
                wintypes.DWORD(sid),
                title,
                wintypes.DWORD(title_len),
                message,
                wintypes.DWORD(msg_len),
                wintypes.DWORD(style),
                wintypes.DWORD(int(timeout)),
                ctypes.byref(response),
                wintypes.BOOL(False),
            )
            if ok_send:
                sent += 1
            else:
                err = ctypes.get_last_error()
                last_err = f"WTSSendMessage failed for session {sid} (winerr={err})"
        except Exception as e:
            last_err = str(e)

    if sent:
        return 0, f"sent:{sent}", ""
    return 2, "", last_err or "no active user session"


def _exit_password_path() -> Path:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(base) / "ITManagerAgent" / "exit_password.json"


def _write_exit_password_record(record: Dict[str, Any]) -> None:
    path = _exit_password_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")


def _derive_key_from_device_token(device_token: str) -> bytes:
    # Deterministic 32-byte key derived from device token.
    # Device token must never be logged or persisted.
    return hashlib.sha256(device_token.encode("utf-8")).digest()


def _decrypt_secret_payload(payload: Dict[str, Any]) -> str:
    """Decrypt an encrypted secret from payload.

    Expected payload shape:
      {
        "secret_v": 1,
        "alg": "aes-256-gcm",
        "nonce_b64": "...",
        "ct_b64": "...",
        "_device_token": "..."  # injected in-memory by agent, never sent by server
      }
    """
    secret_v = int(payload.get("secret_v") or 0)
    if secret_v != 1:
        raise ValueError("unsupported secret_v")

    alg = str(payload.get("alg") or "").strip().lower()
    if alg != "aes-256-gcm":
        raise ValueError("unsupported alg")

    device_token = payload.get("_device_token")
    if not device_token:
        raise ValueError("missing device token")

    nonce_b64 = str(payload.get("nonce_b64") or "").strip()
    ct_b64 = str(payload.get("ct_b64") or "").strip()
    if not nonce_b64 or not ct_b64:
        raise ValueError("missing nonce_b64/ct_b64")

    # Import lazily so the agent can still start even if cryptography isn't installed.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as e:
        raise RuntimeError("cryptography is required for secret decryption") from e

    key = _derive_key_from_device_token(str(device_token))
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    pt = AESGCM(key).decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def get_supported_command_types() -> List[str]:
    """Return a stable list of command types supported by this agent build."""
    # Keep this list in sync with execute_command() and agent-side special handlers.
    return sorted(
        {
            "noop",
            "agent_update",
            "restart",
            "reboot",
            "shutdown",
            "poweroff",
            "w32time_resync",
            "time_resync",
            "w32time_restart",
            "w32time_status",
            "time_get",
            "time_set",
            "inventory",
            "get_inventory",
            "notify",
            "message",
            "user_message",
            "cmd_exec",
            "cmd",
            "powershell_exec",
            "powershell",
            "ps_exec",
            "services_list",
            "service_control",
            "processes_list",
            "process_kill",
            "eventlog_recent",
            "task_list",
            "task_run",
            "task_enable",
            "task_disable",
            "exit_password_set",
            "user_password_set",
            "local_user_create",
            "local_user_enable",
            "local_user_disable",
            "rustdesk_deploy",
        }
    )


def _is_safe_net_user_value(s: str) -> bool:
    # Block newline/NUL; allow spaces and locale characters.
    if s is None:
        return False
    if "\x00" in s or "\r" in s or "\n" in s:
        return False
    return True


def _run_net_user(args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(
            ["net", "user", *args],
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        if completed.returncode != 0:
            msg = (completed.stderr or completed.stdout or "net user failed").strip()
            return completed.returncode or 1, "", msg
        out = (completed.stdout or "ok").strip() or "ok"
        return 0, out, ""
    except Exception as e:
        return 1, "", str(e)


def _run_net_localgroup(args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(
            ["net", "localgroup", *args],
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        if completed.returncode != 0:
            msg = (completed.stderr or completed.stdout or "net localgroup failed").strip()
            return completed.returncode or 1, "", msg
        out = (completed.stdout or "ok").strip() or "ok"
        return 0, out, ""
    except Exception as e:
        return 1, "", str(e)


def _truncate(s: str, limit: int = 20000) -> str:
    s = s or ""
    if len(s) <= limit:
        return s
    return s[:limit] + "\n...<truncated>"


def _run(cmd: str, timeout: int = 120) -> Tuple[int, str, str]:
    run_kwargs = {
        "shell": True,
        "capture_output": True,
        "text": True,
        "timeout": timeout,
    }

    # If this code is invoked from a windowed app (or a service context), make sure
    # we do not create a visible console window for shell commands.
    if os.name == "nt":
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0  # SW_HIDE
            run_kwargs["startupinfo"] = si
        except Exception:
            pass
        run_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    p = subprocess.run(cmd, **run_kwargs)
    out = _truncate((p.stdout or "").strip())
    err = _truncate((p.stderr or "").strip())

    # Windows PowerShell 5.1 may emit progress records to stderr as CLIXML even on success.
    # This is noise for our UI; keep real errors intact by only filtering on exit=0.
    try:
        if int(p.returncode) == 0 and err.startswith("#< CLIXML") and "S=\"progress\"" in err:
            err = ""
    except Exception:
        pass

    return int(p.returncode), out, err


def _escape_ps_single_quotes(s: str) -> str:
    # PowerShell single-quoted string escape
    return s.replace("'", "''")


def _run_powershell(ps_script: str, timeout: int = 120) -> Tuple[int, str, str]:
    ps_script = ps_script or ""

    # Prevent CLIXML progress records in stderr (common on Windows PowerShell 5.1).
    ps_script = "$ProgressPreference='SilentlyContinue';\n" + ps_script
    # Use EncodedCommand to avoid quoting/escaping issues.
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    cmd = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}"
    return _run(cmd, timeout=timeout)


def _clamp_int(v: Any, default: int, min_v: int, max_v: int) -> int:
    x = _as_int(v, default)
    if x < min_v:
        return min_v
    if x > max_v:
        return max_v
    return x


def _sanitize_notify_text(s: str) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ")
    # Avoid cmd metacharacters since this is user-facing.
    s = re.sub(r"[&|<>^\"]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Keep it short to avoid msg.exe limitations.
    return s[:240]


def _as_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _payload_str(payload: Dict[str, Any], key: str) -> str:
    v = payload.get(key)
    if v is None:
        return ""
    return str(v)


def _parse_iso_or_date_time(payload: Dict[str, Any]) -> Tuple[int, str, str]:
    iso = payload.get("iso")
    if not iso:
        d = payload.get("date")
        t = payload.get("time")
        if d and t:
            iso = f"{d}T{t}"

    if not iso:
        return 2, "", "missing payload.iso (or payload.date + payload.time)"

    try:
        # Supports offsets like 2026-01-01T12:34:56+03:00
        dt = datetime.fromisoformat(str(iso))
        if dt.tzinfo is not None:
            dt = dt.astimezone()  # convert to local time
            dt = dt.replace(tzinfo=None)
        return 0, dt.strftime("%Y-%m-%d %H:%M:%S"), ""
    except Exception:
        return 2, "", f"invalid datetime format: {iso}"


def _get_installed_software() -> Dict[str, Any]:
    """Detect specific installed software from Windows registry."""
    software: Dict[str, Any] = {}
    
    # Registry paths for installed programs (both 32-bit and 64-bit)
    reg_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ]
    
    try:
        import winreg
        
        all_programs = []
        for reg_path in reg_paths:
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                try:
                    key = winreg.OpenKey(hive, reg_path)
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                version = ""
                                try:
                                    version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                                except Exception:
                                    pass
                                all_programs.append({"name": name, "version": version})
                            except Exception:
                                pass
                            winreg.CloseKey(subkey)
                        except Exception:
                            pass
                    winreg.CloseKey(key)
                except Exception:
                    pass
        
        # Detect Microsoft Office
        office_patterns = [
            ("Microsoft Office Professional", "Office Pro"),
            ("Microsoft Office Standard", "Office Std"),
            ("Microsoft Office Home", "Office Home"),
            ("Microsoft 365", "Microsoft 365"),
            ("Microsoft Office 365", "Office 365"),
            ("Microsoft Office", "Office"),
        ]
        for prog in all_programs:
            name = prog.get("name", "")
            for pattern, label in office_patterns:
                if pattern.lower() in name.lower():
                    # Extract year/version from name
                    import re
                    year_match = re.search(r'(20\d{2})', name)
                    year = year_match.group(1) if year_match else ""
                    edition = ""
                    if "professional plus" in name.lower():
                        edition = "Pro Plus"
                    elif "professional" in name.lower():
                        edition = "Pro"
                    elif "standard" in name.lower():
                        edition = "Std"
                    elif "home" in name.lower() and "business" in name.lower():
                        edition = "Home & Business"
                    elif "home" in name.lower() and "student" in name.lower():
                        edition = "Home & Student"
                    elif "home" in name.lower():
                        edition = "Home"
                    
                    if "365" in name:
                        software["office"] = f"Microsoft 365 {edition}".strip()
                    elif year:
                        software["office"] = f"Office {year} {edition}".strip()
                    else:
                        software["office"] = f"{label} {prog.get('version', '')}".strip()
                    break
            if "office" in software:
                break
        
        # Detect Radmin Server
        for prog in all_programs:
            name = prog.get("name", "")
            if "radmin" in name.lower() and "server" in name.lower():
                software["radmin"] = f"Radmin Server {prog.get('version', '')}".strip()
                break
        
        # Detect RustDesk
        for prog in all_programs:
            name = prog.get("name", "")
            if "rustdesk" in name.lower():
                software["rustdesk"] = f"RustDesk {prog.get('version', '')}".strip()
                break
        
        # Detect Adobe Photoshop
        for prog in all_programs:
            name = prog.get("name", "")
            if "photoshop" in name.lower() and "adobe" in name.lower():
                # Extract version like CC 2024, CS6, etc.
                import re
                ver_match = re.search(r'(CC\s*\d{4}|CS\d+|\d{4})', name, re.I)
                ver = ver_match.group(1) if ver_match else prog.get('version', '')
                software["photoshop"] = f"Photoshop {ver}".strip()
                break
        
        # Detect AutoCAD
        for prog in all_programs:
            name = prog.get("name", "")
            if "autocad" in name.lower():
                import re
                year_match = re.search(r'(20\d{2})', name)
                year = year_match.group(1) if year_match else prog.get('version', '')
                software["autocad"] = f"AutoCAD {year}".strip()
                break
        
        # Detect SQL Server
        for prog in all_programs:
            name = prog.get("name", "")
            if "sql server" in name.lower() and "microsoft" in name.lower():
                import re
                year_match = re.search(r'(20\d{2})', name)
                year = year_match.group(1) if year_match else ""
                edition = ""
                if "express" in name.lower():
                    edition = "Express"
                elif "standard" in name.lower():
                    edition = "Std"
                elif "enterprise" in name.lower():
                    edition = "Enterprise"
                elif "developer" in name.lower():
                    edition = "Developer"
                software["sql_server"] = f"SQL Server {year} {edition}".strip()
                break
        
        # Detect ESET (Antivirus, Endpoint Security, NOD32, etc.)
        for prog in all_programs:
            name = prog.get("name", "")
            if "eset" in name.lower():
                version = prog.get("version", "")
                # Clean up the name for display
                if "endpoint security" in name.lower():
                    software["eset"] = f"ESET Endpoint Security {version}".strip()
                elif "nod32" in name.lower():
                    software["eset"] = f"ESET NOD32 {version}".strip()
                elif "smart security" in name.lower():
                    software["eset"] = f"ESET Smart Security {version}".strip()
                elif "internet security" in name.lower():
                    software["eset"] = f"ESET Internet Security {version}".strip()
                else:
                    software["eset"] = f"ESET {version}".strip()
                break
                
    except Exception:
        pass
    
    return software


def _get_cpu_info() -> Dict[str, Any]:
    """
    Windows'tan detaylı CPU bilgisi al (WMI veya Registry).
    Returns: {"name": "...", "max_clock_mhz": 3400, "cores": 8, "threads": 16}
    """
    import platform
    cpu_info: Dict[str, Any] = {
        "name": platform.processor(),
        "max_clock_mhz": 0,
        "cores": 0,
        "threads": 0
    }
    
    if platform.system() != "Windows":
        return cpu_info
    
    try:
        import winreg
        # Registry'den CPU bilgisi al
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        )
        try:
            name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            cpu_info["name"] = name.strip()
        except:
            pass
        try:
            mhz, _ = winreg.QueryValueEx(key, "~MHz")
            cpu_info["max_clock_mhz"] = int(mhz)
        except:
            pass
        winreg.CloseKey(key)
    except Exception:
        pass
    
    # Core/Thread sayısı psutil'den
    try:
        import psutil
        cpu_info["cores"] = psutil.cpu_count(logical=False) or 0
        cpu_info["threads"] = psutil.cpu_count(logical=True) or 0
    except:
        pass
    
    return cpu_info


def _get_system_info() -> Dict[str, Any]:
    """wmic csproduct ile Marka, Model, Seri No bilgisi al."""
    result: Dict[str, Any] = {
        "vendor": "",
        "model": "",
        "serial": ""
    }
    
    if os.name != "nt":
        return result
    
    # wmic csproduct get name, vendor, identifyingnumber
    try:
        completed = subprocess.run(
            ["wmic", "csproduct", "get", "name,vendor,identifyingnumber", "/format:csv"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode == 0:
            lines = [l.strip() for l in (completed.stdout or "").splitlines() if l.strip()]
            # CSV format: Node,IdentifyingNumber,Name,Vendor
            for line in lines:
                if line.lower().startswith("node,") or not line:
                    continue
                parts = line.split(",")
                if len(parts) >= 4:
                    result["serial"] = parts[1].strip()
                    result["model"] = parts[2].strip()
                    result["vendor"] = parts[3].strip()
                    break
    except Exception:
        pass
    
    # Fallback: PowerShell
    if not result["vendor"] and not result["model"]:
        try:
            ps_cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_ComputerSystemProduct | Select-Object -Property Vendor,Name,IdentifyingNumber | ConvertTo-Json"
            ]
            completed = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=15)
            if completed.returncode == 0:
                import json
                data = json.loads(completed.stdout.strip())
                result["vendor"] = data.get("Vendor", "") or ""
                result["model"] = data.get("Name", "") or ""
                result["serial"] = data.get("IdentifyingNumber", "") or ""
        except Exception:
            pass
    
    return result


def _get_cpu_temperature() -> float:
    """CPU sıcaklığını derece cinsinden döndür (bulunamazsa 0)."""
    if os.name != "nt":
        return 0.0
    
    # Method 1: WMI MSAcpi_ThermalZoneTemperature (requires admin, not always available)
    try:
        ps_cmd = [
            "powershell", "-NoProfile", "-Command",
            "(Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue | Select-Object -First 1).CurrentTemperature"
        ]
        completed = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=10)
        if completed.returncode == 0:
            temp_str = (completed.stdout or "").strip()
            if temp_str and temp_str.isdigit():
                # WMI returns temperature in tenths of Kelvin
                kelvin_tenths = int(temp_str)
                celsius = (kelvin_tenths / 10.0) - 273.15
                if 0 < celsius < 120:  # sanity check
                    return round(celsius, 1)
    except Exception:
        pass
    
    # Method 2: Open Hardware Monitor / LibreHardwareMonitor WMI (if installed)
    try:
        ps_cmd = [
            "powershell", "-NoProfile", "-Command",
            "(Get-CimInstance -Namespace root/OpenHardwareMonitor -ClassName Sensor -ErrorAction SilentlyContinue | Where-Object {$_.SensorType -eq 'Temperature' -and $_.Name -like '*CPU*'} | Select-Object -First 1).Value"
        ]
        completed = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=10)
        if completed.returncode == 0:
            temp_str = (completed.stdout or "").strip()
            if temp_str:
                try:
                    celsius = float(temp_str)
                    if 0 < celsius < 120:
                        return round(celsius, 1)
                except:
                    pass
    except Exception:
        pass
    
    return 0.0


def _get_bios_serial() -> str:
    """Kasa/BIOS seri numarasını döndürür (Windows)."""
    if os.name != "nt":
        return ""

    # 1) Öncelikle WMIC ile dene (kullanıcının verdiği komut)
    try:
        completed = subprocess.run(
            ["wmic", "bios", "get", "serialnumber"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if completed.returncode == 0:
            output = (completed.stdout or "") + "\n" + (completed.stderr or "")
            for line in output.splitlines():
                s = (line or "").strip()
                if not s:
                    continue
                if s.lower().startswith("serialnumber"):
                    continue
                return s
    except Exception:
        pass

    # 2) WMIC yoksa PowerShell CIM/WMI ile dene
    try:
        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Try { (Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SerialNumber) } Catch { (Get-WmiObject Win32_BIOS).SerialNumber }",
        ]
        completed = subprocess.run(
            ps_cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode == 0:
            s = (completed.stdout or "").strip()
            if s:
                return s
    except Exception:
        pass

    return ""


def _inventory() -> Dict[str, Any]:
    import platform

    # Get detailed CPU info
    cpu_info = _get_cpu_info()
    bios_serial = _get_bios_serial()
    system_info = _get_system_info()
    cpu_temp = _get_cpu_temperature()
    
    info: Dict[str, Any] = {
        "ts": datetime.utcnow().isoformat(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_name": cpu_info.get("name", ""),
        "cpu_clock_mhz": cpu_info.get("max_clock_mhz", 0),
        "cpu_cores": cpu_info.get("cores", 0),
        "cpu_threads": cpu_info.get("threads", 0),
        "cpu_temp": cpu_temp,
        "bios_serial": bios_serial,
        "system_vendor": system_info.get("vendor", ""),
        "system_model": system_info.get("model", ""),
        "system_serial": system_info.get("serial", ""),
        "python": platform.python_version(),
    }

    try:
        import psutil

        vm = psutil.virtual_memory()
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append(
                    {
                        "device": part.device,
                        "mount": part.mountpoint,
                        "fstype": part.fstype,
                        "total": int(usage.total),
                        "used": int(usage.used),
                        "free": int(usage.free),
                    }
                )
            except Exception:
                continue

        info.update(
            {
                "ram_total": int(vm.total),
                "ram_available": int(vm.available),
                "cpu_count": psutil.cpu_count(logical=True),
                "disks": disks,
            }
        )
    except Exception:
        pass

    return info


def execute_command(cmd_type: str, payload: Dict[str, Any]) -> Tuple[int, str, str]:
    cmd_type = (cmd_type or "").strip().lower()
    payload = payload or {}

    if cmd_type in ("", "noop"):
        return 0, "ok", ""

    if cmd_type in ("exit_password_set",):
        try:
            algo = str(payload.get("algo") or "").strip().lower()
            salt_b64 = str(payload.get("salt_b64") or "").strip()
            hash_b64 = str(payload.get("hash_b64") or "").strip()
            iters = int(payload.get("iters") or 0)

            if algo != "pbkdf2_sha256":
                return 2, "", f"unsupported algo: {algo or '-'}"
            if not salt_b64 or not hash_b64 or iters <= 0:
                return 2, "", "missing salt_b64/hash_b64/iters"

            # Validate payload shape early (base64 decode)
            base64.b64decode(salt_b64)
            base64.b64decode(hash_b64)

            _write_exit_password_record(
                {
                    "algo": "pbkdf2_sha256",
                    "salt_b64": salt_b64,
                    "hash_b64": hash_b64,
                    "iters": iters,
                }
            )
            return 0, "exit password updated", ""
        except Exception as e:
            return 1, "", f"exit password update failed: {e}"

    if cmd_type in ("restart", "reboot"):
        return _run("shutdown /r /t 0", timeout=10)

    if cmd_type in ("shutdown", "poweroff"):
        return _run("shutdown /s /t 0", timeout=10)

    if cmd_type in ("w32time_resync", "time_resync"):
        # Requires admin; will fail otherwise.
        return _run("w32tm /resync /force", timeout=30)

    if cmd_type in ("w32time_restart",):
        return _run("sc stop w32time & sc start w32time", timeout=60)

    if cmd_type in ("w32time_status",):
        return _run("w32tm /query /status", timeout=30)

    if cmd_type in ("time_get",):
        ps = """
$dt = Get-Date
$c = [System.Globalization.CultureInfo]::GetCultureInfo('tr-TR')
$pretty = $dt.ToString('d MMMM yyyy dddd HH:mm:ss', $c)
$iso = $dt.ToString('o')
$pretty
\"ISO: $iso\"
""".strip()
        return _run_powershell(ps, timeout=15)

    if cmd_type in ("time_set",):
        code, local_str, err = _parse_iso_or_date_time(payload)
        if code != 0:
            return code, "", err

        local_str = _escape_ps_single_quotes(local_str)
        ps = f"""
$c = [System.Globalization.CultureInfo]::GetCultureInfo('tr-TR')
Set-Date -Date '{local_str}'
$dt = Get-Date
$pretty = $dt.ToString('d MMMM yyyy dddd HH:mm:ss', $c)
$iso = $dt.ToString('o')
$pretty
\"ISO: $iso\"
""".strip()
        return _run_powershell(ps, timeout=30)

    if cmd_type in ("inventory", "get_inventory"):
        inv = _inventory()
        return 0, json.dumps(inv, ensure_ascii=False, indent=2), ""

    if cmd_type in ("notify", "message", "user_message"):
        text = _payload_str(payload, "text").strip() or _payload_str(payload, "message").strip()
        title = _payload_str(payload, "title").strip()

        if title and text:
            merged = f"{title}: {text}"
        else:
            merged = title or text

        merged = _sanitize_notify_text(merged)
        if not merged:
            return 2, "", "missing payload.text (or payload.message)"

        timeout_seconds = _clamp_int(
            payload.get("timeout_seconds", payload.get("timeout")),
            default=15,
            min_v=5,
            max_v=600,
        )

        # Custom-titled message to the logged-on user(s).
        # Title requirement: "Bilgi İşlemden Mesaj" + local date/time.
        now_str = datetime.now().strftime("%d.%m.%Y %H:%M")
        box_title = f"Bilgi İşlemden Mesaj - {now_str}"
        code, out, err = _wts_send_message_to_sessions(box_title, merged, timeout=timeout_seconds)
        if code == 0:
            return code, out, err

        # Fallback: msg.exe (cannot control title bar; will show "Message from ...")
        return _run(f"msg * /TIME:{timeout_seconds} {merged}", timeout=timeout_seconds + 5)

    if cmd_type in ("user_password_set",):
        username = _payload_str(payload, "username").strip()
        if not username:
            return 2, "", "missing payload.username"

        try:
            new_password = _decrypt_secret_payload(payload)
        except Exception as e:
            return 2, "", f"secret decrypt failed: {e}"

        # Uses built-in net.exe; requires admin rights.
        try:
            completed = subprocess.run(
                ["net", "user", username, new_password],
                capture_output=True,
                text=True,
                shell=False,
                timeout=60,
            )
            if completed.returncode != 0:
                msg = (completed.stderr or completed.stdout or "net user failed").strip()
                return completed.returncode or 1, "", msg
            return 0, "ok", ""
        except Exception as e:
            return 1, "", str(e)

    if cmd_type in ("local_user_create",):
        if os.name != "nt":
            return 2, "", "local user create is only available on Windows"

        username = _payload_str(payload, "username").strip()
        if not username:
            return 2, "", "missing payload.username"
        if not _is_safe_net_user_value(username):
            return 2, "", "invalid payload.username"

        try:
            password = _decrypt_secret_payload(payload)
        except Exception as e:
            return 2, "", f"secret decrypt failed: {e}"
        if not password:
            return 2, "", "missing password"
        if not _is_safe_net_user_value(password):
            return 2, "", "invalid password"

                # Prefer PowerShell LocalAccounts when available (handles special chars better).
                u_esc = _escape_ps_single_quotes(username)
                p_esc = _escape_ps_single_quotes(password)

                ps_create = f"""
$ErrorActionPreference='Stop'
$u = '{u_esc}'
$p = '{p_esc}'

if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {{
    $existing = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
    if ($existing) {{ throw 'user already exists' }}
}}

if (Get-Command New-LocalUser -ErrorAction SilentlyContinue) {{
    $sec = ConvertTo-SecureString $p -AsPlainText -Force
    New-LocalUser -Name $u -Password $sec -PasswordNeverExpires:$true -UserMayNotChangePassword:$true | Out-Null
}} else {{
    cmd /c "net user \"$u\" \"$p\" /add" | Out-Null
    if ($LASTEXITCODE -ne 0) {{ throw "net user /add failed (exit=$LASTEXITCODE)" }}
}}

'ok'
""".strip()

                code, out, err = _run_powershell(ps_create, timeout=90)
                if code != 0:
                        # Fallback: net.exe (may not support spaces in password)
                        code2, out2, err2 = _run_net_user([username, password, "/add"], timeout=60)
                        if code2 != 0:
                                return code2, out2, err2 or err

                # Add to local Administrators group. Resolve group name via SID to support localized Windows.
                ps_add_admin = f"""
$ErrorActionPreference='Stop'
$u = '{u_esc}'

$groupObj = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -ErrorAction SilentlyContinue
if ($groupObj -and $groupObj.Name) {{
    $group = $groupObj.Name
}} else {{
    $admin = ([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544').Translate([System.Security.Principal.NTAccount]).Value
    $group = $admin.Split('\\')[-1]
}}

cmd /c "net localgroup \"$group\" \"$u\" /add" | Out-Null
if ($LASTEXITCODE -ne 0) {{ throw "net localgroup failed (group=$group, exit=$LASTEXITCODE)" }}

'ok'
""".strip()

                code3, out3, err3 = _run_powershell(ps_add_admin, timeout=60)
                if code3 == 0:
                        return 0, "ok", ""

                # Try common group names (English/Turkish) as a last resort.
                last_err = err3
                for group in ("Administrators", "Y\u00f6neticiler"):
                        c2, _, e2 = _run_net_localgroup([group, username, "/add"], timeout=60)
                        if c2 == 0:
                                return 0, "ok", ""
                        last_err = last_err or e2

                # User may have been created but group add failed; return error so panel doesn't show a false success.
                return 2, "", f"created but admin group add failed: {last_err or 'unknown error'}"

    if cmd_type in ("local_user_enable", "local_user_disable"):
        if os.name != "nt":
            return 2, "", "local user enable/disable is only available on Windows"

        username = _payload_str(payload, "username").strip()
        if not username:
            return 2, "", "missing payload.username"
        if not _is_safe_net_user_value(username):
            return 2, "", "invalid payload.username"

        u_esc = _escape_ps_single_quotes(username)
        action = "Enable" if cmd_type == "local_user_enable" else "Disable"
        active = "yes" if cmd_type == "local_user_enable" else "no"
        ps = f"""
$ErrorActionPreference='Stop'
$u = '{u_esc}'
if (Get-Command {action}-LocalUser -ErrorAction SilentlyContinue) {{
  {action}-LocalUser -Name $u -ErrorAction Stop
}} else {{
  cmd /c "net user \"$u\" /active:{active}" | Out-String | Out-Null
}}
'ok'
""".strip()
        code, out, err = _run_powershell(ps, timeout=60)
        if code == 0:
            return 0, out or "ok", ""
        return _run_net_user([username, f"/active:{active}"], timeout=60)

    if cmd_type in ("cmd_exec", "cmd"):
        command = _payload_str(payload, "command").strip()
        if not command:
            return 2, "", "missing payload.command"

        timeout = _clamp_int(payload.get("timeout"), default=120, min_v=5, max_v=1800)
        return _run(f"cmd.exe /c {command}", timeout=timeout)

    if cmd_type in ("powershell_exec", "powershell", "ps_exec"):
        script = _payload_str(payload, "script")
        if not script:
            # allow alias: payload.command
            script = _payload_str(payload, "command")
        script = (script or "").strip()
        if not script:
            return 2, "", "missing payload.script"

        timeout = _clamp_int(payload.get("timeout"), default=120, min_v=5, max_v=1800)
        return _run_powershell(script, timeout=timeout)

    # ---- Windows feature modules (core) ----

    if cmd_type in ("services_list",):
        # Compatibility: some field machines still run Windows PowerShell 2.0 where
        # Get-CimInstance is not available. Fall back to Get-WmiObject.
        ps = (
            "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; "
            "try { "
            "  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) { $svcs = Get-CimInstance Win32_Service } "
            "  else { $svcs = Get-WmiObject Win32_Service } "
            "  $svcs | Select-Object Name,DisplayName,State,StartMode | Sort-Object DisplayName | ConvertTo-Json -Depth 3 "
            "} catch { Write-Error ($_ | Out-String); exit 1 }"
        )
        return _run_powershell(ps, timeout=90)

    if cmd_type in ("service_control",):
        name = _payload_str(payload, "name").strip()
        action = _payload_str(payload, "action").strip().lower()
        if not name:
            return 2, "", "missing payload.name"
        if action not in ("start", "stop", "restart"):
            return 2, "", "invalid payload.action (start|stop|restart)"

        name_escaped = _escape_ps_single_quotes(name)
        if action == "start":
            ps = f"Start-Service -Name '{name_escaped}' -ErrorAction Stop; Get-Service -Name '{name_escaped}' | Select-Object Name,Status | ConvertTo-Json -Depth 2"
        elif action == "stop":
            ps = f"Stop-Service -Name '{name_escaped}' -Force -ErrorAction Stop; Get-Service -Name '{name_escaped}' | Select-Object Name,Status | ConvertTo-Json -Depth 2"
        else:
            ps = f"Restart-Service -Name '{name_escaped}' -Force -ErrorAction Stop; Get-Service -Name '{name_escaped}' | Select-Object Name,Status | ConvertTo-Json -Depth 2"
        return _run_powershell(ps, timeout=90)

    if cmd_type in ("processes_list",):
        top_n = _as_int(payload.get("top"), 60)
        if top_n <= 0:
            top_n = 60
        if top_n > 300:
            top_n = 300
        ps = (
            "$procs = Get-Process | Select-Object Id,ProcessName,CPU,WS,PM,StartTime -ErrorAction SilentlyContinue; "
            "$procs | Sort-Object -Property CPU -Descending | Select-Object -First "
            f"{top_n} | "
            "ForEach-Object { $_ | Add-Member -NotePropertyName WorkingSetMB -NotePropertyValue ([math]::Round($_.WS/1MB,1)) -Force; $_ } | "
            "Select-Object Id,ProcessName,CPU,WorkingSetMB,PM,StartTime | ConvertTo-Json -Depth 3"
        )
        return _run_powershell(ps, timeout=60)

    if cmd_type in ("process_kill",):
        pid = payload.get("pid")
        name = _payload_str(payload, "name").strip()
        if pid is None and not name:
            return 2, "", "missing payload.pid or payload.name"

        if pid is not None:
            pid_i = _as_int(pid, -1)
            if pid_i <= 0:
                return 2, "", "invalid payload.pid"
            ps = f"Stop-Process -Id {pid_i} -Force -ErrorAction Stop; 'ok'"
            return _run_powershell(ps, timeout=30)

        name_escaped = _escape_ps_single_quotes(name)
        ps = f"Get-Process -Name '{name_escaped}' -ErrorAction Stop | Stop-Process -Force -ErrorAction Stop; 'ok'"
        return _run_powershell(ps, timeout=30)

    if cmd_type in ("eventlog_recent",):
        log_name = _payload_str(payload, "log").strip() or "System"
        hours = _as_int(payload.get("hours"), 24)
        if hours <= 0:
            hours = 24
        if hours > 24 * 30:
            hours = 24 * 30
        max_events = _as_int(payload.get("max"), 200)
        if max_events <= 0:
            max_events = 200
        if max_events > 2000:
            max_events = 2000

        log_escaped = _escape_ps_single_quotes(log_name)
        # Compatibility: prefer Get-WinEvent; fall back to Get-EventLog on older systems.
        # Normalize property names to match server UI columns.
        ps = (
            "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; "
            f"$start=(Get-Date).AddHours(-{hours}); "
            "try { "
            "  if (Get-Command Get-WinEvent -ErrorAction SilentlyContinue) { "
            f"    Get-WinEvent -FilterHashtable @{{LogName='{log_escaped}'; StartTime=$start}} -MaxEvents {max_events} | "
            "      Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message "
            "  } else { "
            f"    Get-EventLog -LogName '{log_escaped}' -After $start -Newest {max_events} | "
            "      Select-Object @{n='TimeCreated';e={$_.TimeGenerated}}, @{n='Id';e={$_.EventID}}, "
            "        @{n='LevelDisplayName';e={$_.EntryType}}, @{n='ProviderName';e={$_.Source}}, Message "
            "  } | ConvertTo-Json -Depth 4 "
            "} catch { Write-Error ($_ | Out-String); exit 1 }"
        )
        return _run_powershell(ps, timeout=120)

    if cmd_type in ("task_list",):
        ps = (
            "Get-ScheduledTask | "
            "Select-Object TaskName,TaskPath,State | "
            "Sort-Object TaskPath,TaskName | "
            "ConvertTo-Json -Depth 3"
        )
        return _run_powershell(ps, timeout=90)

    if cmd_type in ("task_run",):
        tn = _payload_str(payload, "tn").strip()
        if not tn:
            return 2, "", "missing payload.tn (full task name, e.g. \\\\Microsoft\\Windows\\Defrag\\ScheduledDefrag)"
        tn_escaped = tn.replace('"', '""')
        # schtasks needs the full task name (with path)
        return _run(f'schtasks /Run /TN "{tn_escaped}"', timeout=30)

    return 3, "", f"unknown command type: {cmd_type}"
