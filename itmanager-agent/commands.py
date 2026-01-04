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
from typing import Any, Dict, Tuple


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
    session_ids: list[int] = []
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


def get_supported_command_types() -> list[str]:
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
        }
    )


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


def _inventory() -> Dict[str, Any]:
    import platform

    info: Dict[str, Any] = {
        "ts": datetime.utcnow().isoformat(),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
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

        # Custom-titled message to the logged-on user(s).
        # Title requirement: "Bilgi İşlemden Mesaj" + local date/time.
        now_str = datetime.now().strftime("%d.%m.%Y %H:%M")
        box_title = f"Bilgi İşlemden Mesaj - {now_str}"
        code, out, err = _wts_send_message_to_sessions(box_title, merged, timeout=15)
        if code == 0:
            return code, out, err

        # Fallback: msg.exe (cannot control title bar; will show "Message from ...")
        return _run(f"msg * /TIME:15 {merged}", timeout=15)

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
