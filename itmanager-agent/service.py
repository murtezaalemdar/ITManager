from __future__ import annotations

import sys
import threading
import traceback
import os
from datetime import datetime
from typing import Optional
import servicemanager
import win32event
import win32service
import win32serviceutil
import pywintypes
import ctypes
from pathlib import Path


def _runtime_dir() -> Path:
    # If frozen by PyInstaller, config should live next to the EXE.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _programdata_config_path() -> Path:
    program_data = os.environ.get("PROGRAMDATA") or os.environ.get("ALLUSERSPROFILE") or r"C:\ProgramData"
    return Path(program_data) / "ITManagerAgent" / "config.json"


def _ensure_programdata_config_from_runtime() -> Path:
    """Ensure ProgramData config exists by copying from runtime dir if needed."""
    pd = _programdata_config_path()
    if pd.exists():
        return pd
    try:
        src = _runtime_dir() / "config.json"
        if src.exists():
            pd.parent.mkdir(parents=True, exist_ok=True)
            pd.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass
    return pd


def _boot_log(msg: str) -> None:
    try:
        program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        path = Path(program_data) / "ITManagerAgent" / "service_boot.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with path.open("a", encoding="utf-8", newline="") as f:
            f.write(f"{ts} {msg}\n")
    except Exception:
        pass


_boot_log(f"imported service.py pid={os.getpid()} exe={sys.executable} argv={' '.join(sys.argv)}")


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _msgbox(title: str, text: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(None, text, title, 0x00000040)  # MB_ICONINFORMATION
    except Exception:
        pass


class StopFlag:
    """Thread-safe stop flag for graceful shutdown."""
    def __init__(self) -> None:
        self._evt = threading.Event()

    def set(self) -> None:
        self._evt.set()

    def is_set(self) -> bool:
        return self._evt.is_set()


class ITManagerAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "ITManagerAgent"
    _svc_display_name_ = "ITManager Agent"
    _svc_description_ = "ITManager server ile haberleşen Windows agent (register/heartbeat/command)."

    def __init__(self, args):
        super().__init__(args)
        _boot_log("__init__")
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop_flag = StopFlag()
        self._worker: Optional[threading.Thread] = None
        self._worker_exc: Optional[str] = None

    def _run_agent_worker(self) -> None:
        try:
            # Defer importing agent modules until worker thread.
            # If a build accidentally misses bundled modules, the service will still
            # connect to SCM (avoids 1053) and we will log the real import error.
            from agent import ITManagerAgent, load_config

            # Config path: prefer ProgramData (stable across upgrades), fallback to EXE dir.
            pd = _ensure_programdata_config_from_runtime()
            config_path = pd if pd.exists() else (_runtime_dir() / "config.json")
            _boot_log(f"worker start config={config_path}")
            servicemanager.LogInfoMsg(f"ITManagerAgent worker starting. config={config_path}")
            cfg = load_config(config_path)
            agent = ITManagerAgent(cfg)
            agent.run_forever(stop_flag=self._stop_flag)
        except Exception:
            self._worker_exc = traceback.format_exc()
            _boot_log("worker crashed\n" + self._worker_exc)
            try:
                servicemanager.LogErrorMsg("ITManagerAgent worker crashed:\n" + self._worker_exc)
            except Exception:
                pass
        finally:
            _boot_log("worker exit")
            # Ensure service exits if worker ends unexpectedly.
            try:
                self._stop_flag.set()
            except Exception:
                pass
            try:
                win32event.SetEvent(self.hWaitStop)
            except Exception:
                pass

    def SvcStop(self):
        _boot_log("SvcStop")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_flag.set()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        _boot_log("SvcDoRun entry")
        # Avoid 1053: promptly report service running, do heavy work in a worker thread.
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )

        try:
            self._worker = threading.Thread(target=self._run_agent_worker, daemon=True)
            self._worker.start()
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            _boot_log("reported SERVICE_RUNNING")

            # Wait until stop requested or worker exits.
            while True:
                rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                if self._worker is not None and not self._worker.is_alive():
                    break
        except Exception as e:
            _boot_log(f"SvcDoRun exception: {e!r}")
            servicemanager.LogErrorMsg(f"ITManagerAgent crashed: {e!r}")
            raise

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )


if __name__ == "__main__":
    # When installed as a service executable, the Service Control Manager starts the
    # binary with no extra arguments. In that case we must start the service control
    # dispatcher; otherwise HandleCommandLine() prints usage and exits (1053).
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        _boot_log("__main__ no-args")

        # 1) Normal path: started by SCM -> dispatcher works.
        try:
            _boot_log("starting service dispatcher")
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(ITManagerAgentService)
            servicemanager.StartServiceCtrlDispatcher()
            sys.exit(0)
        except pywintypes.error as e:
            # 1063: The service process could not connect to the service controller.
            if getattr(e, "winerror", None) != 1063:
                _boot_log("dispatcher failed (pywintypes.error)\n" + traceback.format_exc())
                raise
        except Exception:
            _boot_log("dispatcher failed (generic)\n" + traceback.format_exc())
            raise

        # 2) Interactive double-click path: dispatcher fails with 1063.
        _boot_log("interactive launch detected; attempting StartService")
        try:
            win32serviceutil.StartService(ITManagerAgentService._svc_name_)
            _msgbox("ITManager Agent", "Servis başlatılıyor: ITManagerAgent")
        except pywintypes.error as e:
            # 1060: The specified service does not exist as an installed service.
            if getattr(e, "winerror", None) == 1060:
                _msgbox(
                    "ITManager Agent",
                    "Servis kurulu değil. Kurulum için 'install_service_admin.ps1' çalıştırın.",
                )
            elif getattr(e, "winerror", None) == 5 or not _is_admin():
                _msgbox(
                    "ITManager Agent",
                    "Servisi başlatmak için Yönetici yetkisi gerekir. Sağ tık → Yönetici olarak çalıştır veya 'install_service_admin.ps1' kullanın.",
                )
            else:
                _msgbox("ITManager Agent", f"Servis başlatılamadı. Hata: {e}")
        except Exception as e:
            _msgbox("ITManager Agent", f"Servis başlatılamadı. Hata: {e!r}")
    else:
        win32serviceutil.HandleCommandLine(ITManagerAgentService)
