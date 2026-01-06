@echo off
setlocal

REM One-click installer/updater for ITManager Agent
REM Runs setup.ps1 with ExecutionPolicy Bypass and requests elevation when needed.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
set "EC=%ERRORLEVEL%"

echo.
echo [INFO] Servis durumu:
sc.exe query ITManagerAgent

if not "%EC%"=="0" (
	echo.
	echo [ERROR] Kurulum/Update hata ile bitti (code=%EC%).
	echo [HINT] Loglar: C:\ProgramData\ITManagerAgent\agent.log ve update_apply.log
	pause
	exit /b %EC%
) else (
	echo.
	echo [OK] Kurulum/Update tamamlandi.
	timeout /t 5 >nul
)

endlocal
