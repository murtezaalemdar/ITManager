@echo off
setlocal

REM One-click installer/updater for ITManager Agent
REM Runs setup.ps1 with ExecutionPolicy Bypass and requests elevation when needed.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*

endlocal
