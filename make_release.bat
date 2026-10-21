@echo off
rem ===========================================================================
rem  WeakNetTool release builder
rem
rem  Usage:  make_release.bat
rem
rem  Builds Release and packages release\WeakNetTool-<version>-win64\ plus the
rem  matching .zip. The real work is in make_release.ps1 (ASCII-safe; all paths
rem  are derived from the script location, which matters because this project
rem  may live under a non-ASCII path).
rem
rem  NOTE: this file is intentionally ASCII-only.
rem ===========================================================================
setlocal
set "ROOT=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%make_release.ps1"
if errorlevel 1 (
    echo.
    echo [ERROR] release packaging failed.
    exit /b 1
)
endlocal
