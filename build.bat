@echo off
setlocal enabledelayedexpansion

rem ===========================================================================
rem  WeakNetTool build script (MSVC x64 + CMake + Ninja)
rem
rem  Usage:  build.bat            -> Release build
rem          build.bat Debug      -> Debug build
rem          set WINDIVERT_ROOT=D:\sdk\WinDivert-2.2.2-A to use an external SDK
rem
rem  NOTE: this file is intentionally ASCII-only. cmd.exe parses .bat files
rem        using the active code page, so non-ASCII comments can break parsing.
rem        Chinese documentation lives in README.md instead.
rem
rem  What it does:
rem    1) locates Visual Studio through vswhere
rem    2) imports the x64 build environment (vcvars64.bat)
rem    3) configures + builds with CMake/Ninja
rem    4) prints the resulting executable path
rem ===========================================================================

set "BUILD_TYPE=%~1"
if "%BUILD_TYPE%"=="" set "BUILD_TYPE=Release"

set "SRC_DIR=%~dp0"
if "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR:~0,-1%"
set "BUILD_DIR=%SRC_DIR%\build"

rem ---- 1. locate Visual Studio ----------------------------------------------
rem NOTE: vswhere's -requires filter depends on per-component metadata in the VS
rem       state store. Trimmed / custom VS installs can lack that metadata even
rem       though vcvars64.bat exists -- that used to make this script report
rem       "No Visual Studio installation ... was found". So: try vswhere first,
rem       then fall back to scanning the usual install roots for vcvars64.bat.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

set "VSPATH="
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
    if "!VSPATH!"=="" (
        for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSPATH=%%i"
        if not "!VSPATH!"=="" echo [INFO] vswhere: component metadata missing, used installationPath
    )
)

if "%VSPATH%"=="" (
    echo [INFO] vswhere gave no path, scanning common install roots ...
    call :scan_vs
)

if "%VSPATH%"=="" (
    echo [ERROR] No Visual Studio installation with MSVC x64 tools was found.
    echo         Looked via vswhere and under:
    echo           C:\Program Files\Microsoft Visual Studio
    echo           C:\Program Files ^(x86^)\Microsoft Visual Studio
    echo           D:\Microsoft Visual Studio
    echo         If yours lives elsewhere, import vcvars64.bat yourself and run:
    echo           cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    exit /b 1
)
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" (
    echo [ERROR] vcvars64.bat not found under "%VSPATH%".
    exit /b 1
)
echo [INFO] Visual Studio: %VSPATH%
goto :vs_found

rem ---- helper: find <root>\Microsoft Visual Studio\<edition>\VC\Auxiliary\Build ----
rem      (community/Professional/Enterprise/BuildTools ????? VS ???)
:scan_vs
for %%d in (C D E F G) do (
    for /f "delims=" %%y in ('dir /b /ad "%%d:\Microsoft Visual Studio" 2^>nul') do (
        if exist "%%d:\Microsoft Visual Studio\%%y\VC\Auxiliary\Build\vcvars64.bat" (
            set "VSPATH=%%d:\Microsoft Visual Studio\%%y"
        )
    )
    for /f "delims=" %%y in ('dir /b /ad "%%d:\Program Files\Microsoft Visual Studio" 2^>nul') do (
        if exist "%%d:\Program Files\Microsoft Visual Studio\%%y\VC\Auxiliary\Build\vcvars64.bat" (
            set "VSPATH=%%d:\Program Files\Microsoft Visual Studio\%%y"
        )
    )
    for /f "delims=" %%y in ('dir /b /ad "%%d:\Program Files ^(x86^)\Microsoft Visual Studio" 2^>nul') do (
        if exist "%%d:\Program Files (x86)\Microsoft Visual Studio\%%y\VC\Auxiliary\Build\vcvars64.bat" (
            set "VSPATH=%%d:\Program Files (x86)\Microsoft Visual Studio\%%y"
        )
    )
)
exit /b 0

:vs_found

rem ---- 2. import x64 build environment --------------------------------------
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [ERROR] Failed to run vcvars64.bat
    exit /b 1
)

rem ---- 3. make sure cmake / ninja are available (both ship with VS) ---------
where cmake >nul 2>nul
if errorlevel 1 set "PATH=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"
where ninja >nul 2>nul
if errorlevel 1 set "PATH=%VSPATH%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"

where cmake >nul 2>nul
if errorlevel 1 (
    echo [ERROR] cmake still not found. Please install CMake and add it to PATH.
    exit /b 1
)

rem ---- 4. configure + build -------------------------------------------------
echo [INFO] Build type: %BUILD_TYPE%
if defined WINDIVERT_ROOT (
    cmake -S "%SRC_DIR%" -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=%BUILD_TYPE% "-DWINDIVERT_ROOT=%WINDIVERT_ROOT%"
) else (
    cmake -S "%SRC_DIR%" -B "%BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
)
if errorlevel 1 (
    echo [ERROR] CMake configure failed.
    exit /b 1
)

rem Capture the build log and verify the result ourselves: some CMake versions
rem return 0 from "cmake --build" even when the underlying ninja build failed.
set "BUILD_LOG=%TEMP%\weaknet_build.log"
cmake --build "%BUILD_DIR%" > "%BUILD_LOG%" 2>&1
set "BUILD_RC=%ERRORLEVEL%"
type "%BUILD_LOG%"

findstr /C:"FAILED:" /C:"fatal error" /C:"error LNK" /C:"error C" "%BUILD_LOG%" >nul
if not errorlevel 1 (
    echo [ERROR] Build failed - see the compiler/linker messages above.
    exit /b 1
)
if not "%BUILD_RC%"=="0" (
    echo [ERROR] Build failed with exit code %BUILD_RC%.
    exit /b 1
)
if not exist "%BUILD_DIR%\WeakNetTool.exe" (
    echo [ERROR] Build reported success but WeakNetTool.exe was not produced.
    echo         Hint: if the old exe is still running, close it and build again.
    exit /b 1
)

echo.
echo [DONE] Executable: %BUILD_DIR%\WeakNetTool.exe
echo        WinDivert.dll and WinDivert64.sys are copied next to it automatically.
echo        Run as Administrator, e.g.:
echo          %BUILD_DIR%\WeakNetTool.exe --port 8080
endlocal
