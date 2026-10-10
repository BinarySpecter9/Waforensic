@echo off
title WAForensic Engine
cd /d "%~dp0"

echo ================================================
echo   WAForensic - WhatsApp Recovery Engine v0.1.3
echo   100%% offline. Your data never leaves this PC.
echo ================================================
echo.

REM --- Python check ---
py --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install it from python.org first,
    echo then double-click this file again.
    pause
    exit /b 1
)

REM --- Dependencies (auto-install on first run) ---
py -m pip show cryptography >nul 2>&1
if errorlevel 1 (
    echo [*] First run: installing required libraries...
    py -m pip install cryptography pillow
)

REM --- Locate adb ---
set ADB=
where adb >nul 2>&1 && set ADB=adb
if not defined ADB if exist "C:\platform-tools\adb.exe" set ADB="C:\platform-tools\adb.exe"
if not defined ADB if exist "E:\platform-tools\adb.exe" set ADB="E:\platform-tools\adb.exe"
if not defined ADB if exist "%~dp0platform-tools\adb.exe" set ADB="%~dp0platform-tools\adb.exe"

REM --- Sanity: must be extracted, not run from inside the zip ---
if not exist "%~dp0waforensic\cli.py" (
    echo [ERROR] The engine files are missing next to run.bat.
    echo Please RIGHT-CLICK the zip -^> "Extract All", then
    echo double-click run.bat inside the EXTRACTED folder.
    pause
    exit /b 1
)

:menu
echo.
echo   [1] Pull WhatsApp data from phone  (USB)
echo   [2] Decrypt WhatsApp backup  (.crypt12/14/15)
echo   [3] Read chats + find deleted messages  (msgstore.db)
echo   [4] Photo details + GPS location  (EXIF)
echo   [5] Recover deleted files from disk image  (carve)
echo   [6] Build the HTML report
echo   [0] Exit
echo.
set /p choice="  Choose a number: "

if "%choice%"=="1" goto acquire
if "%choice%"=="2" goto decrypt
if "%choice%"=="3" goto parsedb
if "%choice%"=="4" goto exif
if "%choice%"=="5" goto carve
if "%choice%"=="6" goto report
if "%choice%"=="0" exit /b 0
goto menu

:acquire
if not defined ADB (
    echo [ERROR] adb not found. Download platform-tools from:
    echo https://dl.google.com/android/repository/platform-tools-latest-windows.zip
    echo Extract it to C:\platform-tools and run this again.
    pause
    goto menu
)
echo [*] Checking phone...
%ADB% devices
echo [*] Pulling WhatsApp data - this takes a few minutes...
py -m waforensic.cli acquire -o case1
echo.
echo [+] Done. Your data is in the 'case1' folder.
pause
goto menu

:decrypt
set /p f="  Encrypted backup file (e.g. msgstore.db.crypt14): "
set /p k="  Key file (158-byte 'key' file or 64-char hex): "
py -m waforensic.cli decrypt "%f%" "%k%" -o msgstore.db
pause
goto menu

:parsedb
set /p f="  Database file (msgstore.db): "
py -m waforensic.cli db "%f%" --recover-deleted -o messages.json
echo [+] Results saved to messages.json
pause
goto menu

:exif
set /p f="  Photo file (or drag it here): "
py -m waforensic.cli exif "%f%"
pause
goto menu

:carve
set /p f="  Disk image file: "
py -m waforensic.cli carve "%f%" -o carved
echo [+] Recovered files are in the 'carved' folder.
pause
goto menu

:report
py -m waforensic.cli report --manifest carved\manifest.json --db-json messages.json -o report.html
echo [+] Open report.html in your browser.
pause
goto menu
