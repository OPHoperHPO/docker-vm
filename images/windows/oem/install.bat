@echo off
REM =====================================================================
REM C:\OEM\install.bat
REM
REM Auto-executed once on first user logon, by the FirstLogonCommand:
REM   cmd /C if exist "C:\OEM\install.bat" start "Install" "cmd /C C:\OEM\install.bat"
REM defined in dockurr/windows' default win11x64.xml unattend file.
REM
REM Use this as the entry point of your initialization. If you want
REM PowerShell, just call firstboot.ps1 from here.
REM =====================================================================

set LOG=C:\OEM\install.log
echo [%date% %time%] install.bat started >> "%LOG%"

REM ----- example: hand off to PowerShell for the real work -----
if exist "C:\OEM\firstboot.ps1" (
    echo [%date% %time%] launching firstboot.ps1 >> "%LOG%"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\OEM\firstboot.ps1" >> "%LOG%" 2>&1
)

REM ----- you can also run plain commands here -----
REM mkdir C:\Tools
REM choco install -y git vscode

echo [%date% %time%] install.bat finished >> "%LOG%"
exit /b 0
