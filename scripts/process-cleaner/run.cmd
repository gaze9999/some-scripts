@echo off
setlocal
chcp 65001 >nul
set "cleaner_ps=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "cleaner_ps=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%cleaner_ps%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0process-cleaner.ps1" %*
set "cleaner_exit=%errorlevel%"
echo.
pause
exit /b %cleaner_exit%
