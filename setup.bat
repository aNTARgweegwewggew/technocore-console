@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3.11 -m venv .venv 2>nul || py -3.12 -m venv .venv 2>nul || py -m venv .venv
) else (
  python -m venv .venv
)
call .venv\Scripts\python.exe -m pip install --upgrade pip
call .venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Installation failed.
  pause
  exit /b 1
)
echo.
echo Ready. Now run run_console.bat
pause
