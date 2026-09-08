@echo off
cd /d "%~dp0"
title SecureAuth HCI Enhanced - Setup
cls
echo Installing project requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Installation failed. Check Python/pip and internet connection.
  pause
  exit /b 1
)
echo.
echo Starting HCI Enhanced version on http://127.0.0.1:5050
python app.py
pause
