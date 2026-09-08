@echo off
cd /d "%~dp0"
title SecureAuth HCI Enhanced
cls
echo ================================================================
echo   SECUREAUTH HCI ENHANCED
echo   This version runs on http://127.0.0.1:5050
echo   Do NOT open localhost:5000 - that may be the old version.
echo ================================================================
echo.
python app.py
pause
