@echo off
cd /d C:\notebook-reserve

if not exist venv\Scripts\python.exe (
    echo [ERROR] Virtual environment not found: C:\notebook-reserve\venv
    pause
    exit /b 1
)

:loop
echo ========================================
echo Starting Notebook Reserve server...
echo Time: %date% %time%
echo ========================================

call venv\Scripts\activate.bat
python app.py

echo.
echo Server stopped. Restarting in 2 seconds...
timeout /t 2 /nobreak >nul
goto loop