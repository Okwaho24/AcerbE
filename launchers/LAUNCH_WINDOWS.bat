@echo off
TITLE AcerbE™ v3.1.0 — Archer Chain Analytics™

IF "%ACERBE_SECRET_KEY%"=="" (
    echo.
    echo  ACERBE(TM) — SECRET KEY REQUIRED
    SET /P ACERBE_SECRET_KEY="  Enter key: "
    echo.
)

cd /d "%~dp0.."
python -m pip install -r requirements.txt --quiet
python gui\acerbe_gui.py
pause
