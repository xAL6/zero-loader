@echo off
REM zero-loader web console launcher
REM Binds http://127.0.0.1:7890 — localhost only. Do NOT expose.

SET "HERE=%~dp0"
cd /d "%HERE%.."

IF NOT EXIST "%HERE%\.venv" (
    echo [*] First run: creating venv...
    python -m venv "%HERE%\.venv"
    "%HERE%\.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
    "%HERE%\.venv\Scripts\python.exe" -m pip install --quiet -r "%HERE%\requirements.txt"
)

"%HERE%\.venv\Scripts\python.exe" "%HERE%\server.py"
