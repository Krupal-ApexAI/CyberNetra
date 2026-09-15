@echo off
echo ============================================
echo   CyberNetra Controlled Vulnerable Lab
echo   Port 9000 - Isolated Security Sandbox
echo ============================================
cd /d "%~dp0vulnerable_lab"
pip install -r requirements.txt --quiet 2>nul
if not exist .env (
    if exist .env.example copy .env.example .env
)
echo [*] Starting Vulnerable Lab on http://127.0.0.1:9000
python -m uvicorn app.main:app --host 127.0.0.1 --port 9000 --reload
