@echo off
echo ============================================
echo  CloudOps Central v3.0 - Quick Start
echo ============================================

cd backend

REM Check if .env exists
if not exist .env (
    echo.
    echo [SETUP] Creating .env from template...
    copy .env.example .env
    echo.
    echo [ACTION REQUIRED] Edit backend\.env and set:
    echo   SECRET_KEY  - generate with: python -c "import secrets; print(secrets.token_hex(32))"
    echo   ADMIN_PASSWORD - your admin password
    echo   VIEWER_PASSWORD - your viewer password
    echo.
    pause
)

REM Install dependencies
echo [SETUP] Installing Python dependencies...
pip install -r requirements.txt

REM Start backend
echo.
echo [START] Starting CloudOps Central backend on http://localhost:8000
echo [START] API docs available at http://localhost:8000/docs
echo.
uvicorn main:app --reload --port 8000 --host 0.0.0.0
