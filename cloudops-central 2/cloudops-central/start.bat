@echo off
echo ============================================
echo  CloudOps Central v3.0 - Quick Start
echo ============================================
echo.

cd /d "%~dp0backend"

REM ── Step 1: Create .env if missing ───────────────────────────────────────────
if not exist .env (
    echo [SETUP] .env not found — creating one now...
    echo.

    REM Generate SECRET_KEY using Python
    for /f "delims=" %%i in ('python -c "import secrets; print(secrets.token_hex(32))"') do set GENERATED_KEY=%%i

    REM Prompt for passwords
    echo Enter ADMIN password (min 12 chars, 1 uppercase, 1 digit):
    set /p ADMIN_PWD="> "
    echo.
    echo Enter VIEWER password (min 12 chars, 1 uppercase, 1 digit):
    set /p VIEWER_PWD="> "
    echo.

    REM Write .env file
    (
        echo SECRET_KEY=%GENERATED_KEY%
        echo ADMIN_PASSWORD=%ADMIN_PWD%
        echo VIEWER_PASSWORD=%VIEWER_PWD%
        echo DATABASE_URL=sqlite:///./cloudops.db
        echo ALLOWED_ORIGINS=http://localhost:8001,http://127.0.0.1:8001,http://localhost:3000
        echo ADMIN_EMAIL=admin@company.com
        echo VIEWER_EMAIL=viewer@company.com
        echo AWS_DEFAULT_REGION=us-east-1
        echo CACHE_TTL=90
    ) > .env

    echo [OK] .env created with generated SECRET_KEY.
    echo.
) else (
    echo [OK] .env already exists — skipping setup.
    echo.
)

REM ── Step 2: Install dependencies ─────────────────────────────────────────────
echo [SETUP] Installing Python dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] pip install failed. Make sure Python 3.12+ is installed.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.
echo.

REM ── Step 3: Start backend ─────────────────────────────────────────────────────
echo [START] Backend starting on http://localhost:8000
echo [START] API docs at    http://localhost:8000/docs
echo [START] Frontend open  http://localhost:8001  (open index.html in browser)
echo.
echo Login credentials:
echo   Username: admin   Password: (what you set above)
echo   Username: viewer  Password: (what you set above)
echo.
echo Press Ctrl+C to stop.
echo.

uvicorn main:app --reload --port 8000 --host 0.0.0.0
