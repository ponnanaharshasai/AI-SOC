@echo off
cd /d "%~dp0"
echo ========================================================
echo  Starting Autonomous AI-SOC (Ollama + Backend + Dashboard)
echo ========================================================

:: Check and Start Ollama if not running
set OLLAMA_MODELS=D:\Ollama\models
netstat -ano | findstr /R /C:":11434 " >nul
if %errorlevel% neq 0 (
    echo [1/3] Starting Ollama local LLM service (port 11434)...
    start "Ollama Service" cmd /k "set OLLAMA_MODELS=D:\Ollama\models && ollama serve"
    ping 127.0.0.1 -n 4 >nul
) else (
    echo [1/3] Ollama service is already active on port 11434.
)

echo [2/3] Starting FastAPI Backend on http://localhost:8000 ...
start "AI-SOC Backend API" cmd /k "python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

ping 127.0.0.1 -n 4 >nul

echo [3/3] Starting Streamlit SOC Dashboard on http://localhost:8501 ...
start "AI-SOC Dashboard" cmd /k "python -m streamlit run dashboard/app.py --server.port 8501"

echo ========================================================
echo  Autonomous AI-SOC is fully operational!
echo  LLM Service: http://localhost:11434 (Qwen2.5:7b)
echo  Backend:     http://localhost:8000/docs
echo  Dashboard:   http://localhost:8501
echo ========================================================
pause
