@echo off
echo ========================================================
echo  Starting Autonomous AI-SOC (Backend + Dashboard)
echo ========================================================

echo [1/2] Starting FastAPI Backend on http://localhost:8000 ...
start "AI-SOC Backend API" cmd /k "python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 3 /nobreak >nul

echo [2/2] Starting Streamlit SOC Dashboard on http://localhost:8501 ...
start "AI-SOC Dashboard" cmd /k "python -m streamlit run dashboard/app.py --server.port 8501"

echo ========================================================
echo  Autonomous AI-SOC is running!
echo  Backend:   http://localhost:8000/docs
echo  Dashboard: http://localhost:8501
echo ========================================================
pause
