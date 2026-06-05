@echo off
cd /d C:\Users\yo\Documents\bot-clasificador-main\bot-clasificador-main
if not exist ".venv\Scripts\python.exe" python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m src.main
pause
