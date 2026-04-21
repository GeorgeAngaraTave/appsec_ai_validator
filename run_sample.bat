@echo off
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
python -m app.main validate --project sample --findings sample/findings.json --output reports
pause
