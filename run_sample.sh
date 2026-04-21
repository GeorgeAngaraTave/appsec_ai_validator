#!/usr/bin/env bash
set -e
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.main validate --project sample --findings sample/findings.json --output reports
