#!/bin/bash
echo ""
echo " ACERBE™ v3.1.0 — ARCHER CHAIN ANALYTICS™"
echo " ────────────────────────────────────────"
if [ -z "$ACERBE_SECRET_KEY" ]; then
    read -s -p " Enter AcerbE Secret Key: " ACERBE_SECRET_KEY
    echo ""
fi
export ACERBE_SECRET_KEY
cd "$(dirname "$0")/.."
pip3 install -r requirements.txt --quiet
echo " Starting engine..."
python3 gui/acerbe_gui.py
