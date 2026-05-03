#!/usr/bin/env bash

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "[Aftermath] Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "[Aftermath] Installing dependencies..."
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "[Aftermath] Starting UI..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    python app.py
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    QT_QPA_PLATFORM=xcb python app.py
else
    python app.py
fi
