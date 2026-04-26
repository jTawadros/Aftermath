#!/usr/bin/env bash

cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "Virtual environment not found. Creating .venv..."
    python3 -m venv .venv
fi

source .venv/bin/activate

python -m pip show PySide6 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Installing PySide6..."
    python -m pip install PySide6
fi

QT_QPA_PLATFORM=xcb python app.py
