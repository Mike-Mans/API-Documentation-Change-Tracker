#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$REPO/apisentinel/target/release/apisentinel"
LOGFILE="/tmp/apisentinel.log"

if pgrep -f "apisentinel" > /dev/null; then
    echo "Tracker is already running (PID: $(pgrep -f apisentinel))"
    exit 0
fi

export SENTINEL_BB_URL='http://localhost:1234'
export SENTINEL_BB_PASSWORD='#6ZQa6sBX4Vzu'
export RUST_LOG=info

cd "$REPO/apisentinel"
nohup "$BINARY" >> "$LOGFILE" 2>&1 &
PID=$!
echo "Tracker started (PID: $PID) — logs: $LOGFILE"
