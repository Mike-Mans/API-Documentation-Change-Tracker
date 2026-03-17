#!/usr/bin/env bash
# Stop the Kalshi trading bot on the VPS.
# Run this manually or it is invoked automatically by apisentinel
# when API documentation changes or server relocation is detected.
set -euo pipefail

echo "[stop_bot] Stopping kalshi-data and kalshi-control on VPS..."
ssh kalshi 'systemctl stop kalshi-data kalshi-control'
echo "[stop_bot] Done."
