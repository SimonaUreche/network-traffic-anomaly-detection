#!/usr/bin/env bash
set -euo pipefail

# web_server-ul în mod normal primeste cereri
# el insuri face doar:
# - ping la gateway pentru conectivitate
# - nimic altceva — traficul vine din afara

while true; do
    ping -c 1 -W 1 gateway >/dev/null 2>&1 || true
    sleep 30
done