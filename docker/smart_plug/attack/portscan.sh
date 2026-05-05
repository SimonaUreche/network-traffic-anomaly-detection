#!/usr/bin/env bash
echo "[ATTACK] smart_plug compromis — port scan intern..."

# Port scan pe întreaga rețea IoT, inclusiv honeypot (172.20.0.8)
# -sS = SYN scan (stealth scan, nu completează handshake)
# --min-rate 1000 = trimite minim 1000 pachete/secundă
# Scanează toate dispozitivele din subnet:
#   172.20.0.2 (gateway), .3 (web_server), .4 (iot_sensor),
#   .5 (auth_server), .6 (smart_camera), .7 (smart_plug),
#   .8 (honeypot), .53 (dns_server)
nmap -sS --min-rate 500 -p 1-1000 172.20.0.0/24 2>/dev/null || true

echo "[ATTACK] Port scan terminat."