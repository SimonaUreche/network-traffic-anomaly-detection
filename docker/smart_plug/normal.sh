#!/usr/bin/env bash
set -euo pipefail
echo "[smart_plug] Aștept broker MQTT..."
# Așteptăm să se pornească gateway-ul și să fie gata să primească mesaje MQTT înainte de a începe să publicăm statusul prizei
until mosquitto_pub -h gateway -p 1883 -t "health/smart_plug" -m "ready" >/dev/null 2>&1; do
    sleep 2
done

echo "[smart_plug] Conectat. Comportament normal."
#id ul prizei si stare - pornita permanent, pentru simplitate. Puterea consumata o sa fie o valoare random intre 45 si 60 W, actualizata la fiecare 30s
PLUG_ID="plug_001"
STATE="on"

while true; do
    TIMESTAMP=$(date +%s)
    POWER=$(awk -v seed="$RANDOM" 'BEGIN{srand(seed); printf "%.1f", 45 + rand()*15}')
    # la fiecare ciclu (30 secunde) publicam statusul prizei (daca e pornita sau oprita, puterea consumata, timestamp)
    mosquitto_pub \
        -h gateway -p 1883 \
        -t "home/plug/status" \
        -m "{\"id\":\"${PLUG_ID}\",\"state\":\"${STATE}\",\"power\":${POWER},\"ts\":${TIMESTAMP}}" \
        >/dev/null 2>&1 || true
    sleep 30
done
# scopul prizei in sistem este sa avem un dispozitiv simplu, cu un singur protocol de comunicatie (MQTT), o frecventa de comunicare mai mica, si un payload mai simplu
# il folsoim si ca exemplu de dipozitiv compromis