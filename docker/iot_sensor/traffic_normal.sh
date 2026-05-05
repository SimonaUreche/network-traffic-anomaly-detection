#!/usr/bin/env bash
set -euo pipefail

#asteapra brokerul MQTT
until mosquitto_pub -h gateway -p 1883 -t "health/iot_sensor" -m "ready" >/dev/null 2>&1; do
  sleep 1
done

BATTERY=100

while true; do
    # citim un byte random din /dev/urandom(sursa de ransomness din linux) => un nr intre 0-255, il facem modulo 6 
    # => o terperetura intre 19-24 grade 
    # # umiditate între 45-65%    
    TEMP=$(awk -v seed="$RANDOM" 'BEGIN{srand(seed); printf "%.1f", 19 + rand()*6}')
    HUM=$(awk -v seed="$RANDOM" 'BEGIN{srand(seed); printf "%.1f", 45 + rand()*20}')

    # nivelul bateriei scade lent în timp
    BATTERY=$((BATTERY - 1))
    [ "$BATTERY" -lt 20 ] && BATTERY=100
    TIMESTAMP=$(date +%s)
    
    # publica pe topic MQTT — exact ce face un senzor real
    # ne conectam la brokerul MQTT de pe gateway și publicăm un mesaj JSON care conține temperatura, umiditatea, nivelul bateriei și timestamp-ul curent
    # oricine e abonat la topicul "home/sensor/temperature" va primi aceste date, exact ca și cum ar fi un senzor real care trimite date către un broker MQTT
    # trimitem date la un interval aleatoriu între 8 și 12 secunde pentru a simula un senzor care trimite date periodic, dar nu la intervale fixe

    mosquitto_pub \
        -h gateway \
        -p 1883 \
        -t "home/sensor/temperature" \
        -m "{\"temp\":${TEMP},\"humidity\":${HUM},\"battery\":${BATTERY},\"ts\":${TIMESTAMP}}" \
        >/dev/null 2>&1 || true

    INTERVAL=$((8 + RANDOM % 5))
    sleep "$INTERVAL"
done
