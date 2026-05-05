#!/usr/bin/env bash
set -euo pipefail
echo "[smart_camera] Aștept broker MQTT..."
until mosquitto_pub -h gateway -p 1883 -t "health/smart_camera" -m "ready" >/dev/null 2>&1; do
    sleep 2
done

echo "[smart_camera] Conectat. Comportament normal."
CAMERA_ID="cam_001"
FIRMWARE="3.2.1"
FRAME_COUNT=0
MOTION_COUNT=0
while true; do
    TIMESTAMP=$(date +%s)
    FRAME_COUNT=$((FRAME_COUNT + 1))
    MOTION=false
    #la fiecare ciclu incrementam numarul de frame-uri procesate, iar la fiecare 5 frame-uri detectam o miscare
    if [ $((FRAME_COUNT % 5)) -eq 0 ]; then
        MOTION=true
        MOTION_COUNT=$((MOTION_COUNT + 1))
    fi
    
    # la fiecare ciclu (15 secunde) publicam statusul camerei(rezolutie, fps, daca a detectat miscare), iar la fiecare 3 cicluri(45s) publicam un heartbeat
    mosquitto_pub \
        -h gateway -p 1883 \
        -t "home/camera/status" \
        -m "{\"id\":\"${CAMERA_ID}\",\"resolution\":\"1080p\",\"fps\":25,\"motion\":${MOTION},\"motion_count\":${MOTION_COUNT},\"ts\":${TIMESTAMP}}" \
        >/dev/null 2>&1 || true

    if [ $((FRAME_COUNT % 3)) -eq 0 ]; then
        mosquitto_pub \
            -h gateway -p 1883 \
            -t "home/camera/heartbeat" \
            -m "{\"id\":\"${CAMERA_ID}\",\"firmware\":\"${FIRMWARE}\",\"uptime\":${TIMESTAMP}}" \
            >/dev/null 2>&1 || true
    fi

    # la fiecare 10 cicluri(150s) - facem un HTTP GET la web_server pentru a verifica daca exista o noua versiune de firmware disponibila (trimite headerul X-Device-ID ca sa se identifice, si X-Firmware pentru a trimite versiunea curenta)
    # web-serverul raspunde cu json {"update_available": true/false, "latest_version": "x.y.z"} - daca update_available e true, atunci camera ar trebui sa faca un HTTP POST la web_server/upload pentru a trimite un dump al memoriei (simulat printr-un mesaj MQTT) si apoi sa descarce noul firmware (simulat printr-un alt mesaj MQTT)
    # SI 
    if [ $((FRAME_COUNT % 10)) -eq 0 ]; then
        curl -s --max-time 3 \
            -H "X-Device-ID: ${CAMERA_ID}" \
            -H "X-Firmware: ${FIRMWARE}" \
            http://web_server/firmware/check \
            >/dev/null 2>&1 || true
    fi
    sleep 15
done

# SCOPUL CAMEREEI IN SISTEM ESTE SA DEMONSTRAM CA ECOD O SA FUNCTIONEZE SI PE DISPOZITIVE MAI COMPLEXE - DOUA PROTOCOALE DIFERITE, FRECVENTE DIFERITE, payload variabil