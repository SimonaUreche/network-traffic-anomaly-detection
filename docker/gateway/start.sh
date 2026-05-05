#!/usr/bin/env bash 
set -euo pipefail # e = daca avem error ne oprim imd
                  # u = daca avem variabila care nu e definita, o sa ne oprim imd
                  # o = daca avem o comanda intr-un lant care esuaza, lantul de considera esuat
# pornește brokerul MQTT in background
mosquitto -c /etc/mosquitto/mosquitto.conf -v &

# porneste traficul normal
exec /scripts/traffic_normal.sh
