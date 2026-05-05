#!/bin/bash
# Pornește nginx în background (interfața web de configurare a camerei)
nginx -g "daemon on;"

# Apoi rulează scriptul normal (MQTT, heartbeat, firmware check)
exec /normal.sh