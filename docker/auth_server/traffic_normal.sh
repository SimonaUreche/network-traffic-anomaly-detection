#!/usr/bin/env bash
set -euo pipefail

# serverul de auth face un singur lucru - verifica periodic daca gateway-ul e disponibil - mai rar(20 sec) pt. ca serverul de auth e mai puti activ decat un router normal care face ping la toate dispozitivele din retea la fiecare 5 secunde
while true; do
  ping -c 1 -W 1 gateway >/dev/null 2>&1 || true
  sleep 20
done


