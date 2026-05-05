#!/usr/bin/env bash
set -euo pipefail # e = daca avem error ne oprim imd
                  # u = daca avem variabila care nu e definita, o sa ne oprim imd
                  # o = daca avem o comanda intr-un lant care esuaza, lantul de considera esuat

mkdir -p /run/sshd # creez folderul pentru sshd pt ca altfel nu porneste serverul ssh
/usr/sbin/sshd # pornesc serverul ssh in background
 
exec /scripts/traffic_normal.sh
