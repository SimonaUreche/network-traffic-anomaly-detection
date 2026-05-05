#!/usr/bin/env bash
set -euo pipefail

targets=(web_server iot_sensor auth_server)
dns_server_ip=172.20.0.53
dns_names=(web_server.iot.lab auth_server.iot.lab iot_sensor.iot.lab)
ssh_key_path=/root/.ssh/id_rsa
ssh_target=root@172.20.0.5

ensure_ssh_identity() {
  mkdir -p /root/.ssh # creez folderul pt ssh
  chmod 700 /root/.ssh # setez permisiuni restrictive pentru folderul .ssh

  if [ ! -f "$ssh_key_path" ]; then # daca nu exista cheia, o generam
    ssh-keygen -q -t rsa -b 2048 -N "" -f "$ssh_key_path" # genereaza o cheie RSA fara parola, cu dimensiunea de 2048 de biti, si o salveaza la calea specificata
  fi

  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  public_key=$(cat "${ssh_key_path}.pub") # citim cheia publica generata anterior, care se afla in fisierul cu extensia .pub (de exemplu, daca cheia privata este id_rsa, cheia publica va fi in id_rsa.pub)
  if ! grep -qxF "$public_key" /root/.ssh/authorized_keys; then
    printf '%s\n' "$public_key" >> /root/.ssh/authorized_keys
  fi
}

run_ssh_health_check() { # functia de health check pentru SSH - incercam sa ne conectam la serverul de auth folosind ssh, daca reusim inseamna ca serverul e up, daca nu reuseste, inseamna ca e down
  sshpass -p 'password123' ssh \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=3 \
    "$ssh_target" \
    uptime >/dev/null 2>&1 || true
} # folosim parola slaba setata anterior pentru a ne conecta la serverul de auth, ignoram verificarea cheii hostului si setam un timeout de 3 secunde pentru conexiune

ensure_ssh_identity

last_ssh_check=0  # in loop devine timestamp curent

while true; do
#-------------------ping dispozitive din retea-------------------
  for target in "${targets[@]}"; do #la fiecare iteriatie facem ping la toate dispozitivele din retea 
    ping -c 1 -W 1 "$target" >/dev/null 2>&1 || true # -c 1 = trimitem un singur pachet de ping, -W 1 = setam un timeout de 1 secunda pentru raspunsul la ping, redirectionam outputul catre /dev/null pentru a nu afisa nimic in consola, si folosim || true pentru a preveni oprirea scriptului in cazul in care ping-ul esueaza (de exemplu, daca dispozitivul nu raspunde)
  done

#-------------------interogare DNS pentru nume de host din retea-------------------
  for dns_name in "${dns_names[@]}"; do
    dig @"$dns_server_ip" "$dns_name" +short >/dev/null 2>&1 || true
  done

#-------------------health check pentru SSH-------------------
  now=$(date +%s)
  if (( now - last_ssh_check >= 45 )); then
    run_ssh_health_check
    last_ssh_check=$now
  fi
  
  # accesează web_server periodic
  curl -fsS --max-time 3 http://web_server/ >/dev/null 2>&1 || true

  sleep 5
done
