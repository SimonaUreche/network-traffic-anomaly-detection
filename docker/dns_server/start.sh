#!/usr/bin/env bash
set -euo pipefail

exec dnsmasq --conf-file=/etc/dnsmasq.conf --keep-in-foreground
