#!/usr/bin/env bash
set -euo pipefail

nginx # pornesc serverul web nginx in background

exec /scripts/traffic_normal.sh
