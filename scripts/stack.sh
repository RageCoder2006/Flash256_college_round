#!/usr/bin/env bash
# Manage the stack:  scripts/stack.sh up [--observability] | down | status | wipe
# --observability also starts Prometheus (127.0.0.1:9090) and Grafana (127.0.0.1:3001), both loopback only.
set -euo pipefail
cd "$(dirname "$0")/../deploy/stack"
ENVF=.env
need_env() {
  # migrate: the keys were called AB_* before the project was named AVHSOL (tokens are kept, not regenerated)
  if [ -f "$ENVF" ] && grep -q '^AB_' "$ENVF"; then sed -i 's/^AB_/AVHSOL_/' "$ENVF"; echo "migrated credential names in deploy/stack/.env"; fi
  if [ ! -f "$ENVF" ]; then
    umask 077
    {
      echo "AVHSOL_UID=$(id -u)"
      echo "AVHSOL_GID=$(id -g)"
      echo "NEO4J_PASSWORD=$(openssl rand -hex 24)"
      echo "QDRANT_API_KEY=$(openssl rand -hex 24)"
    } > "$ENVF"
    echo "generated credentials in deploy/stack/.env (mode 600, git-ignored)"
  fi
  # API role tokens (added to existing files too). viewer < analyst < operator < admin.
  for role in VIEWER ANALYST OPERATOR ADMIN; do
    if ! grep -q "^AVHSOL_TOKEN_${role}=" "$ENVF"; then
      umask 077
      echo "AVHSOL_TOKEN_${role}=$(openssl rand -hex 24)" >> "$ENVF"
      echo "generated API token for role ${role} in deploy/stack/.env"
    fi
  done
}
observability_env() {
  # Grafana admin password, and a viewer token for Prometheus. Both are written once, mode 600, never committed.
  if ! grep -q '^GRAFANA_ADMIN_PASSWORD=' "$ENVF"; then
    umask 077
    echo "GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 16)" >> "$ENVF"
    echo "generated the Grafana admin password in deploy/stack/.env (user: admin)"
  fi
  umask 077
  grep '^AVHSOL_TOKEN_VIEWER=' "$ENVF" | cut -d= -f2- | tr -d '\n' > prometheus/token
  chmod 600 prometheus/token
  mkdir -p data/prometheus data/grafana
}
PROFILE=()
[ "${2:-}" = "--observability" ] && PROFILE=(--profile observability)
case "${1:-status}" in
  up)
    need_env
    mkdir -p data/neo4j data/qdrant
    if [ "${#PROFILE[@]}" -gt 0 ]; then observability_env; fi
    docker compose "${PROFILE[@]}" --env-file "$ENVF" up -d --wait
    echo "neo4j  bolt://127.0.0.1:7687   browser http://127.0.0.1:7474"
    echo "qdrant http://127.0.0.1:6333"
    if [ "${#PROFILE[@]}" -gt 0 ]; then
      echo "prometheus http://127.0.0.1:9090   grafana http://127.0.0.1:3001 (admin / GRAFANA_ADMIN_PASSWORD in deploy/stack/.env)"
      echo "start the API with AVHSOL_GRAFANA_URL=http://127.0.0.1:3001 to show the link on the Status page"
    fi
    ;;
  down)   docker compose --profile observability --env-file "$ENVF" down ;;
  status) docker compose --profile observability --env-file "$ENVF" ps ;;
  wipe)
    read -r -p "Delete ALL graph and vector data? type 'wipe': " a
    [ "$a" = "wipe" ] || { echo aborted; exit 1; }
    docker compose --profile observability --env-file "$ENVF" down -v
    rm -rf data
    ;;
  *) echo "usage: $0 up [--observability]|down|status|wipe"; exit 2 ;;
esac
