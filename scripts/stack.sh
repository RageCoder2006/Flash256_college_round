#!/usr/bin/env bash
# Manage the Neo4j + Qdrant stack:  scripts/stack.sh up | down | status | reset-secrets | wipe
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
case "${1:-status}" in
  up)
    need_env
    mkdir -p data/neo4j data/qdrant
    docker compose --env-file "$ENVF" up -d --wait
    echo "neo4j  bolt://127.0.0.1:7687   browser http://127.0.0.1:7474"
    echo "qdrant http://127.0.0.1:6333"
    ;;
  down)   docker compose --env-file "$ENVF" down ;;
  status) docker compose --env-file "$ENVF" ps ;;
  wipe)
    read -r -p "Delete ALL graph and vector data? type 'wipe': " a
    [ "$a" = "wipe" ] || { echo aborted; exit 1; }
    docker compose --env-file "$ENVF" down -v
    rm -rf data
    ;;
  *) echo "usage: $0 up|down|status|wipe"; exit 2 ;;
esac
