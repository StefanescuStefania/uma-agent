#!/usr/bin/env bash
# Run the concurrent load test against the distributed UMA-Agent stack.
#
# 20 agents, 4 delegation chains (depth 4-5), 16 honest + 4 attack.
# Results saved to paper_evidence/load_test.json.
#
# Usage:
#   ./scripts/run_load_test.sh
#   N_REQUESTS=50 NETWORK_LATENCY_MS=20 ./scripts/run_load_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

COMPOSE="docker compose -f docker-compose.distributed.yml"
LATENCY="${NETWORK_LATENCY_MS:-10}"
JITTER="${NETWORK_JITTER_MS:-2}"
N_REQUESTS="${N_REQUESTS:-30}"

echo "======================================================================"
echo "  UMA Agent — Concurrent Load Test"
echo "  20 agents (16 honest + 4 attack)  ×  ${N_REQUESTS} req/agent"
echo "  Toxiproxy latency: ${LATENCY} ms ± ${JITTER} ms"
echo "======================================================================"

echo "--> Rebuilding benchmark image (fast: source-only COPY)…"
docker build -f Dockerfile.agent -t uma-agent-benchmark:latest . --quiet

echo "--> Starting backend services…"
NETWORK_LATENCY_MS="$LATENCY" NETWORK_JITTER_MS="$JITTER" \
$COMPOSE up -d postgres keycloak resource-server

echo "--> Waiting for Keycloak…"
until [ "$(docker inspect dist-uma-keycloak --format '{{.State.Health.Status}}' 2>/dev/null)" = "healthy" ]; do
    sleep 5
done
echo "    Keycloak healthy."

echo "--> Starting Toxiproxy…"
NETWORK_LATENCY_MS="$LATENCY" NETWORK_JITTER_MS="$JITTER" \
$COMPOSE up -d toxiproxy
sleep 3

echo "--> Running load test…"
echo ""
docker run --rm \
  --network uma-agent_uma-distributed \
  -e KEYCLOAK_URL=http://dist-uma-toxiproxy:18080 \
  -e RESOURCE_SERVER_URL=http://dist-uma-toxiproxy:15000 \
  -e KEYCLOAK_REALM=test-realm \
  -e CLIENT_ID=test-app \
  -e CHAIN_HMAC_SECRET="uma-agent-chain-hmac-secret-2024" \
  -e TOXIPROXY_API=http://dist-uma-toxiproxy:8474 \
  -e NETWORK_LATENCY_MS="$LATENCY" \
  -e NETWORK_JITTER_MS="$JITTER" \
  -e N_REQUESTS="$N_REQUESTS" \
  -v "$PROJECT_DIR/paper_evidence:/results" \
  uma-agent-benchmark:latest \
  python scenarios/load_test.py \
    --n-requests "$N_REQUESTS" \
    --json-out /results/load_test.json

echo ""
echo "--> Results saved to: paper_evidence/load_test.json"

echo "--> Stopping backend services…"
$COMPOSE down --remove-orphans
echo "Done."
