#!/usr/bin/env bash
# Run the distributed UMA-Agent benchmark (Table VII — network latency variant).
#
# Each service runs in its own container.  Toxiproxy injects configurable
# per-hop latency between the benchmark-agent and the backend services.
#
# Usage:
#   ./scripts/run_distributed_benchmark.sh                  # defaults: 10ms latency, n=30
#   NETWORK_LATENCY_MS=20 ./scripts/run_distributed_benchmark.sh
#   N_HTTP=50 NETWORK_LATENCY_MS=5 ./scripts/run_distributed_benchmark.sh
#
# Results are written to paper_evidence/benchmark_distributed.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

COMPOSE="docker compose -f docker-compose.distributed.yml"
LATENCY="${NETWORK_LATENCY_MS:-10}"
JITTER="${NETWORK_JITTER_MS:-2}"
N_HTTP="${N_HTTP:-30}"
N_PYTHON="${N_PYTHON:-1000}"

echo "======================================================================"
echo "  UMA Agent — Distributed Benchmark"
echo "  Latency:  ${LATENCY} ms ± ${JITTER} ms  (Toxiproxy)"
echo "  Samples:  n_http=${N_HTTP}  n_python=${N_PYTHON}"
echo "======================================================================"
echo ""
echo "--> Building images…"
NETWORK_LATENCY_MS="$LATENCY" \
NETWORK_JITTER_MS="$JITTER" \
N_HTTP="$N_HTTP" \
N_PYTHON="$N_PYTHON" \
$COMPOSE build --quiet

echo "--> Starting backend services (postgres, keycloak, resource-server, toxiproxy)…"
NETWORK_LATENCY_MS="$LATENCY" \
NETWORK_JITTER_MS="$JITTER" \
N_HTTP="$N_HTTP" \
N_PYTHON="$N_PYTHON" \
$COMPOSE up -d postgres keycloak resource-server toxiproxy

echo "--> Running benchmark-agent (output below)…"
echo ""
NETWORK_LATENCY_MS="$LATENCY" \
NETWORK_JITTER_MS="$JITTER" \
N_HTTP="$N_HTTP" \
N_PYTHON="$N_PYTHON" \
$COMPOSE run --rm \
    -e NETWORK_LATENCY_MS="$LATENCY" \
    -e NETWORK_JITTER_MS="$JITTER" \
    -e N_HTTP="$N_HTTP" \
    -e N_PYTHON="$N_PYTHON" \
    benchmark-agent \
    python scenarios/benchmark_distributed.py \
        --n-http "$N_HTTP" \
        --n-python "$N_PYTHON" \
        --json-out /results/benchmark_distributed.json

echo ""
echo "--> Results saved to: paper_evidence/benchmark_distributed.json"
echo ""

echo "--> Stopping backend services…"
$COMPOSE down --remove-orphans

echo ""
echo "Done.  To keep services running for manual inspection:"
echo "  NETWORK_LATENCY_MS=$LATENCY $COMPOSE up -d"
echo "  docker exec -it dist-uma-benchmark-agent bash"
