#!/usr/bin/env bash
# Run the LLM concurrent load test.
#
# Launches 20 separate Docker containers on the uma-network:
#   8  LLM agent containers — real Ollama inference (llama3.2)
#   8  HTTP agent containers — direct UMA protocol, high-throughput
#   4  Attack containers    — T1 / T2 / T3 / T4
#
# All containers start simultaneously via a file-based barrier.
# Results are written to paper_evidence/llm_agents/ and aggregated
# into paper_evidence/llm_load_test.json.
#
# Prerequisites:
#   • Docker running, uma-agent-benchmark:latest image built (auto-built here)
#   • Ollama running on host with llama3.2 pulled:
#       ollama serve   (if not already running)
#       ollama pull llama3.2
#
# Usage:
#   ./scripts/run_llm_load_test.sh
#   N_LLM_REQUESTS=2 N_HTTP_REQUESTS=50 ./scripts/run_llm_load_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

NETWORK="uma-agent_uma-network"
KEYCLOAK_INTERNAL="http://uma-keycloak:8080"
RS_INTERNAL="http://uma-resource-server:5000"
REALM="test-realm"
CLIENT_ID="test-app"
CHAIN_SECRET="uma-agent-chain-hmac-secret-2024"
RESULTS_DIR="$PROJECT_DIR/paper_evidence/llm_agents"
N_LLM_REQUESTS="${N_LLM_REQUESTS:-1}"
N_HTTP_REQUESTS="${N_HTTP_REQUESTS:-30}"
N_ATTACK_REQUESTS="${N_ATTACK_REQUESTS:-30}"
N_AGENTS=20

# Ollama proxy port — used to expose Ollama (which binds 127.0.0.1) to Docker containers
OLLAMA_PROXY_PORT="${OLLAMA_PROXY_PORT:-21434}"
OLLAMA_PROXY_PID=""

# Container name prefix — makes it easy to wait/remove all at once
PREFIX="llm-load"

echo "======================================================================"
echo "  UMA Agent — LLM Concurrent Load Test"
echo "  20 Docker containers: 8 LLM + 8 HTTP + 4 attack"
echo "  LLM backend: Ollama (llama3.2) via host.docker.internal:11434"
echo "  LLM tasks per container  : $N_LLM_REQUESTS"
echo "  HTTP requests per container: $N_HTTP_REQUESTS"
echo "  Attack requests per container: $N_ATTACK_REQUESTS"
echo "======================================================================"

# ── 0. Verify Ollama is running ───────────────────────────────────────────────
echo ""
echo "--> Checking Ollama availability…"
if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "ERROR: Ollama is not running at localhost:11434."
    echo "       Start it with: ollama serve"
    echo "       Then pull the model: ollama pull llama3.2"
    exit 1
fi
if ! curl -sf http://localhost:11434/api/tags | python3 -c \
    "import json,sys; tags=json.load(sys.stdin); \
     names=[m['name'] for m in tags.get('models',[])]; \
     ok=any('llama3.2' in n for n in names); \
     print('llama3.2: found' if ok else 'llama3.2: NOT FOUND'); exit(0 if ok else 1)" 2>/dev/null; then
    echo "WARNING: llama3.2 not found in Ollama — pulling it now…"
    ollama pull llama3.2
fi
echo "    Ollama ready with llama3.2."

# Detect Docker bridge gateway IP for the uma-network (Ollama listens on 127.0.0.1 only,
# so we start a Python proxy on the bridge IP to make it reachable from containers).
BRIDGE_GW=""

# ── 0b. Start Ollama proxy on Docker bridge IP ────────────────────────────────
# We need the uma-network bridge gateway before the network is created.
# Start docker compose first (creates the network), then detect the gateway.
echo "--> Starting backend services early to detect Docker bridge gateway…"
docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d postgres keycloak resource-server 2>/dev/null || true

BRIDGE_GW=$(docker network inspect "$NETWORK" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo "")
if [ -z "$BRIDGE_GW" ]; then
    echo "WARNING: Could not detect Docker bridge gateway. Using 172.19.0.1 as fallback."
    BRIDGE_GW="172.19.0.1"
fi
echo "    Docker bridge gateway: $BRIDGE_GW"

# Kill any existing proxy on this port
pkill -f "ollama_proxy.py" 2>/dev/null || true

# Write and start the proxy script
cat > /tmp/ollama_proxy.py << 'PROXY_EOF'
#!/usr/bin/env python3
import socket, threading, sys, os

LOCAL_HOST = os.environ["PROXY_BIND"]
LOCAL_PORT = int(os.environ.get("PROXY_PORT", "21434"))
REMOTE_HOST = "127.0.0.1"
REMOTE_PORT = 11434
BACKLOG = 100

def _relay(src, dst):
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try: s.shutdown(socket.SHUT_RDWR)
            except: pass
            try: s.close()
            except: pass

def handle(client):
    try:
        # No timeout — Ollama may queue requests for many minutes
        remote = socket.create_connection((REMOTE_HOST, REMOTE_PORT), timeout=None)
        for t in (threading.Thread(target=_relay, args=(client, remote), daemon=True),
                  threading.Thread(target=_relay, args=(remote, client), daemon=True)):
            t.start()
    except Exception as e:
        print(f"Proxy connect error: {e}", file=sys.stderr, flush=True)
        try: client.close()
        except: pass

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((LOCAL_HOST, LOCAL_PORT))
srv.listen(BACKLOG)
print(f"Ollama proxy ready: {LOCAL_HOST}:{LOCAL_PORT} → {REMOTE_HOST}:{REMOTE_PORT}", flush=True)
try:
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()
except KeyboardInterrupt:
    pass
PROXY_EOF

PROXY_BIND="$BRIDGE_GW" PROXY_PORT="$OLLAMA_PROXY_PORT" \
  python3 /tmp/ollama_proxy.py &
OLLAMA_PROXY_PID=$!
sleep 1

# Verify proxy is up
if ! kill -0 "$OLLAMA_PROXY_PID" 2>/dev/null; then
    echo "ERROR: Ollama proxy failed to start. Check if $BRIDGE_GW is a valid interface."
    exit 1
fi
OLLAMA_PROXY_URL="http://${BRIDGE_GW}:${OLLAMA_PROXY_PORT}/v1"
echo "    Ollama proxy started (PID $OLLAMA_PROXY_PID) at $OLLAMA_PROXY_URL"

# Cleanup trap
cleanup() {
    echo ""
    echo "--> Cleaning up…"
    kill "$OLLAMA_PROXY_PID" 2>/dev/null || true
    docker rm $(docker ps -a -q --filter "name=${PREFIX}-") 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Remove any leftover containers from a previous run ─────────────────────
echo "--> Cleaning up any previous containers…"
docker ps -a --filter "name=${PREFIX}-" --format "{{.Names}}" | xargs -r docker rm -f > /dev/null 2>&1 || true

# ── 2. Build benchmark image ──────────────────────────────────────────────────
echo "--> Building benchmark image…"
docker build -f Dockerfile.agent -t uma-agent-benchmark:latest . --quiet

# ── 3. Backend services already started above ─────────────────────────────────
echo "--> Backend services started. Waiting for health checks…"
echo "--> Waiting for Keycloak…"
until [ "$(docker inspect uma-keycloak --format '{{.State.Health.Status}}' 2>/dev/null)" = "healthy" ]; do
    sleep 5
done
echo "    Keycloak healthy."

echo "--> Waiting for Resource Server…"
until docker exec uma-resource-server curl -sf http://localhost:5000/ > /dev/null 2>&1; do
    sleep 5
done
echo "    Resource Server healthy."

# ── 4. Create results directories ─────────────────────────────────────────────
echo "--> Preparing results directory…"
mkdir -p "$RESULTS_DIR/ready"
rm -f "$RESULTS_DIR/ready/"* "$RESULTS_DIR/start_flag" "$RESULTS_DIR/agent-"*.json

# ── 5. Build delegation chains ────────────────────────────────────────────────
echo "--> Building delegation chains in temporary container…"
docker run --rm \
    --name "${PREFIX}-chain-builder" \
    --network "$NETWORK" \
    -e KEYCLOAK_URL="$KEYCLOAK_INTERNAL" \
    -e RESOURCE_SERVER_URL="$RS_INTERNAL" \
    -e KEYCLOAK_REALM="$REALM" \
    -e CLIENT_ID="$CLIENT_ID" \
    -e CHAIN_HMAC_SECRET="$CHAIN_SECRET" \
    -v "$RESULTS_DIR:/results" \
    uma-agent-benchmark:latest \
    python scenarios/build_chains.py --out /results/chains.json

CHAINS_FILE="$RESULTS_DIR/chains.json"
echo "    Chains written to $CHAINS_FILE"

# ── 6. Extract chain claims ───────────────────────────────────────────────────
echo "--> Parsing chain claim headers…"

_chain() {
    python3 -c "import json; d=json.load(open('$CHAINS_FILE')); print(d['$1']['$2'])"
}
_attack() {
    python3 -c "import json; d=json.load(open('$CHAINS_FILE')); print(d['attacks']['$1'])"
}

# LLM agents use chain_A (depths 1-4) and chain_B (depths 1-4)
CLAIM_A1="$(_chain chain_A 1)" ; CLAIM_A2="$(_chain chain_A 2)"
CLAIM_A3="$(_chain chain_A 3)" ; CLAIM_A4="$(_chain chain_A 4)"
CLAIM_B1="$(_chain chain_B 1)" ; CLAIM_B2="$(_chain chain_B 2)"
CLAIM_B3="$(_chain chain_B 3)" ; CLAIM_B4="$(_chain chain_B 4)"

# HTTP agents use chain_C (depths 1,2,4,5) and chain_D (depths 1,2,4,5)
CLAIM_C1="$(_chain chain_C 1)" ; CLAIM_C2="$(_chain chain_C 2)"
CLAIM_C4="$(_chain chain_C 4)" ; CLAIM_C5="$(_chain chain_C 5)"
CLAIM_D1="$(_chain chain_D 1)" ; CLAIM_D2="$(_chain chain_D 2)"
CLAIM_D4="$(_chain chain_D 4)" ; CLAIM_D5="$(_chain chain_D 5)"

# Attack chain claims
CLAIM_T1="$(_attack T1)" ; CLAIM_T2="$(_attack T2)"
CLAIM_T3="$(_attack T3)" ; CLAIM_T4="$(_attack T4)"

echo "    Chain claims extracted."

# ── 7. Common docker run arguments ────────────────────────────────────────────

common_run() {
    docker run -d \
        --network "$NETWORK" \
        --add-host "host.docker.internal:host-gateway" \
        -e KEYCLOAK_URL="$KEYCLOAK_INTERNAL" \
        -e RESOURCE_SERVER_URL="$RS_INTERNAL" \
        -e KEYCLOAK_REALM="$REALM" \
        -e CLIENT_ID="$CLIENT_ID" \
        -e OLLAMA_BASE_URL="$OLLAMA_PROXY_URL" \
        -e RESULTS_DIR="/results" \
        -e READY_DIR="/results/ready" \
        -e START_FILE="/results/start_flag" \
        -e N_AGENTS="$N_AGENTS" \
        -v "$RESULTS_DIR:/results" \
        "$@" \
        uma-agent-benchmark:latest \
        python scenarios/llm_agent_worker.py
}

# ── 8. Launch 8 LLM agent containers (chain_A depths 1-4, chain_B depths 1-4) ─
echo ""
echo "--> Launching 8 LLM agent containers (real Ollama inference)…"

common_run --name "${PREFIX}-cm-a-llm" \
    -e AGENT_ID="cm-a-llm" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_A1" -e CHAIN_NAME="chain_A" -e CHAIN_DEPTH=1 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-ra-a-llm" \
    -e AGENT_ID="ra-a-llm" -e USERNAME="risk-analyst" -e PASSWORD="risk-pass123" \
    -e CHAIN_CLAIM="$CLAIM_A2" -e CHAIN_NAME="chain_A" -e CHAIN_DEPTH=2 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-de-a-llm" \
    -e AGENT_ID="de-a-llm" -e USERNAME="data-extractor" -e PASSWORD="extractor-pass123" \
    -e CHAIN_CLAIM="$CLAIM_A3" -e CHAIN_NAME="chain_A" -e CHAIN_DEPTH=3 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-rv-a-llm" \
    -e AGENT_ID="rv-a-llm" -e USERNAME="report-validator" -e PASSWORD="validator-pass123" \
    -e CHAIN_CLAIM="$CLAIM_A4" -e CHAIN_NAME="chain_A" -e CHAIN_DEPTH=4 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-cm-b-llm" \
    -e AGENT_ID="cm-b-llm" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_B1" -e CHAIN_NAME="chain_B" -e CHAIN_DEPTH=1 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-ra-b-llm" \
    -e AGENT_ID="ra-b-llm" -e USERNAME="risk-analyst" -e PASSWORD="risk-pass123" \
    -e CHAIN_CLAIM="$CLAIM_B2" -e CHAIN_NAME="chain_B" -e CHAIN_DEPTH=2 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-de-b-llm" \
    -e AGENT_ID="de-b-llm" -e USERNAME="data-extractor" -e PASSWORD="extractor-pass123" \
    -e CHAIN_CLAIM="$CLAIM_B3" -e CHAIN_NAME="chain_B" -e CHAIN_DEPTH=3 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

common_run --name "${PREFIX}-rv-b-llm" \
    -e AGENT_ID="rv-b-llm" -e USERNAME="report-validator" -e PASSWORD="validator-pass123" \
    -e CHAIN_CLAIM="$CLAIM_B4" -e CHAIN_NAME="chain_B" -e CHAIN_DEPTH=4 \
    -e USE_LLM=true -e IS_ATTACK=false -e N_REQUESTS="$N_LLM_REQUESTS"

echo "    8 LLM containers launched."

# ── 9. Launch 8 HTTP agent containers (chain_C + chain_D) ────────────────────
echo "--> Launching 8 HTTP agent containers (direct UMA protocol)…"

common_run --name "${PREFIX}-cm-c-http" \
    -e AGENT_ID="cm-c-http" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_C1" -e CHAIN_NAME="chain_C" -e CHAIN_DEPTH=1 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-ra-c-http" \
    -e AGENT_ID="ra-c-http" -e USERNAME="risk-analyst" -e PASSWORD="risk-pass123" \
    -e CHAIN_CLAIM="$CLAIM_C2" -e CHAIN_NAME="chain_C" -e CHAIN_DEPTH=2 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-rv-c-http" \
    -e AGENT_ID="rv-c-http" -e USERNAME="report-validator" -e PASSWORD="validator-pass123" \
    -e CHAIN_CLAIM="$CLAIM_C4" -e CHAIN_NAME="chain_C" -e CHAIN_DEPTH=4 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-ar-c-http" \
    -e AGENT_ID="ar-c-http" -e USERNAME="audit-reader" -e PASSWORD="audit-pass123" \
    -e CHAIN_CLAIM="$CLAIM_C5" -e CHAIN_NAME="chain_C" -e CHAIN_DEPTH=5 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-cm-d-http" \
    -e AGENT_ID="cm-d-http" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_D1" -e CHAIN_NAME="chain_D" -e CHAIN_DEPTH=1 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-ra-d-http" \
    -e AGENT_ID="ra-d-http" -e USERNAME="risk-analyst" -e PASSWORD="risk-pass123" \
    -e CHAIN_CLAIM="$CLAIM_D2" -e CHAIN_NAME="chain_D" -e CHAIN_DEPTH=2 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-rv-d-http" \
    -e AGENT_ID="rv-d-http" -e USERNAME="report-validator" -e PASSWORD="validator-pass123" \
    -e CHAIN_CLAIM="$CLAIM_D4" -e CHAIN_NAME="chain_D" -e CHAIN_DEPTH=4 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

common_run --name "${PREFIX}-ar-d-http" \
    -e AGENT_ID="ar-d-http" -e USERNAME="audit-reader" -e PASSWORD="audit-pass123" \
    -e CHAIN_CLAIM="$CLAIM_D5" -e CHAIN_NAME="chain_D" -e CHAIN_DEPTH=5 \
    -e USE_LLM=false -e IS_ATTACK=false -e N_REQUESTS="$N_HTTP_REQUESTS"

echo "    8 HTTP containers launched."

# ── 10. Launch 4 attack containers (T1–T4) ────────────────────────────────────
echo "--> Launching 4 attack containers (T1–T4)…"

common_run --name "${PREFIX}-attack-t1" \
    -e AGENT_ID="attack-t1" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_T1" -e CHAIN_NAME="attack" -e CHAIN_DEPTH=-1 \
    -e USE_LLM=false -e IS_ATTACK=true -e ATTACK_CLASS=T1 -e N_REQUESTS="$N_ATTACK_REQUESTS"

common_run --name "${PREFIX}-attack-t2" \
    -e AGENT_ID="attack-t2" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_T2" -e CHAIN_NAME="attack" -e CHAIN_DEPTH=-1 \
    -e USE_LLM=false -e IS_ATTACK=true -e ATTACK_CLASS=T2 -e N_REQUESTS="$N_ATTACK_REQUESTS"

# T3: risk-analyst's valid RPT, but chain terminus is data-extractor → mismatch → blocked
common_run --name "${PREFIX}-attack-t3" \
    -e AGENT_ID="attack-t3" -e USERNAME="risk-analyst" -e PASSWORD="risk-pass123" \
    -e CHAIN_CLAIM="$CLAIM_T3" -e CHAIN_NAME="attack" -e CHAIN_DEPTH=-1 \
    -e USE_LLM=false -e IS_ATTACK=true -e ATTACK_CLASS=T3 -e N_REQUESTS="$N_ATTACK_REQUESTS"

common_run --name "${PREFIX}-attack-t4" \
    -e AGENT_ID="attack-t4" -e USERNAME="compliance-manager" -e PASSWORD="compliance-pass123" \
    -e CHAIN_CLAIM="$CLAIM_T4" -e CHAIN_NAME="attack" -e CHAIN_DEPTH=-1 \
    -e USE_LLM=false -e IS_ATTACK=true -e ATTACK_CLASS=T4 -e N_REQUESTS="$N_ATTACK_REQUESTS"

echo "    4 attack containers launched."
echo ""
echo "    Total: $N_AGENTS containers running in separate Docker containers."

# ── 11. Wait for all containers to write their ready flag ─────────────────────
echo "--> Waiting for all $N_AGENTS containers to signal ready…"
DEADLINE=$(( $(date +%s) + 300 ))
while true; do
    READY_COUNT=$(ls "$RESULTS_DIR/ready/" 2>/dev/null | wc -l)
    printf "\r    Ready: %d / %d   " "$READY_COUNT" "$N_AGENTS"

    if [ "$READY_COUNT" -ge "$N_AGENTS" ]; then
        echo ""
        break
    fi

    # Show any containers that exited early (error)
    EARLY_EXIT=$(docker ps -a --filter "name=${PREFIX}-" --filter "status=exited" \
                 --format "{{.Names}}" 2>/dev/null | head -3)
    if [ -n "$EARLY_EXIT" ]; then
        echo ""
        echo "    WARNING: Containers exited early: $EARLY_EXIT"
        echo "    Showing logs for first early exit:"
        docker logs "$(echo "$EARLY_EXIT" | head -1)" --tail 20 2>&1 | sed 's/^/    | /'
    fi

    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo ""
        echo "ERROR: Timeout waiting for all containers to be ready."
        echo "       Containers that did NOT signal ready:"
        READY_LIST=$(ls "$RESULTS_DIR/ready/" 2>/dev/null)
        for name in cm-a-llm ra-a-llm de-a-llm rv-a-llm cm-b-llm ra-b-llm de-b-llm rv-b-llm \
                    cm-c-http ra-c-http rv-c-http ar-c-http cm-d-http ra-d-http rv-d-http ar-d-http \
                    attack-t1 attack-t2 attack-t3 attack-t4; do
            echo "$READY_LIST" | grep -q "^$name$" || echo "         $name"
        done
        docker ps --filter "name=${PREFIX}-" --format "table {{.Names}}\t{{.Status}}"
        exit 1
    fi
    sleep 2
done

# ── 12. Fire start signal ─────────────────────────────────────────────────────
echo "--> All containers ready. Firing start signal…"
touch "$RESULTS_DIR/start_flag"
START_EPOCH=$(date +%s)
echo "    Start fired at $(date -u '+%H:%M:%S UTC')"

# ── 13. Wait for all containers to finish ────────────────────────────────────
echo "--> Waiting for all containers to complete…"
ALL_CONTAINER_NAMES=$(docker ps -a --filter "name=${PREFIX}-" --format "{{.Names}}" | grep -v chain-builder)
docker wait $ALL_CONTAINER_NAMES > /dev/null
END_EPOCH=$(date +%s)
ELAPSED=$(( END_EPOCH - START_EPOCH ))
echo "    All containers finished. Wall time from start: ${ELAPSED}s"

# ── 14. Show per-container exit codes ────────────────────────────────────────
echo ""
echo "Container statuses:"
docker ps -a --filter "name=${PREFIX}-" --format "  {{.Names}}\t{{.Status}}" | sort

# ── 15. Aggregate results ────────────────────────────────────────────────────
echo ""
echo "--> Aggregating results…"
python3 scenarios/aggregate_llm_results.py \
    --dir "$RESULTS_DIR" \
    --out paper_evidence/llm_load_test.json

echo ""
echo "Results:"
echo "  paper_evidence/llm_load_test.json   — aggregated JSON"
echo "  paper_evidence/llm_agents/          — per-container JSON files"
echo ""
echo "Done."
