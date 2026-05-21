# UMA-Agent: Secure AI Agent Delegation via UMA 2.0

A protocol extension to [User-Managed Access 2.0](https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html) that enforces authorized delegation chains for multi-agent LLM systems.

**Protocol extension URN:** `urn:uma-agent:delegation-chain:1.0`
**Transport:** `X-Uma-Delegation-Chain` header (base64url-encoded, HMAC-SHA256 signed)

---

## What it adds to plain UMA

Standard UMA 2.0 validates *who* holds a token. UMA-Agent adds:

| Property | Plain UMA | UMA-Agent |
|---|---|---|
| Agent identity tracking | ✗ | ✓ chain_id, members[] |
| Delegation depth limit | ✗ | ✓ max_depth enforced |
| Scope monotonicity across hops | ✗ | ✓ child ⊆ parent scopes |
| Chain tamper detection | ✗ | ✓ HMAC-SHA256 independent of AS |
| T4 prompt injection protection | ✗ | ✓ server-side, LLM-independent |
| Tamper-evident audit trail | ✗ | ✓ HMAC hash chain in PostgreSQL |

---

## Attack classes blocked

| Class | Description | Enforcement |
|---|---|---|
| **T1** | Scope escalation — agent requests scope not in chain | `granted_scopes` check |
| **T2** | Depth exceeded — chain longer than `max_depth` | `len(members) ≤ max_depth` |
| **T3** | Token replay — chain presented by wrong terminus | `X-Agent-Id == members[-1]` |
| **T4** | Prompt injection — injected LLM instruction causes unauthorized scope request | Server-side; independent of LLM output |
| **TAMPER** | Chain forgery — contents modified without HMAC secret | `chain_hash` recomputed on every request |

---

## Stack

- **Keycloak 24.0.0** `:8080` — authorization server (OAuth 2.0 / UMA 2.0)
- **PostgreSQL 16** `:5432` — Keycloak storage + tamper-evident audit trail
- **FastAPI** `:5000` — resource server with chain validation middleware
- **Python 3.12** — agent framework, scenarios, tests

---

## Quick start

```bash
# 1. Start services
docker compose up -d

# 2. Initialize realm + users (wait ~30s for Keycloak)
python3 keycloak/init-keycloak.py

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Run tests (no LLM needed — offline by default)
python3 -m pytest tests/ -q
# → 273 passed (integration tests auto-skip when servers are down)
```

---

## Scenarios

All scenarios write to stdout and optionally to a JSON file via `--json-out`.

```bash
# DORA Article 9 compliance workflow — 4-phase, real LLM (Ollama or Groq)
python3 scenarios/dora_article9_workflow.py [--backend groq] [--json-out results.json]

# Deep delegation demo — 5-agent chain, scope narrowing at each hop, T1 attack at depth 5
python3 scenarios/deep_delegation_demo.py [--json-out results.json]

# Attack scenarios — T1/T2/T3/T4/TAMPER over real HTTP
python3 scenarios/attack_scenarios.py [--json-out results.json]

# Statistical benchmark — n=30 HTTP, n=1000 Python, baseline vs chain overhead
python3 scenarios/benchmark.py [--json-out results.json]

# Comparison analysis — feature matrix vs RFC 8693 / Macaroons / Biscuits
python3 scenarios/comparison_analysis.py [--json-out results.json]
```

---

## Key benchmark numbers

| Operation | Mean (ms) | Std | p95 |
|---|---|---|---|
| Authentication (Keycloak password grant) | 197.4 | 2.1 | 202.8 |
| RPT exchange (ticket → token) | 10.2 | 2.2 | 13.5 |
| Resource read — plain UMA (no chain) | 16.0 | 3.5 | 20.0 |
| Resource read + chain depth 1 | 19.4 | 4.4 | 25.6 |
| Resource read + chain depth 2 | 15.5 | 3.3 | 20.2 |
| Resource read + chain depth 3 | 16.0 | 2.8 | 20.8 |
| Chain init (POST /api/delegation/init) | 20.1 | 3.0 | 24.6 |
| Chain sign (POST /api/delegation/sign) | 18.3 | 3.1 | 23.0 |
| Chain validation (Python, any depth) | ~5 µs | — | — |

Chain validation is O(1) — single HMAC verify, depth-invariant.
Per-request chain overhead over plain UMA is 0–3 ms (within noise).
Chain signing adds ~18–20 ms per delegation hop, incurred once at agent startup.

---

## Distributed evaluation — separate containers with network latency

The `docker-compose.distributed.yml` stack reproduces Table VII (network latency)
and the concurrent load test from the paper's evaluation section.
All services run in **separate containers** on a Docker bridge network;
[Toxiproxy](https://github.com/Shopify/toxiproxy) injects a configurable
per-hop delay (default **10 ms ± 2 ms**) between the agent containers and
the backend services.

### Architecture

```
Agent container ──→ Toxiproxy :18080 ──→ Keycloak :8080
                ──→ Toxiproxy :15000 ──→ Resource Server :5000
Resource Server ──→ Keycloak :8080  (direct, no proxy)
```

### How the containers are built

**Keycloak** (`keycloak/keycloak:24.0.0`):
- Realm imported on first start from `keycloak/` (read-only mount)
- Healthcheck uses `bash -c 'echo > /dev/tcp/localhost/8080'`
  (the image has no `curl` — a pitfall to be aware of)

**Resource Server** (built from `Dockerfile`):
- `python:3.12-slim` + FastAPI + uvicorn
- `CHAIN_HMAC_SECRET` set via env; never exposed to agents
- Talks directly to Keycloak (no proxy) so its own JWT validation latency
  is not counted in the agent-side measurements

**Agent / Benchmark container** (built from `Dockerfile.agent`):
- Builds `FROM uma-agent-resource-server:latest` (reuses cached apt/pip layers — <1 s build)
- Only re-COPYs `agents/`, `scenarios/`, `demos/` so source changes are instant
- Connects to Keycloak and Resource Server through Toxiproxy
- Also used for the optional Ollama / Groq LLM agent demos (Docker Compose profiles)

**Toxiproxy** (`ghcr.io/shopify/toxiproxy:2.9.0`):
- Proxy definitions loaded from `docker/toxiproxy.json`
- Latency toxics injected at benchmark startup via REST API (no privileged `tc netem` needed)
- Inspect live: `curl http://localhost:8474/proxies`

### Network-latency benchmark results (n = 30, +10 ms per hop)

| Operation | Mean (ms) | Std | p95 | Overhead |
|---|---:|---:|---:|---:|
| Authentication (Keycloak) | 230.5 | 10.4 | 250.0 | — |
| RPT exchange | 40.1 | 5.3 | 48.6 | — |
| Resource read — no chain | 21.3 | 2.5 | 26.0 | baseline |
| Resource read — depth 1 | 28.0 | 4.0 | 32.6 | +6.7 ms |
| Resource read — depth 2 | 22.3 | 2.4 | 27.2 | +1.0 ms |
| Resource read — depth 3 | 22.3 | 3.1 | 28.6 | +0.9 ms |
| Chain init | 26.9 | 4.3 | 33.0 | one-time/root |
| Chain sign | 23.0 | 2.9 | 28.7 | one-time/hop |

Chain overhead at depths 2–3 is **≤ 1 ms** even with real network latency —
HMAC validation remains O(1) under network conditions.

### Concurrent load test — HTTP agents (20 agents, n = 30 req/agent)

**Setup:** 4 server-signed delegation chains (depth 4 and 5), one agent per depth
level per chain (16 honest agents) + 4 attack agents (T1–T4).
Each agent authenticates with their **own** Keycloak credentials.
The chain terminus must match the RPT's `preferred_username` (T3 enforcement).
All 20 agents start simultaneously behind a `threading.Barrier`.

```
Wall time:     4.47 s      Throughput: 134.1 req/s
Honest:   480 / 480 OK    Attacks blocked: 120 / 120  (100 %)
```

**Honest agent latency under concurrent load:**

| Mean | p50 | p95 | p99 |
|---:|---:|---:|---:|
| 146.6 ms | 148.0 ms | 181.2 ms | 195.3 ms |

**Per-depth latency — O(1) under concurrent load:**

| Depth | n | Mean (ms) | p95 | p99 |
|---:|---:|---:|---:|---:|
| 1 | 120 | 146.6 | 181.5 | 189.2 |
| 2 | 120 | 147.1 | 178.4 | 194.6 |
| 3 | 60 | 146.5 | 176.8 | 197.4 |
| 4 | 120 | 146.1 | 184.9 | 192.2 |
| 5 | 60 | 146.8 | 176.2 | 193.9 |

All depths indistinguishable (p99 spread < 9 ms).

**Attack blocking under concurrent load:**

| Class | Blocked | Rate |
|---|---:|---:|
| T1 — scope escalation | 30/30 | 100% |
| T2 — depth exceeded | 30/30 | 100% |
| T3 — token replay | 30/30 | 100% |
| T4 — HMAC tamper | 30/30 | 100% |

---

### LLM agent concurrent load test — 20 separate Docker containers

This test runs **real LLM-backed agents** (`LLMAgent` + Ollama/llama3.2) each in
their own Docker container, sharing only the Keycloak and Resource Server backend.

**Container breakdown:**

| Role | Count | Backend | Requests |
|---|---:|---|---:|
| LLM honest agents (chains A + B, depths 1–4) | 8 | Ollama llama3.2 | 1 task/agent |
| HTTP honest agents (chains C + D, depths 1,2,4,5) | 8 | Direct HTTP | 30 req/agent |
| Attack agents (T1, T2, T3, T4) | 4 | Direct HTTP | 30 req/agent |
| **Total** | **20** | | **368 requests** |

**Results (measured on 31 GB / 28-CPU host, Ollama llama3.2):**

```
Containers:    20 separate Docker containers, simultaneous start
Honest OK:     248 / 248     Attacks blocked: 120 / 120  (100 %)
Wall time:     224 s         Throughput:      1.6 req/s
```

**LLM agent task latency** (includes Keycloak auth + LLM reasoning + UMA ticket + resource read):

| Mean | p50 | p95 | p99 |
|---:|---:|---:|---:|
| 167.8 s | 166.6 s | 213.2 s | 217.5 s |

*Note: Ollama serialises LLM requests; 8 concurrent agents queue behind one another.
The UMA protocol adds ≤ 3 ms overhead — HMAC validation is O(1) regardless of LLM latency.*

**HTTP agent latency under concurrent LLM load** (pure UMA protocol, no LLM):

| Mean | p50 | p95 | p99 |
|---:|---:|---:|---:|
| 234.0 ms | 251.2 ms | 263.8 ms | 269.3 ms |

**Per-depth HTTP latency — O(1) confirmed under LLM load:**

| Depth | n | Mean (ms) | p95 | p99 |
|---:|---:|---:|---:|---:|
| 1 | 60 | 233.2 | 264.1 | 272.1 |
| 2 | 60 | 240.0 | 263.5 | 267.2 |
| 4 | 60 | 233.7 | 263.2 | 270.0 |
| 5 | 60 | 228.9 | 263.2 | 265.8 |

All depths indistinguishable (p99 spread < 7 ms). Chain validation cost is depth-invariant even when 20 containers run concurrently.

**Attack blocking:**

| Class | Blocked | Rate |
|---|---:|---:|
| T1 — scope escalation | 30/30 | 100% |
| T2 — depth exceeded | 30/30 | 100% |
| T3 — token replay | 30/30 | 100% |
| T4 — HMAC tamper | 30/30 | 100% |

### Running the distributed tests

```bash
# Network-latency benchmark (Table VII)
./scripts/run_distributed_benchmark.sh

# HTTP concurrent load test (20 threads in one container)
./scripts/run_load_test.sh

# LLM concurrent load test (20 separate Docker containers, real Ollama inference)
# Prerequisites: Ollama running with llama3.2 pulled (ollama pull llama3.2)
./scripts/run_llm_load_test.sh

# Tune parameters
NETWORK_LATENCY_MS=20 N_HTTP=50 ./scripts/run_distributed_benchmark.sh
N_REQUESTS=50 NETWORK_LATENCY_MS=15 ./scripts/run_load_test.sh
N_LLM_REQUESTS=2 N_HTTP_REQUESTS=50 ./scripts/run_llm_load_test.sh

# Optional LLM agent demos
docker compose -f docker-compose.distributed.yml --profile ollama up --build ollama-agent
GROQ_API_KEY=gsk_... docker compose -f docker-compose.distributed.yml --profile groq up --build groq-agent
```

Raw JSON results:
- `evaluation_results/benchmark_distributed.json` — Table VII distributed latency
- `evaluation_results/load_test.json` — HTTP concurrent load (20 threads)
- `evaluation_results/llm_load_test.json` — LLM concurrent load (20 containers)

---

## Repository structure

```
uma-agent/
├── agents/
│   ├── chain_claim.py          # DelegationChainClaim — the protocol extension
│   ├── llm_agent.py            # LLMAgent with UMA tool calling (Ollama / Groq)
│   ├── uma_client.py           # UMA 2.0 token client (auth, RPT exchange)
│   └── database.py             # PostgreSQL audit trail writer
│
├── resource_server/
│   └── app.py                  # FastAPI server — chain validation middleware
│
├── keycloak/
│   └── init-keycloak.py        # Realm, clients, users, resources setup
│
├── scenarios/
│   ├── dora_article9_workflow.py   # DORA Article 9 use case
│   ├── deep_delegation_demo.py     # 5-agent chain with flux visualization
│   ├── attack_scenarios.py         # T1–T4 + TAMPER live HTTP demonstrations
│   ├── benchmark.py                # Statistical latency benchmark
│   ├── benchmark_distributed.py    # Distributed latency benchmark (Toxiproxy)
│   ├── load_test.py                # HTTP concurrent load test (20 threads)
│   ├── build_chains.py             # Pre-build delegation chains for LLM load test
│   ├── llm_agent_worker.py         # Single-agent worker for LLM load test containers
│   ├── aggregate_llm_results.py    # Aggregate per-container LLM load test results
│   └── comparison_analysis.py      # Feature matrix vs alternatives
│
├── tests/                      # 273 tests (integration tests auto-skip if servers down)
│   ├── test_chain_claim.py         # 60 tests — T1–T4, HMAC, attack priority
│   ├── test_llm_agent.py           # 30 tests — chain construction, scope monotonicity
│   ├── test_resource_server_protocol.py  # 25 tests — protocol + delegation endpoints
│   ├── test_dora_workflow.py        # 35 tests — PhaseTimer, phases, build_summary
│   ├── test_attack_scenarios.py     # 25 tests — T1/T2/T3/TAMPER offline + HTTP
│   ├── test_benchmark.py            # 27 tests — stats, measure, O(1) assertion
│   ├── test_comparison_analysis.py  # 33 tests — feature matrix, LOC, latency
│   └── test_deep_delegation_demo.py # 38 tests — 5-agent chain, visualization, verify
│
├── demos/
│   └── dora_llm_demo.py        # Interactive LLM demo (authorized / delegated / T4)
│
├── scripts/
│   ├── init_database.py            # Initialize PostgreSQL tables
│   ├── create_test_users.py        # Create Keycloak DORA users
│   ├── reset_test_users.py         # Reset users to clean state
│   ├── fix_test_users.py           # Fix user configuration issues
│   ├── view_audit_trail.py         # Query and display audit events
│   ├── run_distributed_benchmark.sh # Table VII: network-latency benchmark
│   ├── run_load_test.sh            # HTTP concurrent load test (20 threads)
│   └── run_llm_load_test.sh        # LLM concurrent load test (20 Docker containers)
│
├── docker/
│   └── toxiproxy.json          # Toxiproxy proxy definitions for distributed stack
│
├── evaluation_results/
│   ├── benchmark_distributed.json  # Table VII measured results
│   ├── load_test.json              # HTTP load test results
│   ├── llm_load_test.json          # LLM load test results (20 containers)
│   └── llm_agents/                 # Per-agent JSON outputs from LLM load test
│
├── docker-compose.yml              # Keycloak + PostgreSQL + resource server
├── docker-compose.distributed.yml  # Distributed stack with Toxiproxy
├── Dockerfile                      # Resource server image
├── Dockerfile.agent                # Agent/benchmark image (built from RS image)
├── TESTING.md                      # Detailed distributed evaluation documentation
├── start.sh                        # Convenience script to bring up the full stack
└── requirements.txt
```

---

## LLM backends

The agent framework uses the OpenAI-compatible API and supports two free backends:

| Backend | Flag | Default model | Notes |
|---|---|---|---|
| Ollama (local) | `--backend ollama` | `llama3.2` | No API key, runs locally |
| Groq (cloud) | `--backend groq` | `llama-3.3-70b-versatile` | Free tier, set `GROQ_API_KEY` |

Scenarios that don't use `--backend` (like `deep_delegation_demo.py`) call `_dispatch_tool` directly and require no LLM.

---

## Test users (DORA scenario)

| User | Password | Role |
|---|---|---|
| compliance-manager | compliance-pass123 | Root agent — full scopes |
| risk-analyst | risk-pass123 | Depth 2 — documents + database |
| data-extractor | extractor-pass123 | Depth 3 — database only |
| report-validator | validator-pass123 | Depth 4 — database read-only |
| audit-reader | audit-pass123 | Depth 5 — database read (deep delegation demo) |

---

## Audit endpoints

| Endpoint | Description |
|---|---|
| `GET /api/audit/verify` | Recompute HMAC chain; report `chain_intact` + `broken_links` |
| `GET /api/audit/events` | All audit events with agent_id, resource, scope, attack_class |
| `GET /api/audit/security-blocks` | Events where access was denied, grouped by attack class |
| `GET /api/delegation-chains` | Registered DelegationChainClaims with full membership |

---

## Defense-in-depth: what if the authorization server is compromised?

The `chain_hash` field is `HMAC-SHA256(CHAIN_HMAC_SECRET, canonical_json)` where `CHAIN_HMAC_SECRET` lives only on the resource server — it is never shared with Keycloak. An attacker who can forge RPTs (AS compromise) still cannot construct a valid chain claim without this secret. Any forgery attempt is rejected as TAMPER and recorded in the audit trail.

---

## Citation

```bibtex
@software{uma_agent_2026,
  author  = {Stefanescu, Stefania},
  title   = {UMA-Agent: Secure AI Agent Delegation via UMA 2.0},
  year    = {2026},
  url     = {https://github.com/StefanescuStefania/uma-agent}
}
```
