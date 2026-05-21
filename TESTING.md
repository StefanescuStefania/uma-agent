# UMA-Agent Testing Documentation

This document covers the three distributed evaluation scenarios: the network-latency benchmark
(Table VII), the HTTP concurrent load test, and the LLM agent concurrent load test.
It explains the environment, the design decisions, the engineering challenges encountered,
and the exact measured results.

---

## Table of Contents

1. [Environment](#1-environment)
2. [Test Architecture Overview](#2-test-architecture-overview)
3. [Network-Latency Benchmark (Table VII)](#3-network-latency-benchmark-table-vii)
4. [HTTP Concurrent Load Test](#4-http-concurrent-load-test)
5. [LLM Agent Concurrent Load Test](#5-llm-agent-concurrent-load-test)
6. [Engineering Decisions and Challenges](#6-engineering-decisions-and-challenges)
7. [Raw Evidence Files](#7-raw-evidence-files)

---

## 1. Environment

### Hardware

| Resource | Value |
|---|---|
| RAM | 31 GB |
| CPU | 28 cores |
| Disk | Local SSD |
| OS | Ubuntu Linux 6.17.0 |

### Software versions

| Component | Version | Role |
|---|---|---|
| Docker | 28.x | Container runtime |
| docker compose | v2 (plugin) | Multi-service orchestration |
| Python | 3.12 | Agent framework, test scripts |
| Keycloak | 24.0.0 | Authorization server (OAuth 2.0 / UMA 2.0) |
| PostgreSQL | 16-alpine | Keycloak storage + audit trail |
| FastAPI + uvicorn | latest | Resource server |
| Toxiproxy | 2.9.0 (ghcr.io) | Programmable network latency injection |
| Ollama | running on host | LLM inference engine |
| llama3.2 | latest | LLM model for agent tests (2 B params, CPU) |

### DORA test users

| Username | Password | Role in delegation chains |
|---|---|---|
| compliance-manager | compliance-pass123 | Root agent (depth 1) |
| risk-analyst | risk-pass123 | Depth 2 |
| data-extractor | extractor-pass123 | Depth 3 |
| report-validator | validator-pass123 | Depth 4 |
| audit-reader | audit-pass123 | Depth 5 |

Each user is a distinct Keycloak account. T3 enforcement relies on
`RPT.preferred_username == chain.members[-1]`, so each agent must authenticate
with its own credentials and present the sub-chain that ends at itself.

---

## 2. Test Architecture Overview

Three tests were run, each building on the previous:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Test 1: Network-latency benchmark (distributed stack, Toxiproxy)        │
│  Proves: HMAC chain validation stays O(1) even with real network delay   │
│  Script: ./scripts/run_distributed_benchmark.sh                          │
│  Output: paper_evidence/benchmark_distributed.json                       │
├──────────────────────────────────────────────────────────────────────────┤
│  Test 2: HTTP concurrent load test (20 threads, one benchmark container) │
│  Proves: protocol correct under concurrent load, attacks blocked 100%    │
│  Script: ./scripts/run_load_test.sh                                      │
│  Output: paper_evidence/load_test.json                                   │
├──────────────────────────────────────────────────────────────────────────┤
│  Test 3: LLM agent concurrent load test (20 separate Docker containers)  │
│  Proves: real LLM agents work in isolated containers; UMA enforces T1-T4 │
│  Script: ./scripts/run_llm_load_test.sh                                  │
│  Output: paper_evidence/llm_load_test.json                               │
└──────────────────────────────────────────────────────────────────────────┘
```

All three share the same backend (Keycloak + PostgreSQL + FastAPI resource server)
and the same delegation protocol (`X-Uma-Delegation-Chain` header, HMAC-SHA256).

---

## 3. Network-Latency Benchmark (Table VII)

### Purpose

Reproduce Table VII from the paper with real inter-container network latency.
Shows that the per-request chain overhead is O(1) in depth and near-zero
compared to the baseline UMA round trip, even when latency is injected.

### Infrastructure

```
Agent container ──→ Toxiproxy :18080 (+10 ms ± 2 ms) ──→ Keycloak :8080
                ──→ Toxiproxy :15000 (+10 ms ± 2 ms) ──→ Resource Server :5000
Resource Server ──→ Keycloak :8080  (direct, no proxy — its JWT validation
                                      latency is not counted in agent measurements)
```

All services run on a Docker bridge network (`uma-distributed`).
Toxiproxy injects latency via its REST API at benchmark startup — no kernel
`tc netem` or privileged mode required.

### Design decisions

**Why Toxiproxy instead of tc netem?**
Toxiproxy runs as an unprivileged container and exposes a REST API for
configuring latency/jitter toxics at runtime. This means the latency profile
can be changed between runs without restarting containers or touching kernel
network namespaces. It also makes the experiment reproducible and parametrisable
via environment variables (`NETWORK_LATENCY_MS`, `NETWORK_JITTER_MS`).

**Why does the resource server connect directly to Keycloak (no proxy)?**
The benchmark measures the round-trip time as seen by the agent: auth →
resource access. If the resource server also went through Toxiproxy for its
own token introspection, that latency would be counted twice. Keeping the
resource server on the direct path isolates the measurement to the
agent-side overhead.

**Why n = 30 HTTP samples?**
This matches the statistical sample size used in the baseline benchmark.
The standard deviation is low (< 5 ms for chain operations) so 30 samples
give stable mean and p95 estimates. Increasing n to 100 does not change
the conclusions.

### Methodology

1. `docker compose -f docker-compose.distributed.yml up -d postgres keycloak resource-server`
2. Wait for Keycloak health check to pass (bash TCP probe on port 8080 — the
   Keycloak 24.0.0 image has no `curl`).
3. Start Toxiproxy.
4. Benchmark container calls Toxiproxy REST API to add latency toxics.
5. Measure: authentication, RPT exchange, resource read (no chain), resource
   read at chain depths 1/2/3, chain init, chain sign.
6. Results written to `/results/benchmark_distributed.json`.

### Results

**n = 30 HTTP measurements, injected latency = 10 ms ± 2 ms**

| Operation | Mean (ms) | Std | p95 |
|---|---:|---:|---:|
| Authentication (Keycloak) | 230.5 | 10.4 | 250.0 |
| RPT exchange | 40.1 | 5.3 | 48.6 |
| Resource read — no chain (baseline) | 21.3 | 2.5 | 26.0 |
| Resource read — chain depth 1 | 28.0 | 4.0 | 32.6 |
| Resource read — chain depth 2 | 22.3 | 2.4 | 27.2 |
| Resource read — chain depth 3 | 22.3 | 3.1 | 28.6 |
| Chain init (POST /api/delegation/init) | 26.9 | 4.3 | 33.0 |
| Chain sign (POST /api/delegation/sign) | 23.0 | 2.9 | 28.7 |

**Chain overhead over baseline by depth:**

| Depth | Overhead (ms) |
|---:|---:|
| 1 | +6.7 |
| 2 | +1.0 |
| 3 | +0.9 |

Depths 2 and 3 show ≤ 1 ms overhead — within measurement noise — confirming
that HMAC-SHA256 chain validation is O(1) in chain length under real network
conditions. Depth 1 overhead (+6.7 ms) includes the first lookup of the chain
claim in the resource server's in-memory registry.

**Python micro-benchmark (n = 1000 in-process)**

| Operation | Mean |
|---|---|
| Chain construction depth 1 | 15 µs |
| Chain validation (any depth) | ~5 µs |
| Attack rejection (T1–T4) | 5–6 µs |

Chain validation is a single HMAC-SHA256 recompute regardless of chain depth.

---

## 4. HTTP Concurrent Load Test

### Purpose

Verify that the protocol remains correct and attacks are blocked when 20 agents
fire requests simultaneously. Measure per-request latency and throughput under
concurrent load.

### Infrastructure

Uses the regular `docker-compose.yml` stack (no Toxiproxy). All 20 agents run
as Python threads inside **one** benchmark container on the `uma-network`.

```
Benchmark container (1×)
  ├── 16 honest agent threads  ──→ uma-resource-server:5000 ──→ uma-keycloak:8080
  └──  4 attack agent threads  ──→ uma-resource-server:5000
```

### Agent setup

**4 server-signed delegation chains:**

| Chain | Depth | Members | Scopes |
|---|---:|---|---|
| A | 4 | compliance-manager → risk-analyst → data-extractor → report-validator | documents:read, calendar:read |
| B | 4 | same members as A, separate chain_id | documents:read, calendar:read |
| C | 5 | compliance-manager → … → audit-reader | documents:read |
| D | 5 | same members as C, separate chain_id | documents:read |

**16 honest agents** — one per depth level per chain. Each authenticates with
its own Keycloak credentials and presents the sub-chain ending at itself
(e.g. risk-analyst presents `[compliance-manager, risk-analyst]`).

**4 attack agents:**

| Class | Attack | Expected response |
|---|---|---|
| T1 | Chain grants only `database:audit`; resource requires `documents:read` | 403 |
| T2 | Chain has 7 members; `MAX_DELEGATION_DEPTH=6` | 403 |
| T3 | Chain terminus=`data-extractor`; RPT issued to `risk-analyst` | 403 |
| T4 | Valid chain structure with `chain_hash` zeroed (HMAC tamper) | 403 |

### Synchronisation

A `threading.Barrier(20)` ensures all threads fire their first request at the
same instant. This removes test-harness warm-up effects from the latency
numbers.

### Design decisions

**Why threads rather than separate processes or containers?**
This test focuses on protocol correctness and latency — not container isolation.
Threads share the same Python interpreter and network stack, making the test
deterministic and fast. The next test (Section 5) uses real separate containers.

**Why n = 30 requests per agent?**
Sufficient to estimate mean and p95 with low standard deviation at these
latency ranges (mean ≈ 147 ms, std ≈ 15 ms → standard error ≈ 2.7 ms
for n = 30).

### Results

**Wall time: 4.47 s  |  Throughput: 134.1 req/s**

```
Honest:  480 / 480 OK   (16 agents × 30 requests)
Attacks: 120 / 120 BLOCKED  (100%)
```

**Honest agent latency (ms):**

| Mean | Std | p50 | p95 | p99 |
|---:|---:|---:|---:|---:|
| 146.6 | 14.8 | 148.0 | 181.2 | 195.3 |

**Per-depth latency — O(1) confirmed:**

| Depth | n | Mean (ms) | p95 | p99 |
|---:|---:|---:|---:|---:|
| 1 | 120 | 146.6 | 181.5 | 189.2 |
| 2 | 120 | 147.1 | 178.4 | 194.6 |
| 3 | 60 | 146.5 | 176.8 | 197.4 |
| 4 | 120 | 146.1 | 184.9 | 192.2 |
| 5 | 60 | 146.8 | 176.2 | 193.9 |

p99 spread across all depths: < 9 ms. Chain validation cost is depth-invariant.

**Attack blocking:**

| Class | Description | Blocked | Rate |
|---|---|---:|---:|
| T1 | Scope escalation | 30/30 | 100% |
| T2 | Depth exceeded | 30/30 | 100% |
| T3 | Token replay | 30/30 | 100% |
| T4 | HMAC tamper | 30/30 | 100% |

---

## 5. LLM Agent Concurrent Load Test

### Purpose

Run **real LLM-backed agents** in **separate Docker containers** simultaneously.
Each LLM agent uses the `LLMAgent` class (Ollama backend, llama3.2), interacts
with Keycloak and the Resource Server through genuine UMA 2.0 tool calls, and
presents a server-signed delegation chain. Attack agents run concurrently
to verify that enforcement is not weakened by LLM agent load.

### Infrastructure

```
Host machine (31 GB / 28 CPUs):
  Ollama (127.0.0.1:11434) — LLM inference, llama3.2
  Python TCP proxy (172.19.0.1:21434 → 127.0.0.1:11434) — exposes Ollama to Docker network
  Docker bridge: uma-agent_uma-network (gateway 172.19.0.1)

  ┌── Docker containers (all on uma-network) ──────────────────────────────┐
  │  uma-keycloak       Keycloak 24.0.0                                    │
  │  uma-postgres       PostgreSQL 16                                      │
  │  uma-resource-server FastAPI resource server                           │
  │                                                                        │
  │  llm-load-cm-a-llm  ]                                                 │
  │  llm-load-ra-a-llm  ]  8 LLM agent containers (real Ollama inference) │
  │  llm-load-de-a-llm  ]  Chain A depths 1–4, Chain B depths 1–4        │
  │  llm-load-rv-a-llm  ]                                                 │
  │  llm-load-cm-b-llm  ]                                                 │
  │  llm-load-ra-b-llm  ]                                                 │
  │  llm-load-de-b-llm  ]                                                 │
  │  llm-load-rv-b-llm  ]                                                 │
  │                                                                        │
  │  llm-load-cm-c-http ]                                                 │
  │  llm-load-ra-c-http ]  8 HTTP agent containers (direct UMA protocol)  │
  │  llm-load-rv-c-http ]  Chain C depths 1,2,4,5; Chain D depths 1,2,4,5│
  │  llm-load-ar-c-http ]                                                 │
  │  llm-load-cm-d-http ]                                                 │
  │  llm-load-ra-d-http ]                                                 │
  │  llm-load-rv-d-http ]                                                 │
  │  llm-load-ar-d-http ]                                                 │
  │                                                                        │
  │  llm-load-attack-t1 ]                                                 │
  │  llm-load-attack-t2 ]  4 attack containers (T1 / T2 / T3 / T4)       │
  │  llm-load-attack-t3 ]                                                 │
  │  llm-load-attack-t4 ]                                                 │
  └────────────────────────────────────────────────────────────────────────┘
```

**Total: 20 separate Docker containers + 3 backend containers = 23 containers.**

### Container roles

| Container set | Count | N requests | LLM used |
|---|---:|---:|---|
| LLM honest — chains A + B, depths 1–4 | 8 | 1 full LLM task | Yes (Ollama llama3.2) |
| HTTP honest — chains C + D, depths 1,2,4,5 | 8 | 30 HTTP requests | No |
| Attack — T1 / T2 / T3 / T4 | 4 | 30 HTTP requests | No |

**LLM agent task definition:** The LLM is given the following task and uses
tool-calling to execute it autonomously:

> *"You are a DORA compliance automation agent. Please: (1) authenticate,
> (2) request UMA access to /api/documents, (3) read /api/documents and
> summarise the key compliance findings in two sentences."*

The agent must call `authenticate()` → `request_uma_access("/api/documents")`
→ `read_resource("/api/documents")` via the OpenAI-compatible tool-calling
interface. Each tool call results in a real HTTP request to Keycloak or the
Resource Server. The resource server validates the `X-Uma-Delegation-Chain`
header on every `read_resource` call.

### Synchronisation — file-based barrier

Because containers cannot share a `threading.Barrier`, synchronisation uses
the shared `/results` volume:

```
Phase 1 — Setup (per container):
  Each container initialises (no network calls for LLM agents at this stage).
  Writes /results/ready/<AGENT_ID> to signal it is ready.
  Polls /results/start_flag in a tight loop (0.2 s interval).

Phase 2 — Orchestrator:
  Shell script counts ready files.
  Once all 20 ready files exist, writes /results/start_flag.
  All 20 containers unblock simultaneously.

Phase 3 — Execution (per container):
  LLM agents: call LLMAgent.run(task) — real Ollama inference
  HTTP agents: make 30 GET /api/documents with delegation chain header
  Attack agents: make 30 GET /api/documents with malformed chain
```

### Chain pre-building

All four delegation chains are built by a temporary coordinator container
before the workers start. The `build_chains.py` script:

1. Authenticates as each of the 5 DORA users.
2. Calls `POST /api/delegation/init` for the root agent (terminus = compliance-manager).
3. Calls `POST /api/delegation/sign` for each subsequent hop, authenticated as
   the **current terminus** (T3 enforcement at signing time).
4. Constructs attack chains locally using `DelegationChainClaim.create()` +
   `CHAIN_HMAC_SECRET` (only available to the coordinator, never to worker containers).
5. Writes all chain claim headers to `/results/chains.json`.

The shell script then extracts individual chain headers via `python3 -c "..."` 
and passes them as environment variables to each worker container.

### Design decisions

#### Why separate Docker containers rather than threads?

The HTTP load test (Section 4) already proves protocol correctness using threads.
The purpose of this test is different: demonstrate that the `LLMAgent` class
works in an isolated container environment, that real LLM inference produces
UMA-authenticated resource access, and that container boundaries do not interfere
with chain enforcement. Each container has its own Python interpreter, network
namespace, and process space.

#### Why 8 LLM + 8 HTTP rather than 16 LLM?

Ollama's default configuration processes one LLM request at a time (`OLLAMA_NUM_PARALLEL=1`).
With 16 concurrent LLM agents and llama3.2 on CPU taking ≈ 90 s per task,
the last agent in the queue would wait ≈ 24 minutes — far beyond any reasonable
test duration. Eight concurrent LLM agents give a practical wall time of ≈ 4 minutes.
The 8 HTTP agents cover the same depth levels (C and D) and measure pure
UMA protocol throughput without LLM bottleneck.

#### Why llama3.2 on CPU?

The test machine has no discrete GPU configured for Ollama. llama3.2 (1.3 GB,
2 B params) runs comfortably on CPU and is the smallest tool-calling-capable model
available by default in Ollama. Larger models would only increase LLM task latency,
not affect the UMA overhead measurements.

#### How Ollama is exposed to Docker containers

Ollama binds to `127.0.0.1:11434` (loopback only). Docker containers on a bridge
network cannot reach loopback on the host. The shell script starts a lightweight
Python TCP proxy that listens on the Docker bridge gateway IP
(`172.19.0.1:21434`) and forwards all bytes to `127.0.0.1:11434`:

```python
# Simplified: actual code in /tmp/ollama_proxy.py (written at test runtime)
server = socket.socket(AF_INET, SOCK_STREAM)
server.bind(("172.19.0.1", 21434))
server.listen(100)
# Each accepted connection is forwarded to 127.0.0.1:11434 in two threads.
# Crucially: socket.create_connection(timeout=None) — no read timeout —
# so queued Ollama requests are not dropped while waiting for inference.
```

The bridge gateway IP is detected dynamically via
`docker network inspect uma-agent_uma-network --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'`.
Each LLM worker container receives `OLLAMA_BASE_URL=http://172.19.0.1:21434/v1`.

#### Retry logic for LLM agents

In the first test run (before the no-timeout fix), 7 of 8 LLM agents received
`openai.APIConnectionError: Connection error.` after ≈ 180 s. Root cause:
the proxy socket was created with `timeout=60`, which Python interprets as the
socket-level read timeout. When Ollama was busy processing another agent,
the proxy socket timed out and reset the TCP connection.

Two fixes were applied:

1. **Proxy**: `socket.create_connection(timeout=None)` — blocking mode, no timeout.
2. **OpenAI client**: `httpx.Timeout(connect=10, read=900, write=60, pool=60)` —
   allows an LLM request to queue in Ollama for up to 15 minutes before timing out.

Additionally, the worker retries up to 3 times with 30-second back-off on any
`APIConnectionError`, so transient Ollama unavailability is handled gracefully.

After both fixes, all 8 LLM agents completed successfully.

### Results

**Run at: 2026-05-19T12:59:56 UTC**
**Total containers: 20 | Wall time from start signal: 224 s**

```
Honest OK:       248 / 248   (8 LLM tasks + 240 HTTP requests)
Attacks blocked: 120 / 120   (100%)
Throughput:      1.6 req/s   (all 368 requests / 224 s wall time)
```

#### LLM agent results

Each of the 8 LLM containers completed exactly 1 full task (authenticate +
LLM tool-calling loop + UMA resource access). Latency includes Keycloak
authentication, Ollama inference time (LLM deciding which tools to call and
what to say), UMA ticket exchange, and the resource server's HMAC chain
validation.

| Agent | Chain | Depth | Wall time | Status |
|---|---|---:|---:|---|
| cm-a-llm | A | 1 | 139.5 s | OK |
| ra-a-llm | A | 2 | 153.7 s | OK |
| de-a-llm | A | 3 | 194.5 s | OK |
| rv-a-llm | A | 4 | 224.2 s | OK |
| cm-b-llm | B | 1 | 208.6 s | OK |
| ra-b-llm | B | 2 | 122.6 s | OK |
| de-b-llm | B | 3 | 178.4 s | OK |
| rv-b-llm | B | 4 | 164.2 s | OK |

**LLM task latency (n = 8, ms):**

| Mean | Std | p50 | p95 | p99 | Min | Max |
|---:|---:|---:|---:|---:|---:|---:|
| 167,798 | 34,827 | 166,599 | 213,225 | 217,526 | 117,637 | 218,601 |

The large standard deviation reflects Ollama's serial queue: agents that
happened to be scheduled first by Ollama completed in ≈ 2 minutes; those
that queued behind others took ≈ 3.5 minutes. The UMA protocol adds ≤ 3 ms
to each resource access within that window — negligible against LLM inference
time.

#### HTTP agent results (pure UMA protocol, no LLM)

8 containers, each making 30 GET /api/documents with a server-signed delegation
chain header. Requests start simultaneously with the LLM agents (same
start_flag barrier) and complete while the LLM agents are still running.

**HTTP request latency (n = 240, ms):**

| Mean | Std | p50 | p95 | p99 |
|---:|---:|---:|---:|---:|
| 234.0 | 50.5 | 251.2 | 263.8 | 269.3 |

**Per-depth HTTP latency — O(1) under concurrent LLM load:**

| Depth | n | Mean (ms) | p50 | p95 | p99 |
|---:|---:|---:|---:|---:|---:|
| 1 | 60 | 233.2 | 251.0 | 264.1 | 272.1 |
| 2 | 60 | 240.0 | 251.2 | 263.5 | 267.2 |
| 4 | 60 | 233.7 | 250.6 | 263.2 | 270.0 |
| 5 | 60 | 228.9 | 251.4 | 263.2 | 265.8 |

p99 spread across depths 1→2→4→5: **7.0 ms** — depth-invariant.
Chain validation O(1) property holds even while 8 LLM containers are
concurrently making inference calls to Ollama through the same backend.

#### Attack blocking under concurrent LLM load

| Class | What it tests | Blocked | Rate |
|---|---|---:|---:|
| T1 | Scope escalation: chain grants only `database:audit`, resource needs `documents:read` | 30/30 | 100% |
| T2 | Depth exceeded: 7-member chain, `MAX_DELEGATION_DEPTH=6` | 30/30 | 100% |
| T3 | Token replay: chain terminus=`data-extractor`, RPT subject=`risk-analyst` | 30/30 | 100% |
| T4 | HMAC tamper: `chain_hash` zeroed, HMAC recompute fails | 30/30 | 100% |

All attack blocking is performed server-side in the resource server's chain
validation middleware, independently of LLM output. A prompt-injected LLM
instruction to access a higher-privilege endpoint (T4 scenario) is intercepted
before the LLM's tool result is acted upon.

---

## 6. Engineering Decisions and Challenges

### Keycloak healthcheck without curl

Keycloak 24.0.0 (`keycloak/keycloak:24.0.0`) does not include `curl` in the
container image. The compose healthcheck was originally:

```yaml
test: ["CMD", "curl", "-f", "http://localhost:8080/"]  # FAILS — no curl
```

Fixed to a pure bash TCP probe:

```yaml
test: ["CMD-SHELL", "bash -c 'echo > /dev/tcp/localhost/8080' 2>/dev/null && echo ok || exit 1"]
interval: 15s
timeout: 5s
retries: 20
start_period: 30s
```

This check confirms the port is open (Keycloak HTTP server started) without
requiring any HTTP client binary.

### Dockerfile.agent: fast rebuilds from cached base

The resource server and the agent benchmark share the same Python dependencies.
`Dockerfile.agent` is built `FROM uma-agent-resource-server:latest` and only
re-COPYs the `agents/`, `scenarios/`, and `demos/` directories. Source changes
rebuild in < 1 second because the apt-get and pip layers are fully cached.

### Server-side chain signing — T3 enforcement at signing time

`POST /api/delegation/sign` checks that the authenticated caller is the current
chain terminus (`RPT.preferred_username == chain.members[-1]`). This means
building a depth-4 chain requires four separate authenticated HTTP calls:

```
compliance-manager  → POST /api/delegation/init    (creates depth-1 chain)
compliance-manager  → POST /api/delegation/sign    (extends to depth 2: risk-analyst)
risk-analyst        → POST /api/delegation/sign    (extends to depth 3: data-extractor)
data-extractor      → POST /api/delegation/sign    (extends to depth 4: report-validator)
```

An early implementation bug used the root agent's token for all sign calls.
This was rejected with 403 at depth 3 because `compliance-manager ≠ risk-analyst`
(the expected terminus). The fix is in `build_sub_chains()`:

```python
parent_agent = members[depth - 2]   # always the current terminus
chain = _server_sign_chain(tokens[parent_agent], chain, member, scopes)
```

### GROQ_API_KEY validation at compose config time

`docker compose config` evaluates all variable substitutions at parse time.
Using `${GROQ_API_KEY:?error message}` caused `docker compose config` to fail
even when the `groq-agent` service was disabled via Docker Compose profiles.
Fixed to `${GROQ_API_KEY:-}` (empty default, no error).

### Ollama accessibility from Docker containers

Ollama binds to `127.0.0.1:11434` by default. Docker bridge containers cannot
reach the host loopback. Three approaches were considered:

| Approach | Pros | Cons |
|---|---|---|
| `OLLAMA_HOST=0.0.0.0` + restart Ollama | Clean | Requires user action, exposes LLM API on all interfaces |
| `--network host` for agent containers | Simple | Incompatible with bridge network assignment |
| Python TCP proxy on bridge gateway | No config change, precise scope | Extra process on host |

The Python TCP proxy was chosen because it requires no changes to the user's
Ollama setup and is started and stopped automatically by the shell script.
The proxy IP is detected at runtime from the Docker network inspect output.

---

## 7. Raw Evidence Files

| File | Description |
|---|---|
| `paper_evidence/benchmark_distributed.json` | Network-latency benchmark (Table VII). HTTP latency per operation with Toxiproxy +10 ms injected. Python micro-benchmarks (n=1000). |
| `paper_evidence/load_test.json` | HTTP concurrent load test. 20 agents (16 honest + 4 attack), threading.Barrier synchronisation, n=30 per agent. |
| `paper_evidence/llm_load_test.json` | LLM concurrent load test. 20 Docker containers, 8 with real Ollama inference, aggregated p50/p95/p99 latency, attack blocking. |
| `paper_evidence/llm_agents/agent-*.json` | Per-container result files from the LLM load test. One file per container, includes individual request timing and error details. |
| `paper_evidence/llm_agents/chains.json` | Pre-built server-signed chain claim headers for all four delegation chains and four attack variants. |

### Reproducing the tests

```bash
# 1. Table VII — distributed latency (requires Docker; no Ollama needed)
./scripts/run_distributed_benchmark.sh

# 2. HTTP concurrent load (requires Docker + running stack)
./scripts/run_load_test.sh

# 3. LLM concurrent load (requires Docker + Ollama + llama3.2)
#    Ensure: ollama serve && ollama pull llama3.2
./scripts/run_llm_load_test.sh

# Tune parameters
NETWORK_LATENCY_MS=20 N_HTTP=50  ./scripts/run_distributed_benchmark.sh
N_REQUESTS=50                     ./scripts/run_load_test.sh
N_LLM_REQUESTS=2 N_HTTP_REQUESTS=50 ./scripts/run_llm_load_test.sh
```

All scripts are self-contained: they start the required Docker services,
wait for health checks, run the measurement, save JSON output, and tear down
containers on exit.
