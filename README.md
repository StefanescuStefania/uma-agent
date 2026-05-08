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

## Repository structure

```
uma-agent/
├── agents/
│   ├── chain_claim.py          # DelegationChainClaim — the protocol extension
│   └── llm_agent.py            # LLMAgent with UMA tool calling (Ollama / Groq)
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
│   └── comparison_analysis.py     # Feature matrix vs alternatives
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
│   ├── init_database.py        # Initialize PostgreSQL tables
│   ├── create_test_users.py    # Create Keycloak DORA users
│   ├── reset_test_users.py     # Reset users to clean state
│   ├── fix_test_users.py       # Fix user configuration issues
│   └── view_audit_trail.py     # Query and display audit events
│
├── docker-compose.yml          # Keycloak + PostgreSQL + resource server
├── Dockerfile                  # Resource server image
├── requirements.txt
└── start.sh                    # One-shot startup helper
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
