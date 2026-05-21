#!/usr/bin/env python3
"""
UMA Agent — Concurrent Load Test (20 agents, 4 chains, depth 4-5)

Architecture
────────────
  4 server-signed delegation chains (depth 4 and 5):
    Chain A (depth 4): compliance-manager → risk-analyst → data-extractor → report-validator
    Chain B (depth 4): same members, separate chain_id (second parallel instance)
    Chain C (depth 5): compliance-manager → risk-analyst → data-extractor → report-validator → audit-reader
    Chain D (depth 5): same members as C, separate chain_id

  16 honest agents — 4 per chain, one at each depth level.
  Each agent authenticates with their OWN Keycloak credentials and presents
  the sub-chain whose terminus matches their preferred_username:
    e.g., risk-analyst presents the depth-2 sub-chain [compliance-manager, risk-analyst]

  4 attack agents — one per threat class:
    T1  scope escalation  — chain grants database:audit, accesses /api/documents (needs documents:read)
    T2  depth exceeded    — chain has 7 members, MAX_DELEGATION_DEPTH=6
    T3  token replay      — chain terminus=data-extractor but RPT issued to risk-analyst
    T4  HMAC tamper       — valid chain with corrupted chain_hash

Metrics
───────
  • Throughput (req/s) across all honest agents
  • Honest latency: p50 / p95 / p99
  • Attack blocking: confirmed 100% for T1-T4 under concurrent load
  • Per-chain and per-depth breakdown

Configuration
─────────────
  KEYCLOAK_URL        http://localhost:8080
  RESOURCE_SERVER_URL http://localhost:5000
  KEYCLOAK_REALM      test-realm
  CLIENT_ID           test-app
  CHAIN_HMAC_SECRET   uma-agent-chain-hmac-secret-2024
  TOXIPROXY_API       (optional — adds latency if set)
  NETWORK_LATENCY_MS  10
  NETWORK_JITTER_MS   2
  N_REQUESTS          30  (per agent)
  N_WORKERS           20  (total agents)

Usage
─────
  python3 scenarios/load_test.py
  python3 scenarios/load_test.py --n-requests 50 --json-out paper_evidence/load_test.json
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.chain_claim import DelegationChainClaim

# ─── Configuration ────────────────────────────────────────────────────────────

KEYCLOAK_URL       = os.environ.get("KEYCLOAK_URL",        "http://localhost:8080")
REALM              = os.environ.get("KEYCLOAK_REALM",       "test-realm")
RESOURCE_SERVER    = os.environ.get("RESOURCE_SERVER_URL",  "http://localhost:5000")
CLIENT_ID          = os.environ.get("CLIENT_ID",            "test-app")
CHAIN_SECRET       = os.environ.get("CHAIN_HMAC_SECRET",    "uma-agent-chain-hmac-secret-2024")
TOXIPROXY_API      = os.environ.get("TOXIPROXY_API",        None)
NETWORK_LATENCY_MS = int(os.environ.get("NETWORK_LATENCY_MS", "10"))
NETWORK_JITTER_MS  = int(os.environ.get("NETWORK_JITTER_MS",  "2"))

# DORA users: username → password
DORA_USERS = {
    "compliance-manager": "compliance-pass123",
    "risk-analyst":       "risk-pass123",
    "data-extractor":     "extractor-pass123",
    "report-validator":   "validator-pass123",
    "audit-reader":       "audit-pass123",
}

# ─── Service readiness & Toxiproxy ────────────────────────────────────────────

def _wait_for_services(timeout: int = 240) -> None:
    checks: List[Tuple[str, str]] = []
    if TOXIPROXY_API:
        checks.append((f"{TOXIPROXY_API}/version", "Toxiproxy"))
    checks.append((f"{KEYCLOAK_URL}/realms/{REALM}", "Keycloak"))
    checks.append((f"{RESOURCE_SERVER}/",            "Resource Server"))
    deadline = time.time() + timeout
    for url, name in checks:
        print(f"  Waiting for {name}…", end=" ", flush=True)
        while time.time() < deadline:
            try:
                if requests.get(url, timeout=5).status_code < 500:
                    print("ready"); break
            except requests.RequestException:
                pass
            time.sleep(3)
        else:
            raise RuntimeError(f"{name} not ready after {timeout}s at {url}")


def _configure_toxiproxy() -> None:
    if not TOXIPROXY_API or NETWORK_LATENCY_MS == 0:
        return
    print(f"  Injecting latency: {NETWORK_LATENCY_MS} ms ± {NETWORK_JITTER_MS} ms…",
          end=" ", flush=True)
    for proxy_name in ("keycloak", "resource-server"):
        try:
            requests.post(
                f"{TOXIPROXY_API}/proxies/{proxy_name}/toxics",
                json={"name": "latency", "type": "latency", "stream": "downstream",
                      "attributes": {"latency": NETWORK_LATENCY_MS,
                                     "jitter":  NETWORK_JITTER_MS}},
                timeout=5,
            )
        except requests.RequestException:
            pass
    print("done")


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _get_token(username: str, password: str) -> str:
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": CLIENT_ID,
              "username": username, "password": password, "scope": "openid"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _get_rpt(resource_path: str, user_token: str) -> Optional[str]:
    probe = requests.get(f"{RESOURCE_SERVER}{resource_path}", timeout=15)
    m = re.search(r'ticket="([^"]+)"', probe.headers.get("WWW-Authenticate", ""))
    if not m:
        return None
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
              "ticket": m.group(1)},
        headers={"Authorization": f"Bearer {user_token}"},
        timeout=15,
    )
    return r.json().get("access_token") if r.status_code == 200 else None


# ─── Server-side chain building ───────────────────────────────────────────────

def _server_init_chain(token: str, scopes: List[str]) -> str:
    """POST /api/delegation/init → root chain (terminus = requesting user)."""
    r = requests.post(
        f"{RESOURCE_SERVER}/api/delegation/init",
        json={"requested_scopes": scopes},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["chain_claim"]


def _server_sign_chain(token: str, parent_chain: str,
                       child_agent_id: str, scopes: List[str]) -> str:
    """POST /api/delegation/sign → extend chain by one hop."""
    r = requests.post(
        f"{RESOURCE_SERVER}/api/delegation/sign",
        json={"parent_chain": parent_chain,
              "child_agent_id": child_agent_id,
              "requested_scopes": scopes},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["chain_claim"]


def build_sub_chains(tokens: Dict[str, str], members: List[str],
                     scopes: List[str]) -> Dict[int, str]:
    """
    Build server-signed sub-chains for all prefix depths.

    Each sign step is authenticated with the CURRENT terminus agent's token
    (enforced by the resource server's T3 check on /api/delegation/sign).

    Returns {depth: chain_claim_b64} where depth = len(members[:depth]).
    """
    chains: Dict[int, str] = {}
    root_token = tokens[members[0]]
    chain = _server_init_chain(root_token, scopes)   # terminus = members[0]
    chains[1] = chain
    for depth, member in enumerate(members[1:], start=2):
        # The current terminus is members[depth-2]; they must sign the extension
        parent_agent = members[depth - 2]
        chain = _server_sign_chain(tokens[parent_agent], chain, member, scopes)
        chains[depth] = chain
    return chains


# ─── Statistics ───────────────────────────────────────────────────────────────

def _percentile(data: List[float], pct: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = (pct / 100) * (len(s) - 1)
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return round(s[lo] + (k - lo) * (s[hi] - s[lo]), 2)


def _stats(samples: List[float]) -> Dict[str, Any]:
    if not samples:
        return {}
    return {
        "n":      len(samples),
        "mean":   round(statistics.mean(samples), 2),
        "std":    round(statistics.stdev(samples), 2) if len(samples) > 1 else 0.0,
        "p50":    _percentile(samples, 50),
        "p95":    _percentile(samples, 95),
        "p99":    _percentile(samples, 99),
        "min":    round(min(samples), 2),
        "max":    round(max(samples), 2),
    }


# ─── Agent workers ────────────────────────────────────────────────────────────

@dataclasses.dataclass
class RequestRecord:
    agent_id:    str
    chain_id:    str
    depth:       int
    latency_ms:  float
    http_status: int
    agent_type:  str   # "honest" | "attack"
    attack_class: str  # "" | "T1" | "T2" | "T3" | "T4"
    blocked:     bool
    error:       str = ""


class HonestAgentWorker:
    def __init__(self, agent_id: str, chain_id: str, depth: int,
                 chain_claim: str, rpt: str,
                 barrier: threading.Barrier, n_requests: int) -> None:
        self.agent_id    = agent_id
        self.chain_id    = chain_id
        self.depth       = depth
        self.chain_claim = chain_claim
        self.rpt         = rpt
        self.barrier     = barrier
        self.n_requests  = n_requests

    def run(self) -> List[RequestRecord]:
        session = requests.Session()
        self.barrier.wait()                    # synchronised start
        records: List[RequestRecord] = []
        for _ in range(self.n_requests):
            t0 = time.perf_counter()
            try:
                r = session.get(
                    f"{RESOURCE_SERVER}/api/documents",
                    headers={"Authorization":       f"Bearer {self.rpt}",
                             "X-Uma-Delegation-Chain": self.chain_claim},
                    timeout=30,
                )
                latency = (time.perf_counter() - t0) * 1000
                records.append(RequestRecord(
                    agent_id=self.agent_id, chain_id=self.chain_id,
                    depth=self.depth, latency_ms=latency,
                    http_status=r.status_code, agent_type="honest",
                    attack_class="", blocked=(r.status_code == 403),
                ))
            except Exception as exc:
                latency = (time.perf_counter() - t0) * 1000
                records.append(RequestRecord(
                    agent_id=self.agent_id, chain_id=self.chain_id,
                    depth=self.depth, latency_ms=latency,
                    http_status=-1, agent_type="honest",
                    attack_class="", blocked=True, error=str(exc),
                ))
        return records


class AttackAgentWorker:
    def __init__(self, attack_class: str, chain_claim: str, rpt: str,
                 barrier: threading.Barrier, n_requests: int) -> None:
        self.attack_class = attack_class
        self.chain_claim  = chain_claim
        self.rpt          = rpt
        self.barrier      = barrier
        self.n_requests   = n_requests

    def run(self) -> List[RequestRecord]:
        session = requests.Session()
        self.barrier.wait()
        records: List[RequestRecord] = []
        for _ in range(self.n_requests):
            t0 = time.perf_counter()
            try:
                r = session.get(
                    f"{RESOURCE_SERVER}/api/documents",
                    headers={"Authorization":       f"Bearer {self.rpt}",
                             "X-Uma-Delegation-Chain": self.chain_claim},
                    timeout=30,
                )
                latency = (time.perf_counter() - t0) * 1000
                records.append(RequestRecord(
                    agent_id=f"attack-{self.attack_class}", chain_id="attack",
                    depth=-1, latency_ms=latency, http_status=r.status_code,
                    agent_type="attack", attack_class=self.attack_class,
                    blocked=(r.status_code == 403),
                ))
            except Exception as exc:
                latency = (time.perf_counter() - t0) * 1000
                records.append(RequestRecord(
                    agent_id=f"attack-{self.attack_class}", chain_id="attack",
                    depth=-1, latency_ms=latency, http_status=-1,
                    agent_type="attack", attack_class=self.attack_class,
                    blocked=True, error=str(exc),
                ))
        return records


# ─── Setup phase ──────────────────────────────────────────────────────────────

def setup(n_requests: int) -> Tuple[List, List, Dict]:
    print("\n  ── Authentication & token acquisition ──────────────────────────")
    tokens: Dict[str, str] = {}
    rpts:   Dict[str, str] = {}
    for username, password in DORA_USERS.items():
        print(f"  {username}…", end=" ", flush=True)
        tok = _get_token(username, password)
        rpt = _get_rpt("/api/documents", tok)
        if not rpt:
            raise RuntimeError(f"{username} could not obtain RPT — no UMA permission")
        tokens[username] = tok
        rpts[username]   = rpt
        print("OK")

    print("\n  ── Building server-signed delegation chains ─────────────────────")
    SCOPES_D4 = ["documents:read", "calendar:read"]
    SCOPES_D5 = ["documents:read"]

    MEMBERS_D4 = ["compliance-manager", "risk-analyst",
                  "data-extractor",     "report-validator"]
    MEMBERS_D5 = ["compliance-manager", "risk-analyst",
                  "data-extractor",     "report-validator", "audit-reader"]

    print("  Chain A (depth 4)…", end=" ", flush=True)
    chain_A = build_sub_chains(tokens, MEMBERS_D4, SCOPES_D4)
    print("OK")

    print("  Chain B (depth 4, parallel instance)…", end=" ", flush=True)
    chain_B = build_sub_chains(tokens, MEMBERS_D4, SCOPES_D4)
    print("OK")

    print("  Chain C (depth 5)…", end=" ", flush=True)
    chain_C = build_sub_chains(tokens, MEMBERS_D5, SCOPES_D5)
    print("OK")

    print("  Chain D (depth 5, parallel instance)…", end=" ", flush=True)
    chain_D = build_sub_chains(tokens, MEMBERS_D5, SCOPES_D5)
    print("OK")

    print("\n  ── Building attack chains ───────────────────────────────────────")

    # T1: scope escalation — chain grants only database:audit; /api/documents needs documents:read
    t1_chain = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager"],
        granted_scopes=["database:audit"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )
    print(f"  T1 chain: scopes=['database:audit'], depth=1 → /api/documents blocked (needs documents:read)")

    # T2: depth exceeded — 7 members, MAX_DELEGATION_DEPTH=6
    t2_chain = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager", "ag1", "ag2", "ag3", "ag4", "ag5", "attack-t2"],
        granted_scopes=["documents:read"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )
    print(f"  T2 chain: depth=7 > MAX=6 → blocked")

    # T3: token replay — chain terminus=data-extractor but presenting with risk-analyst's RPT
    t3_chain = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager", "risk-analyst", "data-extractor"],
        granted_scopes=["documents:read"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )
    print(f"  T3 chain: terminus=data-extractor, RPT=risk-analyst → T3 blocked")

    # T4: HMAC tamper — valid structure, corrupted chain_hash
    valid_base = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager"],
        granted_scopes=["documents:read"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )
    t4_chain = dataclasses.replace(valid_base, chain_hash="0" * 64)
    print(f"  T4 chain: chain_hash zeroed → HMAC mismatch blocked")

    # Synchronisation barrier — all 20 threads wait here before firing requests
    n_workers = 20
    barrier = threading.Barrier(n_workers, timeout=60)

    # ── Honest agents (16) ────────────────────────────────────────────────────
    # Chain A (depth 4): agents at depth 1, 2, 3, 4
    # Chain B (depth 4): agents at depth 1, 2, 3, 4
    # Chain C (depth 5): agents at depth 1, 2, 4, 5
    # Chain D (depth 5): agents at depth 1, 2, 4, 5
    honest: List[HonestAgentWorker] = [
        # ── Chain A ──────────────────────────────────────────────────────────
        HonestAgentWorker("compliance-manager", "chain_A", 1, chain_A[1], rpts["compliance-manager"], barrier, n_requests),
        HonestAgentWorker("risk-analyst",       "chain_A", 2, chain_A[2], rpts["risk-analyst"],       barrier, n_requests),
        HonestAgentWorker("data-extractor",     "chain_A", 3, chain_A[3], rpts["data-extractor"],     barrier, n_requests),
        HonestAgentWorker("report-validator",   "chain_A", 4, chain_A[4], rpts["report-validator"],   barrier, n_requests),
        # ── Chain B ──────────────────────────────────────────────────────────
        HonestAgentWorker("compliance-manager", "chain_B", 1, chain_B[1], rpts["compliance-manager"], barrier, n_requests),
        HonestAgentWorker("risk-analyst",       "chain_B", 2, chain_B[2], rpts["risk-analyst"],       barrier, n_requests),
        HonestAgentWorker("data-extractor",     "chain_B", 3, chain_B[3], rpts["data-extractor"],     barrier, n_requests),
        HonestAgentWorker("report-validator",   "chain_B", 4, chain_B[4], rpts["report-validator"],   barrier, n_requests),
        # ── Chain C (depth 5) ─────────────────────────────────────────────────
        HonestAgentWorker("compliance-manager", "chain_C", 1, chain_C[1], rpts["compliance-manager"], barrier, n_requests),
        HonestAgentWorker("risk-analyst",       "chain_C", 2, chain_C[2], rpts["risk-analyst"],       barrier, n_requests),
        HonestAgentWorker("report-validator",   "chain_C", 4, chain_C[4], rpts["report-validator"],   barrier, n_requests),
        HonestAgentWorker("audit-reader",       "chain_C", 5, chain_C[5], rpts["audit-reader"],       barrier, n_requests),
        # ── Chain D (depth 5) ─────────────────────────────────────────────────
        HonestAgentWorker("compliance-manager", "chain_D", 1, chain_D[1], rpts["compliance-manager"], barrier, n_requests),
        HonestAgentWorker("risk-analyst",       "chain_D", 2, chain_D[2], rpts["risk-analyst"],       barrier, n_requests),
        HonestAgentWorker("report-validator",   "chain_D", 4, chain_D[4], rpts["report-validator"],   barrier, n_requests),
        HonestAgentWorker("audit-reader",       "chain_D", 5, chain_D[5], rpts["audit-reader"],       barrier, n_requests),
    ]

    # ── Attack agents (4) ─────────────────────────────────────────────────────
    attacks: List[AttackAgentWorker] = [
        AttackAgentWorker("T1", t1_chain.to_header_value(), rpts["compliance-manager"], barrier, n_requests),
        AttackAgentWorker("T2", t2_chain.to_header_value(), rpts["compliance-manager"], barrier, n_requests),
        AttackAgentWorker("T3", t3_chain.to_header_value(), rpts["risk-analyst"],       barrier, n_requests),
        AttackAgentWorker("T4", t4_chain.to_header_value(), rpts["compliance-manager"], barrier, n_requests),
    ]

    meta = {
        "n_honest":  len(honest),
        "n_attacks": len(attacks),
        "n_total":   len(honest) + len(attacks),
        "chains": {
            "chain_A": {"depth": 4, "members": MEMBERS_D4, "scopes": SCOPES_D4},
            "chain_B": {"depth": 4, "members": MEMBERS_D4, "scopes": SCOPES_D4},
            "chain_C": {"depth": 5, "members": MEMBERS_D5, "scopes": SCOPES_D5},
            "chain_D": {"depth": 5, "members": MEMBERS_D5, "scopes": SCOPES_D5},
        },
    }
    return honest, attacks, meta


# ─── Load test runner ─────────────────────────────────────────────────────────

def run_load_test(honest: List, attacks: List,
                  n_requests: int) -> Tuple[List[RequestRecord], float, float]:
    all_workers = honest + attacks
    n_workers   = len(all_workers)

    print(f"\n  ── Concurrent load test: {n_workers} agents × {n_requests} req = "
          f"{n_workers * n_requests} total ──────────")
    print(f"  Workers: {len(honest)} honest  +  {len(attacks)} attack  "
          f"(barrier-synchronised start)")

    all_records: List[RequestRecord] = []
    t_start = t_end = 0.0

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [pool.submit(w.run) for w in all_workers]
        t_start = time.perf_counter()
        for fut in as_completed(futures):
            batch = fut.result()
            all_records.extend(batch)
        t_end = time.perf_counter()

    wall_time = t_end - t_start
    return all_records, t_start, wall_time


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyse(records: List[RequestRecord],
            wall_time: float, meta: Dict) -> Dict:
    honest_ok   = [r for r in records if r.agent_type == "honest" and r.http_status == 200]
    honest_fail = [r for r in records if r.agent_type == "honest" and r.http_status != 200]
    attack_recs = [r for r in records if r.agent_type == "attack"]

    honest_latencies = [r.latency_ms for r in honest_ok]
    attack_blocked   = [r for r in attack_recs if r.blocked]

    total_requests  = len(records)
    honest_total    = len([r for r in records if r.agent_type == "honest"])
    attack_total    = len(attack_recs)
    throughput      = total_requests / wall_time if wall_time > 0 else 0

    # Per-depth latency breakdown
    by_depth: Dict[int, List[float]] = {}
    for r in honest_ok:
        by_depth.setdefault(r.depth, []).append(r.latency_ms)

    # Per-chain latency breakdown
    by_chain: Dict[str, List[float]] = {}
    for r in honest_ok:
        by_chain.setdefault(r.chain_id, []).append(r.latency_ms)

    # Attack breakdown
    by_attack: Dict[str, Dict] = {}
    for ac in ("T1", "T2", "T3", "T4"):
        recs = [r for r in attack_recs if r.attack_class == ac]
        blocked = [r for r in recs if r.blocked]
        by_attack[ac] = {
            "total":      len(recs),
            "blocked":    len(blocked),
            "block_rate": round(len(blocked) / len(recs) * 100, 1) if recs else 0,
        }

    return {
        "wall_time_s":       round(wall_time, 3),
        "total_requests":    total_requests,
        "honest_successful": len(honest_ok),
        "honest_failed":     len(honest_fail),
        "attack_total":      attack_total,
        "attack_blocked":    len(attack_blocked),
        "attack_block_rate": round(len(attack_blocked) / attack_total * 100, 1) if attack_total else 0,
        "throughput_rps":    round(throughput, 1),
        "latency_all_ms":    _stats(honest_latencies),
        "latency_by_depth":  {d: _stats(lats) for d, lats in sorted(by_depth.items())},
        "latency_by_chain":  {c: _stats(lats) for c, lats in sorted(by_chain.items())},
        "attack_detail":     by_attack,
        "meta":              meta,
    }


# ─── Report printer ───────────────────────────────────────────────────────────

def print_report(result: Dict, nw: Optional[Dict] = None) -> None:
    la = result["latency_all_ms"]

    print("\n  ══════════════════════════════════════════════════════════════════")
    print("  UMA Agent — Concurrent Load Test Results")
    print("  ══════════════════════════════════════════════════════════════════")
    if nw and nw.get("toxiproxy_api"):
        print(f"  Network:  {nw['keycloak_url']}  +  {nw['resource_server_url']}")
        print(f"  Toxiproxy: {nw['toxiproxy_api']}  "
              f"(+{nw['injected_latency_ms']} ms ± {nw['injected_jitter_ms']} ms)")
    print()
    print(f"  Wall time:         {result['wall_time_s']:.2f} s")
    print(f"  Total requests:    {result['total_requests']}")
    print(f"    Honest (OK):     {result['honest_successful']}")
    print(f"    Honest (fail):   {result['honest_failed']}")
    print(f"    Attack total:    {result['attack_total']}")
    print(f"    Attack blocked:  {result['attack_blocked']}  "
          f"({result['attack_block_rate']:.1f}%)")
    print(f"  Throughput:        {result['throughput_rps']:.1f} req/s")
    print()
    print("  ── Honest agent latency (ms) ─────────────────────────────────────")
    print(f"  {'Metric':<8}  {'Mean':>7}  {'Std':>6}  {'p50':>7}  {'p95':>7}  {'p99':>7}")
    print(f"  {'':<8}  {la['mean']:>7.1f}  {la['std']:>6.1f}  "
          f"{la['p50']:>7.1f}  {la['p95']:>7.1f}  {la['p99']:>7.1f}")
    print()
    print("  ── Per-depth latency (ms) ────────────────────────────────────────")
    print(f"  {'Depth':<8}  {'n':>5}  {'mean':>7}  {'p50':>7}  {'p95':>7}  {'p99':>7}")
    for depth, st in result["latency_by_depth"].items():
        print(f"  {depth:<8}  {st['n']:>5}  {st['mean']:>7.1f}  "
              f"{st['p50']:>7.1f}  {st['p95']:>7.1f}  {st['p99']:>7.1f}")
    print()
    print("  ── Per-chain latency (ms) ────────────────────────────────────────")
    print(f"  {'Chain':<10}  {'depth':>5}  {'n':>5}  {'mean':>7}  {'p95':>7}")
    meta_chains = result["meta"]["chains"]
    for chain_id, st in result["latency_by_chain"].items():
        d = meta_chains.get(chain_id, {}).get("depth", "?")
        print(f"  {chain_id:<10}  {str(d):>5}  {st['n']:>5}  "
              f"{st['mean']:>7.1f}  {st['p95']:>7.1f}")
    print()
    print("  ── Attack blocking (T1-T4) ───────────────────────────────────────")
    for ac, det in result["attack_detail"].items():
        bar = "✓ BLOCKED" if det["block_rate"] == 100.0 else "✗ PARTIAL"
        print(f"  {ac}  {det['blocked']:>4}/{det['total']}  "
              f"{det['block_rate']:>5.1f}%  {bar}")
    print()
    print("  ══════════════════════════════════════════════════════════════════\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="UMA Agent Concurrent Load Test")
    p.add_argument("--n-requests", type=int,
                   default=int(os.environ.get("N_REQUESTS", "30")),
                   help="Requests per agent (default 30)")
    p.add_argument("--json-out",   metavar="FILE", default=None)
    return p.parse_args()


def main() -> None:
    import logging
    logging.basicConfig(level=logging.WARNING)
    args = _parse_args()

    print("\n  ── Service startup ─────────────────────────────────────────────")
    _wait_for_services()
    _configure_toxiproxy()

    honest, attacks, meta = setup(args.n_requests)

    records, t_start, wall_time = run_load_test(honest, attacks, args.n_requests)

    result = analyse(records, wall_time, meta)
    result["run_at"] = datetime.now(timezone.utc).isoformat()
    result["network"] = {
        "keycloak_url":        KEYCLOAK_URL,
        "resource_server_url": RESOURCE_SERVER,
        "toxiproxy_api":       TOXIPROXY_API,
        "injected_latency_ms": NETWORK_LATENCY_MS,
        "injected_jitter_ms":  NETWORK_JITTER_MS,
    }

    nw = result["network"]
    print_report(result, nw)

    if args.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"  JSON written to: {args.json_out}\n")


if __name__ == "__main__":
    main()
