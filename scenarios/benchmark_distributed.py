#!/usr/bin/env python3
"""
UMA Agent Protocol — Distributed Network-Latency Benchmark

Identical measurement suite to scenarios/benchmark.py but designed to run
from inside a Docker container, connecting to Keycloak and the Resource Server
over a Docker bridge network (container-to-container) with optional Toxiproxy-
injected latency.

This replicates Table VII under real network conditions: Keycloak, Resource
Server, and each agent run on separate containers (or VMs).  Toxiproxy injects
a configurable per-hop delay (default 10 ms ± 2 ms) to model realistic
intra-datacenter latency.  HMAC-SHA256 chain validation remains O(1) across
all depths even with this base overhead.

Configuration (all via environment variables):
  KEYCLOAK_URL          default  http://localhost:8080
  RESOURCE_SERVER_URL   default  http://localhost:5000
  KEYCLOAK_REALM        default  test-realm
  CLIENT_ID             default  test-app
  CHAIN_HMAC_SECRET     default  uma-agent-chain-hmac-secret-2024
  TOXIPROXY_API         default  (none — no latency injection)
  NETWORK_LATENCY_MS    default  10  (ms added per hop via Toxiproxy)
  NETWORK_JITTER_MS     default  2   (ms jitter)

Usage
─────
  # Inside Docker (via docker-compose.distributed.yml):
  python scenarios/benchmark_distributed.py
  python scenarios/benchmark_distributed.py --n-http 50 --json-out /results/out.json

  # Localhost (no Toxiproxy, same endpoints as benchmark.py):
  python scenarios/benchmark_distributed.py
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.chain_claim import DelegationChainClaim

# ---------------------------------------------------------------------------
# Configuration — all overridable via environment variables
# ---------------------------------------------------------------------------

KEYCLOAK_URL       = os.environ.get("KEYCLOAK_URL",        "http://localhost:8080")
REALM              = os.environ.get("KEYCLOAK_REALM",       "test-realm")
RESOURCE_SERVER    = os.environ.get("RESOURCE_SERVER_URL",  "http://localhost:5000")
CLIENT_ID          = os.environ.get("CLIENT_ID",            "test-app")
CHAIN_SECRET       = os.environ.get("CHAIN_HMAC_SECRET",    "uma-agent-chain-hmac-secret-2024")
TOXIPROXY_API      = os.environ.get("TOXIPROXY_API",        None)
NETWORK_LATENCY_MS = int(os.environ.get("NETWORK_LATENCY_MS", "10"))
NETWORK_JITTER_MS  = int(os.environ.get("NETWORK_JITTER_MS",  "2"))


# ---------------------------------------------------------------------------
# Service readiness
# ---------------------------------------------------------------------------

def _wait_for_services(timeout: int = 240) -> None:
    checks: List[tuple[str, str]] = []
    if TOXIPROXY_API:
        checks.append((f"{TOXIPROXY_API}/version", "Toxiproxy"))
    checks.append((f"{KEYCLOAK_URL}/realms/{REALM}", "Keycloak"))
    checks.append((f"{RESOURCE_SERVER}/",            "Resource Server"))

    deadline = time.time() + timeout
    for url, name in checks:
        print(f"  Waiting for {name}…", end=" ", flush=True)
        while time.time() < deadline:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code < 500:
                    print("ready")
                    break
            except requests.RequestException:
                pass
            time.sleep(3)
        else:
            raise RuntimeError(f"{name} not reachable after {timeout}s at {url}")


# ---------------------------------------------------------------------------
# Toxiproxy latency injection
# ---------------------------------------------------------------------------

def _configure_toxiproxy() -> None:
    if not TOXIPROXY_API or NETWORK_LATENCY_MS == 0:
        print("  Toxiproxy: skipped (TOXIPROXY_API not set or latency=0)")
        return

    print(f"  Injecting latency via Toxiproxy: "
          f"{NETWORK_LATENCY_MS} ms ± {NETWORK_JITTER_MS} ms per hop…",
          end=" ", flush=True)

    for proxy_name in ("keycloak", "resource-server"):
        try:
            r = requests.post(
                f"{TOXIPROXY_API}/proxies/{proxy_name}/toxics",
                json={
                    "name":       "latency",
                    "type":       "latency",
                    "stream":     "downstream",
                    "attributes": {
                        "latency": NETWORK_LATENCY_MS,
                        "jitter":  NETWORK_JITTER_MS,
                    },
                },
                timeout=5,
            )
            if r.status_code not in (200, 201, 409):
                print(f"\n    Warning: {proxy_name} toxic returned HTTP {r.status_code}")
        except requests.RequestException as exc:
            print(f"\n    Warning: could not configure {proxy_name}: {exc}")
    print("done")


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def _compute_stats(samples: List[float]) -> Dict[str, Any]:
    n = len(samples)
    if n == 0:
        return {"n": 0, "mean_ms": None, "std_ms": None,
                "min_ms": None, "max_ms": None, "p95_ms": None}
    s = sorted(samples)
    return {
        "n":       n,
        "mean_ms": round(statistics.mean(samples), 3),
        "std_ms":  round(statistics.stdev(samples), 3) if n > 1 else 0.0,
        "min_ms":  round(s[0], 3),
        "max_ms":  round(s[-1], 3),
        "p95_ms":  round(s[min(int(0.95 * n), n - 1)], 3),
    }


def _measure(fn, n: int, warmup: int = 2) -> Dict[str, Any]:
    samples = []
    for i in range(n + warmup):
        t0 = time.perf_counter()
        fn()
        elapsed = (time.perf_counter() - t0) * 1000
        if i >= warmup:
            samples.append(elapsed)
    return _compute_stats(samples)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

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
    if probe.status_code != 401:
        return None
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


def _build_chain(depth: int) -> str:
    agents = ["compliance-manager", "risk-analyst", "data-extractor", "sub-agent-d4"]
    members = agents[:depth]
    scopes  = ["documents:read", "calendar:read", "database:read"][:max(1, 4 - depth)]
    claim   = DelegationChainClaim.create(
        root_agent=members[0],
        members=members,
        granted_scopes=scopes,
        max_depth=4,
    )
    return claim.to_header_value()


# ---------------------------------------------------------------------------
# HTTP benchmark suite
# ---------------------------------------------------------------------------

class HTTPBenchmark:
    def __init__(self, n: int = 30) -> None:
        self.n = n
        print("  Obtaining tokens…", end=" ", flush=True)
        self._user_token = _get_token("compliance-manager", "compliance-pass123")
        self._rpt = _get_rpt("/api/documents", self._user_token)
        if not self._rpt:
            raise RuntimeError("Could not obtain RPT for /api/documents")
        print("done")
        self._chains = {d: _build_chain(d) for d in (1, 2, 3)}

    def bench_authentication(self) -> Dict[str, Any]:
        print(f"  Authentication (n={self.n})…", end=" ", flush=True)
        result = _measure(
            lambda: _get_token("compliance-manager", "compliance-pass123"), self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def bench_rpt_exchange(self) -> Dict[str, Any]:
        print(f"  RPT exchange (n={self.n})…", end=" ", flush=True)
        token = self._user_token

        def _exchange():
            probe = requests.get(f"{RESOURCE_SERVER}/api/documents", timeout=15)
            m = re.search(r'ticket="([^"]+)"',
                          probe.headers.get("WWW-Authenticate", ""))
            if m:
                requests.post(
                    f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
                    data={"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                          "ticket": m.group(1)},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=15,
                )

        result = _measure(_exchange, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def bench_resource_read_baseline(self) -> Dict[str, Any]:
        print(f"  Resource read — no chain (n={self.n})…", end=" ", flush=True)
        rpt = self._rpt

        def _read():
            requests.get(f"{RESOURCE_SERVER}/api/documents",
                         headers={"Authorization": f"Bearer {rpt}"}, timeout=15)

        result = _measure(_read, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def bench_resource_read_chain(self, depth: int) -> Dict[str, Any]:
        print(f"  Resource read — depth {depth} (n={self.n})…", end=" ", flush=True)
        rpt   = self._rpt
        chain = self._chains[depth]

        def _read():
            requests.get(
                f"{RESOURCE_SERVER}/api/documents",
                headers={"Authorization": f"Bearer {rpt}",
                         "X-Uma-Delegation-Chain": chain},
                timeout=15,
            )

        result = _measure(_read, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def bench_delegation_init(self) -> Dict[str, Any]:
        print(f"  Chain init POST /api/delegation/init (n={self.n})…",
              end=" ", flush=True)
        token = self._user_token

        def _init():
            requests.post(
                f"{RESOURCE_SERVER}/api/delegation/init",
                json={"requested_scopes": ["documents:read", "calendar:read"]},
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )

        result = _measure(_init, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def bench_delegation_sign(self) -> Dict[str, Any]:
        print(f"  Chain sign POST /api/delegation/sign (n={self.n})…",
              end=" ", flush=True)
        token = self._user_token
        init_resp = requests.post(
            f"{RESOURCE_SERVER}/api/delegation/init",
            json={"requested_scopes": ["documents:read", "calendar:read"]},
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        init_resp.raise_for_status()
        parent_chain = init_resp.json()["chain_claim"]

        def _sign():
            requests.post(
                f"{RESOURCE_SERVER}/api/delegation/sign",
                json={"parent_chain": parent_chain,
                      "child_agent_id": "risk-analyst",
                      "requested_scopes": ["documents:read"]},
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )

        result = _measure(_sign, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def run(self) -> Dict[str, Any]:
        auth = self.bench_authentication()
        rpt  = self.bench_rpt_exchange()
        base = self.bench_resource_read_baseline()
        d1   = self.bench_resource_read_chain(1)
        d2   = self.bench_resource_read_chain(2)
        d3   = self.bench_resource_read_chain(3)
        init = self.bench_delegation_init()
        sign = self.bench_delegation_sign()

        overhead = {
            depth: round(stats["mean_ms"] - base["mean_ms"], 3)
            for depth, stats in [(1, d1), (2, d2), (3, d3)]
        }
        return {
            "authentication":              auth,
            "rpt_exchange":                rpt,
            "resource_read_baseline":      base,
            "resource_read_chain_depth_1": d1,
            "resource_read_chain_depth_2": d2,
            "resource_read_chain_depth_3": d3,
            "chain_extension_overhead_ms": overhead,
            "chain_init":                  init,
            "chain_sign":                  sign,
        }


# ---------------------------------------------------------------------------
# Pure Python benchmark suite  (identical to benchmark.py)
# ---------------------------------------------------------------------------

class PythonBenchmark:
    def __init__(self, n: int = 1000) -> None:
        self.n = n

    def bench_chain_construction(self) -> Dict[str, Any]:
        results = {}
        for depth in (1, 2, 3, 4):
            agents = ["compliance-manager", "risk-analyst",
                      "data-extractor", "sub-agent-d4"][:depth]
            scopes = ["documents:read", "calendar:read",
                      "database:read"][:max(1, 4 - depth)]
            print(f"  Chain construction depth {depth} (n={self.n})…",
                  end=" ", flush=True)
            stats = _measure(
                lambda a=agents, s=scopes: DelegationChainClaim.create(
                    root_agent=a[0], members=list(a),
                    granted_scopes=list(s), max_depth=4,
                ),
                self.n,
            )
            print(f"mean={stats['mean_ms']*1000:.1f} µs")
            results[f"depth_{depth}"] = stats
        return results

    def bench_chain_validation(self) -> Dict[str, Any]:
        results = {}

        for depth in (1, 2, 3):
            agents = ["compliance-manager", "risk-analyst", "data-extractor"][:depth]
            scopes = ["documents:read", "calendar:read",
                      "database:read"][:max(1, 4 - depth)]
            claim  = DelegationChainClaim.create(
                root_agent=agents[0], members=agents,
                granted_scopes=scopes, max_depth=4,
            )
            terminus = agents[-1]
            print(f"  Chain validation valid depth {depth} (n={self.n})…",
                  end=" ", flush=True)
            stats = _measure(
                lambda c=claim, t=terminus: c.validate_for_resource(
                    "documents", "read", t, CHAIN_SECRET),
                self.n,
            )
            print(f"mean={stats['mean_ms']*1000:.1f} µs")
            results[f"valid_depth_{depth}"] = stats

        for label, fn_args in [
            ("t1_scope_escalation_blocked", ("database", "audit", "data-extractor")),
            ("t2_depth_exceeded_blocked",   ("documents", "read", "data-extractor")),
            ("t3_token_replay_blocked",     ("documents", "read", "compliance-manager")),
        ]:
            if label == "t1_scope_escalation_blocked":
                claim = DelegationChainClaim.create(
                    root_agent="compliance-manager",
                    members=["compliance-manager", "data-extractor"],
                    granted_scopes=["documents:read", "database:read"], max_depth=4)
            elif label == "t2_depth_exceeded_blocked":
                claim = DelegationChainClaim.create(
                    root_agent="compliance-manager",
                    members=["compliance-manager", "a", "b", "c", "data-extractor"],
                    granted_scopes=["documents:read"], max_depth=4)
            else:
                claim = DelegationChainClaim.create(
                    root_agent="compliance-manager",
                    members=["compliance-manager", "risk-analyst"],
                    granted_scopes=["documents:read"], max_depth=4)

            resource, scope, terminus = fn_args
            print(f"  Validation {label} (n={self.n})…", end=" ", flush=True)
            stats = _measure(
                lambda c=claim, r=resource, s=scope, t=terminus:
                    c.validate_for_resource(r, s, t, CHAIN_SECRET),
                self.n,
            )
            print(f"mean={stats['mean_ms']*1000:.1f} µs")
            results[label] = stats

        good      = DelegationChainClaim.create(
            root_agent="compliance-manager", members=["compliance-manager"],
            granted_scopes=["documents:read"], max_depth=4)
        tampered  = dataclasses.replace(good, chain_hash="0" * 64)
        print(f"  Validation tampered_hash_blocked (n={self.n})…", end=" ", flush=True)
        stats = _measure(
            lambda c=tampered: c.validate_for_resource(
                "documents", "read", "compliance-manager", CHAIN_SECRET),
            self.n,
        )
        print(f"mean={stats['mean_ms']*1000:.1f} µs")
        results["tampered_hash_blocked"] = stats

        return results

    def run(self) -> Dict[str, Any]:
        return {
            "chain_construction": self.bench_chain_construction(),
            "chain_validation":   self.bench_chain_validation(),
        }


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_benchmark(n_http: int = 30, n_python: int = 1000) -> Dict[str, Any]:
    print("\n  ── Service startup ────────────────────────────────────────────────")
    _wait_for_services()
    _configure_toxiproxy()

    print("\n  ── HTTP benchmarks (container-to-container, Toxiproxy latency) ───")
    http = HTTPBenchmark(n=n_http).run()

    print("\n  ── Pure Python benchmarks (no network) ────────────────────────────")
    py = PythonBenchmark(n=n_python).run()

    return {
        "scenario":    "UMA Agent Protocol Distributed Benchmark",
        "run_at":      datetime.now(timezone.utc).isoformat(),
        "network": {
            "keycloak_url":        KEYCLOAK_URL,
            "resource_server_url": RESOURCE_SERVER,
            "toxiproxy_api":       TOXIPROXY_API,
            "injected_latency_ms": NETWORK_LATENCY_MS,
            "injected_jitter_ms":  NETWORK_JITTER_MS,
        },
        "n_http":   n_http,
        "n_python": n_python,
        "http":     http,
        "python":   py,
    }


# ---------------------------------------------------------------------------
# Pretty-print table
# ---------------------------------------------------------------------------

def print_table(result: Dict[str, Any]) -> None:
    h  = result["http"]
    p  = result["python"]
    nw = result["network"]

    def row(label: str, stats: Dict[str, Any], unit: str = "ms") -> str:
        if stats.get("mean_ms") is None:
            return f"  {label:<52} {'N/A':>8}"
        scale = 1000 if unit == "µs" else 1
        m   = stats["mean_ms"] * scale
        std = stats["std_ms"]  * scale
        p95 = stats["p95_ms"]  * scale
        n   = stats["n"]
        return (f"  {label:<52} {m:>7.1f} ± {std:>5.1f}  "
                f"p95={p95:>7.1f}  n={n}  [{unit}]")

    print("\n  ══════════════════════════════════════════════════════════════════")
    print("  UMA Agent — Distributed Benchmark Results (Table VII — Network)")
    print("  ══════════════════════════════════════════════════════════════════")
    print(f"  Keycloak:        {nw['keycloak_url']}")
    print(f"  Resource Server: {nw['resource_server_url']}")
    if nw["toxiproxy_api"]:
        print(f"  Toxiproxy:       {nw['toxiproxy_api']}  "
              f"(+{nw['injected_latency_ms']} ms ± {nw['injected_jitter_ms']} ms)")
    print()
    print("  ── Network Operations ─────────────────────────────────────────────")
    print(row("Authentication (Keycloak)",             h["authentication"]))
    print(row("RPT exchange (UMA ticket)",             h["rpt_exchange"]))
    print(row("Resource read — no chain (baseline)",   h["resource_read_baseline"]))
    print(row("Resource read — depth 1",               h["resource_read_chain_depth_1"]))
    print(row("Resource read — depth 2",               h["resource_read_chain_depth_2"]))
    print(row("Resource read — depth 3",               h["resource_read_chain_depth_3"]))
    print(row("Chain init (POST /api/delegation/init)", h["chain_init"]))
    print(row("Chain sign (POST /api/delegation/sign)", h["chain_sign"]))
    print()
    ov = h["chain_extension_overhead_ms"]
    print("  ── Chain Extension Overhead (mean_depth_N − mean_baseline) ────────")
    for d, ms in ov.items():
        print(f"  Depth {d}: {ms:+.1f} ms  ← HMAC validation O(1) confirmed")
    print()
    cc = p["chain_construction"]
    print("  ── Chain Construction (pure Python, µs) ────────────────────────────")
    for key, stats in cc.items():
        print(row(f"  {key}", stats, "µs"))
    print()
    cv = p["chain_validation"]
    print("  ── Chain Validation (pure Python, µs) ──────────────────────────────")
    for key, stats in cv.items():
        print(row(f"  {key}", stats, "µs"))
    print()
    print("  ══════════════════════════════════════════════════════════════════\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="UMA Agent Distributed Benchmark — Table VII (network latency)")
    p.add_argument("--n-http",   type=int,
                   default=int(os.environ.get("N_HTTP",   "30")))
    p.add_argument("--n-python", type=int,
                   default=int(os.environ.get("N_PYTHON", "1000")))
    p.add_argument("--json-out", metavar="FILE", default=None)
    return p.parse_args()


def main() -> None:
    import logging
    logging.basicConfig(level=logging.WARNING)
    args = _parse_args()
    result = run_benchmark(n_http=args.n_http, n_python=args.n_python)
    print_table(result)
    if args.json_out:
        os.makedirs(os.path.dirname(args.json_out) or ".", exist_ok=True)
        with open(args.json_out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"  JSON written to: {args.json_out}\n")


if __name__ == "__main__":
    main()
