#!/usr/bin/env python3
"""
UMA Agent Protocol — Performance Benchmark (Step 5)

Measures the latency of each protocol operation and computes the overhead
introduced by the urn:uma-agent:delegation-chain:1.0 extension.

Measurements
────────────
  HTTP operations  (N=30, against live Keycloak + resource server)
    • Authentication      — Keycloak password grant
    • RPT exchange        — permission ticket → RPT
    • Resource read (baseline)     — plain UMA, no chain header
    • Resource read + chain depth 1 — UMA + DelegationChainClaim (depth 1)
    • Resource read + chain depth 2 — UMA + DelegationChainClaim (depth 2)
    • Resource read + chain depth 3 — UMA + DelegationChainClaim (depth 3)

  Pure Python operations  (N=1000, no network)
    • Chain construction at depths 1–4
    • Chain validation (valid)  at depths 1–3
    • Chain validation (T1 blocked)
    • Chain validation (T2 blocked)
    • Chain validation (T3 blocked)
    • Chain validation (tampered hash)

Statistics reported: mean, std, min, max, p95 (all in ms)

Usage
─────
  python3 scenarios/benchmark.py
  python3 scenarios/benchmark.py --n-http 50 --n-python 2000
  python3 scenarios/benchmark.py --json-out results.json
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

KEYCLOAK_URL    = "http://localhost:8080"
REALM           = "test-realm"
RESOURCE_SERVER = "http://localhost:5000"
CLIENT_ID       = "test-app"
CHAIN_SECRET    = "uma-agent-chain-hmac-secret-2024"


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def compute_stats(samples: List[float]) -> Dict[str, Any]:
    n = len(samples)
    if n == 0:
        return {"n": 0, "mean_ms": None, "std_ms": None,
                "min_ms": None, "max_ms": None, "p95_ms": None}
    sorted_s = sorted(samples)
    p95_idx  = min(int(0.95 * n), n - 1)
    return {
        "n":       n,
        "mean_ms": round(statistics.mean(samples), 3),
        "std_ms":  round(statistics.stdev(samples), 3) if n > 1 else 0.0,
        "min_ms":  round(sorted_s[0], 3),
        "max_ms":  round(sorted_s[-1], 3),
        "p95_ms":  round(sorted_s[p95_idx], 3),
    }


def _measure(fn, n: int, warmup: int = 2) -> Dict[str, Any]:
    """Run fn() n times, return stats. Skips first `warmup` results."""
    samples = []
    for i in range(n + warmup):
        t0 = time.perf_counter()
        fn()
        elapsed = (time.perf_counter() - t0) * 1000
        if i >= warmup:
            samples.append(elapsed)
    return compute_stats(samples)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def _get_token(username: str, password: str) -> str:
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": CLIENT_ID,
              "username": username, "password": password, "scope": "openid"},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _get_rpt(resource_path: str, user_token: str) -> Optional[str]:
    probe = requests.get(f"{RESOURCE_SERVER}{resource_path}", timeout=10)
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
        timeout=10,
    )
    return r.json().get("access_token") if r.status_code == 200 else None


def _build_chain(depth: int) -> str:
    """Build a valid DelegationChainClaim header value at the given depth."""
    agents = ["compliance-manager", "risk-analyst",
              "data-extractor", "sub-agent-d4"]
    members = agents[:depth]
    scopes  = ["documents:read", "calendar:read",
               "database:read"][:max(1, 4 - depth)]
    claim = DelegationChainClaim.create(
        root_agent=members[0],
        members=members,
        granted_scopes=scopes,
        max_depth=4,
    )
    return claim.to_header_value()


# ---------------------------------------------------------------------------
# HTTP benchmarks
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

        # Pre-build chain headers so construction cost isn't in the read timings
        self._chains = {d: _build_chain(d) for d in (1, 2, 3)}

    # -- authentication ------------------------------------------------------

    def bench_authentication(self) -> Dict[str, Any]:
        print(f"  Benchmarking authentication (n={self.n})…", end=" ", flush=True)
        result = _measure(
            lambda: _get_token("compliance-manager", "compliance-pass123"),
            self.n,
        )
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    # -- RPT exchange --------------------------------------------------------

    def bench_rpt_exchange(self) -> Dict[str, Any]:
        print(f"  Benchmarking RPT exchange (n={self.n})…", end=" ", flush=True)

        def _exchange():
            token = self._user_token
            probe = requests.get(f"{RESOURCE_SERVER}/api/documents", timeout=10)
            m = re.search(r'ticket="([^"]+)"',
                          probe.headers.get("WWW-Authenticate", ""))
            if m:
                requests.post(
                    f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
                    data={"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                          "ticket": m.group(1)},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )

        result = _measure(_exchange, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    # -- resource read (baseline — no chain header) --------------------------

    def bench_resource_read_baseline(self) -> Dict[str, Any]:
        print(f"  Benchmarking resource read baseline/no-chain (n={self.n})…",
              end=" ", flush=True)
        rpt = self._rpt

        def _read():
            requests.get(
                f"{RESOURCE_SERVER}/api/documents",
                headers={"Authorization": f"Bearer {rpt}"},
                timeout=10,
            )

        result = _measure(_read, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    # -- resource read with chain at depth D ---------------------------------

    def bench_resource_read_with_chain(self, depth: int) -> Dict[str, Any]:
        print(f"  Benchmarking resource read + chain depth {depth} (n={self.n})…",
              end=" ", flush=True)
        rpt   = self._rpt
        chain = self._chains[depth]

        def _read():
            requests.get(
                f"{RESOURCE_SERVER}/api/documents",
                headers={"Authorization": f"Bearer {rpt}",
                         "X-Uma-Delegation-Chain": chain},
                timeout=10,
            )

        result = _measure(_read, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    # -- delegation chain init (server-side signing) -------------------------

    def bench_delegation_init(self) -> Dict[str, Any]:
        print(f"  Benchmarking delegation chain init (n={self.n})…",
              end=" ", flush=True)
        token = self._user_token

        def _init():
            requests.post(
                f"{RESOURCE_SERVER}/api/delegation/init",
                json={"requested_scopes": ["documents:read", "calendar:read"]},
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )

        result = _measure(_init, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    # -- delegation chain sign (extend by one hop) ---------------------------

    def bench_delegation_sign(self) -> Dict[str, Any]:
        print(f"  Benchmarking delegation chain sign/extend (n={self.n})…",
              end=" ", flush=True)
        token = self._user_token

        # Obtain a stable root chain once; signing cost is what we measure.
        init_resp = requests.post(
            f"{RESOURCE_SERVER}/api/delegation/init",
            json={"requested_scopes": ["documents:read", "calendar:read"]},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        init_resp.raise_for_status()
        parent_chain = init_resp.json()["chain_claim"]

        def _sign():
            requests.post(
                f"{RESOURCE_SERVER}/api/delegation/sign",
                json={
                    "parent_chain": parent_chain,
                    "child_agent_id": "risk-analyst",
                    "requested_scopes": ["documents:read"],
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )

        result = _measure(_sign, self.n)
        print(f"mean={result['mean_ms']:.1f} ms")
        return result

    def run(self) -> Dict[str, Any]:
        auth   = self.bench_authentication()
        rpt    = self.bench_rpt_exchange()
        base   = self.bench_resource_read_baseline()
        d1     = self.bench_resource_read_with_chain(1)
        d2     = self.bench_resource_read_with_chain(2)
        d3     = self.bench_resource_read_with_chain(3)
        init   = self.bench_delegation_init()
        sign   = self.bench_delegation_sign()

        # Chain extension overhead = read_with_chain - baseline
        overhead = {
            depth: round(
                stats["mean_ms"] - base["mean_ms"], 3
            )
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
# Pure Python benchmarks
# ---------------------------------------------------------------------------

class PythonBenchmark:
    def __init__(self, n: int = 1000) -> None:
        self.n = n

    # -- chain construction --------------------------------------------------

    def bench_chain_construction(self) -> Dict[str, Any]:
        results = {}
        for depth in (1, 2, 3, 4):
            agents  = ["compliance-manager", "risk-analyst",
                       "data-extractor", "sub-agent-d4"][:depth]
            scopes  = ["documents:read", "calendar:read",
                       "database:read"][:max(1, 4 - depth)]
            print(f"  Benchmarking chain construction depth {depth} (n={self.n})…",
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

    # -- chain validation ----------------------------------------------------

    def bench_chain_validation(self) -> Dict[str, Any]:
        results = {}

        # Valid chains at depths 1–3
        for depth in (1, 2, 3):
            agents = ["compliance-manager", "risk-analyst",
                      "data-extractor"][:depth]
            scopes = ["documents:read", "calendar:read",
                      "database:read"][:max(1, 4 - depth)]
            claim  = DelegationChainClaim.create(
                root_agent=agents[0], members=agents,
                granted_scopes=scopes, max_depth=4,
            )
            terminus = agents[-1]
            print(f"  Benchmarking chain validation valid depth {depth} (n={self.n})…",
                  end=" ", flush=True)
            stats = _measure(
                lambda c=claim, t=terminus: c.validate_for_resource(
                    "documents", "read", t, CHAIN_SECRET,
                ),
                self.n,
            )
            print(f"mean={stats['mean_ms']*1000:.1f} µs")
            results[f"valid_depth_{depth}"] = stats

        # T1 rejection
        leaf = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "data-extractor"],
            granted_scopes=["documents:read", "database:read"],
            max_depth=4,
        )
        print(f"  Benchmarking validation T1 rejection (n={self.n})…",
              end=" ", flush=True)
        stats = _measure(
            lambda c=leaf: c.validate_for_resource(
                "database", "audit", "data-extractor", CHAIN_SECRET,
            ),
            self.n,
        )
        print(f"mean={stats['mean_ms']*1000:.1f} µs")
        results["t1_scope_escalation_blocked"] = stats

        # T2 rejection
        deep = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "a", "b", "c", "data-extractor"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        print(f"  Benchmarking validation T2 rejection (n={self.n})…",
              end=" ", flush=True)
        stats = _measure(
            lambda c=deep: c.validate_for_resource(
                "documents", "read", "data-extractor", CHAIN_SECRET,
            ),
            self.n,
        )
        print(f"mean={stats['mean_ms']*1000:.1f} µs")
        results["t2_depth_exceeded_blocked"] = stats

        # T3 rejection
        chain_mid = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "risk-analyst"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        print(f"  Benchmarking validation T3 rejection (n={self.n})…",
              end=" ", flush=True)
        stats = _measure(
            lambda c=chain_mid: c.validate_for_resource(
                "documents", "read", "compliance-manager", CHAIN_SECRET,
            ),
            self.n,
        )
        print(f"mean={stats['mean_ms']*1000:.1f} µs")
        results["t3_token_replay_blocked"] = stats

        # HMAC tamper rejection
        good = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        tampered = dataclasses.replace(good, chain_hash="0" * 64)
        print(f"  Benchmarking validation tamper rejection (n={self.n})…",
              end=" ", flush=True)
        stats = _measure(
            lambda c=tampered: c.validate_for_resource(
                "documents", "read", "compliance-manager", CHAIN_SECRET,
            ),
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
# Full benchmark runner
# ---------------------------------------------------------------------------

def run_benchmark(n_http: int = 30, n_python: int = 1000) -> Dict[str, Any]:
    print("\n  ── HTTP benchmarks (live Keycloak + resource server) ──────────")
    http = HTTPBenchmark(n=n_http).run()

    print("\n  ── Pure Python benchmarks (chain construction & validation) ───")
    py = PythonBenchmark(n=n_python).run()

    return {
        "scenario": "UMA Agent Protocol Overhead Benchmark",
        "run_at": datetime.now(timezone.utc).isoformat(),
        "n_http": n_http,
        "n_python": n_python,
        "http": http,
        "python": py,
    }


# ---------------------------------------------------------------------------
# Human-readable summary table
# ---------------------------------------------------------------------------

def print_table(result: Dict[str, Any]) -> None:
    h = result["http"]
    p = result["python"]

    def row(label: str, stats: Dict[str, Any], unit: str = "ms") -> str:
        if stats.get("mean_ms") is None:
            return f"  {label:<46} {'N/A':>8}"
        scale = 1000 if unit == "µs" else 1
        m  = stats["mean_ms"] * scale
        s  = stats["std_ms"]  * scale
        p95 = stats["p95_ms"] * scale
        n  = stats["n"]
        return (f"  {label:<46} {m:>7.2f} ± {s:>6.2f}  "
                f"p95={p95:>7.2f}  n={n}  [{unit}]")

    print("\n  ══════════════════════════════════════════════════════════════")
    print("  UMA Agent Protocol Overhead — Benchmark Results")
    print("  ══════════════════════════════════════════════════════════════")
    print()
    print("  ── Network Operations (mean ± std, all in ms) ─────────────────")
    print(row("Authentication (Keycloak password grant)",
              h["authentication"]))
    print(row("RPT exchange (permission ticket → token)",
              h["rpt_exchange"]))
    print(row("Resource read — baseline (plain UMA, no chain)",
              h["resource_read_baseline"]))
    print(row("Resource read — chain depth 1",
              h["resource_read_chain_depth_1"]))
    print(row("Resource read — chain depth 2",
              h["resource_read_chain_depth_2"]))
    print(row("Resource read — chain depth 3",
              h["resource_read_chain_depth_3"]))
    print(row("Delegation chain init (POST /api/delegation/init)",
              h["chain_init"]))
    print(row("Delegation chain sign (POST /api/delegation/sign)",
              h["chain_sign"]))
    print()

    ov = h["chain_extension_overhead_ms"]
    print("  ── Chain Extension Overhead (mean_with_chain − mean_baseline) ─")
    for d, ms in ov.items():
        print(f"  Depth {d}: {ms:+.3f} ms")
    print()

    cc = p["chain_construction"]
    print("  ── Chain Construction (pure Python, µs) ──────────────────────")
    for key, stats in cc.items():
        print(row(f"  {key}", stats, "µs"))
    print()

    cv = p["chain_validation"]
    print("  ── Chain Validation (pure Python, µs) ────────────────────────")
    for key, stats in cv.items():
        print(row(f"  {key}", stats, "µs"))
    print()
    print("  ══════════════════════════════════════════════════════════════\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="UMA Agent Benchmark — Step 5")
    p.add_argument("--n-http",   type=int, default=30,
                   help="HTTP sample count (default 30)")
    p.add_argument("--n-python", type=int, default=1000,
                   help="Python sample count (default 1000)")
    p.add_argument("--json-out", metavar="FILE", default=None)
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    import logging
    logging.basicConfig(level=logging.WARNING)

    result = run_benchmark(n_http=args.n_http, n_python=args.n_python)
    print_table(result)

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"  JSON written to: {args.json_out}\n")


if __name__ == "__main__":
    main()
