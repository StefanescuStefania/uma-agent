#!/usr/bin/env python3
"""
Aggregate per-container results from the LLM concurrent load test.

Reads all agent-*.json files from --dir and writes a unified
llm_load_test.json to --out.

Usage:
    python scenarios/aggregate_llm_results.py \
        --dir paper_evidence/llm_agents \
        --out paper_evidence/llm_load_test.json
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List


def _percentile(data: List[float], pct: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = (pct / 100) * (len(s) - 1)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return round(s[lo] + (k - lo) * (s[hi] - s[lo]), 2)


def _stats(samples: List[float]) -> Dict[str, Any]:
    if not samples:
        return {"n": 0}
    return {
        "n":    len(samples),
        "mean": round(statistics.mean(samples), 2),
        "std":  round(statistics.stdev(samples), 2) if len(samples) > 1 else 0.0,
        "p50":  _percentile(samples, 50),
        "p95":  _percentile(samples, 95),
        "p99":  _percentile(samples, 99),
        "min":  round(min(samples), 2),
        "max":  round(max(samples), 2),
    }


def _print_report(result: Dict[str, Any]) -> None:
    print()
    print("  " + "═" * 66)
    print("  UMA Agent — LLM Concurrent Load Test Results")
    print("  " + "═" * 66)
    print(f"  Containers : {result['n_containers']}  "
          f"({result['n_llm_agents']} LLM + "
          f"{result['n_http_agents']} HTTP + "
          f"{result['n_attack_agents']} attack)")
    print(f"  Requests   : {result['total_requests']} total  "
          f"({result['honest_successful']} honest OK  "
          f"+ {result['attack_total']} attack)")
    print(f"  Attacks    : {result['attack_blocked']}/{result['attack_total']} blocked  "
          f"({result['attack_block_rate']:.1f}%)")
    print(f"  Wall time  : {result['wall_time_s']:.1f} s")
    print(f"  Throughput : {result['throughput_rps']:.1f} req/s")

    if (s := result.get("latency_llm_task_ms")) and s.get("n", 0) > 0:
        print()
        print("  ── LLM task latency (includes LLM inference + UMA protocol) ──")
        print(f"  n={s['n']}  mean={s['mean']:.0f} ms  "
              f"p50={s['p50']:.0f}  p95={s['p95']:.0f}  p99={s['p99']:.0f}")

    if (s := result.get("latency_http_request_ms")) and s.get("n", 0) > 0:
        print()
        print("  ── HTTP request latency (pure UMA protocol overhead) ─────────")
        print(f"  n={s['n']}  mean={s['mean']:.1f} ms  "
              f"p50={s['p50']:.1f}  p95={s['p95']:.1f}  p99={s['p99']:.1f}")

    print()
    print("  ── Per-depth latency (HTTP agents) ───────────────────────────")
    print(f"  {'Depth':<6}  {'n':>5}  {'mean':>8}  {'p50':>8}  {'p95':>8}  {'p99':>8}")
    for depth_str, st in sorted(result["latency_by_depth"].items(), key=lambda x: int(x[0])):
        if st.get("n", 0) == 0:
            continue
        print(f"  {depth_str:<6}  {st['n']:>5}  "
              f"{st['mean']:>7.1f}  {st['p50']:>7.1f}  {st['p95']:>7.1f}  {st['p99']:>7.1f}")

    print()
    print("  ── Attack blocking ───────────────────────────────────────────")
    for ac in ("T1", "T2", "T3", "T4"):
        det = result["attack_detail"].get(ac, {})
        if not det:
            continue
        bar = "✓ BLOCKED" if det["block_rate"] == 100.0 else "✗ PARTIAL"
        print(f"  {ac}  {det['blocked']:>4}/{det['total']}  "
              f"{det['block_rate']:>5.1f}%  {bar}")

    print()
    print("  ── Per-container summary ─────────────────────────────────────")
    print(f"  {'Agent':28}  {'Type':6}  {'Depth':>5}  {'OK/N':>7}  {'wall':>7}")
    for a in result["agents"]:
        ok_n = f"{a['successful']}/{a['n_requests']}"
        print(f"  {a['agent_id']:28}  {a['agent_type']:6}  "
              f"{a['chain_depth']:>5}  {ok_n:>7}  {a['wall_time_s']:>6.1f}s")

    print("  " + "═" * 66)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate LLM load test results")
    parser.add_argument("--dir", default="paper_evidence/llm_agents",
                        help="Directory containing agent-*.json files")
    parser.add_argument("--out", default="paper_evidence/llm_load_test.json",
                        help="Output JSON path")
    args = parser.parse_args()

    files = sorted(glob.glob(os.path.join(args.dir, "agent-*.json")))
    if not files:
        print(f"ERROR: No agent-*.json files found in {args.dir}", file=sys.stderr)
        sys.exit(1)

    print(f"  Aggregating {len(files)} agent result files…")
    all_agents = [json.load(open(f)) for f in files]

    honest_agents = [a for a in all_agents if a["agent_type"] in ("llm", "http")]
    attack_agents = [a for a in all_agents if a["agent_type"] == "attack"]
    llm_agents    = [a for a in all_agents if a["agent_type"] == "llm"]
    http_agents   = [a for a in all_agents if a["agent_type"] == "http"]

    # Latency collections
    llm_latencies  = [r["latency_ms"] for a in llm_agents
                      for r in a["requests"] if not r.get("error") and r["http_status"] == 200]
    http_latencies = [r["latency_ms"] for a in http_agents
                      for r in a["requests"] if r["http_status"] == 200]
    all_honest_ok  = llm_latencies + http_latencies

    # Attack stats
    attack_stats: Dict[str, Any] = {}
    total_blocked = 0
    total_attack_reqs = 0
    for ac in ("T1", "T2", "T3", "T4"):
        recs = [r for a in attack_agents
                if a.get("attack_class") == ac
                for r in a["requests"]]
        blocked = [r for r in recs if r["blocked"]]
        if recs:
            attack_stats[ac] = {
                "total":      len(recs),
                "blocked":    len(blocked),
                "block_rate": round(len(blocked) / len(recs) * 100, 1),
            }
            total_blocked    += len(blocked)
            total_attack_reqs += len(recs)

    # Wall time: max across all containers (parallel execution)
    wall_times = [a["wall_time_s"] for a in all_agents if a["wall_time_s"] > 0]
    total_wall = max(wall_times) if wall_times else 0.0

    total_requests = sum(len(a["requests"]) for a in all_agents)
    throughput = total_requests / total_wall if total_wall > 0 else 0.0

    # Per-depth breakdown (HTTP honest agents only — LLM agents track task latency separately)
    by_depth: Dict[str, List[float]] = {}
    for a in http_agents:
        d = str(a["chain_depth"])
        for r in a["requests"]:
            if r["http_status"] == 200:
                by_depth.setdefault(d, []).append(r["latency_ms"])

    result: Dict[str, Any] = {
        "run_at":              datetime.now(timezone.utc).isoformat(),
        "n_containers":        len(all_agents),
        "n_llm_agents":        len(llm_agents),
        "n_http_agents":       len(http_agents),
        "n_attack_agents":     len(attack_agents),
        "total_requests":      total_requests,
        "honest_successful":   len(all_honest_ok),
        "attack_total":        total_attack_reqs,
        "attack_blocked":      total_blocked,
        "attack_block_rate":   round(total_blocked / total_attack_reqs * 100, 1)
                               if total_attack_reqs else 0.0,
        "wall_time_s":         round(total_wall, 3),
        "throughput_rps":      round(throughput, 1),
        "latency_all_honest_ms":   _stats(all_honest_ok),
        "latency_llm_task_ms":     _stats(llm_latencies),
        "latency_http_request_ms": _stats(http_latencies),
        "latency_by_depth":    {d: _stats(lats) for d, lats in sorted(by_depth.items())},
        "attack_detail":       attack_stats,
        "agents": [
            {
                "agent_id":    a["agent_id"],
                "agent_type":  a["agent_type"],
                "username":    a["username"],
                "chain_name":  a.get("chain_name", ""),
                "chain_depth": a["chain_depth"],
                "n_requests":  a["n_requests"],
                "successful":  sum(1 for r in a["requests"] if r["http_status"] == 200),
                "wall_time_s": a["wall_time_s"],
            }
            for a in sorted(all_agents, key=lambda x: x["agent_id"])
        ],
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"  JSON written to {args.out}")

    _print_report(result)


if __name__ == "__main__":
    main()
