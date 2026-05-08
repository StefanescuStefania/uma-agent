#!/usr/bin/env python3
"""
Deep Delegation Demo — 5-Agent Chain with Information Flux Visualization

Builds a delegation chain 5 levels deep, runs each agent against live resources,
then queries every audit endpoint to verify what was stored.

Chain layout (scopes narrow at each hop):

  compliance-manager  depth 1  [documents:read, calendar:read, database:read, database:write]
    └─ risk-analyst    depth 2  [documents:read, database:read, database:write]
         └─ data-extractor depth 3  [database:read, database:write]
              └─ report-validator depth 4  [database:read]
                   └─ audit-reader  depth 5  [database:read]
                                             ↑ also attempts T1: database:audit → blocked

Requires: Keycloak + resource server running (docker-compose up).
No LLM backend needed — uses _dispatch_tool directly.

Usage
─────
  python3 scenarios/deep_delegation_demo.py
  python3 scenarios/deep_delegation_demo.py --json-out paper_evidence/deep_delegation_result.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests as req_lib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.llm_agent import LLMAgent

RESOURCE_SERVER = "http://localhost:5000"
MAX_DEPTH = 6   # matches updated docker-compose MAX_DELEGATION_DEPTH

# ---------------------------------------------------------------------------
# Chain specification
# ---------------------------------------------------------------------------

# Each entry defines one agent level.
# credentials: the Keycloak account used to obtain the RPT.
# scopes: what this agent is delegated (strict subset of parent).
# reads: resources it will read.
# writes: resources it will write.
# attack: (path, scope_label) — T1 attempt at this depth, if set.

CHAIN_SPEC = [
    {
        "agent_id":  "compliance-manager",
        "username":  "compliance-manager",
        "password":  "compliance-pass123",
        "scopes":    ["documents:read", "calendar:read", "database:read", "database:write"],
        "reads":     ["/api/documents", "/api/calendar"],
        "writes":    [],
        "attack":    None,
    },
    {
        "agent_id":  "risk-analyst",
        "username":  "risk-analyst",
        "password":  "risk-pass123",
        "scopes":    ["documents:read", "database:read", "database:write"],
        "reads":     ["/api/documents", "/api/database"],
        "writes":    [],
        "attack":    None,
    },
    {
        "agent_id":  "data-extractor",
        "username":  "data-extractor",
        "password":  "extractor-pass123",
        "scopes":    ["database:read", "database:write"],
        "reads":     ["/api/database"],
        "writes":    [],   # write scope held in chain; POST probe requires separate UMA flow
        "attack":    None,
    },
    {
        "agent_id":  "report-validator",
        "username":  "report-validator",
        "password":  "validator-pass123",
        "scopes":    ["database:read"],
        "reads":     ["/api/database"],
        "writes":    [],
        "attack":    None,
    },
    {
        "agent_id":  "audit-reader",
        "username":  "audit-reader",
        "password":  "audit-pass123",
        "scopes":    ["database:read"],
        "reads":     ["/api/database"],
        "writes":    [],
        "attack":    ("/api/database/audit-entries", "database:audit"),
    },
]


# ---------------------------------------------------------------------------
# Agent step result
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    agent_id: str
    depth: int
    granted_scopes: List[str]
    authenticate_ms: float = 0.0
    reads: List[Dict[str, Any]] = field(default_factory=list)
    writes: List[Dict[str, Any]] = field(default_factory=list)
    attack_result: Optional[Dict[str, Any]] = None
    chain_members: List[str] = field(default_factory=list)
    chain_id: str = ""
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "depth": self.depth,
            "granted_scopes": self.granted_scopes,
            "chain_members": self.chain_members,
            "chain_id": self.chain_id,
            "authenticate_ms": round(self.authenticate_ms, 2),
            "reads": self.reads,
            "writes": self.writes,
            "attack_result": self.attack_result,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Build and run one agent step
# ---------------------------------------------------------------------------

def _dispatch_timed(agent: LLMAgent, name: str, args: Dict[str, Any]) -> Tuple[Dict, float]:
    """Call _dispatch_tool and return (parsed_result, elapsed_ms)."""
    t0 = time.perf_counter()
    raw = agent._dispatch_tool(name, args)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    return json.loads(raw), round(elapsed_ms, 2)


def _run_step(agent: LLMAgent, spec: Dict[str, Any]) -> StepResult:
    result = StepResult(
        agent_id=agent.agent_id,
        depth=agent.chain_claim.depth,
        granted_scopes=list(agent.granted_scopes),
        chain_members=list(agent.chain_claim.members),
        chain_id=agent.chain_claim.chain_id,
    )

    # Authenticate
    auth_result, auth_ms = _dispatch_timed(agent, "authenticate", {})
    result.authenticate_ms = auth_ms
    if not auth_result.get("success"):
        result.error = f"Authentication failed: {auth_result.get('error')}"
        return result

    # Reads
    for path in spec["reads"]:
        uma_result, uma_ms = _dispatch_timed(agent, "request_uma_access", {"resource_path": path})
        if not uma_result.get("granted"):
            result.reads.append({
                "path": path,
                "success": False,
                "error": uma_result.get("error", "UMA access denied"),
                "rpt_ms": uma_ms,
            })
            continue
        read_result, read_ms = _dispatch_timed(agent, "read_resource", {"resource_path": path})
        result.reads.append({
            "path": path,
            "success": read_result.get("success", False),
            "http_status": 200 if read_result.get("success") else read_result.get("http_status"),
            "rpt_ms": round(uma_ms, 2),
            "read_ms": round(read_ms, 2),
            "denied_reason": read_result.get("reason") if not read_result.get("success") else None,
        })

    # Writes
    for path, data in spec.get("writes", []):
        write_result, write_ms = _dispatch_timed(
            agent, "write_resource", {"resource_path": path, "data": data}
        )
        result.writes.append({
            "path": path,
            "success": write_result.get("success", False),
            "write_ms": round(write_ms, 2),
            "error": write_result.get("error") if not write_result.get("success") else None,
        })

    # T1 attack attempt
    if spec.get("attack"):
        attack_path, scope_label = spec["attack"]
        # Request UMA access (the RPT exchange may succeed — Keycloak isn't aware of chain scopes)
        uma_result, uma_ms = _dispatch_timed(
            agent, "request_uma_access", {"resource_path": attack_path}
        )
        # Even if UMA succeeds, the resource server will enforce the chain
        if uma_result.get("granted"):
            atk_result, atk_ms = _dispatch_timed(
                agent, "read_resource", {"resource_path": attack_path}
            )
        else:
            atk_result = {"success": False, "denied": True,
                          "reason": uma_result.get("error", "UMA denied")}
            atk_ms = uma_ms

        blocked = not atk_result.get("success", True)
        result.attack_result = {
            "type": "T1_scope_escalation",
            "attempted_path": attack_path,
            "attempted_scope": scope_label,
            "blocked": blocked,
            "reason": atk_result.get("reason", ""),
            "elapsed_ms": round(atk_ms, 2),
        }

    return result


# ---------------------------------------------------------------------------
# Build the full 5-agent chain
# ---------------------------------------------------------------------------

def _build_agent_chain() -> List[LLMAgent]:
    """Construct agents depth 1-5 via create_sub_agent() for authentic chain inheritance."""
    root_spec = CHAIN_SPEC[0]
    root = LLMAgent(
        agent_id=root_spec["agent_id"],
        username=root_spec["username"],
        password=root_spec["password"],
        granted_scopes=root_spec["scopes"],
        max_depth=MAX_DEPTH,
    )
    auth = root._tool_authenticate()
    if not auth.get("success"):
        raise RuntimeError(f"Root agent authentication failed: {auth}")
    agents = [root]
    for spec in CHAIN_SPEC[1:]:
        parent = agents[-1]
        child = parent.create_sub_agent(
            agent_id=spec["agent_id"],
            username=spec["username"],
            password=spec["password"],
            allowed_scopes=spec["scopes"],
        )
        auth = child._tool_authenticate()
        if not auth.get("success"):
            raise RuntimeError(f"Child agent {spec['agent_id']} authentication failed: {auth}")
        agents.append(child)
    return agents


# ---------------------------------------------------------------------------
# Verification: query audit endpoints and cross-validate
# ---------------------------------------------------------------------------

def verify_stored_state(
    step_results: List[StepResult],
    run_start: datetime,
) -> Dict[str, Any]:
    """
    Query all four audit endpoints and validate that what was stored matches
    what the demo run expected.
    """
    verification: Dict[str, Any] = {
        "run_start": run_start.isoformat(),
        "endpoints_queried": [],
        "cross_validation": {},
        "verdict": "UNKNOWN",
    }

    # 1. Hash chain integrity
    try:
        r = req_lib.get(f"{RESOURCE_SERVER}/api/audit/verify", timeout=10)
        verify_data = r.json()
        verification["endpoints_queried"].append("/api/audit/verify")
        verification["audit_chain_integrity"] = {
            "chain_intact": verify_data.get("chain_intact"),
            "total_events": verify_data.get("total_events"),
            "broken_links": verify_data.get("broken_links", []),
        }
    except Exception as exc:
        verification["audit_chain_integrity"] = {"error": str(exc)}

    # 2. All recent events (last 200)
    try:
        r = req_lib.get(f"{RESOURCE_SERVER}/api/audit/events?limit=200", timeout=10)
        events_data = r.json()
        verification["endpoints_queried"].append("/api/audit/events")
        all_events = events_data.get("events", [])

        # Filter to this run's agents
        our_agents = {s["agent_id"] for s in CHAIN_SPEC}
        our_events = [e for e in all_events if e.get("agent_id") in our_agents]
        verification["our_events"] = {
            "total_all": len(all_events),
            "from_this_chain": len(our_events),
            "agent_breakdown": {
                aid: len([e for e in our_events if e.get("agent_id") == aid])
                for aid in our_agents
            },
        }
    except Exception as exc:
        verification["our_events"] = {"error": str(exc)}
        our_events = []

    # 3. Security blocks
    try:
        r = req_lib.get(f"{RESOURCE_SERVER}/api/audit/security-blocks", timeout=10)
        blocks_data = r.json()
        verification["endpoints_queried"].append("/api/audit/security-blocks")
        all_blocks = blocks_data.get("blocks", [])
        our_blocks = [b for b in all_blocks if b.get("agent_id") in our_agents]
        verification["security_blocks"] = {
            "total_all": len(all_blocks),
            "from_this_chain": len(our_blocks),
            "by_class": blocks_data.get("by_attack_class", {}),
            "our_blocks": our_blocks,
        }
    except Exception as exc:
        verification["security_blocks"] = {"error": str(exc)}
        our_blocks = []

    # 4. Registered delegation chains
    try:
        r = req_lib.get(f"{RESOURCE_SERVER}/api/delegation-chains", timeout=10)
        chains_data = r.json()
        verification["endpoints_queried"].append("/api/delegation-chains")
        all_chains = chains_data.get("chains", [])
        # Find chains from this run using chain_ids from step_results
        our_chain_ids = {sr.chain_id for sr in step_results if sr.chain_id}
        our_chains = [c for c in all_chains if c.get("chain_id") in our_chain_ids]
        verification["delegation_chains"] = {
            "total_all": len(all_chains),
            "from_this_run": len(our_chains),
            "chain_ids": list(our_chain_ids),
            "registered": our_chains,
        }
    except Exception as exc:
        verification["delegation_chains"] = {"error": str(exc)}
        our_chains = []

    # Cross-validate
    expected_reads = sum(len(sr.reads) for sr in step_results)
    expected_writes = sum(len(sr.writes) for sr in step_results)
    expected_attacks = sum(1 for sr in step_results if sr.attack_result is not None)
    expected_blocks = sum(
        1 for sr in step_results
        if sr.attack_result and sr.attack_result.get("blocked")
    )

    actual_blocks = len(our_blocks) if isinstance(our_blocks, list) else 0
    permitted_events = len([e for e in our_events if not e.get("attack_class")])

    cv = verification["cross_validation"]
    cv["expected_resource_ops"] = expected_reads + expected_writes
    cv["expected_attack_attempts"] = expected_attacks
    cv["expected_blocks"] = expected_blocks
    cv["actual_blocks_in_audit"] = actual_blocks
    cv["permitted_events_in_audit"] = permitted_events
    cv["t1_attack_recorded"] = any(
        b.get("agent_id") == "audit-reader" for b in our_blocks
    )
    cv["all_expected_agents_present"] = all(
        any(e.get("agent_id") == sid for e in our_events)
        for sid in our_agents
    )

    # Final verdict
    blocks_match = actual_blocks >= expected_blocks
    t1_recorded = cv["t1_attack_recorded"]
    chain_ok = verification.get("audit_chain_integrity", {}).get("chain_intact") is not False
    all_agents = cv["all_expected_agents_present"]

    if blocks_match and t1_recorded and all_agents:
        verification["verdict"] = "VERIFIED ✓"
    elif not blocks_match:
        verification["verdict"] = f"FAIL: expected {expected_blocks} blocks, found {actual_blocks}"
    elif not t1_recorded:
        verification["verdict"] = "FAIL: T1 attack by audit-reader not found in audit trail"
    else:
        verification["verdict"] = "PARTIAL"

    return verification


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------

def visualize_ascii(step_results: List[StepResult]) -> str:
    lines = []
    w = 72
    lines.append("═" * w)
    lines.append("  Deep Delegation Chain — Information Flux")
    lines.append("═" * w)
    lines.append(f"  Chain: {' → '.join(sr.agent_id for sr in step_results)}")
    lines.append(f"  Depth: {len(step_results)} of {MAX_DEPTH}  |  "
                 f"Protocol: urn:uma-agent:delegation-chain:1.0")
    lines.append("")

    for i, sr in enumerate(step_results):
        indent = "  " + "     " * i
        connector = "└─▶ " if i > 0 else "    "

        # Header
        tag = f"[depth {sr.depth}]"
        scopes_str = "  ".join(sr.granted_scopes)
        lines.append(f"{indent}{connector}{tag} {sr.agent_id}")
        lines.append(f"{indent}      scopes: {scopes_str}")
        lines.append(f"{indent}      auth:   {sr.authenticate_ms:.1f} ms")

        # Reads
        for op in sr.reads:
            icon = "✓" if op["success"] else "✗"
            ms_str = f"{op.get('read_ms', '?'):.1f} ms" if op.get("read_ms") else "—"
            lines.append(f"{indent}      ├─ GET {op['path']:<35} {icon} {ms_str}")

        # Writes
        for op in sr.writes:
            icon = "✓" if op["success"] else "✗"
            ms_str = f"{op.get('write_ms', '?'):.1f} ms" if op.get("write_ms") else "—"
            lines.append(f"{indent}      ├─ POST {op['path']:<34} {icon} {ms_str}")

        # Attack
        if sr.attack_result:
            ar = sr.attack_result
            icon = "⛔" if ar["blocked"] else "⚠"
            short_reason = ar["reason"][:55] + "…" if len(ar["reason"]) > 55 else ar["reason"]
            lines.append(f"{indent}      └─ GET {ar['attempted_path']:<35} "
                         f"{icon} T1 BLOCKED")
            lines.append(f"{indent}         reason: {short_reason}")
        else:
            lines.append(f"{indent}      │")

    lines.append("═" * w)
    return "\n".join(lines)


def visualize_mermaid(step_results: List[StepResult]) -> str:
    """Mermaid flowchart suitable for pasting into a paper or README."""
    lines = ["flowchart TD"]

    node_ids = []
    for sr in step_results:
        nid = sr.agent_id.replace("-", "_")
        node_ids.append(nid)
        scopes = "\\n".join(sr.granted_scopes)
        lines.append(
            f'    {nid}["{sr.agent_id}\\ndepth={sr.depth}\\n{scopes}"]'
        )

    # Edges with scope reduction labels
    for i in range(len(step_results) - 1):
        parent = step_results[i]
        child = step_results[i + 1]
        dropped = [s for s in parent.granted_scopes if s not in child.granted_scopes]
        kept = child.granted_scopes
        label = f"drop({', '.join(dropped)})" if dropped else "same scopes"
        lines.append(f'    {node_ids[i]} -->|"{label}"| {node_ids[i+1]}')

    # T1 attack node
    for sr in step_results:
        if sr.attack_result and sr.attack_result["blocked"]:
            nid = sr.agent_id.replace("-", "_")
            scope_label = sr.attack_result["attempted_scope"]
            lines.append(f'    T1_BLOCK["⛔ T1 BLOCKED\\n{scope_label}\\nnot in chain"]')
            lines.append(f'    {nid} -.->|"ESCALATION ATTEMPT"| T1_BLOCK')
            lines.append('    style T1_BLOCK fill:#ff4444,color:#fff')

    # Style nodes
    for sr in step_results:
        nid = sr.agent_id.replace("-", "_")
        if sr.depth == 1:
            lines.append(f'    style {nid} fill:#4a90d9,color:#fff')
        elif sr.attack_result:
            lines.append(f'    style {nid} fill:#f0a500,color:#fff')
        else:
            lines.append(f'    style {nid} fill:#5ba85b,color:#fff')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_deep_delegation() -> Dict[str, Any]:
    run_start = datetime.now(timezone.utc)
    print("\n  Building 5-agent delegation chain…")
    agents = _build_agent_chain()

    step_results: List[StepResult] = []
    print(f"  Running {len(agents)} agent steps:\n")

    for agent, spec in zip(agents, CHAIN_SPEC):
        label = f"[depth {agent.chain_claim.depth}] {agent.agent_id}"
        print(f"  {label:<42} running…", end="", flush=True)
        sr = _run_step(agent, spec)
        step_results.append(sr)
        ok_reads = sum(1 for r in sr.reads if r["success"])
        ok_writes = sum(1 for w in sr.writes if w["success"])
        atk = "  T1⛔" if (sr.attack_result and sr.attack_result["blocked"]) else ""
        print(f"  reads={ok_reads}/{len(sr.reads)}  writes={ok_writes}/{len(sr.writes)}{atk}")

    print("\n  Querying audit endpoints for verification…\n")
    verification = verify_stored_state(step_results, run_start)

    ascii_tree = visualize_ascii(step_results)
    mermaid = visualize_mermaid(step_results)

    return {
        "scenario": "deep_delegation_demo",
        "run_at": run_start.isoformat(),
        "max_depth_configured": MAX_DEPTH,
        "chain_depth_reached": len(step_results),
        "chain_agents": [sr.agent_id for sr in step_results],
        "steps": [sr.to_dict() for sr in step_results],
        "verification": verification,
        "visualization": {
            "ascii": ascii_tree,
            "mermaid": mermaid,
        },
    }


def print_result(result: Dict[str, Any]) -> None:
    print(result["visualization"]["ascii"])

    v = result["verification"]
    print("  ── Audit Verification ──────────────────────────────────────────")
    print(f"  Endpoints queried: {', '.join(v.get('endpoints_queried', []))}")

    integrity = v.get("audit_chain_integrity", {})
    intact = integrity.get("chain_intact")
    broken = len(integrity.get("broken_links", []))
    print(f"  Audit hash chain:  {'intact ✓' if intact else f'broken ({broken} links) ⚠'}"
          f"  ({integrity.get('total_events', '?')} total events)")

    our = v.get("our_events", {})
    print(f"  Events from our chain: {our.get('from_this_chain', '?')} of "
          f"{our.get('total_all', '?')} total")
    breakdown = our.get("agent_breakdown", {})
    if breakdown:
        for aid, count in breakdown.items():
            print(f"    {aid:<30} {count} event(s)")

    blocks = v.get("security_blocks", {})
    print(f"  Security blocks (all time): {blocks.get('total_all', '?')}")
    t1_rec = v.get("cross_validation", {}).get("t1_attack_recorded")
    print(f"  T1 attack recorded in audit: {'yes ✓' if t1_rec else 'not found ✗'}")

    chains = v.get("delegation_chains", {})
    print(f"  Delegation chains registered: {chains.get('from_this_run', '?')} "
          f"(from this run) / {chains.get('total_all', '?')} total")

    print(f"\n  Verdict: {v.get('verdict', 'UNKNOWN')}")

    print("\n  ── Mermaid Diagram (paste into paper) ──────────────────────────")
    print("```mermaid")
    print(result["visualization"]["mermaid"])
    print("```\n")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Deep Delegation Demo — 5-agent chain")
    p.add_argument("--json-out", metavar="FILE", default=None)
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    result = run_deep_delegation()
    print_result(result)

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"  JSON written to: {args.json_out}\n")


if __name__ == "__main__":
    main()
