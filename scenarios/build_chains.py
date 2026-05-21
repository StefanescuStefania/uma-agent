#!/usr/bin/env python3
"""
Build server-signed delegation chains for the LLM concurrent load test.

Connects to Keycloak and the Resource Server (via server-side signing endpoints)
to produce four fully-signed delegation chains and four attack chain headers.
Writes chains.json to --out (default /results/chains.json).

Usage (inside Docker container on uma-network):
    python scenarios/build_chains.py --out /results/chains.json
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from typing import Dict, List

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.chain_claim import DelegationChainClaim

KEYCLOAK_URL  = os.environ.get("KEYCLOAK_URL",        "http://localhost:8080")
REALM         = os.environ.get("KEYCLOAK_REALM",       "test-realm")
RS_URL        = os.environ.get("RESOURCE_SERVER_URL",  "http://localhost:5000")
CLIENT_ID     = os.environ.get("CLIENT_ID",            "test-app")
CHAIN_SECRET  = os.environ.get("CHAIN_HMAC_SECRET",    "uma-agent-chain-hmac-secret-2024")

DORA_USERS: Dict[str, str] = {
    "compliance-manager": "compliance-pass123",
    "risk-analyst":       "risk-pass123",
    "data-extractor":     "extractor-pass123",
    "report-validator":   "validator-pass123",
    "audit-reader":       "audit-pass123",
}


def _wait_for_services(timeout: int = 300) -> None:
    checks = [
        (f"{KEYCLOAK_URL}/realms/{REALM}", "Keycloak"),
        (f"{RS_URL}/", "Resource Server"),
    ]
    for url, name in checks:
        print(f"  Waiting for {name}…", end=" ", flush=True)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if requests.get(url, timeout=5).status_code < 500:
                    print("ready")
                    break
            except requests.RequestException:
                pass
            time.sleep(3)
        else:
            raise RuntimeError(f"{name} not ready after {timeout}s at {url}")


def _get_token(username: str, password: str) -> str:
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": CLIENT_ID,
              "username": username, "password": password, "scope": "openid"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _server_init_chain(token: str, scopes: List[str]) -> str:
    r = requests.post(
        f"{RS_URL}/api/delegation/init",
        json={"requested_scopes": scopes},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["chain_claim"]


def _server_sign_chain(token: str, parent_chain: str,
                       child_agent_id: str, scopes: List[str]) -> str:
    r = requests.post(
        f"{RS_URL}/api/delegation/sign",
        json={"parent_chain": parent_chain, "child_agent_id": child_agent_id,
              "requested_scopes": scopes},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["chain_claim"]


def build_sub_chains(tokens: Dict[str, str],
                     members: List[str],
                     scopes: List[str]) -> Dict[str, str]:
    """Build server-signed sub-chains for all prefix depths."""
    chains: Dict[str, str] = {}
    root_token = tokens[members[0]]
    chain = _server_init_chain(root_token, scopes)
    chains["1"] = chain
    for depth, member in enumerate(members[1:], start=2):
        parent_agent = members[depth - 2]
        chain = _server_sign_chain(tokens[parent_agent], chain, member, scopes)
        chains[str(depth)] = chain
    return chains


def main() -> None:
    parser = argparse.ArgumentParser(description="Build delegation chains for LLM load test")
    parser.add_argument("--out", default="/results/chains.json")
    args = parser.parse_args()

    _wait_for_services()

    print("\nAuthenticating DORA users…")
    tokens: Dict[str, str] = {}
    for username, password in DORA_USERS.items():
        tokens[username] = _get_token(username, password)
        print(f"  {username}: OK")

    SCOPES_D4 = ["documents:read", "calendar:read"]
    SCOPES_D5 = ["documents:read"]
    MEMBERS_D4 = ["compliance-manager", "risk-analyst", "data-extractor", "report-validator"]
    MEMBERS_D5 = ["compliance-manager", "risk-analyst", "data-extractor",
                  "report-validator", "audit-reader"]

    print("\nBuilding server-signed delegation chains…")

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

    print("\nBuilding attack chain headers…")

    # T1: scope escalation — chain only has database:audit; /api/documents needs documents:read
    t1 = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager"],
        granted_scopes=["database:audit"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )

    # T2: depth exceeded — 7 members, MAX_DELEGATION_DEPTH=6
    t2 = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager", "ag1", "ag2", "ag3", "ag4", "ag5", "attack-t2"],
        granted_scopes=["documents:read"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )

    # T3: token replay — terminus=data-extractor but we'll present risk-analyst's RPT
    t3 = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager", "risk-analyst", "data-extractor"],
        granted_scopes=["documents:read"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )

    # T4: HMAC tamper — valid structure, zeroed chain_hash
    valid_base = DelegationChainClaim.create(
        root_agent="compliance-manager",
        members=["compliance-manager"],
        granted_scopes=["documents:read"],
        max_depth=6, hmac_secret=CHAIN_SECRET,
    )
    t4 = dataclasses.replace(valid_base, chain_hash="0" * 64)

    print("  T1 (scope mismatch), T2 (depth exceeded), T3 (terminus mismatch), T4 (HMAC tamper): OK")

    result = {
        "chain_A": chain_A,
        "chain_B": chain_B,
        "chain_C": chain_C,
        "chain_D": chain_D,
        "attacks": {
            "T1": t1.to_header_value(),
            "T2": t2.to_header_value(),
            "T3": t3.to_header_value(),
            "T4": t4.to_header_value(),
        },
        "metadata": {
            "members_D4": MEMBERS_D4,
            "members_D5": MEMBERS_D5,
            "scopes_D4": SCOPES_D4,
            "scopes_D5": SCOPES_D5,
        },
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nChains written to {args.out}")


if __name__ == "__main__":
    main()
