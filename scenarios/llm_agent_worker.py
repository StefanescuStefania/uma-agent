#!/usr/bin/env python3
"""
LLM Agent Worker — single-container participant in the concurrent LLM load test.

Each Docker container runs exactly one instance of this script.  Configuration
is entirely via environment variables so the same image can serve all roles.

Modes
─────
  LLM    (USE_LLM=true)   real LLMAgent with Ollama; measures end-to-end
                          task latency including LLM inference + UMA protocol
  HTTP   (IS_ATTACK=false) direct HTTP with delegation chain header; measures
                          per-request protocol latency at high throughput
  Attack (IS_ATTACK=true) sends crafted malformed requests; expects 403

File-based barrier (synchronised start across containers)
────────────────────────────────────────────────────────
  1. Worker initialises (fast, no network).
  2. Worker writes READY_DIR/<AGENT_ID> to signal it is ready.
  3. Worker polls START_FILE (written by the shell orchestrator once all N
     workers have written their ready flag).
  4. All workers fire their requests simultaneously.

Environment variables
─────────────────────
  AGENT_ID            unique identifier (container name suffix)
  USERNAME            Keycloak username
  PASSWORD            Keycloak password
  CHAIN_CLAIM         pre-signed delegation chain header (base64url)
  CHAIN_NAME          chain_A / chain_B / chain_C / chain_D / attack
  CHAIN_DEPTH         depth of the sub-chain terminus (1–5, or -1 for attack)
  N_REQUESTS          number of tasks/requests per worker (default 5/30/30)
  USE_LLM             true  → real LLM inference via Ollama
  IS_ATTACK           true  → attack mode (sends malformed chain)
  ATTACK_CLASS        T1 / T2 / T3 / T4
  N_AGENTS            total workers for barrier count (default 20)
  RESULTS_DIR         output directory (default /results)
  READY_DIR           barrier ready-flag dir (default /results/ready)
  START_FILE          barrier start-flag file (default /results/start_flag)
  KEYCLOAK_URL        default http://localhost:8080
  KEYCLOAK_REALM      default test-realm
  CLIENT_ID           default test-app
  RESOURCE_SERVER_URL default http://localhost:5000
  RESOURCE_PATH       default /api/documents
  OLLAMA_BASE_URL     default http://host.docker.internal:11434/v1
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.chain_claim import DelegationChainClaim

# ─── Configuration ────────────────────────────────────────────────────────────

AGENT_ID     = os.environ["AGENT_ID"]
USERNAME     = os.environ["USERNAME"]
PASSWORD     = os.environ["PASSWORD"]
CHAIN_CLAIM  = os.environ.get("CHAIN_CLAIM", "")
CHAIN_NAME   = os.environ.get("CHAIN_NAME", "")
CHAIN_DEPTH  = int(os.environ.get("CHAIN_DEPTH", "1"))
N_REQUESTS   = int(os.environ.get("N_REQUESTS", "5"))
USE_LLM      = os.environ.get("USE_LLM", "false").lower() == "true"
IS_ATTACK    = os.environ.get("IS_ATTACK", "false").lower() == "true"
ATTACK_CLASS = os.environ.get("ATTACK_CLASS", "")
N_AGENTS     = int(os.environ.get("N_AGENTS", "20"))

RESULTS_DIR  = os.environ.get("RESULTS_DIR", "/results")
READY_DIR    = os.environ.get("READY_DIR",   "/results/ready")
START_FILE   = os.environ.get("START_FILE",  "/results/start_flag")

KEYCLOAK_URL        = os.environ.get("KEYCLOAK_URL",        "http://localhost:8080")
REALM               = os.environ.get("KEYCLOAK_REALM",      "test-realm")
RESOURCE_SERVER_URL = os.environ.get("RESOURCE_SERVER_URL", "http://localhost:5000")
CLIENT_ID           = os.environ.get("CLIENT_ID",           "test-app")
RESOURCE_PATH       = os.environ.get("RESOURCE_PATH",       "/api/documents")
OLLAMA_BASE_URL     = os.environ.get("OLLAMA_BASE_URL",     "http://host.docker.internal:11434/v1")

logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s  [{AGENT_ID}]  %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)
# Suppress noisy libs
for lib in ("httpx", "httpcore", "urllib3", "openai"):
    logging.getLogger(lib).setLevel(logging.WARNING)


# ─── Data ─────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class RequestRecord:
    latency_ms:  float
    http_status: int
    blocked:     bool
    error:       str = ""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_token() -> str:
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": CLIENT_ID,
              "username": USERNAME, "password": PASSWORD, "scope": "openid"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _get_rpt(token: str, resource_path: str) -> Optional[str]:
    probe = requests.get(f"{RESOURCE_SERVER_URL}{resource_path}", timeout=15)
    m = re.search(r'ticket="([^"]+)"', probe.headers.get("WWW-Authenticate", ""))
    if not m:
        return None
    r = requests.post(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data={"grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
              "ticket": m.group(1)},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    return r.json().get("access_token") if r.status_code == 200 else None


def _signal_ready() -> None:
    os.makedirs(READY_DIR, exist_ok=True)
    open(os.path.join(READY_DIR, AGENT_ID), "w").close()
    logger.info("Ready flag written — waiting for start signal")


def _wait_for_start(timeout: int = 600) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(START_FILE):
            logger.info("Start signal received — beginning requests")
            return
        time.sleep(0.2)
    raise TimeoutError(f"Start signal not received within {timeout}s")


# ─── Agent modes ──────────────────────────────────────────────────────────────

def run_llm_mode() -> List[RequestRecord]:
    """
    Real LLM agent: each task runs a full LLMAgent.run() cycle.

    The pre-signed CHAIN_CLAIM is injected so the agent never needs
    CHAIN_HMAC_SECRET.  The LLM is asked to authenticate and read a resource;
    latency covers Keycloak auth + LLM inference + UMA ticket exchange +
    resource read with chain validation.

    Retries up to 3 times with 30-second back-off on connection errors
    (Ollama serialises requests — queued agents may see a dropped connection
    if the wait exceeds the server-side idle timeout).
    """
    from agents.llm_agent import LLMAgent
    from openai import OpenAI

    chain = DelegationChainClaim.from_header_value(CHAIN_CLAIM)
    task = (
        "You are a DORA compliance automation agent. "
        "Please: (1) authenticate, (2) request UMA access to /api/documents, "
        "(3) read /api/documents and summarise the key compliance findings "
        "in two sentences."
    )

    # Stagger LLM agents so they don't all hit Ollama at exactly t=0.
    # STAGGER_DELAY_S is set per-container by the shell orchestrator.
    stagger = int(os.environ.get("STAGGER_DELAY_S", "0"))
    if stagger > 0:
        logger.info(f"Stagger delay: sleeping {stagger}s before starting LLM task")
        time.sleep(stagger)

    _signal_ready()
    _wait_for_start()

    records: List[RequestRecord] = []
    for i in range(N_REQUESTS):
        t0 = time.perf_counter()
        last_error = ""
        ok = False
        # Retry up to 3 times on connection error (Ollama queue drop-offs)
        for attempt in range(3):
            try:
                agent = LLMAgent(
                    agent_id=AGENT_ID,
                    username=USERNAME,
                    password=PASSWORD,
                    granted_scopes=chain.granted_scopes,
                    pre_signed_chain_claim=chain,
                    keycloak_url=KEYCLOAK_URL,
                    realm=REALM,
                    resource_server_url=RESOURCE_SERVER_URL,
                    backend="ollama",
                    base_url=OLLAMA_BASE_URL,
                    # Generous read timeout: Ollama may queue the request for
                    # several minutes if other agents are being served.
                    ollama_timeout=900,
                )
                response = agent.run(task, max_turns=10)
                ok = bool(response and len(response.strip()) > 20)
                last_error = ""
                break
            except Exception as exc:
                last_error = str(exc)
                if attempt < 2:
                    wait_s = 30 * (attempt + 1)
                    logger.warning(f"LLM task {i+1} attempt {attempt+1} failed: {exc} "
                                   f"— retrying in {wait_s}s")
                    time.sleep(wait_s)

        latency = (time.perf_counter() - t0) * 1000
        records.append(RequestRecord(
            latency_ms=latency,
            http_status=200 if ok else -1,
            blocked=False,
            error=last_error if not ok else "",
        ))
        logger.info(f"LLM task {i+1}/{N_REQUESTS}: {latency:.0f} ms  "
                    f"({'OK' if ok else 'FAIL: ' + last_error[:60]})")

    return records


def run_http_mode() -> List[RequestRecord]:
    """
    High-throughput HTTP mode: authenticate once, then make N_REQUESTS
    GET requests with the delegation chain header.  Latency measures only
    the chain validation + resource read (UMA protocol overhead).
    """
    logger.info("Authenticating with Keycloak…")
    token = _get_token()
    logger.info("Obtaining UMA RPT…")
    rpt = _get_rpt(token, RESOURCE_PATH)
    if not rpt:
        raise RuntimeError(f"Could not obtain RPT for {RESOURCE_PATH}")

    _signal_ready()
    _wait_for_start()

    session = requests.Session()
    records: List[RequestRecord] = []
    for _ in range(N_REQUESTS):
        t0 = time.perf_counter()
        try:
            r = session.get(
                f"{RESOURCE_SERVER_URL}{RESOURCE_PATH}",
                headers={
                    "Authorization":         f"Bearer {rpt}",
                    "X-Uma-Delegation-Chain": CHAIN_CLAIM,
                },
                timeout=30,
            )
            latency = (time.perf_counter() - t0) * 1000
            records.append(RequestRecord(
                latency_ms=latency,
                http_status=r.status_code,
                blocked=(r.status_code == 403),
            ))
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            records.append(RequestRecord(
                latency_ms=latency, http_status=-1, blocked=True, error=str(exc)))

    return records


def run_attack_mode() -> List[RequestRecord]:
    """
    Attack mode: authenticate as a legitimate DORA user (valid RPT) but
    present a malformed delegation chain.  All requests should be 403.

    T3 uses risk-analyst's RPT with a chain whose terminus is data-extractor
    → chain.members[-1] ≠ rpt.preferred_username.
    T1/T2/T4 use compliance-manager's RPT with wrong-scope / depth-exceeded /
    HMAC-tampered chains respectively.
    """
    logger.info(f"Attack mode {ATTACK_CLASS}: authenticating as {USERNAME}…")
    token = _get_token()
    rpt = _get_rpt(token, RESOURCE_PATH)

    _signal_ready()
    _wait_for_start()

    session = requests.Session()
    records: List[RequestRecord] = []
    for _ in range(N_REQUESTS):
        t0 = time.perf_counter()
        try:
            r = session.get(
                f"{RESOURCE_SERVER_URL}{RESOURCE_PATH}",
                headers={
                    "Authorization":         f"Bearer {rpt}",
                    "X-Uma-Delegation-Chain": CHAIN_CLAIM,
                },
                timeout=30,
            )
            latency = (time.perf_counter() - t0) * 1000
            blocked = r.status_code == 403
            records.append(RequestRecord(
                latency_ms=latency,
                http_status=r.status_code,
                blocked=blocked,
            ))
        except Exception as exc:
            latency = (time.perf_counter() - t0) * 1000
            records.append(RequestRecord(
                latency_ms=latency, http_status=-1, blocked=True, error=str(exc)))

    return records


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    logger.info(
        f"Worker started: USE_LLM={USE_LLM} IS_ATTACK={IS_ATTACK} "
        f"ATTACK_CLASS={ATTACK_CLASS or 'none'} N_REQUESTS={N_REQUESTS} "
        f"CHAIN_NAME={CHAIN_NAME} DEPTH={CHAIN_DEPTH}"
    )

    t_wall_start = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()

    if IS_ATTACK:
        records = run_attack_mode()
        agent_type = "attack"
    elif USE_LLM:
        records = run_llm_mode()
        agent_type = "llm"
    else:
        records = run_http_mode()
        agent_type = "http"

    wall_time_s = time.perf_counter() - t_wall_start
    completed_at = datetime.now(timezone.utc).isoformat()

    ok_count = sum(1 for r in records if r.http_status == 200)
    logger.info(
        f"Done: {ok_count}/{len(records)} OK  wall={wall_time_s:.1f}s"
    )

    result = {
        "agent_id":    AGENT_ID,
        "agent_type":  agent_type,
        "username":    USERNAME,
        "chain_name":  CHAIN_NAME,
        "chain_depth": CHAIN_DEPTH,
        "attack_class": ATTACK_CLASS,
        "n_requests":  N_REQUESTS,
        "requests":    [dataclasses.asdict(r) for r in records],
        "wall_time_s": round(wall_time_s, 3),
        "started_at":  started_at,
        "completed_at": completed_at,
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)
    out_file = os.path.join(RESULTS_DIR, f"agent-{AGENT_ID}.json")
    with open(out_file, "w") as f:
        json.dump(result, f, indent=2)

    print(
        f"[{AGENT_ID}] {agent_type.upper():6s}  "
        f"{ok_count}/{len(records)} OK  {wall_time_s:.1f}s  → {out_file}"
    )


if __name__ == "__main__":
    main()
