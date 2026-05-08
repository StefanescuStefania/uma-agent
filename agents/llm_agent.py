"""
LLM Agent — OpenAI-compatible tool calling over UMA 2.0

Addresses W6 (agents are simulated Python objects, not real LLM-based systems).
Implements a real LLM-backed agent whose only interface to protected resources
is through UMA-enforced tool calls.  The DelegationChainClaim is attached to
every request, enabling T1–T4 enforcement at the resource server even when
the LLM attempts to follow adversarial instructions (T4: prompt injection).

Backends (no paid API required)
────────────────────────────────
  Ollama (default, free, local):
      Install:  https://ollama.com  →  ollama pull llama3.2
      Use:      LLMAgent(..., backend="ollama", model="llama3.2")

  Groq (free tier, cloud, fast):
      Sign up:  https://console.groq.com  →  free API key
      Use:      LLMAgent(..., backend="groq", model="llama-3.3-70b-versatile",
                         api_key="gsk_...")

Both backends expose an OpenAI-compatible REST interface, so this module uses
the `openai` SDK for both.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import requests
from openai import OpenAI

from agents.chain_claim import DelegationChainClaim

logger = logging.getLogger(__name__)

_KEYCLOAK_URL = "http://localhost:8080"
_REALM = "test-realm"
_RESOURCE_SERVER_URL = "http://localhost:5000"
_CLIENT_ID = "test-app"

# OpenAI-compatible base URLs
_BACKEND_URLS: Dict[str, str] = {
    "ollama": "http://localhost:11434/v1",
    "groq": "https://api.groq.com/openai/v1",
}

# Sensible default models per backend
_DEFAULT_MODELS: Dict[str, str] = {
    "ollama": "llama3.2",
    "groq": "llama-3.3-70b-versatile",
}


def _openai_tools(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert from Anthropic-style tool defs to OpenAI function-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


class LLMAgent:
    """
    Real LLM-backed agent using OpenAI-compatible tool calling.

    Each agent instance holds an identity (agent_id), a set of granted
    authorization scopes, and a DelegationChainClaim that records the full
    delegation path from the root agent to this agent.  Every resource access
    sends the claim in X-Uma-Delegation-Chain so the resource server can
    enforce T1–T4 independently of the LLM's own reasoning.

    Delegation creates a child LLMAgent with the parent's members list
    extended by the child's identity and scopes reduced to the intersection
    of parent and requested scopes (scope monotonicity).
    """

    _TOOL_DEFS: List[Dict[str, Any]] = [
        {
            "name": "authenticate",
            "description": (
                "Authenticate with Keycloak to obtain an access token. "
                "Must be called before any resource access."
            ),
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "request_uma_access",
            "description": (
                "Negotiate UMA 2.0 access to a protected resource: "
                "triggers the permission-ticket → RPT exchange. "
                "Call this before read_resource or write_resource."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "resource_path": {
                        "type": "string",
                        "description": "API path, e.g. /api/documents or /api/calendar",
                    }
                },
                "required": ["resource_path"],
            },
        },
        {
            "name": "read_resource",
            "description": (
                "Read a UMA-protected resource using the previously obtained RPT "
                "and this agent's delegation chain claim."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "resource_path": {
                        "type": "string",
                        "description": "API path, e.g. /api/documents",
                    }
                },
                "required": ["resource_path"],
            },
        },
        {
            "name": "write_resource",
            "description": (
                "Write data to a UMA-protected resource using the previously "
                "obtained RPT and this agent's delegation chain claim."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "resource_path": {
                        "type": "string",
                        "description": "API path, e.g. /api/documents",
                    },
                    "data": {
                        "type": "object",
                        "description": "JSON body to POST to the resource.",
                    },
                },
                "required": ["resource_path", "data"],
            },
        },
    ]

    def __init__(
        self,
        agent_id: str,
        username: str,
        password: str,
        granted_scopes: List[str],
        delegation_chain: Optional[List[str]] = None,
        max_depth: int = 4,
        keycloak_url: str = _KEYCLOAK_URL,
        realm: str = _REALM,
        resource_server_url: str = _RESOURCE_SERVER_URL,
        backend: str = "ollama",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        pre_signed_chain_claim: Optional[DelegationChainClaim] = None,
    ) -> None:
        """
        Parameters
        ----------
        backend               : "ollama" (default, local, free) or "groq" (free tier)
        model                 : model name; defaults to llama3.2 for ollama,
                                llama-3.3-70b-versatile for groq
        api_key               : required for groq; reads GROQ_API_KEY env var if omitted
        base_url              : override the backend URL (e.g. remote Ollama instance)
        pre_signed_chain_claim: a server-signed DelegationChainClaim received from
                                POST /api/delegation/sign; used by sub-agents so they
                                never need to sign their own chain locally.
        """
        self.agent_id = agent_id
        self.username = username
        self.password = password
        self.granted_scopes = list(granted_scopes)
        self.max_depth = max_depth
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.resource_server_url = resource_server_url
        self.backend = backend
        self.model = model or _DEFAULT_MODELS.get(backend, "llama3.2")

        if pre_signed_chain_claim is not None:
            # Sub-agent: use the server-signed claim provided by the parent;
            # max_depth comes from the server, not from the constructor default.
            self.chain_claim = pre_signed_chain_claim
            self.max_depth = pre_signed_chain_claim.max_depth
            self._chain_server_signed = True
        else:
            # Root agent: build a local placeholder; will be replaced by a
            # server-signed claim once _tool_authenticate() obtains a token.
            members = list(delegation_chain or []) + [agent_id]
            self.chain_claim = DelegationChainClaim.create(
                root_agent=members[0],
                members=members,
                granted_scopes=granted_scopes,
                max_depth=max_depth,
            )
            self._chain_server_signed = False

        self._access_token: Optional[str] = None
        self._rpt_cache: Dict[str, str] = {}   # resource_path → RPT

        # Resolve API key
        resolved_key = (
            api_key
            or os.environ.get("GROQ_API_KEY", "")
            or "ollama"   # Ollama ignores the key but the SDK requires a non-empty string
        )
        resolved_url = base_url or _BACKEND_URLS.get(backend, _BACKEND_URLS["ollama"])

        self._client = OpenAI(api_key=resolved_key, base_url=resolved_url)
        self._oai_tools = _openai_tools(self._TOOL_DEFS)

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def _tool_authenticate(self) -> Dict[str, Any]:
        try:
            r = requests.post(
                f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": _CLIENT_ID,
                    "username": self.username,
                    "password": self.password,
                    "scope": "openid",
                },
                timeout=10,
            )
            r.raise_for_status()
            self._access_token = r.json()["access_token"]

            # Root agents get their chain claim signed by the resource server
            # so CHAIN_HMAC_SECRET is never needed in the agent process.
            if not self._chain_server_signed:
                self._fetch_server_signed_chain()

            return {
                "success": True,
                "agent_id": self.agent_id,
                "granted_scopes": self.granted_scopes,
                "chain_depth": self.chain_claim.depth,
                "chain_server_signed": self._chain_server_signed,
                "message": f"Authenticated as {self.username}",
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _fetch_server_signed_chain(self) -> None:
        """Replace the local placeholder chain claim with a server-signed one."""
        try:
            r = requests.post(
                f"{self.resource_server_url}/api/delegation/init",
                json={"requested_scopes": self.granted_scopes},
                headers={"Authorization": f"Bearer {self._access_token}"},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                self.chain_claim = DelegationChainClaim.from_header_value(data["chain_claim"])
                self._chain_server_signed = True
                logger.info("[%s] chain claim server-signed (depth=%d)", self.agent_id, self.chain_claim.depth)
            else:
                logger.warning(
                    "[%s] /api/delegation/init returned %d — using local chain claim as fallback",
                    self.agent_id, r.status_code,
                )
        except Exception as exc:
            logger.warning("[%s] Could not fetch server-signed chain: %s", self.agent_id, exc)

    def _tool_request_uma_access(self, resource_path: str) -> Dict[str, Any]:
        if not self._access_token:
            return {"granted": False, "error": "Not authenticated — call authenticate first."}
        try:
            # Probe: expect 401 + permission ticket
            r = requests.get(f"{self.resource_server_url}{resource_path}", timeout=10)
            if r.status_code != 401:
                return {"granted": False, "error": f"Expected 401, got {r.status_code}"}

            m = re.search(r'ticket="([^"]+)"', r.headers.get("WWW-Authenticate", ""))
            if not m:
                return {"granted": False, "error": "No permission ticket in 401 response"}

            rpt_r = requests.post(
                f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
                    "ticket": m.group(1),
                },
                headers={"Authorization": f"Bearer {self._access_token}"},
                timeout=10,
            )
            if rpt_r.status_code == 200:
                self._rpt_cache[resource_path] = rpt_r.json()["access_token"]
                return {"granted": True, "resource_path": resource_path}
            return {
                "granted": False,
                "resource_path": resource_path,
                "http_status": rpt_r.status_code,
                "error": "Authorization server denied RPT — insufficient privileges",
            }
        except Exception as exc:
            return {"granted": False, "error": str(exc)}

    def _tool_read_resource(self, resource_path: str) -> Dict[str, Any]:
        rpt = self._rpt_cache.get(resource_path)
        if not rpt:
            return {
                "success": False,
                "error": f"No RPT for {resource_path} — call request_uma_access first.",
            }
        try:
            r = requests.get(
                f"{self.resource_server_url}{resource_path}",
                headers={
                    "Authorization": f"Bearer {rpt}",
                    "X-Uma-Delegation-Chain": self.chain_claim.to_header_value(),
                    "X-Agent-Id": self.agent_id,
                },
                timeout=10,
            )
            if r.status_code == 200:
                return {"success": True, "data": r.json()}
            body = r.json() if "application/json" in r.headers.get("content-type", "") else {}
            return {
                "success": False,
                "http_status": r.status_code,
                "denied": True,
                "reason": body.get("detail", "Access denied by resource server"),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _tool_write_resource(self, resource_path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        if not self._access_token:
            return {"success": False, "error": "Not authenticated — call authenticate first."}

        # Probe the write endpoint for a fresh RPT covering the write scope.
        # A GET-derived RPT may only cover read; POST requires its own ticket.
        write_cache_key = f"{resource_path}:write"
        rpt = self._rpt_cache.get(write_cache_key) or self._rpt_cache.get(resource_path)

        if not rpt:
            # Try to negotiate access via a POST probe
            probe = self._tool_request_uma_access(resource_path)
            if not probe.get("granted"):
                return {"success": False, "error": f"Could not obtain RPT for write: {probe.get('error')}"}
            rpt = self._rpt_cache.get(resource_path)

        try:
            r = requests.post(
                f"{self.resource_server_url}{resource_path}",
                json=data,
                headers={
                    "Authorization": f"Bearer {rpt}",
                    "X-Uma-Delegation-Chain": self.chain_claim.to_header_value(),
                    "X-Agent-Id": self.agent_id,
                },
                timeout=10,
            )
            if r.status_code == 200:
                self._rpt_cache[write_cache_key] = rpt
                return {"success": True, "data": r.json()}
            body = r.json() if "application/json" in r.headers.get("content-type", "") else {}
            return {
                "success": False,
                "http_status": r.status_code,
                "denied": True,
                "reason": body.get("detail", "Access denied by resource server"),
            }
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _dispatch_tool(self, name: str, tool_input: Dict[str, Any]) -> str:
        if name == "authenticate":
            result = self._tool_authenticate()
        elif name == "request_uma_access":
            result = self._tool_request_uma_access(tool_input["resource_path"])
        elif name == "read_resource":
            result = self._tool_read_resource(tool_input["resource_path"])
        elif name == "write_resource":
            if "resource_path" not in tool_input or "data" not in tool_input:
                result = {"error": "write_resource requires resource_path and data parameters"}
            else:
                result = self._tool_write_resource(tool_input["resource_path"], tool_input["data"])
        else:
            result = {"error": f"Unknown tool: {name}"}
        return json.dumps(result)

    # ------------------------------------------------------------------
    # Agentic loop
    # ------------------------------------------------------------------

    def run(self, task: str, max_turns: int = 12) -> str:
        """
        Execute a task in a tool-calling loop using the configured LLM backend.

        Returns the model's final text response.
        """
        system = (
            f"You are an autonomous compliance automation agent.\n"
            f"Agent identity:   {self.agent_id}\n"
            f"Granted scopes:   {', '.join(self.granted_scopes)}\n"
            f"Delegation depth: {self.chain_claim.depth} / {self.max_depth}\n\n"
            "Use the provided tools to interact with UMA-protected compliance resources. "
            "Always call authenticate (with no arguments) before accessing any resource. "
            "The authorization layer enforces your scope boundaries — "
            "any access outside your granted scopes will be blocked and audited.\n\n"
            "Available resource paths (use these exact strings):\n"
            "  /api/documents          — DORA ICT risk policy documents\n"
            "  /api/calendar           — DORA compliance schedule and deadlines\n"
            "  /api/database           — ICT transaction records\n"
            "  /api/database/audit-entries — audit log (requires database:audit scope)\n\n"
            "Workflow: always call request_uma_access(resource_path) first, "
            "then read_resource(resource_path) or write_resource(resource_path, data). "
            "resource_path must be a plain string like \"/api/documents\"."
        )

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
        ]

        for _ in range(max_turns):
            response = self._client.chat.completions.create(
                model=self.model,
                tools=self._oai_tools,
                tool_choice="auto",
                messages=messages,
            )

            msg = response.choices[0].message
            messages.append(msg)   # append the assistant message object

            tool_calls = msg.tool_calls or []

            if not tool_calls:
                return msg.content or ""

            for tc in tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}

                logger.info("[%s] tool_call  %s(%s)", self.agent_id, fn_name,
                            tc.function.arguments[:160])
                result_str = self._dispatch_tool(fn_name, fn_args)
                logger.info("[%s] tool_result %s", self.agent_id, result_str[:200])

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_str,
                })

        return "(max_turns reached without final response)"

    # ------------------------------------------------------------------
    # Delegation factory
    # ------------------------------------------------------------------

    def create_sub_agent(
        self,
        agent_id: str,
        username: str,
        password: str,
        allowed_scopes: List[str],
    ) -> "LLMAgent":
        """
        Spawn a child LLM agent with delegated identity and server-signed chain.

        The resource server is the sole signing authority: it verifies that the
        caller is the current chain terminus, enforces scope monotonicity and the
        server-side depth ceiling, then returns a signed child chain claim.
        The child agent receives this pre-signed claim and never needs
        CHAIN_HMAC_SECRET in its own environment.
        """
        if not self._access_token:
            raise ValueError("Parent agent must authenticate before creating a sub-agent")

        # Quick pre-flight: catch clearly empty scope intersections before the network call
        local_effective = [s for s in allowed_scopes if s in self.granted_scopes]
        if not local_effective:
            raise ValueError(
                f"Delegation scope intersection is empty: "
                f"parent={self.granted_scopes}, requested={allowed_scopes}"
            )

        r = requests.post(
            f"{self.resource_server_url}/api/delegation/sign",
            json={
                "parent_chain": self.chain_claim.to_header_value(),
                "child_agent_id": agent_id,
                "requested_scopes": allowed_scopes,
            },
            headers={"Authorization": f"Bearer {self._access_token}"},
            timeout=10,
        )
        if r.status_code != 200:
            detail = r.json().get("detail", r.text) if r.headers.get("content-type", "").startswith("application/json") else r.text
            raise ValueError(f"Delegation signing failed (HTTP {r.status_code}): {detail}")

        data = r.json()
        signed_child_claim = DelegationChainClaim.from_header_value(data["chain_claim"])
        effective_scopes = data["granted_scopes"]

        return LLMAgent(
            agent_id=agent_id,
            username=username,
            password=password,
            granted_scopes=effective_scopes,
            pre_signed_chain_claim=signed_child_claim,
            keycloak_url=self.keycloak_url,
            realm=self.realm,
            resource_server_url=self.resource_server_url,
            backend=self.backend,
            model=self.model,
            base_url=str(self._client.base_url),
        )
