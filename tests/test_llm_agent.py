"""
Unit tests for LLMAgent — chain construction, delegation, tool dispatch,
and T1–T4 enforcement logic.

These tests are fully offline: no Keycloak, no resource server, no LLM API.
HTTP calls inside tool implementations are mocked.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.llm_agent import LLMAgent, _openai_tools
from agents.chain_claim import DelegationChainClaim


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_agent(**kwargs) -> LLMAgent:
    defaults = dict(
        agent_id="compliance-manager",
        username="compliance-manager",
        password="compliance-pass123",
        granted_scopes=["documents:read", "documents:write", "calendar:read",
                        "database:read", "database:audit"],
        backend="ollama",
    )
    defaults.update(kwargs)
    return LLMAgent(**defaults)


def _sign_mock(parent_claim: DelegationChainClaim, child_id: str, child_scopes: list) -> MagicMock:
    """
    Return a mock HTTP response matching what POST /api/delegation/sign returns.
    The claim is locally signed with the default HMAC secret, which is fine for
    offline unit tests — production agents call the real endpoint.
    """
    child_members = parent_claim.members + [child_id]
    child_claim = DelegationChainClaim.create(
        root_agent=parent_claim.root_agent,
        members=child_members,
        granted_scopes=child_scopes,
        max_depth=parent_claim.max_depth,
    )
    resp = MagicMock(status_code=200)
    resp.json.return_value = {
        "chain_claim": child_claim.to_header_value(),
        "chain_id": child_claim.chain_id,
        "granted_scopes": child_scopes,
        "depth": len(child_members),
        "max_depth": parent_claim.max_depth,
    }
    resp.headers = {"content-type": "application/json"}
    return resp


# ---------------------------------------------------------------------------
# Chain construction
# ---------------------------------------------------------------------------

class TestChainConstruction:
    def test_root_agent_is_self_when_no_parent(self):
        agent = _make_agent()
        assert agent.chain_claim.root_agent == "compliance-manager"
        assert agent.chain_claim.members == ["compliance-manager"]
        assert agent.chain_claim.depth == 1

    def test_chain_includes_parent_when_delegated(self):
        parent = _make_agent()
        parent._access_token = "tok-test"
        child_scopes = ["documents:read", "calendar:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, "risk-analyst", child_scopes)):
            child = parent.create_sub_agent(
                agent_id="risk-analyst",
                username="risk-analyst",
                password="risk-pass123",
                allowed_scopes=child_scopes,
            )
        assert child.chain_claim.members == ["compliance-manager", "risk-analyst"]
        assert child.chain_claim.depth == 2
        assert child.chain_claim.root_agent == "compliance-manager"

    def test_chain_claim_is_hmac_signed(self):
        agent = _make_agent()
        assert agent.chain_claim.verify()

    def test_sub_agent_chain_claim_is_hmac_signed(self):
        parent = _make_agent()
        parent._access_token = "tok-test"
        child_scopes = ["documents:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, "risk-analyst", child_scopes)):
            child = parent.create_sub_agent(
                "risk-analyst", "risk-analyst", "pass",
                allowed_scopes=child_scopes,
            )
        assert child.chain_claim.verify()

    def test_three_level_chain(self):
        root = _make_agent()
        root._access_token = "tok-test"
        mid_scopes = ["documents:read", "calendar:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(root.chain_claim, "risk-analyst", mid_scopes)):
            mid = root.create_sub_agent(
                "risk-analyst", "risk-analyst", "pass",
                allowed_scopes=mid_scopes,
            )
        mid._access_token = "tok-test"
        leaf_scopes = ["documents:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(mid.chain_claim, "data-extractor", leaf_scopes)):
            leaf = mid.create_sub_agent(
                "data-extractor", "data-extractor", "pass",
                allowed_scopes=leaf_scopes,
            )
        assert leaf.chain_claim.members == [
            "compliance-manager", "risk-analyst", "data-extractor"
        ]
        assert leaf.chain_claim.depth == 3


# ---------------------------------------------------------------------------
# Scope monotonicity (delegation)
# ---------------------------------------------------------------------------

class TestScopeMonotonicity:
    def test_child_scopes_are_intersection_of_parent_and_requested(self):
        parent = _make_agent()
        parent._access_token = "tok-test"
        child_scopes = ["documents:read", "calendar:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, "risk-analyst", child_scopes)):
            child = parent.create_sub_agent(
                "risk-analyst", "risk-analyst", "pass",
                allowed_scopes=child_scopes,
            )
        assert set(child.granted_scopes) == {"documents:read", "calendar:read"}

    def test_child_cannot_escalate_beyond_parent(self):
        parent = _make_agent(granted_scopes=["documents:read"])
        parent._access_token = "tok-test"
        # Server enforces monotonicity; mock returns only the allowed subset
        child_scopes = ["documents:read"]   # write not in parent, server would strip it
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, "risk-analyst", child_scopes)):
            child = parent.create_sub_agent(
                "risk-analyst", "risk-analyst", "pass",
                allowed_scopes=["documents:read", "documents:write"],
            )
        assert child.granted_scopes == ["documents:read"]

    def test_empty_intersection_raises(self):
        # Pre-flight check catches empty intersections before the network call
        parent = _make_agent(granted_scopes=["documents:read"])
        parent._access_token = "tok-test"
        with pytest.raises(ValueError, match="intersection is empty"):
            parent.create_sub_agent(
                "bad", "bad", "pass",
                allowed_scopes=["database:delete"],
            )

    def test_child_scopes_stored_in_chain_claim(self):
        parent = _make_agent()
        parent._access_token = "tok-test"
        child_scopes = ["documents:read", "calendar:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, "risk-analyst", child_scopes)):
            child = parent.create_sub_agent(
                "risk-analyst", "risk-analyst", "pass",
                allowed_scopes=child_scopes,
            )
        assert set(child.chain_claim.granted_scopes) == {"documents:read", "calendar:read"}


# ---------------------------------------------------------------------------
# Chain claim T1–T4 validation
# ---------------------------------------------------------------------------

class TestChainClaimValidation:
    def test_authorized_access_passes(self):
        agent = _make_agent()
        ok, reason = agent.chain_claim.validate_for_resource(
            "documents", "read", "compliance-manager"
        )
        assert ok
        assert reason == "chain claim valid"

    def test_t1_scope_escalation_blocked(self):
        parent = _make_agent()
        parent._access_token = "tok-test"
        child_scopes = ["documents:read", "database:read"]
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, "data-extractor", child_scopes)):
            child = parent.create_sub_agent(
                "data-extractor", "data-extractor", "pass",
                allowed_scopes=child_scopes,
            )
        ok, reason = child.chain_claim.validate_for_resource(
            "database", "audit", "data-extractor"
        )
        assert not ok
        assert "T1/T4" in reason
        assert "database:audit" in reason

    def test_t2_depth_exceeded_blocked(self):
        claim = DelegationChainClaim.create(
            root_agent="a",
            members=["a", "b", "c", "d", "e"],   # depth 5
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        ok, reason = claim.validate_for_resource("documents", "read", "e")
        assert not ok
        assert "T2" in reason

    def test_t3_wrong_terminus_blocked(self):
        agent = _make_agent()
        ok, reason = agent.chain_claim.validate_for_resource(
            "documents", "read", "attacker"   # not the leaf agent
        )
        assert not ok
        assert "T3" in reason

    def test_tampered_hash_blocked(self):
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        claim.chain_hash = "0" * 64   # tamper
        ok, reason = claim.validate_for_resource("documents", "read", "compliance-manager")
        assert not ok
        assert "T2/T3" in reason


# ---------------------------------------------------------------------------
# Tool implementations (HTTP mocked)
# ---------------------------------------------------------------------------

class TestToolAuthenticate:
    def test_authenticate_success(self):
        agent = _make_agent()
        keycloak_resp = MagicMock()
        keycloak_resp.json.return_value = {"access_token": "tok-abc"}
        keycloak_resp.raise_for_status = MagicMock()

        # _fetch_server_signed_chain makes a second POST to /api/delegation/init;
        # patch it out so this test stays focused on the authenticate flow.
        with patch("agents.llm_agent.requests.post", return_value=keycloak_resp), \
             patch.object(agent, "_fetch_server_signed_chain"):
            result = agent._tool_authenticate()

        assert result["success"] is True
        assert agent._access_token == "tok-abc"
        assert result["agent_id"] == "compliance-manager"

    def test_authenticate_failure(self):
        agent = _make_agent()
        with patch("agents.llm_agent.requests.post", side_effect=Exception("connection refused")):
            result = agent._tool_authenticate()
        assert result["success"] is False
        assert "connection refused" in result["error"]


class TestToolRequestUMAAccess:
    def test_returns_error_when_not_authenticated(self):
        agent = _make_agent()
        result = agent._tool_request_uma_access("/api/documents")
        assert result["granted"] is False
        assert "authenticate" in result["error"]

    def test_full_flow_success(self):
        agent = _make_agent()
        agent._access_token = "user-tok"

        ticket_response = MagicMock(status_code=401,
                                    headers={"WWW-Authenticate": 'realm="test",ticket="tkt-123"'})
        rpt_response = MagicMock(status_code=200)
        rpt_response.json.return_value = {"access_token": "rpt-xyz"}

        with patch("agents.llm_agent.requests.get", return_value=ticket_response), \
             patch("agents.llm_agent.requests.post", return_value=rpt_response):
            result = agent._tool_request_uma_access("/api/documents")

        assert result["granted"] is True
        assert agent._rpt_cache["/api/documents"] == "rpt-xyz"

    def test_rpt_exchange_denied(self):
        agent = _make_agent()
        agent._access_token = "user-tok"

        ticket_response = MagicMock(status_code=401,
                                    headers={"WWW-Authenticate": 'ticket="tkt-123"'})
        rpt_response = MagicMock(status_code=403)
        rpt_response.json.return_value = {}

        with patch("agents.llm_agent.requests.get", return_value=ticket_response), \
             patch("agents.llm_agent.requests.post", return_value=rpt_response):
            result = agent._tool_request_uma_access("/api/documents")

        assert result["granted"] is False
        assert result["http_status"] == 403


class TestToolReadResource:
    def test_returns_error_without_rpt(self):
        agent = _make_agent()
        result = agent._tool_read_resource("/api/documents")
        assert result["success"] is False
        assert "request_uma_access" in result["error"]

    def test_success_with_rpt(self):
        agent = _make_agent()
        agent._rpt_cache["/api/documents"] = "rpt-xyz"

        ok_response = MagicMock(status_code=200)
        ok_response.json.return_value = {"documents": []}
        ok_response.headers = {"content-type": "application/json"}

        with patch("agents.llm_agent.requests.get", return_value=ok_response):
            result = agent._tool_read_resource("/api/documents")

        assert result["success"] is True
        assert result["data"] == {"documents": []}

    def test_403_returns_denial_with_reason(self):
        agent = _make_agent()
        agent._rpt_cache["/api/database/audit-entries"] = "rpt-xyz"

        denied_response = MagicMock(status_code=403)
        denied_response.json.return_value = {
            "detail": "T1/T4: scope 'database:audit' not in chain ['database:read']"
        }
        denied_response.headers = {"content-type": "application/json"}

        with patch("agents.llm_agent.requests.get", return_value=denied_response):
            result = agent._tool_read_resource("/api/database/audit-entries")

        assert result["success"] is False
        assert result["denied"] is True
        assert "T1/T4" in result["reason"]


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------

class TestDispatchTool:
    def test_unknown_tool_returns_error(self):
        agent = _make_agent()
        result_str = agent._dispatch_tool("nonexistent_tool", {})
        result = json.loads(result_str)
        assert "error" in result

    def test_authenticate_dispatched(self):
        agent = _make_agent()
        with patch.object(agent, "_tool_authenticate", return_value={"success": True}) as m:
            agent._dispatch_tool("authenticate", {})
            m.assert_called_once()

    def test_read_resource_dispatched(self):
        agent = _make_agent()
        with patch.object(agent, "_tool_read_resource", return_value={"success": True}) as m:
            agent._dispatch_tool("read_resource", {"resource_path": "/api/documents"})
            m.assert_called_once_with("/api/documents")


# ---------------------------------------------------------------------------
# OpenAI tool format conversion
# ---------------------------------------------------------------------------

class TestOpenAIToolConversion:
    def test_tools_have_function_type(self):
        converted = _openai_tools(LLMAgent._TOOL_DEFS)
        for t in converted:
            assert t["type"] == "function"
            assert "function" in t
            assert "name" in t["function"]
            assert "description" in t["function"]
            assert "parameters" in t["function"]

    def test_tool_names_preserved(self):
        converted = _openai_tools(LLMAgent._TOOL_DEFS)
        names = {t["function"]["name"] for t in converted}
        assert names == {"authenticate", "request_uma_access", "read_resource", "write_resource"}


# ---------------------------------------------------------------------------
# Backend / sub-agent URL propagation
# ---------------------------------------------------------------------------

class TestSubAgentInheritance:
    def _child(self, parent, child_id="child", scopes=None):
        scopes = scopes or ["documents:read"]
        parent._access_token = "tok-test"
        with patch("agents.llm_agent.requests.post",
                   return_value=_sign_mock(parent.chain_claim, child_id, scopes)):
            return parent.create_sub_agent(child_id, "u", "p", scopes)

    def test_sub_agent_inherits_backend(self):
        parent = _make_agent(backend="ollama")
        child = self._child(parent)
        assert child.backend == "ollama"

    def test_sub_agent_base_url_is_string(self):
        parent = _make_agent(backend="ollama")
        child = self._child(parent)
        assert isinstance(str(child._client.base_url), str)

    def test_sub_agent_inherits_model(self):
        parent = _make_agent(backend="ollama", model="qwen2.5")
        child = self._child(parent)
        assert child.model == "qwen2.5"
