"""
Unit tests for the DORA Article 9 workflow (Step 3).

All tests are fully offline — no Keycloak, no resource server, no LLM API.

Tests verify:
  - 3-level delegation chain is constructed correctly
  - Per-tool timing instrumentation records the right fields
  - Phase result dicts have the required schema
  - T4 block detection works from tool call logs
  - build_summary() aggregates timing and security events correctly
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from agents.llm_agent import LLMAgent
from scenarios.dora_article9_workflow import (
    PhaseTimer,
    _timed_root_agent,
    _timed_sub_agent,
    build_summary,
    run_phase_1,
    run_phase_2,
    run_phase_3,
    run_phase_4_t4,
    run_workflow,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_root(backend="ollama") -> LLMAgent:
    agent = LLMAgent(
        agent_id="compliance-manager",
        username="compliance-manager",
        password="compliance-pass123",
        granted_scopes=[
            "documents:read", "documents:write",
            "calendar:read",
            "database:read", "database:write", "database:audit",
        ],
        backend=backend,
    )
    # Offline unit tests skip authentication; set a fake token so create_sub_agent works.
    agent._access_token = "offline-test-token"
    return agent


from agents.chain_claim import DelegationChainClaim


def _sign_response_for(json_body: dict) -> MagicMock:
    """Build the mock POST /api/delegation/sign or /api/delegation/init response."""
    if "parent_chain" in json_body:
        # delegation/sign
        parent_claim = DelegationChainClaim.from_header_value(json_body["parent_chain"])
        child_id = json_body["child_agent_id"]
        child_scopes = [s for s in json_body["requested_scopes"] if s in parent_claim.granted_scopes]
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
    else:
        # delegation/init or other — raise to keep tests from hitting Keycloak
        raise Exception("offline")
    resp.headers = {"content-type": "application/json"}
    return resp


def _sign_side_effect(url, **kwargs):
    return _sign_response_for(kwargs.get("json", {}))


def _mock_run(agent: LLMAgent, response: str = "Mock LLM response") -> None:
    """Patch agent.run() to skip LLM calls and return a fixed string."""
    agent.run = MagicMock(return_value=response)  # type: ignore[method-assign]


# ---------------------------------------------------------------------------
# PhaseTimer — instrumentation
# ---------------------------------------------------------------------------

class TestPhaseTimer:
    def test_records_each_tool_call(self):
        agent = _make_root()
        timer = PhaseTimer(agent)
        with patch.object(agent, "_tool_authenticate", return_value={"success": True}):
            agent._dispatch_tool("authenticate", {})
        assert len(timer.tool_calls) == 1
        assert timer.tool_calls[0]["tool"] == "authenticate"
        assert "elapsed_ms" in timer.tool_calls[0]

    def test_elapsed_ms_is_positive(self):
        agent = _make_root()
        timer = PhaseTimer(agent)
        with patch.object(agent, "_tool_authenticate", return_value={"success": True}):
            agent._dispatch_tool("authenticate", {})
        assert timer.tool_calls[0]["elapsed_ms"] > 0

    def test_phase_total_ms_after_start_stop(self):
        import time
        agent = _make_root()
        timer = PhaseTimer(agent)
        timer.start()
        time.sleep(0.01)
        timer.stop()
        assert timer.phase_total_ms() >= 10.0

    def test_timing_breakdown_has_required_keys(self):
        agent = _make_root()
        timer = PhaseTimer(agent)
        timer.start()
        timer.stop()
        bd = timer.timing_breakdown()
        for key in ("chain_construction_ms", "authenticate_ms", "rpt_exchanges",
                    "resource_reads", "resource_writes", "phase_total_ms"):
            assert key in bd, f"Missing key: {key}"

    def test_timing_breakdown_groups_by_tool(self):
        agent = _make_root()
        timer = PhaseTimer(agent)

        with patch.object(agent, "_tool_authenticate", return_value={"success": True}):
            agent._dispatch_tool("authenticate", {})
        with patch.object(agent, "_tool_request_uma_access",
                          return_value={"granted": True}):
            agent._dispatch_tool("request_uma_access", {"resource_path": "/api/documents"})

        bd = timer.timing_breakdown()
        assert bd["authenticate_ms"] is not None
        assert len(bd["rpt_exchanges"]) == 1
        assert bd["rpt_exchanges"][0]["path"] == "/api/documents"

    def test_t4_blocks_detects_denied_t1_t4(self):
        agent = _make_root()
        timer = PhaseTimer(agent)

        denied = {
            "success": False,
            "denied": True,
            "reason": "T1/T4: scope 'database:audit' not in chain",
        }
        with patch.object(agent, "_tool_read_resource", return_value=denied):
            agent._rpt_cache["/api/database/audit-entries"] = "tok"
            agent._dispatch_tool("read_resource",
                                 {"resource_path": "/api/database/audit-entries"})

        blocks = timer.t4_blocks()
        assert len(blocks) == 1
        assert "/api/database/audit-entries" in blocks[0]["path"]
        assert "T1/T4" in blocks[0]["reason"]
        assert "detection_ms" in blocks[0]

    def test_t4_blocks_empty_for_successful_access(self):
        agent = _make_root()
        timer = PhaseTimer(agent)
        with patch.object(agent, "_tool_read_resource",
                          return_value={"success": True, "data": {}}):
            agent._rpt_cache["/api/documents"] = "tok"
            agent._dispatch_tool("read_resource", {"resource_path": "/api/documents"})
        assert timer.t4_blocks() == []


# ---------------------------------------------------------------------------
# Agent factory — chain construction timing
# ---------------------------------------------------------------------------

class TestTimedAgentFactory:
    def test_timed_root_returns_agent_and_positive_ms(self):
        agent, ms = _timed_root_agent("ollama", None)
        assert isinstance(agent, LLMAgent)
        assert ms >= 0.0

    def test_timed_sub_returns_correct_chain(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect):
            child, ms = _timed_sub_agent(
                root, "risk-analyst", "risk-analyst", "pass",
                ["documents:read", "calendar:read"],
            )
        assert child.chain_claim.members == ["compliance-manager", "risk-analyst"]
        assert ms >= 0.0

    def test_three_level_chain_has_depth_3(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect):
            mid, _ = _timed_sub_agent(
                root, "risk-analyst", "risk-analyst", "pass",
                ["documents:read", "calendar:read", "database:read"],
            )
            mid._access_token = "offline-test-token"
            leaf, _ = _timed_sub_agent(
                mid, "data-extractor", "data-extractor", "pass",
                ["documents:read", "database:read"],
            )
        assert leaf.chain_claim.depth == 3
        assert leaf.chain_claim.members == [
            "compliance-manager", "risk-analyst", "data-extractor"
        ]


# ---------------------------------------------------------------------------
# Phase result schema
# ---------------------------------------------------------------------------

REQUIRED_PHASE_KEYS = {
    "phase", "agent", "chain", "chain_depth",
    "granted_scopes", "task_summary", "timing",
    "resources_accessed", "outcome", "llm_response",
}

REQUIRED_TIMING_KEYS = {
    "chain_construction_ms", "authenticate_ms",
    "rpt_exchanges", "resource_reads", "resource_writes",
    "phase_total_ms",
}


def _mock_phase_run(backend="ollama"):
    """Patch agent.run and all HTTP calls to run phases offline."""
    return patch("agents.llm_agent.requests.post", side_effect=Exception("offline")), \
           patch("agents.llm_agent.requests.get", side_effect=Exception("offline")), \
           patch.object(LLMAgent, "run", return_value="Mock LLM response")


class TestPhaseResultSchema:
    def test_phase_1_has_required_keys(self):
        with patch.object(LLMAgent, "run", return_value="ok"):
            result, _ = run_phase_1("ollama", None)
        for key in REQUIRED_PHASE_KEYS:
            assert key in result, f"Phase 1 missing key: {key}"

    def test_phase_1_timing_has_required_keys(self):
        with patch.object(LLMAgent, "run", return_value="ok"):
            result, _ = run_phase_1("ollama", None)
        for key in REQUIRED_TIMING_KEYS:
            assert key in result["timing"], f"Phase 1 timing missing key: {key}"

    def test_phase_1_chain_depth_is_1(self):
        with patch.object(LLMAgent, "run", return_value="ok"):
            result, _ = run_phase_1("ollama", None)
        assert result["chain_depth"] == 1
        assert result["agent"] == "compliance-manager"

    def test_phase_2_chain_depth_is_2(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", return_value="ok"):
            result, _ = run_phase_2(root)
        assert result["chain_depth"] == 2
        assert result["agent"] == "risk-analyst"
        assert result["chain"] == ["compliance-manager", "risk-analyst"]

    def test_phase_2_scopes_subset_of_parent(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", return_value="ok"):
            result, _ = run_phase_2(root)
        parent_scopes = set(root.granted_scopes)
        child_scopes = set(result["granted_scopes"])
        assert child_scopes.issubset(parent_scopes)

    def test_phase_3_chain_depth_is_3(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", return_value="ok"):
            _, risk_analyst = run_phase_2(root)
            risk_analyst._access_token = "offline-test-token"
            result, _ = run_phase_3(risk_analyst)
        assert result["chain_depth"] == 3
        assert result["agent"] == "data-extractor"
        assert result["chain"] == [
            "compliance-manager", "risk-analyst", "data-extractor"
        ]

    def test_phase_3_cannot_escalate_beyond_risk_analyst(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", return_value="ok"):
            _, risk_analyst = run_phase_2(root)
            risk_analyst._access_token = "offline-test-token"
            result, _ = run_phase_3(risk_analyst)
        # database:audit is NOT in risk-analyst's scopes so cannot be in data-extractor
        assert "database:audit" not in result["granted_scopes"]

    def test_phase_4_has_attack_fields(self):
        root = _make_root()
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", return_value="ok"):
            result = run_phase_4_t4(root)
        assert "attack_class" in result
        assert result["attack_class"] == "T4"
        assert "t4_blocks" in result
        assert "blocked" in result
        assert "injected_resource" in result
        assert result["injected_resource"] == "/api/database/audit-entries"

    def test_phase_4_chain_depth_is_3(self):
        root = _make_root()
        # Phase 4 uses risk_analyst as parent so the chain is depth 3
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", return_value="ok"):
            _, risk_analyst = run_phase_2(root)
            risk_analyst._access_token = "offline-test-token"
            result = run_phase_4_t4(risk_analyst)
        assert result["chain_depth"] == 3


# ---------------------------------------------------------------------------
# build_summary
# ---------------------------------------------------------------------------

class TestBuildSummary:
    def _make_phases(self) -> list:
        p1 = {
            "phase": 1, "chain_depth": 1, "outcome": "success",
            "timing": {
                "chain_construction_ms": 0.1,
                "authenticate_ms": 50.0,
                "rpt_exchanges": [{"path": "/api/documents", "ms": 120.0}],
                "resource_reads": [{"path": "/api/documents", "ms": 25.0}],
                "resource_writes": [],
                "phase_total_ms": 300.0,
            },
            "t4_blocks": [],
        }
        p2 = {
            "phase": 2, "chain_depth": 2, "outcome": "success",
            "timing": {
                "chain_construction_ms": 0.2,
                "authenticate_ms": 48.0,
                "rpt_exchanges": [{"path": "/api/calendar", "ms": 115.0}],
                "resource_reads": [{"path": "/api/calendar", "ms": 22.0}],
                "resource_writes": [],
                "phase_total_ms": 280.0,
            },
            "t4_blocks": [],
        }
        p4 = {
            "phase": 4, "chain_depth": 3, "outcome": "T4-blocked",
            "blocked": True,
            "timing": {
                "chain_construction_ms": 0.3,
                "authenticate_ms": 52.0,
                "rpt_exchanges": [],
                "resource_reads": [],
                "resource_writes": [],
                "phase_total_ms": 200.0,
            },
            "t4_blocks": [{
                "tool": "read_resource",
                "path": "/api/database/audit-entries",
                "reason": "T1/T4: scope 'database:audit' not in chain",
                "detection_ms": 30.0,
            }],
        }
        return [p1, p2, p4]

    def test_total_wall_ms_is_present(self):
        phases = self._make_phases()
        summary = build_summary(phases, 1234.5)
        assert summary["total_wall_ms"] == 1234.5

    def test_phases_succeeded_count(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["phases_succeeded"] == 2

    def test_phases_blocked_count(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["phases_blocked"] == 1

    def test_chain_depths_observed(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["chain_depths_observed"] == [1, 2, 3]

    def test_mean_authenticate_ms(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["timing_ms"]["mean_authenticate"] == round((50 + 48 + 52) / 3, 2)

    def test_mean_rpt_exchange_ms(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["timing_ms"]["mean_rpt_exchange"] == round((120 + 115) / 2, 2)

    def test_mean_resource_read_ms(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["timing_ms"]["mean_resource_read"] == round((25 + 22) / 2, 2)

    def test_security_blocks_t4_counted(self):
        phases = self._make_phases()
        summary = build_summary(phases, 0)
        assert summary["security_blocks_by_class"]["T4"] == 1
        assert summary["security_blocks_by_class"]["T1"] == 0

    def test_empty_phases_gives_none_means(self):
        summary = build_summary([], 0)
        assert summary["timing_ms"]["mean_authenticate"] is None
        assert summary["phases_succeeded"] == 0


# ---------------------------------------------------------------------------
# run_workflow — integration smoke test (LLM mocked)
# ---------------------------------------------------------------------------

def _mock_run_with_auth(self_agent, task, max_turns=12):
    """Side effect for LLMAgent.run: simulates authentication by setting a token."""
    self_agent._access_token = "offline-test-token"
    return "ok"


class TestRunWorkflowSchema:
    """
    run_workflow() creates agents internally so we can't pre-set _access_token.
    We use _mock_run_with_auth as a side_effect so that each agent gets a token
    when run() is called, making subsequent create_sub_agent() calls work offline.
    """

    def _run_offline(self):
        with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect), \
             patch.object(LLMAgent, "run", autospec=True, side_effect=_mock_run_with_auth):
            return run_workflow(backend="ollama")

    def test_workflow_result_has_top_level_keys(self):
        result = self._run_offline()
        for key in ("scenario", "run_at", "backend", "model", "phases", "summary"):
            assert key in result, f"Missing top-level key: {key}"

    def test_workflow_has_four_phases(self):
        result = self._run_offline()
        assert len(result["phases"]) == 4

    def test_workflow_phases_are_numbered_1_to_4(self):
        result = self._run_offline()
        phase_nums = [p["phase"] for p in result["phases"]]
        assert phase_nums == [1, 2, 3, 4]

    def test_workflow_chain_depths_are_1_2_3_3(self):
        result = self._run_offline()
        depths = [p["chain_depth"] for p in result["phases"]]
        assert depths == [1, 2, 3, 3]

    def test_workflow_result_is_json_serialisable(self):
        result = self._run_offline()
        json.dumps(result, default=str)

    def test_workflow_summary_has_timing_fields(self):
        result = self._run_offline()
        summary = result["summary"]
        for key in ("total_wall_ms", "phases_total", "phases_succeeded",
                    "security_blocks_by_class", "timing_ms", "chain_depths_observed"):
            assert key in summary, f"Summary missing key: {key}"

    def test_workflow_phase_4_is_t4_scenario(self):
        result = self._run_offline()
        phase4 = result["phases"][3]
        assert phase4["attack_class"] == "T4"
        assert phase4["chain_depth"] == 3
