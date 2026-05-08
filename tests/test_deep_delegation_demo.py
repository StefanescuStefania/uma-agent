"""
Unit tests for scenarios/deep_delegation_demo.py

All offline — no Keycloak, no resource server, no LLM.
Integration tests auto-skip when servers are not running.
"""

import json
import pytest
import requests as req_lib
from unittest.mock import MagicMock, patch

from agents.chain_claim import DelegationChainClaim
from scenarios.deep_delegation_demo import (
    CHAIN_SPEC,
    MAX_DEPTH,
    StepResult,
    _build_agent_chain,
    _dispatch_timed,
    verify_stored_state,
    visualize_ascii,
    visualize_mermaid,
)


def _make_sign_response(json_body: dict) -> MagicMock:
    """Build the mock POST /api/delegation/sign response from the request body."""
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
    resp.headers = {"content-type": "application/json"}
    return resp


def _build_chain_offline():
    """
    Offline version of _build_agent_chain() for unit tests.
    Sets fake access tokens and mocks the /api/delegation/sign endpoint so no
    server is needed.
    """
    def _sign_side_effect(url, **kwargs):
        return _make_sign_response(kwargs.get("json", {}))

    with patch("agents.llm_agent.requests.post", side_effect=_sign_side_effect):
        # Root agent needs a fake token before it can create sub-agents
        from scenarios.deep_delegation_demo import CHAIN_SPEC, MAX_DEPTH
        from agents.llm_agent import LLMAgent
        root_spec = CHAIN_SPEC[0]
        root = LLMAgent(
            agent_id=root_spec["agent_id"],
            username=root_spec["username"],
            password=root_spec["password"],
            granted_scopes=root_spec["scopes"],
            max_depth=MAX_DEPTH,
        )
        root._access_token = "offline-test-token"
        agents = [root]
        for spec in CHAIN_SPEC[1:]:
            parent = agents[-1]
            child = parent.create_sub_agent(
                agent_id=spec["agent_id"],
                username=spec["username"],
                password=spec["password"],
                allowed_scopes=spec["scopes"],
            )
            child._access_token = "offline-test-token"
            agents.append(child)
        return agents


# ---------------------------------------------------------------------------
# Server availability check
# ---------------------------------------------------------------------------

def _servers_up() -> bool:
    try:
        req_lib.get("http://localhost:5000/", timeout=2)
        req_lib.get("http://localhost:8080/realms/test-realm/.well-known/"
                    "openid-configuration", timeout=2)
        return True
    except Exception:
        return False


skip_if_down = pytest.mark.skipif(
    not _servers_up(), reason="Keycloak / resource server not running"
)


# ---------------------------------------------------------------------------
# Chain specification
# ---------------------------------------------------------------------------

class TestChainSpec:
    def test_five_agents_defined(self):
        assert len(CHAIN_SPEC) == 5

    def test_agent_ids_ordered(self):
        ids = [s["agent_id"] for s in CHAIN_SPEC]
        assert ids == [
            "compliance-manager", "risk-analyst", "data-extractor",
            "report-validator", "audit-reader",
        ]

    def test_scope_monotonicity_across_chain(self):
        for i in range(1, len(CHAIN_SPEC)):
            parent_scopes = set(CHAIN_SPEC[i - 1]["scopes"])
            child_scopes = set(CHAIN_SPEC[i]["scopes"])
            assert child_scopes <= parent_scopes, (
                f"Scope violation at depth {i+1}: child {child_scopes} "
                f"not subset of parent {parent_scopes}"
            )

    def test_compliance_manager_has_widest_scopes(self):
        root_scopes = set(CHAIN_SPEC[0]["scopes"])
        assert "documents:read" in root_scopes
        assert "calendar:read" in root_scopes
        assert "database:read" in root_scopes
        assert "database:write" in root_scopes

    def test_audit_reader_has_narrowest_scopes(self):
        leaf_scopes = CHAIN_SPEC[-1]["scopes"]
        assert leaf_scopes == ["database:read"]

    def test_only_leaf_has_attack(self):
        attacks = [s for s in CHAIN_SPEC if s["attack"] is not None]
        assert len(attacks) == 1
        assert attacks[0]["agent_id"] == "audit-reader"

    def test_attack_is_database_audit(self):
        attack = CHAIN_SPEC[-1]["attack"]
        assert attack is not None
        path, scope = attack
        assert "audit-entries" in path
        assert "audit" in scope

    def test_max_depth_is_6(self):
        assert MAX_DEPTH == 6


# ---------------------------------------------------------------------------
# StepResult
# ---------------------------------------------------------------------------

class TestStepResult:
    def test_to_dict_has_required_keys(self):
        sr = StepResult(
            agent_id="compliance-manager",
            depth=1,
            granted_scopes=["documents:read"],
        )
        d = sr.to_dict()
        for key in ("agent_id", "depth", "granted_scopes", "chain_members",
                    "chain_id", "authenticate_ms", "reads", "writes",
                    "attack_result", "error"):
            assert key in d

    def test_defaults_are_empty(self):
        sr = StepResult(agent_id="x", depth=1, granted_scopes=[])
        assert sr.reads == []
        assert sr.writes == []
        assert sr.attack_result is None
        assert sr.error is None


# ---------------------------------------------------------------------------
# _build_agent_chain (offline — chain construction only)
# ---------------------------------------------------------------------------

class TestBuildAgentChain:
    def test_returns_five_agents(self):
        agents = _build_chain_offline()
        assert len(agents) == 5

    def test_depths_are_1_to_5(self):
        agents = _build_chain_offline()
        for i, agent in enumerate(agents, start=1):
            assert agent.chain_claim.depth == i, (
                f"Agent {agent.agent_id} should be at depth {i}, "
                f"got {agent.chain_claim.depth}"
            )

    def test_chain_members_accumulate(self):
        agents = _build_chain_offline()
        for i, agent in enumerate(agents):
            assert len(agent.chain_claim.members) == i + 1

    def test_leaf_chain_has_all_five_members(self):
        agents = _build_chain_offline()
        leaf = agents[-1]
        assert leaf.chain_claim.members == [
            "compliance-manager", "risk-analyst", "data-extractor",
            "report-validator", "audit-reader",
        ]

    def test_scope_monotonicity_in_chain(self):
        agents = _build_chain_offline()
        for i in range(1, len(agents)):
            parent_scopes = set(agents[i - 1].granted_scopes)
            child_scopes = set(agents[i].granted_scopes)
            assert child_scopes <= parent_scopes

    def test_all_claims_hmac_valid(self):
        agents = _build_chain_offline()
        for agent in agents:
            assert agent.chain_claim.verify(), (
                f"HMAC invalid for {agent.agent_id}"
            )

    def test_max_depth_is_6(self):
        agents = _build_chain_offline()
        for agent in agents:
            assert agent.max_depth == MAX_DEPTH

    def test_leaf_does_not_exceed_max_depth(self):
        agents = _build_chain_offline()
        leaf = agents[-1]
        assert leaf.chain_claim.depth <= leaf.max_depth

    def test_audit_reader_has_own_credentials(self):
        agents = _build_chain_offline()
        audit_reader = agents[-1]
        assert audit_reader.agent_id == "audit-reader"
        assert audit_reader.username == "audit-reader"


# ---------------------------------------------------------------------------
# Visualization — offline
# ---------------------------------------------------------------------------

class TestVisualizeAscii:
    def _make_steps(self):
        agents = _build_chain_offline()
        steps = []
        for i, (agent, spec) in enumerate(zip(agents, CHAIN_SPEC)):
            sr = StepResult(
                agent_id=agent.agent_id,
                depth=agent.chain_claim.depth,
                granted_scopes=list(agent.granted_scopes),
                chain_members=list(agent.chain_claim.members),
                authenticate_ms=5.0 + i,
                reads=[{"path": p, "success": True, "read_ms": 12.0}
                       for p in spec["reads"]],
            )
            if spec["attack"]:
                path, scope = spec["attack"]
                sr.attack_result = {
                    "type": "T1_scope_escalation",
                    "attempted_path": path,
                    "attempted_scope": scope,
                    "blocked": True,
                    "reason": "T1/T4: scope 'database:audit' not in chain",
                    "elapsed_ms": 9.5,
                }
            steps.append(sr)
        return steps

    def test_output_is_string(self):
        tree = visualize_ascii(self._make_steps())
        assert isinstance(tree, str)

    def test_all_agent_ids_present(self):
        tree = visualize_ascii(self._make_steps())
        for spec in CHAIN_SPEC:
            assert spec["agent_id"] in tree

    def test_all_depths_present(self):
        tree = visualize_ascii(self._make_steps())
        for d in range(1, 6):
            assert f"depth {d}" in tree

    def test_t1_blocked_shown(self):
        tree = visualize_ascii(self._make_steps())
        assert "T1 BLOCKED" in tree or "BLOCKED" in tree

    def test_scope_reduction_visible(self):
        tree = visualize_ascii(self._make_steps())
        assert "database:read" in tree
        assert "documents:read" in tree


class TestVisualizeMermaid:
    def _make_steps(self):
        agents = _build_chain_offline()
        steps = []
        for i, (agent, spec) in enumerate(zip(agents, CHAIN_SPEC)):
            sr = StepResult(
                agent_id=agent.agent_id,
                depth=agent.chain_claim.depth,
                granted_scopes=list(agent.granted_scopes),
                chain_members=list(agent.chain_claim.members),
            )
            if spec["attack"]:
                path, scope = spec["attack"]
                sr.attack_result = {
                    "type": "T1_scope_escalation",
                    "attempted_path": path,
                    "attempted_scope": scope,
                    "blocked": True,
                    "reason": "T1/T4: scope not in chain",
                    "elapsed_ms": 9.5,
                }
            steps.append(sr)
        return steps

    def test_starts_with_flowchart(self):
        diagram = visualize_mermaid(self._make_steps())
        assert diagram.startswith("flowchart")

    def test_all_agents_appear(self):
        diagram = visualize_mermaid(self._make_steps())
        for spec in CHAIN_SPEC:
            # agent_id with hyphens replaced by underscores becomes node id
            nid = spec["agent_id"].replace("-", "_")
            assert nid in diagram

    def test_t1_block_node_present(self):
        diagram = visualize_mermaid(self._make_steps())
        assert "T1_BLOCK" in diagram or "BLOCKED" in diagram

    def test_scope_drop_labels_present(self):
        diagram = visualize_mermaid(self._make_steps())
        assert "drop(" in diagram


# ---------------------------------------------------------------------------
# verify_stored_state — mocked HTTP
# ---------------------------------------------------------------------------

class TestVerifyStoredState:
    def _step_results(self):
        from datetime import timezone
        agents = _build_chain_offline()
        steps = []
        for agent, spec in zip(agents, CHAIN_SPEC):
            sr = StepResult(
                agent_id=agent.agent_id,
                depth=agent.chain_claim.depth,
                granted_scopes=list(agent.granted_scopes),
                chain_members=list(agent.chain_claim.members),
                chain_id=agent.chain_claim.chain_id,
            )
            if spec["attack"]:
                path, scope = spec["attack"]
                sr.attack_result = {
                    "type": "T1_scope_escalation",
                    "attempted_path": path,
                    "attempted_scope": scope,
                    "blocked": True,
                    "reason": "T1: scope not in chain",
                    "elapsed_ms": 9.5,
                }
            steps.append(sr)
        return steps

    def _mock_response(self, data: dict) -> MagicMock:
        m = MagicMock()
        m.json.return_value = data
        return m

    def test_verdict_verified_when_t1_recorded(self):
        steps = self._step_results()
        our_chain_ids = {sr.chain_id for sr in steps}
        audit_reader_chain_id = steps[-1].chain_id

        with patch("scenarios.deep_delegation_demo.req_lib.get") as mock_get:
            def side_effect(url, **kwargs):
                if "verify" in url:
                    return self._mock_response({
                        "chain_intact": True, "total_events": 20, "broken_links": []
                    })
                elif "security-blocks" in url:
                    return self._mock_response({
                        "total_blocks": 1,
                        "by_attack_class": {"T1": 1},
                        "blocks": [{"agent_id": "audit-reader", "attack_class": "T1",
                                    "resource": "database", "scope": "audit"}],
                    })
                elif "events" in url:
                    return self._mock_response({
                        "total_returned": 10,
                        "security_blocks": 1,
                        "events": [
                            {"agent_id": aid, "attack_class": None}
                            for aid in ["compliance-manager", "risk-analyst",
                                        "data-extractor", "report-validator", "audit-reader"]
                        ],
                    })
                elif "delegation-chains" in url:
                    return self._mock_response({
                        "total": 5,
                        "chains": [{"chain_id": cid} for cid in our_chain_ids],
                    })
                return self._mock_response({})

            mock_get.side_effect = side_effect
            from datetime import datetime, timezone
            v = verify_stored_state(steps, datetime.now(timezone.utc))

        assert v["verdict"] == "VERIFIED ✓"
        assert v["cross_validation"]["t1_attack_recorded"] is True
        assert v["cross_validation"]["expected_blocks"] == 1
        assert v["cross_validation"]["actual_blocks_in_audit"] == 1

    def test_verdict_fail_when_t1_not_recorded(self):
        steps = self._step_results()
        with patch("scenarios.deep_delegation_demo.req_lib.get") as mock_get:
            def side_effect(url, **kwargs):
                if "verify" in url:
                    return self._mock_response({
                        "chain_intact": True, "total_events": 10, "broken_links": []
                    })
                elif "security-blocks" in url:
                    return self._mock_response({
                        "total_blocks": 0, "by_attack_class": {}, "blocks": []
                    })
                elif "events" in url:
                    return self._mock_response({
                        "total_returned": 5, "security_blocks": 0,
                        "events": [{"agent_id": "compliance-manager", "attack_class": None}],
                    })
                elif "delegation-chains" in url:
                    return self._mock_response({"total": 0, "chains": []})
                return self._mock_response({})
            mock_get.side_effect = side_effect
            from datetime import datetime, timezone
            v = verify_stored_state(steps, datetime.now(timezone.utc))

        assert "FAIL" in v["verdict"] or v["verdict"] != "VERIFIED ✓"

    def test_all_four_endpoints_queried(self):
        steps = self._step_results()
        with patch("scenarios.deep_delegation_demo.req_lib.get") as mock_get:
            mock_get.return_value = self._mock_response({
                "chain_intact": True, "total_events": 0, "broken_links": [],
                "total_blocks": 0, "by_attack_class": {}, "blocks": [],
                "total_returned": 0, "security_blocks": 0, "events": [],
                "total": 0, "chains": [],
            })
            from datetime import datetime, timezone
            v = verify_stored_state(steps, datetime.now(timezone.utc))

        assert len(v["endpoints_queried"]) == 4

    def test_cross_validation_keys_present(self):
        steps = self._step_results()
        with patch("scenarios.deep_delegation_demo.req_lib.get") as mock_get:
            mock_get.return_value = self._mock_response({
                "chain_intact": True, "total_events": 0, "broken_links": [],
                "total_blocks": 0, "by_attack_class": {}, "blocks": [],
                "total_returned": 0, "security_blocks": 0, "events": [],
                "total": 0, "chains": [],
            })
            from datetime import datetime, timezone
            v = verify_stored_state(steps, datetime.now(timezone.utc))

        for key in ("expected_resource_ops", "expected_attack_attempts",
                    "expected_blocks", "actual_blocks_in_audit",
                    "t1_attack_recorded", "all_expected_agents_present"):
            assert key in v["cross_validation"]


# ---------------------------------------------------------------------------
# Integration — requires live servers
# ---------------------------------------------------------------------------

class TestDeepDelegationIntegration:
    @skip_if_down
    def test_full_run_returns_five_steps(self):
        from scenarios.deep_delegation_demo import run_deep_delegation
        result = run_deep_delegation()
        assert len(result["steps"]) == 5

    @skip_if_down
    def test_all_permitted_reads_succeed(self):
        from scenarios.deep_delegation_demo import run_deep_delegation
        result = run_deep_delegation()
        for step in result["steps"]:
            for read in step["reads"]:
                assert read["success"], (
                    f"{step['agent_id']} failed to read {read['path']}: "
                    f"{read.get('denied_reason')}"
                )

    @skip_if_down
    def test_t1_attack_blocked(self):
        from scenarios.deep_delegation_demo import run_deep_delegation
        result = run_deep_delegation()
        audit_reader_step = next(
            s for s in result["steps"] if s["agent_id"] == "audit-reader"
        )
        assert audit_reader_step["attack_result"] is not None
        assert audit_reader_step["attack_result"]["blocked"] is True
        assert "T1" in audit_reader_step["attack_result"]["reason"] or \
               "T4" in audit_reader_step["attack_result"]["reason"]

    @skip_if_down
    def test_verification_verdict_is_verified(self):
        from scenarios.deep_delegation_demo import run_deep_delegation
        result = run_deep_delegation()
        assert result["verification"]["verdict"] == "VERIFIED ✓"

    @skip_if_down
    def test_all_agent_events_in_audit(self):
        from scenarios.deep_delegation_demo import run_deep_delegation
        result = run_deep_delegation()
        breakdown = result["verification"]["our_events"]["agent_breakdown"]
        for spec in CHAIN_SPEC:
            assert breakdown.get(spec["agent_id"], 0) > 0, (
                f"No audit events found for {spec['agent_id']}"
            )

    @skip_if_down
    def test_result_is_json_serializable(self):
        from scenarios.deep_delegation_demo import run_deep_delegation
        result = run_deep_delegation()
        dumped = json.dumps(result, default=str)
        reloaded = json.loads(dumped)
        assert reloaded["chain_depth_reached"] == 5
