"""
Unit tests for Step 4 attack scenarios.

All offline — no Keycloak, no resource server, no LLM API.
HTTP tests auto-skip when servers are down.
"""

import dataclasses
import json
from unittest.mock import MagicMock, patch, call

import pytest
import requests as req_lib

from agents.chain_claim import DelegationChainClaim
from scenarios.attack_scenarios import (
    _build_chain,
    _get_rpt,
    _request,
    _result,
    _user_token,
    attack_t1_scope_escalation,
    attack_t2_depth_exceeded,
    attack_t3_token_replay,
    attack_tampered_chain,
    run_all_attacks,
)

# ---------------------------------------------------------------------------
# Skip integration tests when servers are not available
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
# _build_chain helper
# ---------------------------------------------------------------------------

class TestBuildChain:
    def test_depth_1_chain_has_one_member(self):
        from agents.chain_claim import DelegationChainClaim
        header = _build_chain(["compliance-manager"], ["documents:read"])
        claim = DelegationChainClaim.from_header_value(header)
        assert claim.depth == 1
        assert claim.members == ["compliance-manager"]

    def test_depth_2_chain_has_two_members(self):
        header = _build_chain(
            ["compliance-manager", "risk-analyst"], ["documents:read"]
        )
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.from_header_value(header)
        assert claim.depth == 2
        assert "risk-analyst" in claim.members

    def test_depth_3_chain_has_three_members(self):
        header = _build_chain(
            ["compliance-manager", "risk-analyst", "data-extractor"],
            ["documents:read", "database:read"],
        )
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.from_header_value(header)
        assert claim.depth == 3

    def test_chain_is_hmac_signed(self):
        header = _build_chain(
            ["compliance-manager", "risk-analyst"], ["documents:read"]
        )
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.from_header_value(header)
        assert claim.verify()


# ---------------------------------------------------------------------------
# _result helper
# ---------------------------------------------------------------------------

class TestResultHelper:
    def _mock_response(self, status: int, body: dict) -> MagicMock:
        r = MagicMock()
        r.status_code = status
        r.json.return_value = body
        return r

    def test_passed_when_status_matches(self):
        r = self._mock_response(403, {"detail": "T1/T4: scope not in chain"})
        result = _result("T1_test", "desc", r, 403, "T1")
        assert result["passed"] is True

    def test_failed_when_status_mismatches(self):
        r = self._mock_response(200, {})
        result = _result("T1_test", "desc", r, 403, "T1")
        assert result["passed"] is False

    def test_result_has_required_keys(self):
        r = self._mock_response(403, {"detail": "blocked"})
        result = _result("T1_test", "desc", r, 403, "T1")
        for key in ("attack", "description", "expected_http", "actual_http",
                    "passed", "attack_class", "server_reason", "timestamp"):
            assert key in result

    def test_attack_class_stored(self):
        r = self._mock_response(403, {})
        result = _result("test", "desc", r, 403, "T2")
        assert result["attack_class"] == "T2"

    def test_baseline_attack_class_none(self):
        r = self._mock_response(200, {})
        result = _result("baseline", "allowed", r, 200, None)
        assert result["attack_class"] is None


# ---------------------------------------------------------------------------
# T1 offline logic
# ---------------------------------------------------------------------------

class TestT1Logic:
    def test_t1_chain_does_not_contain_audit_scope(self):
        header = _build_chain(
            ["compliance-manager", "risk-analyst", "data-extractor"],
            ["documents:read", "database:read"],
        )
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.from_header_value(header)
        assert "database:audit" not in claim.granted_scopes

    def test_t1_claim_rejects_audit_scope(self):
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "data-extractor"],
            granted_scopes=["documents:read", "database:read"],
            max_depth=4,
        )
        ok, reason = claim.validate_for_resource("database", "audit", "data-extractor")
        assert not ok
        assert "T1" in reason or "T4" in reason

    def test_t1_claim_allows_permitted_scope(self):
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "data-extractor"],
            granted_scopes=["documents:read", "database:read"],
            max_depth=4,
        )
        ok, reason = claim.validate_for_resource("database", "read", "data-extractor")
        assert ok


# ---------------------------------------------------------------------------
# T2 offline logic
# ---------------------------------------------------------------------------

class TestT2Logic:
    def test_t2_five_members_exceeds_max_4(self):
        from agents.chain_claim import DelegationChainClaim
        deep = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "a", "b", "c", "data-extractor"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        ok, reason = deep.validate_for_resource("documents", "read", "data-extractor")
        assert not ok
        assert "T2" in reason

    def test_t2_exactly_four_members_passes(self):
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "a", "b", "data-extractor"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        ok, reason = claim.validate_for_resource("documents", "read", "data-extractor")
        assert ok


# ---------------------------------------------------------------------------
# T3 offline logic
# ---------------------------------------------------------------------------

class TestT3Logic:
    def test_t3_wrong_terminus_blocked(self):
        from agents.chain_claim import DelegationChainClaim
        chain = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "risk-analyst"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        ok, reason = chain.validate_for_resource(
            "documents", "read", "compliance-manager"
        )
        assert not ok
        assert "T3" in reason

    def test_t3_correct_terminus_passes(self):
        from agents.chain_claim import DelegationChainClaim
        chain = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager", "risk-analyst"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        ok, _ = chain.validate_for_resource(
            "documents", "read", "risk-analyst"
        )
        assert ok


# ---------------------------------------------------------------------------
# Tamper detection offline
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_zeroed_hash_detected(self):
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        tampered = dataclasses.replace(claim, chain_hash="0" * 64)
        ok, reason = tampered.validate_for_resource(
            "documents", "read", "compliance-manager"
        )
        assert not ok
        assert "mismatch" in reason.lower() or "T2/T3" in reason

    def test_inflated_scopes_detected_by_hmac(self):
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        # inflate scopes without re-signing
        inflated = dataclasses.replace(
            claim, granted_scopes=["documents:read", "database:audit"]
        )
        ok, reason = inflated.validate_for_resource(
            "database", "audit", "compliance-manager"
        )
        assert not ok

    def test_valid_claim_passes_tamper_check(self):
        from agents.chain_claim import DelegationChainClaim
        claim = DelegationChainClaim.create(
            root_agent="compliance-manager",
            members=["compliance-manager"],
            granted_scopes=["documents:read"],
            max_depth=4,
        )
        assert claim.verify()


# ---------------------------------------------------------------------------
# run_all_attacks result schema (HTTP mocked)
# ---------------------------------------------------------------------------

class TestRunAllAttacksSchema:
    @skip_if_down
    def test_all_attack_keys_present(self):
        result = run_all_attacks(backend="ollama", skip_t4=True)
        assert "attacks" in result
        assert "summary" in result
        for key in ("T1", "T2", "T3", "TAMPER", "T4"):
            assert key in result["attacks"]

    @skip_if_down
    def test_t1_attack_has_blocked_case(self):
        result = run_all_attacks(backend="ollama", skip_t4=True)
        t1 = result["attacks"]["T1"]
        blocked = [c for c in t1 if c.get("attack_class") == "T1"]
        assert len(blocked) > 0
        for b in blocked:
            assert b["actual_http"] == 403

    @skip_if_down
    def test_t2_attack_has_blocked_case(self):
        result = run_all_attacks(backend="ollama", skip_t4=True)
        t2 = result["attacks"]["T2"]
        blocked = [c for c in t2 if c.get("attack_class") == "T2"]
        assert len(blocked) >= 2  # depth 5 and depth 6

    @skip_if_down
    def test_t3_attack_has_blocked_case(self):
        result = run_all_attacks(backend="ollama", skip_t4=True)
        t3 = result["attacks"]["T3"]
        blocked = [c for c in t3 if c.get("attack_class") == "T3"]
        assert len(blocked) >= 2

    @skip_if_down
    def test_t1_baseline_is_allowed(self):
        result = run_all_attacks(backend="ollama", skip_t4=True)
        t1 = result["attacks"]["T1"]
        allowed = [c for c in t1 if c.get("attack") == "T1_baseline_allowed"]
        assert len(allowed) == 1
        assert allowed[0]["actual_http"] == 200

    @skip_if_down
    def test_summary_counts_correct(self):
        result = run_all_attacks(backend="ollama", skip_t4=True)
        s = result["summary"]
        assert s["total_cases"] == s["passed"] + s["failed"]
        assert s["failed"] == 0
