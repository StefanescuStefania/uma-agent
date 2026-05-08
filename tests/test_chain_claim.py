"""
Test suite for the UMA Delegation Chain Claim protocol extension.

This module provides exhaustive coverage of the core research contribution:
  urn:uma-agent:delegation-chain:1.0

Each attack class addressed by the extension has its own test section so
the security properties are clearly traceable from test name to paper claim.

Attack classes under test
─────────────────────────
  T1 — Scope escalation   : child requests scope absent from delegation chain
  T2 — Depth exceeded     : delegation chain longer than configured maximum
  T3 — Token replay       : non-terminus agent presents a chain claim
  T4 — Prompt injection   : LLM-generated tool call requests out-of-scope resource

All tests run offline — no Keycloak, resource server, or LLM API required.
"""

import base64
import json
import time
import unittest
from copy import deepcopy

from agents.chain_claim import DelegationChainClaim, CLAIM_FORMAT_URN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_claim(
    root: str = "compliance-manager",
    members: list | None = None,
    scopes: list | None = None,
    max_depth: int = 4,
) -> DelegationChainClaim:
    members = members or [root]
    scopes = scopes or ["documents:read"]
    return DelegationChainClaim.create(
        root_agent=root,
        members=members,
        granted_scopes=scopes,
        max_depth=max_depth,
    )


# ---------------------------------------------------------------------------
# 1. Claim format and construction
# ---------------------------------------------------------------------------

class TestClaimFormatURN(unittest.TestCase):
    """The protocol is identified by a versioned URN."""

    def test_urn_value(self):
        self.assertEqual(CLAIM_FORMAT_URN, "urn:uma-agent:delegation-chain:1.0")

    def test_claim_has_all_required_fields(self):
        claim = _make_claim()
        for field in ("chain_id", "root_agent", "members", "granted_scopes",
                      "max_depth", "issued_at", "chain_hash"):
            self.assertTrue(hasattr(claim, field), f"Missing field: {field}")

    def test_chain_id_is_non_empty_string(self):
        claim = _make_claim()
        self.assertIsInstance(claim.chain_id, str)
        self.assertGreater(len(claim.chain_id), 0)

    def test_issued_at_is_recent_unix_timestamp(self):
        before = int(time.time()) - 2
        claim = _make_claim()
        after = int(time.time()) + 2
        self.assertGreaterEqual(claim.issued_at, before)
        self.assertLessEqual(claim.issued_at, after)


# ---------------------------------------------------------------------------
# 2. Depth property
# ---------------------------------------------------------------------------

class TestDepthProperty(unittest.TestCase):
    """depth is derived from len(members), not stored separately."""

    def test_depth_single_agent(self):
        claim = _make_claim(members=["compliance-manager"])
        self.assertEqual(claim.depth, 1)

    def test_depth_two_agents(self):
        claim = _make_claim(members=["cm", "risk-analyst"])
        self.assertEqual(claim.depth, 2)

    def test_depth_four_agents(self):
        claim = _make_claim(members=["a", "b", "c", "d"])
        self.assertEqual(claim.depth, 4)

    def test_leaf_agent_is_last_member(self):
        claim = _make_claim(members=["root", "middle", "leaf"])
        self.assertEqual(claim.leaf_agent, "leaf")

    def test_leaf_agent_single(self):
        claim = _make_claim(members=["only"])
        self.assertEqual(claim.leaf_agent, "only")


# ---------------------------------------------------------------------------
# 3. HMAC signing and integrity
# ---------------------------------------------------------------------------

class TestHMACIntegrity(unittest.TestCase):
    """chain_hash is an HMAC-SHA256 over the canonical payload."""

    def test_claim_is_signed_on_create(self):
        claim = _make_claim()
        self.assertNotEqual(claim.chain_hash, "")
        self.assertEqual(len(claim.chain_hash), 64)  # hex SHA-256

    def test_valid_claim_verifies(self):
        claim = _make_claim()
        self.assertTrue(claim.verify())

    def test_tampered_root_agent_fails_verification(self):
        claim = _make_claim()
        claim.root_agent = "attacker"
        self.assertFalse(claim.verify())

    def test_tampered_members_fails_verification(self):
        claim = _make_claim(members=["cm", "analyst"])
        claim.members.append("injected-agent")
        self.assertFalse(claim.verify())

    def test_tampered_scopes_fails_verification(self):
        claim = _make_claim(scopes=["documents:read"])
        claim.granted_scopes.append("database:admin")
        self.assertFalse(claim.verify())

    def test_tampered_max_depth_fails_verification(self):
        claim = _make_claim(max_depth=4)
        claim.max_depth = 99
        self.assertFalse(claim.verify())

    def test_tampered_hash_directly_fails_verification(self):
        claim = _make_claim()
        claim.chain_hash = "0" * 64
        self.assertFalse(claim.verify())

    def test_canonical_payload_is_deterministic(self):
        claim = _make_claim()
        p1 = claim._canonical_payload()
        p2 = claim._canonical_payload()
        self.assertEqual(p1, p2)

    def test_canonical_payload_sorts_scopes(self):
        claim = _make_claim(scopes=["z:scope", "a:scope", "m:scope"])
        payload = json.loads(claim._canonical_payload())
        self.assertEqual(payload["granted_scopes"], sorted(["z:scope", "a:scope", "m:scope"]))

    def test_different_secrets_produce_different_hashes(self):
        claim1 = DelegationChainClaim.create(
            "root", ["root"], ["documents:read"], hmac_secret="secret-A"
        )
        claim2 = DelegationChainClaim.create(
            "root", ["root"], ["documents:read"], hmac_secret="secret-B"
        )
        self.assertNotEqual(claim1.chain_hash, claim2.chain_hash)

    def test_wrong_secret_fails_verification(self):
        claim = DelegationChainClaim.create(
            "root", ["root"], ["documents:read"], hmac_secret="correct-secret"
        )
        self.assertFalse(claim.verify("wrong-secret"))


# ---------------------------------------------------------------------------
# 4. Serialisation round-trip
# ---------------------------------------------------------------------------

class TestSerialization(unittest.TestCase):
    """Claims are serialised to base64url JSON for the X-Uma-Delegation-Chain header."""

    def test_to_header_value_is_base64url_string(self):
        claim = _make_claim()
        value = claim.to_header_value()
        self.assertIsInstance(value, str)
        # Must not contain standard base64 padding characters
        # (to_header_value strips '=')
        for ch in ("+", "/"):
            self.assertNotIn(ch, value)

    def test_round_trip_preserves_chain_id(self):
        claim = _make_claim()
        recovered = DelegationChainClaim.from_header_value(claim.to_header_value())
        self.assertEqual(recovered.chain_id, claim.chain_id)

    def test_round_trip_preserves_members(self):
        claim = _make_claim(members=["cm", "analyst", "executor"])
        recovered = DelegationChainClaim.from_header_value(claim.to_header_value())
        self.assertEqual(recovered.members, claim.members)

    def test_round_trip_preserves_scopes(self):
        claim = _make_claim(scopes=["documents:read", "calendar:read"])
        recovered = DelegationChainClaim.from_header_value(claim.to_header_value())
        self.assertEqual(set(recovered.granted_scopes), set(claim.granted_scopes))

    def test_round_trip_preserves_hash(self):
        claim = _make_claim()
        recovered = DelegationChainClaim.from_header_value(claim.to_header_value())
        self.assertEqual(recovered.chain_hash, claim.chain_hash)

    def test_recovered_claim_still_verifies(self):
        claim = _make_claim(members=["root", "child"], scopes=["documents:read", "calendar:read"])
        recovered = DelegationChainClaim.from_header_value(claim.to_header_value())
        self.assertTrue(recovered.verify())

    def test_extra_fields_in_header_are_ignored(self):
        """from_header_value must not crash if the header contains unknown fields."""
        claim = _make_claim()
        raw = json.loads(base64.urlsafe_b64decode(
            claim.to_header_value() + "==="
        ))
        raw["future_extension_field"] = "some-value"
        encoded = base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip("=")
        recovered = DelegationChainClaim.from_header_value(encoded)
        self.assertEqual(recovered.chain_id, claim.chain_id)


# ---------------------------------------------------------------------------
# 5. T1 — Scope escalation
# ---------------------------------------------------------------------------

class TestT1ScopeEscalation(unittest.TestCase):
    """
    T1: A child agent's chain claim does not include the scope it is
    requesting.  The resource server must reject the request even if the
    agent holds a valid RPT.
    """

    def test_t1_blocked_when_scope_absent_from_chain(self):
        # Chain only grants documents:read; agent tries to access database:audit
        claim = _make_claim(
            members=["compliance-manager", "data-extractor"],
            scopes=["documents:read", "database:read"],
        )
        ok, reason = claim.validate_for_resource("database", "audit", "data-extractor")
        self.assertFalse(ok)
        self.assertIn("T1/T4", reason)
        self.assertIn("database:audit", reason)

    def test_t1_blocked_when_chain_has_no_scopes(self):
        claim = DelegationChainClaim.create(
            root_agent="root",
            members=["root"],
            granted_scopes=[],   # explicitly empty — bypass helper's default
            max_depth=4,
        )
        ok, reason = claim.validate_for_resource("documents", "read", "root")
        self.assertFalse(ok)
        self.assertIn("T1/T4", reason)

    def test_t1_passed_when_scope_present(self):
        claim = _make_claim(
            members=["compliance-manager", "risk-analyst"],
            scopes=["documents:read", "calendar:read"],
        )
        ok, reason = claim.validate_for_resource("documents", "read", "risk-analyst")
        self.assertTrue(ok)
        self.assertEqual(reason, "chain claim valid")

    def test_t1_partial_resource_name_does_not_match(self):
        # scope 'database:read' must not satisfy 'database:audit' request
        claim = _make_claim(scopes=["database:read"])
        ok, _ = claim.validate_for_resource("database", "audit", "compliance-manager")
        self.assertFalse(ok)

    def test_t1_requires_exact_resource_scope_pair(self):
        claim = _make_claim(scopes=["documents:read"])
        # 'documents' alone with a different scope should fail
        ok, _ = claim.validate_for_resource("documents", "write", "compliance-manager")
        self.assertFalse(ok)


# ---------------------------------------------------------------------------
# 6. T2 — Depth exceeded
# ---------------------------------------------------------------------------

class TestT2DepthExceeded(unittest.TestCase):
    """
    T2: The delegation chain is longer than the configured maximum depth.
    The resource server must reject the request to prevent unbounded delegation.
    """

    def test_t2_blocked_when_depth_exceeds_max(self):
        # 5 members, max_depth=4
        claim = _make_claim(members=["a", "b", "c", "d", "e"], max_depth=4)
        ok, reason = claim.validate_for_resource("documents", "read", "e")
        self.assertFalse(ok)
        self.assertIn("T2", reason)
        self.assertIn("5", reason)  # actual depth
        self.assertIn("4", reason)  # max depth

    def test_t2_passes_at_exact_max_depth(self):
        # 4 members, max_depth=4  → depth == max → allowed
        claim = _make_claim(
            members=["a", "b", "c", "d"],
            scopes=["documents:read"],
            max_depth=4,
        )
        ok, reason = claim.validate_for_resource("documents", "read", "d")
        self.assertTrue(ok, f"Unexpected failure: {reason}")

    def test_t2_blocked_one_over_max(self):
        claim = _make_claim(
            members=["a", "b", "c", "d", "e"],
            scopes=["documents:read"],
            max_depth=4,
        )
        ok, _ = claim.validate_for_resource("documents", "read", "e")
        self.assertFalse(ok)

    def test_t2_single_agent_always_valid_depth(self):
        claim = _make_claim(members=["root"], scopes=["documents:read"], max_depth=1)
        ok, _ = claim.validate_for_resource("documents", "read", "root")
        self.assertTrue(ok)

    def test_t2_max_depth_one_rejects_two_deep(self):
        claim = _make_claim(members=["root", "child"], scopes=["documents:read"], max_depth=1)
        ok, reason = claim.validate_for_resource("documents", "read", "child")
        self.assertFalse(ok)
        self.assertIn("T2", reason)


# ---------------------------------------------------------------------------
# 7. T3 — Token replay
# ---------------------------------------------------------------------------

class TestT3TokenReplay(unittest.TestCase):
    """
    T3: An agent presents a chain claim where it is not the terminus (last
    member).  This prevents a compromised ancestor from replaying a
    descendant's chain claim, or a peer from using another's claim.
    """

    def test_t3_blocked_when_presenter_is_not_terminus(self):
        claim = _make_claim(members=["compliance-manager", "risk-analyst"])
        # compliance-manager tries to present a chain where risk-analyst is the terminus
        ok, reason = claim.validate_for_resource(
            "documents", "read", "compliance-manager"
        )
        self.assertFalse(ok)
        self.assertIn("T3", reason)

    def test_t3_blocked_with_completely_unknown_agent(self):
        claim = _make_claim(members=["cm", "analyst"])
        ok, reason = claim.validate_for_resource("documents", "read", "attacker")
        self.assertFalse(ok)
        self.assertIn("T3", reason)

    def test_t3_passes_for_correct_terminus(self):
        claim = _make_claim(
            members=["compliance-manager", "risk-analyst"],
            scopes=["documents:read"],
        )
        ok, reason = claim.validate_for_resource("documents", "read", "risk-analyst")
        self.assertTrue(ok)

    def test_t3_blocked_for_root_using_delegated_chain(self):
        # Root agent tries to use a 3-deep chain where a grandchild is the leaf
        claim = _make_claim(members=["root", "child", "grandchild"], scopes=["documents:read"])
        ok, reason = claim.validate_for_resource("documents", "read", "root")
        self.assertFalse(ok)
        self.assertIn("T3", reason)

    def test_t3_blocked_for_middle_node(self):
        claim = _make_claim(members=["root", "mid", "leaf"], scopes=["documents:read"])
        ok, reason = claim.validate_for_resource("documents", "read", "mid")
        self.assertFalse(ok)
        self.assertIn("T3", reason)


# ---------------------------------------------------------------------------
# 8. T4 — Prompt injection
# ---------------------------------------------------------------------------

class TestT4PromptInjection(unittest.TestCase):
    """
    T4: An adversarial prompt causes an LLM agent to call a resource tool
    with a scope that is not in the agent's delegation chain.  The resource
    server rejects the request via the same scope-check logic as T1.

    These tests verify the enforcement path is identical to T1 — the
    distinction is in the *cause* of the out-of-scope request (adversarial
    input vs. coding bug), not in the detection mechanism.
    """

    def test_t4_blocked_when_injected_resource_not_in_chain(self):
        # data-extractor's chain only has documents:read and database:read
        claim = _make_claim(
            members=["compliance-manager", "data-extractor"],
            scopes=["documents:read", "database:read"],
        )
        # LLM was prompted to access /api/database/audit-entries
        ok, reason = claim.validate_for_resource("database", "audit", "data-extractor")
        self.assertFalse(ok)
        self.assertIn("T1/T4", reason)

    def test_t4_blocked_injected_admin_scope(self):
        claim = _make_claim(
            members=["risk-analyst"],
            scopes=["documents:read"],
        )
        # Prompt injection: "access /api/admin"
        ok, reason = claim.validate_for_resource("admin", "read", "risk-analyst")
        self.assertFalse(ok)
        self.assertIn("T1/T4", reason)

    def test_t4_injected_write_blocked_when_only_read_granted(self):
        claim = _make_claim(
            members=["data-extractor"],
            scopes=["documents:read"],
        )
        # Injected: "write the documents resource"
        ok, reason = claim.validate_for_resource("documents", "write", "data-extractor")
        self.assertFalse(ok)
        self.assertIn("T1/T4", reason)

    def test_t4_legitimate_request_still_passes(self):
        """Ensure T4 enforcement does not block authorized resources."""
        claim = _make_claim(
            members=["compliance-manager", "data-extractor"],
            scopes=["documents:read", "database:read"],
        )
        ok, reason = claim.validate_for_resource("documents", "read", "data-extractor")
        self.assertTrue(ok)

    def test_t4_multiple_valid_scopes_still_blocks_absent_scope(self):
        claim = _make_claim(
            scopes=["documents:read", "calendar:read", "database:read"],
        )
        # Injection requests a scope not in the list
        ok, reason = claim.validate_for_resource("database", "audit", "compliance-manager")
        self.assertFalse(ok)
        self.assertIn("T1/T4", reason)


# ---------------------------------------------------------------------------
# 9. Interaction of multiple attack conditions
# ---------------------------------------------------------------------------

class TestAttackClassPriority(unittest.TestCase):
    """
    When a tampered/replayed claim also violates depth or scope,
    the HMAC check fires first (guards against forged metadata).
    """

    def test_tampered_claim_rejected_before_depth_check(self):
        claim = _make_claim(members=["a", "b", "c", "d", "e"], max_depth=4)
        claim.chain_hash = "bad" + "0" * 61
        ok, reason = claim.validate_for_resource("documents", "read", "e")
        self.assertFalse(ok)
        # HMAC check fires first; its label is "T2/T3: chain_hash mismatch"
        self.assertIn("chain_hash mismatch", reason)
        # The depth-exceeded message must not appear since we stopped at HMAC
        self.assertNotIn("chain depth", reason)

    def test_valid_hash_but_wrong_terminus_reports_t3(self):
        claim = _make_claim(members=["cm", "analyst"], scopes=["documents:read"])
        ok, reason = claim.validate_for_resource("documents", "read", "impostor")
        self.assertFalse(ok)
        self.assertIn("T3", reason)


# ---------------------------------------------------------------------------
# 10. Comparative properties (paper Table II)
# ---------------------------------------------------------------------------

class TestComparativeProperties(unittest.TestCase):
    """
    DelegationChainClaim.comparison_properties() returns the feature matrix
    used in the paper to differentiate UMA-Agent from RFC 8693, Macaroons,
    and Biscuits.
    """

    def setUp(self):
        self.props = DelegationChainClaim.comparison_properties()

    def test_all_four_systems_present(self):
        systems = set(self.props.keys())
        self.assertIn("RFC 8693 Token Exchange", systems)
        self.assertIn("Macaroons", systems)
        self.assertIn("Biscuits", systems)
        self.assertIn("UMA-Agent (this work)", systems)

    def test_uma_agent_is_standards_based(self):
        self.assertTrue(self.props["UMA-Agent (this work)"]["standards_based"])

    def test_uma_agent_has_explicit_chain_provenance(self):
        self.assertTrue(self.props["UMA-Agent (this work)"]["explicit_chain_provenance"])

    def test_uma_agent_has_tamper_evident_audit(self):
        self.assertTrue(self.props["UMA-Agent (this work)"]["tamper_evident_audit"])

    def test_uma_agent_has_llm_agent_integration(self):
        self.assertTrue(self.props["UMA-Agent (this work)"]["llm_agent_integration"])

    def test_uma_agent_has_depth_enforcement(self):
        self.assertTrue(self.props["UMA-Agent (this work)"]["depth_enforcement"])

    def test_rfc8693_lacks_explicit_chain_provenance(self):
        self.assertFalse(self.props["RFC 8693 Token Exchange"]["explicit_chain_provenance"])

    def test_rfc8693_lacks_depth_enforcement(self):
        self.assertFalse(self.props["RFC 8693 Token Exchange"]["depth_enforcement"])

    def test_macaroons_not_standards_based(self):
        self.assertFalse(self.props["Macaroons"]["standards_based"])

    def test_biscuits_not_standards_based(self):
        self.assertFalse(self.props["Biscuits"]["standards_based"])

    def test_all_systems_have_scope_monotonicity(self):
        for system, props in self.props.items():
            self.assertTrue(
                props["scope_monotonicity"],
                f"{system} should have scope_monotonicity"
            )


if __name__ == "__main__":
    unittest.main()
