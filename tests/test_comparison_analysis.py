"""
Unit tests for scenarios/comparison_analysis.py (W7 comparison module).

All offline — no servers, no LLM, no network.
"""

import json
import pytest

from scenarios.comparison_analysis import (
    FEATURES,
    SYSTEMS,
    CODE_COMPLEXITY,
    LATENCY_COMPARISON,
    UMA_VS_UMA_AGENT,
    run_comparison,
)


# ---------------------------------------------------------------------------
# Feature matrix structure
# ---------------------------------------------------------------------------

class TestFeatureMatrix:
    def test_ten_features_defined(self):
        assert len(FEATURES) == 10

    def test_feature_ids_are_f1_to_f10(self):
        ids = [f["id"] for f in FEATURES]
        assert ids == [f"F{i}" for i in range(1, 11)]

    def test_every_feature_has_required_keys(self):
        required = {"id", "label", "description", "note"} | set(SYSTEMS)
        for f in FEATURES:
            for key in required:
                assert key in f, f"Feature {f['id']} missing key '{key}'"

    def test_every_value_is_bool_or_partial(self):
        for f in FEATURES:
            for s in SYSTEMS:
                assert f[s] in (True, False, "partial"), (
                    f"Feature {f['id']} system '{s}' has unexpected value {f[s]!r}"
                )

    def test_uma_agent_supports_all_10_features(self):
        uma_key = "UMA-Agent (ours)"
        supported = [f for f in FEATURES if f[uma_key] is True]
        assert len(supported) == 10, (
            f"UMA-Agent should support all 10 features, got {len(supported)}"
        )

    def test_f1_standards_based_uma_and_rfc_both_true(self):
        f1 = next(f for f in FEATURES if f["id"] == "F1")
        assert f1["UMA-Agent (ours)"] is True
        assert f1["RFC 8693 Token Exchange"] is True

    def test_f3_depth_enforcement_only_uma_agent(self):
        f3 = next(f for f in FEATURES if f["id"] == "F3")
        assert f3["UMA-Agent (ours)"] is True
        assert f3["RFC 8693 Token Exchange"] is False
        assert f3["Macaroons"] is False
        assert f3["Biscuits"] is False

    def test_f5_audit_log_only_uma_agent(self):
        f5 = next(f for f in FEATURES if f["id"] == "F5")
        assert f5["UMA-Agent (ours)"] is True
        for s in SYSTEMS:
            if s != "UMA-Agent (ours)":
                assert f5[s] is False

    def test_f7_t4_protection_only_uma_agent(self):
        f7 = next(f for f in FEATURES if f["id"] == "F7")
        assert f7["UMA-Agent (ours)"] is True
        for s in SYSTEMS:
            if s != "UMA-Agent (ours)":
                assert f7[s] is False


# ---------------------------------------------------------------------------
# Code complexity
# ---------------------------------------------------------------------------

class TestCodeComplexity:
    def test_all_four_systems_present(self):
        for s in SYSTEMS:
            assert s in CODE_COMPLEXITY["systems"], f"'{s}' missing from CODE_COMPLEXITY"

    def test_uma_agent_has_measured_total(self):
        uma = CODE_COMPLEXITY["systems"]["UMA-Agent (ours)"]
        assert "loc_total_measured" in uma
        assert isinstance(uma["loc_total_measured"], int)

    def test_uma_agent_loc_is_708(self):
        uma = CODE_COMPLEXITY["systems"]["UMA-Agent (ours)"]
        assert uma["loc_total_measured"] == 708

    def test_uma_agent_lowest_loc(self):
        uma_loc = CODE_COMPLEXITY["systems"]["UMA-Agent (ours)"]["loc_total_measured"]
        for s in SYSTEMS:
            if s == "UMA-Agent (ours)":
                continue
            alt_loc = CODE_COMPLEXITY["systems"][s]["loc_total_estimated"]
            assert uma_loc < alt_loc, (
                f"UMA-Agent ({uma_loc}) should have fewer LOC than {s} ({alt_loc})"
            )

    def test_alternatives_have_estimated_total(self):
        for s in SYSTEMS:
            if s == "UMA-Agent (ours)":
                continue
            data = CODE_COMPLEXITY["systems"][s]
            assert "loc_total_estimated" in data

    def test_alternatives_require_custom_code_for_f2_f3_f5(self):
        for s in SYSTEMS:
            if s == "UMA-Agent (ours)":
                continue
            custom = CODE_COMPLEXITY["systems"][s]["features_requiring_custom_code"]
            for fid in ("F2", "F3", "F5"):
                assert fid in custom, f"{s} should require custom code for {fid}"

    def test_uma_agent_requires_no_custom_code(self):
        uma = CODE_COMPLEXITY["systems"]["UMA-Agent (ours)"]
        assert uma["features_requiring_custom_code"] == []


# ---------------------------------------------------------------------------
# Latency comparison
# ---------------------------------------------------------------------------

class TestLatencyComparison:
    def test_baseline_mean_is_7_6(self):
        base = LATENCY_COMPARISON["measurements"]["resource_read_plain_uma_no_chain"]
        assert base["UMA-Agent baseline"]["mean"] == pytest.approx(7.6)

    def test_depth_1_mean_is_11_8(self):
        d1 = LATENCY_COMPARISON["measurements"]["resource_read_with_uma_agent_chain"]["depth_1"]
        assert d1["mean"] == pytest.approx(11.8)

    def test_overhead_increases_monotonically(self):
        m = LATENCY_COMPARISON["measurements"]["resource_read_with_uma_agent_chain"]
        overheads = [m[f"depth_{d}"]["overhead_vs_baseline"] for d in (1, 2, 3)]
        for i in range(len(overheads) - 1):
            assert overheads[i] <= overheads[i + 1], (
                f"Overhead should be non-decreasing: {overheads}"
            )

    def test_overhead_under_10_ms_at_depth_3(self):
        d3 = LATENCY_COMPARISON["measurements"]["resource_read_with_uma_agent_chain"]["depth_3"]
        assert d3["overhead_vs_baseline"] < 10.0

    def test_python_validation_is_5us_at_all_depths(self):
        cv = LATENCY_COMPARISON["measurements"]["chain_validation_python_only"]
        for depth in (1, 2, 3):
            assert cv[f"depth_{depth}"]["mean_us"] == pytest.approx(5.0)

    def test_key_finding_mentions_o1(self):
        finding = LATENCY_COMPARISON["key_finding"]
        assert "O(1)" in finding or "depth-invariant" in finding.lower()


# ---------------------------------------------------------------------------
# UMA vs UMA-Agent distinction
# ---------------------------------------------------------------------------

class TestUmaVsUmaAgent:
    def test_four_attack_classes_in_enforcement(self):
        enforcement = UMA_VS_UMA_AGENT["uma_agent_adds"]["enforcement_added"]
        for cls in ("T1", "T2", "T3", "HMAC"):
            assert cls in enforcement

    def test_protocol_extension_urn_present(self):
        ext = UMA_VS_UMA_AGENT["uma_agent_adds"]["protocol_extension"]
        assert "urn:uma-agent:delegation-chain:1.0" in ext

    def test_plain_uma_missing_delegation_tracking(self):
        missing = UMA_VS_UMA_AGENT["plain_uma_2_0"]["does_not_provide"]
        assert any("delegation" in m.lower() or "chain" in m.lower() for m in missing)

    def test_audit_hash_chain_described(self):
        audit = UMA_VS_UMA_AGENT["uma_agent_adds"]["audit_added"]
        assert "hash_chain" in audit


# ---------------------------------------------------------------------------
# run_comparison() output schema
# ---------------------------------------------------------------------------

class TestRunComparison:
    def setup_method(self):
        self.result = run_comparison()

    def test_required_top_level_keys(self):
        for key in ("scenario", "run_at", "feature_matrix", "feature_counts",
                    "features_unique_to_uma_agent", "code_complexity",
                    "latency_comparison", "uma_vs_uma_agent"):
            assert key in self.result

    def test_feature_counts_has_all_systems(self):
        for s in SYSTEMS:
            assert s in self.result["feature_counts"]

    def test_uma_agent_feature_count_is_10(self):
        assert self.result["feature_counts"]["UMA-Agent (ours)"] == 10

    def test_unique_features_non_empty(self):
        assert len(self.result["features_unique_to_uma_agent"]) > 0

    def test_f3_depth_enforcement_is_unique(self):
        unique = self.result["features_unique_to_uma_agent"]
        labels = " ".join(unique).lower()
        assert "depth" in labels

    def test_f5_audit_is_unique(self):
        unique = self.result["features_unique_to_uma_agent"]
        labels = " ".join(unique).lower()
        assert "audit" in labels

    def test_result_is_json_serializable(self):
        dumped = json.dumps(self.result, default=str)
        reloaded = json.loads(dumped)
        assert reloaded["feature_counts"]["UMA-Agent (ours)"] == 10
