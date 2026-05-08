"""
Unit tests for Step 5 benchmark.

Tests the statistics helpers and the pure-Python benchmark functions
offline.  The HTTP benchmark tests are skipped when servers are down.
"""

import statistics as _stats
from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib

from scenarios.benchmark import (
    PythonBenchmark,
    compute_stats,
    _build_chain,
    _measure,
    run_benchmark,
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
# compute_stats
# ---------------------------------------------------------------------------

class TestComputeStats:
    def test_mean_correct(self):
        s = compute_stats([10.0, 20.0, 30.0])
        assert s["mean_ms"] == pytest.approx(20.0, rel=1e-3)

    def test_std_correct(self):
        samples = [10.0, 20.0, 30.0]
        s = compute_stats(samples)
        assert s["std_ms"] == pytest.approx(_stats.stdev(samples), rel=1e-3)

    def test_min_max(self):
        s = compute_stats([5.0, 15.0, 25.0])
        assert s["min_ms"] == 5.0
        assert s["max_ms"] == 25.0

    def test_p95_on_100_samples(self):
        samples = [float(i) for i in range(1, 101)]
        s = compute_stats(samples)
        assert s["p95_ms"] == pytest.approx(95.0, abs=1.0)

    def test_single_sample_std_is_zero(self):
        s = compute_stats([42.0])
        assert s["std_ms"] == 0.0

    def test_empty_returns_none_fields(self):
        s = compute_stats([])
        assert s["mean_ms"] is None
        assert s["n"] == 0

    def test_n_field_correct(self):
        s = compute_stats([1.0, 2.0, 3.0])
        assert s["n"] == 3

    def test_all_required_keys_present(self):
        s = compute_stats([1.0, 2.0])
        for key in ("n", "mean_ms", "std_ms", "min_ms", "max_ms", "p95_ms"):
            assert key in s


# ---------------------------------------------------------------------------
# _measure
# ---------------------------------------------------------------------------

class TestMeasure:
    def test_returns_stats_dict(self):
        call_count = [0]
        def fn():
            call_count[0] += 1
        s = _measure(fn, n=5, warmup=0)
        assert s["n"] == 5

    def test_warmup_samples_excluded(self):
        call_count = [0]
        def fn():
            call_count[0] += 1
        _measure(fn, n=5, warmup=3)
        assert call_count[0] == 8  # 5 + 3

    def test_elapsed_is_positive(self):
        import time
        s = _measure(lambda: time.sleep(0.001), n=3, warmup=0)
        assert s["mean_ms"] >= 1.0


# ---------------------------------------------------------------------------
# _build_chain (same helper as attack scenarios)
# ---------------------------------------------------------------------------

class TestBuildChainHelper:
    def test_depth_1_valid(self):
        from agents.chain_claim import DelegationChainClaim
        h = _build_chain(1)
        c = DelegationChainClaim.from_header_value(h)
        assert c.depth == 1
        assert c.verify()

    def test_depth_4_valid(self):
        from agents.chain_claim import DelegationChainClaim
        h = _build_chain(4)
        c = DelegationChainClaim.from_header_value(h)
        assert c.depth == 4
        assert c.verify()


# ---------------------------------------------------------------------------
# PythonBenchmark
# ---------------------------------------------------------------------------

class TestPythonBenchmark:
    def setup_method(self):
        self.bench = PythonBenchmark(n=20)  # fast for tests

    def test_chain_construction_returns_four_depths(self):
        result = self.bench.bench_chain_construction()
        for d in (1, 2, 3, 4):
            assert f"depth_{d}" in result

    def test_chain_construction_mean_is_positive(self):
        result = self.bench.bench_chain_construction()
        for key, stats in result.items():
            assert stats["mean_ms"] > 0, f"{key} mean is not positive"

    def test_chain_construction_n_is_correct(self):
        result = self.bench.bench_chain_construction()
        for key, stats in result.items():
            assert stats["n"] == 20, f"{key} n={stats['n']}, expected 20"

    def test_chain_validation_returns_expected_keys(self):
        result = self.bench.bench_chain_validation()
        for key in ("valid_depth_1", "valid_depth_2", "valid_depth_3",
                    "t1_scope_escalation_blocked",
                    "t2_depth_exceeded_blocked",
                    "t3_token_replay_blocked",
                    "tampered_hash_blocked"):
            assert key in result, f"Missing key: {key}"

    def test_valid_chain_validation_mean_positive(self):
        result = self.bench.bench_chain_validation()
        for d in (1, 2, 3):
            assert result[f"valid_depth_{d}"]["mean_ms"] > 0

    def test_attack_validation_mean_positive(self):
        result = self.bench.bench_chain_validation()
        for key in ("t1_scope_escalation_blocked",
                    "t2_depth_exceeded_blocked",
                    "t3_token_replay_blocked"):
            assert result[key]["mean_ms"] > 0, f"{key} mean not positive"

    def test_chain_validation_depth_invariant(self):
        """Validation time should not grow significantly with depth (O(1))."""
        result = self.bench.bench_chain_validation()
        d1 = result["valid_depth_1"]["mean_ms"]
        d3 = result["valid_depth_3"]["mean_ms"]
        # depth 3 should be within 5x of depth 1 (HMAC is constant cost)
        assert d3 < d1 * 5, (
            f"Validation time grew too much with depth: d1={d1:.4f} d3={d3:.4f}"
        )

    def test_full_python_bench_result_schema(self):
        result = self.bench.run()
        assert "chain_construction" in result
        assert "chain_validation" in result

    def test_result_is_json_serialisable(self):
        import json
        result = self.bench.run()
        json.dumps(result)  # must not raise


# ---------------------------------------------------------------------------
# run_benchmark schema (HTTP mocked)
# ---------------------------------------------------------------------------

class TestRunBenchmarkSchema:
    @skip_if_down
    def test_full_result_has_top_level_keys(self):
        result = run_benchmark(n_http=3, n_python=10)
        for key in ("scenario", "run_at", "n_http", "n_python", "http", "python"):
            assert key in result

    @skip_if_down
    def test_http_result_has_all_measurement_keys(self):
        result = run_benchmark(n_http=3, n_python=10)
        for key in ("authentication", "rpt_exchange",
                    "resource_read_baseline",
                    "resource_read_chain_depth_1",
                    "resource_read_chain_depth_2",
                    "resource_read_chain_depth_3",
                    "chain_extension_overhead_ms"):
            assert key in result["http"], f"HTTP missing key: {key}"

    @skip_if_down
    def test_overhead_keys_are_depths_1_2_3(self):
        result = run_benchmark(n_http=3, n_python=10)
        overhead = result["http"]["chain_extension_overhead_ms"]
        assert set(overhead.keys()) == {1, 2, 3}

    @skip_if_down
    def test_chain_extension_overhead_is_small(self):
        """Chain overhead vs baseline should be under 20 ms."""
        result = run_benchmark(n_http=5, n_python=10)
        for d, ms in result["http"]["chain_extension_overhead_ms"].items():
            assert ms < 20.0, f"Depth {d} overhead {ms:.2f} ms exceeds 20 ms"

    @skip_if_down
    def test_full_result_is_json_serialisable(self):
        import json
        result = run_benchmark(n_http=3, n_python=10)
        json.dumps(result, default=str)
