"""loom.rambudget tests."""

import pytest
from loom.rambudget import DEFAULT_RSS_MB, RamBudget


class TestRamBudgetBasics:
    def test_estimate_known_tool(self):
        # nuclei is documented as 104MB
        assert RamBudget.estimate("nuclei") == 104 * 1024 * 1024

    def test_estimate_unknown_tool_uses_default(self):
        # Unknown tools fall back to 50MB
        assert RamBudget.estimate("unknown-tool") == 50 * 1024 * 1024

    def test_estimate_override(self):
        assert RamBudget.estimate("nuclei", default_mb=200) == 200 * 1024 * 1024

    def test_all_defaults_are_reasonable(self):
        # All defaults must be > 0 and < 1GB (sanity)
        for tool, mb in DEFAULT_RSS_MB.items():
            assert 0 < mb < 1024, f"{tool} default {mb}MB out of range"


class TestRamBudgetTracking:
    def test_initial_state(self):
        b = RamBudget(max_bytes=1 * 1024**3)  # 1GB
        snap = b.snapshot()
        assert snap["used_gb"] == 0
        assert snap["max_gb"] == 1.0
        assert snap["remaining_gb"] == 1.0
        assert snap["instances"] == {}

    def test_acquire_release(self):
        b = RamBudget(max_bytes=1 * 1024**3)
        b.acquire("nuclei")
        assert b.used_bytes == 104 * 1024 * 1024
        assert b.snapshot()["instances"] == {"nuclei": 1}
        b.release("nuclei")
        assert b.used_bytes == 0
        assert b.snapshot()["instances"] == {"nuclei": 0}

    def test_can_start_below_budget(self):
        b = RamBudget(max_bytes=200 * 1024**2)  # 200MB
        assert b.can_start("httpx")  # 80MB fits
        b.acquire("httpx")
        # Now 80MB used, 120MB left — httpx(80) fits but katana(200) doesn't
        assert b.can_start("httpx")
        assert not b.can_start("katana")

    def test_acquire_over_budget_raises(self):
        b = RamBudget(max_bytes=50 * 1024**2)  # 50MB
        with pytest.raises(RuntimeError, match="RAM budget exceeded"):
            b.acquire("nuclei")  # 104MB > 50MB cap

    def test_release_clamps_at_zero(self):
        b = RamBudget(max_bytes=1 * 1024**3)
        b.release("nuclei")  # never acquired — should not go negative
        assert b.used_bytes == 0

    def test_multiple_instances(self):
        b = RamBudget(max_bytes=1 * 1024**3)
        for _ in range(5):
            b.acquire("httpx")  # 80MB each = 400MB
        snap = b.snapshot()
        assert snap["instances"] == {"httpx": 5}
        # 5 × 80MB = 400MB; float math → 0.390625 GB. Allow 0.011 fuzz.
        assert abs(snap["used_gb"] - 0.4) < 0.011
        b.release("httpx")
        b.release("httpx")
        assert b.snapshot()["instances"] == {"httpx": 3}

    def test_20gb_default(self):
        b = RamBudget()  # default 20GB
        assert b.max_bytes == 20 * 1024**3
        # Can fit lots of nuclei
        for _ in range(100):
            assert b.can_start("nuclei")
            b.acquire("nuclei")
        snap = b.snapshot()
        # 100 nuclei * 104MB = 10.4GB < 20GB cap
        assert snap["used_gb"] < 20
        assert snap["remaining_gb"] > 0


class TestRamBudgetConcurrency:
    def test_thread_safe_acquire_release(self):
        import threading
        b = RamBudget(max_bytes=10 * 1024**3)
        errors = []
        def worker():
            try:
                for _ in range(10):
                    if b.can_start("httpx"):
                        b.acquire("httpx")
                        b.release("httpx")
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors
        # All released — used should be 0
        assert b.used_bytes == 0
