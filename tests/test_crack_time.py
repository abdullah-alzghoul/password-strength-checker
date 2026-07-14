"""Unit tests for the crack_time module."""

from src.core.crack_time import estimate_crack_times, humanize_seconds


class TestHumanizeSeconds:
    def test_sub_second_is_instant(self):
        assert humanize_seconds(0.5) == "instantly"

    def test_seconds_range(self):
        assert "second" in humanize_seconds(30)

    def test_days_range(self):
        assert "day" in humanize_seconds(60 * 60 * 24 * 3)

    def test_years_range(self):
        assert "year" in humanize_seconds(60 * 60 * 24 * 365 * 5)

    def test_huge_values_use_scientific_notation(self):
        result = humanize_seconds(10**30)
        assert "e" in result.lower()


class TestEstimateCrackTimes:
    def test_returns_one_estimate_per_scenario(self):
        estimates = estimate_crack_times(40.0)
        assert len(estimates) == 3

    def test_weak_entropy_cracks_fast_under_fast_hash(self):
        estimates = estimate_crack_times(10.0)
        fast_hash = next(e for e in estimates if "fast hash" in e.scenario)
        assert fast_hash.seconds_to_crack < 1

    def test_strong_entropy_takes_longer_than_weak(self):
        weak = estimate_crack_times(20.0)[0]
        strong = estimate_crack_times(80.0)[0]
        assert strong.seconds_to_crack > weak.seconds_to_crack

    def test_online_scenario_slower_than_offline_fast(self):
        estimates = estimate_crack_times(50.0)
        online = next(e for e in estimates if "Online" in e.scenario)
        offline_fast = next(e for e in estimates if "fast hash" in e.scenario)
        assert online.seconds_to_crack > offline_fast.seconds_to_crack
