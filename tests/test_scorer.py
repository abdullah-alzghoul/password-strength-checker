"""Unit tests for the scorer module."""

from src.core.scorer import analyze_password, build_warnings
from src.core.pattern_detector import PatternResult
from src.core.entropy import StrengthLevel


class TestAnalyzePassword:
    def test_common_password_lowers_effective_entropy(self):
        result = analyze_password("password", wordlist={"password"})
        assert result.effective_entropy_bits < result.raw_entropy_bits
        assert result.pattern_detail.is_common_password is True

    def test_strong_random_password_unaffected(self):
        result = analyze_password("Xk9$mQ2vL7!p", wordlist={"password"})
        assert result.effective_entropy_bits == result.raw_entropy_bits
        assert result.strength in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG)

    def test_effective_entropy_never_negative(self):
        result = analyze_password("111", wordlist={"111"})
        assert result.effective_entropy_bits >= 0.0

    def test_warnings_populated_for_weak_password(self):
        result = analyze_password("qwerty123", wordlist=set())
        assert len(result.warnings) > 0

    def test_no_warnings_for_clean_password(self):
        result = analyze_password("Xk9$mQ2vL7!p", wordlist=set())
        assert result.warnings == []


class TestBuildWarnings:
    def test_common_password_warning(self):
        pattern = PatternResult(is_common_password=True, matched_common_word="password")
        warnings = build_warnings(pattern)
        assert len(warnings) == 1
        assert "password" in warnings[0]

    def test_multiple_warnings(self):
        pattern = PatternResult(
            has_sequential=True, sequential_matches=["123"],
            has_repeated_chars=True, repeated_matches=["aaa"],
        )
        warnings = build_warnings(pattern)
        assert len(warnings) == 2