"""Unit tests for the scorer module."""

from unittest.mock import patch

from src.core.breach_checker import BreachResult
from src.core.entropy import StrengthLevel
from src.core.mutation_simulator import MutationResult
from src.core.pattern_detector import PatternResult
from src.core.scorer import analyze_password, build_score_breakdown, build_warnings


class TestAnalyzePassword:
    def test_common_password_lowers_effective_entropy(self):
        result = analyze_password("password", wordlist={"password"}, check_breaches=False)
        assert result.effective_entropy_bits < result.raw_entropy_bits
        assert result.pattern_detail.is_common_password is True

    def test_strong_random_password_unaffected(self):
        result = analyze_password("Xk9$mQ2vL7!p", wordlist={"password"}, check_breaches=False)
        assert result.effective_entropy_bits == result.raw_entropy_bits
        assert result.strength in (StrengthLevel.STRONG, StrengthLevel.VERY_STRONG)

    def test_effective_entropy_never_negative(self):
        result = analyze_password("111", wordlist={"111"}, check_breaches=False)
        assert result.effective_entropy_bits >= 0.0

    def test_warnings_populated_for_weak_password(self):
        result = analyze_password("qwerty123", wordlist=set(), check_breaches=False)
        assert len(result.warnings) > 0

    def test_no_warnings_for_clean_password(self):
        result = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        assert result.warnings == []

    def test_check_breaches_false_skips_network_call(self):
        result = analyze_password("anything", check_breaches=False)
        assert result.breach_detail.checked is False

    def test_username_match_flagged_via_pattern_detail(self):
        result = analyze_password(
            "abdullah2026!", wordlist=set(), check_breaches=False, username="abdullah"
        )
        assert result.pattern_detail.has_personal_info is True
        assert any("username" in w.lower() for w in result.warnings)

    def test_crack_time_estimates_populated(self):
        result = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        assert len(result.crack_time_estimates) == 3
        assert all(e.seconds_to_crack >= 0 for e in result.crack_time_estimates)

    def test_compliance_checks_populated(self):
        result = analyze_password("Str0ng!Passw0rd123", wordlist=set(), check_breaches=False)
        assert len(result.compliance_checks) == 3

    def test_mutation_detail_populated(self):
        result = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        assert result.mutation_detail.vulnerable is False

    def test_mutation_penalty_applied_for_variant_password(self):
        result = analyze_password("password2026", wordlist={"password"}, check_breaches=False)
        assert result.mutation_detail.vulnerable is True
        assert result.effective_entropy_bits < result.raw_entropy_bits

    def test_score_breakdown_populated(self):
        result = analyze_password("password", wordlist={"password"}, check_breaches=False)
        assert len(result.score_breakdown) >= 1
        assert result.score_breakdown[0].label.startswith("Base entropy")

    @patch("src.core.scorer.check_breach")
    def test_breached_password_overrides_strength(self, mock_check_breach):
        mock_check_breach.return_value = BreachResult(
            checked=True, is_breached=True, breach_count=50000
        )

        result = analyze_password("Xk9$mQ2vL7!p", wordlist=set())
        assert result.strength == StrengthLevel.COMPROMISED
        assert any("breach" in w.lower() for w in result.warnings)

    @patch("src.core.scorer.check_breach")
    def test_clean_password_not_overridden(self, mock_check_breach):
        mock_check_breach.return_value = BreachResult(checked=True, is_breached=False)

        result = analyze_password("Xk9$mQ2vL7!p", wordlist=set())
        assert result.strength != StrengthLevel.COMPROMISED


class TestBuildWarnings:
    def test_common_password_warning(self):
        pattern = PatternResult(is_common_password=True, matched_common_word="password")
        breach = BreachResult(checked=True, is_breached=False)
        warnings = build_warnings(pattern, breach, MutationResult())
        assert len(warnings) == 1
        assert "password" in warnings[0]

    def test_multiple_warnings(self):
        pattern = PatternResult(
            has_sequential=True,
            sequential_matches=["123"],
            has_repeated_chars=True,
            repeated_matches=["aaa"],
        )
        breach = BreachResult(checked=True, is_breached=False)
        warnings = build_warnings(pattern, breach, MutationResult())
        assert len(warnings) == 2

    def test_breach_warning_takes_priority_position(self):
        pattern = PatternResult()
        breach = BreachResult(checked=True, is_breached=True, breach_count=100)
        warnings = build_warnings(pattern, breach, MutationResult())
        assert len(warnings) == 1
        assert "100" in warnings[0]

    def test_personal_info_warning_included(self):
        pattern = PatternResult(has_personal_info=True, personal_info_matches=["abdullah"])
        breach = BreachResult(checked=True, is_breached=False)
        warnings = build_warnings(pattern, breach, MutationResult())
        assert len(warnings) == 1
        assert "abdullah" in warnings[0]

    def test_mutation_warning_included_when_not_exact_common_match(self):
        pattern = PatternResult(is_common_password=False)
        breach = BreachResult(checked=True, is_breached=False)
        mutation = MutationResult(vulnerable=True, base_word="password")
        warnings = build_warnings(pattern, breach, mutation)
        assert len(warnings) == 1
        assert "password" in warnings[0]

    def test_mutation_warning_suppressed_when_already_exact_common_match(self):
        pattern = PatternResult(is_common_password=True, matched_common_word="password")
        breach = BreachResult(checked=True, is_breached=False)
        mutation = MutationResult(vulnerable=True, base_word="password")
        warnings = build_warnings(pattern, breach, mutation)
        assert len(warnings) == 1


class TestBuildScoreBreakdown:
    def test_clean_password_only_has_base_entropy(self):
        breakdown = build_score_breakdown(50.0, PatternResult(), MutationResult(), 0.0)
        assert len(breakdown) == 1
        assert breakdown[0].points == 50.0

    def test_common_password_shows_negative_penalty(self):
        pattern = PatternResult(is_common_password=True, matched_common_word="password")
        breakdown = build_score_breakdown(37.6, pattern, MutationResult(), 0.0)
        assert len(breakdown) == 2
        assert breakdown[1].points == -40.0

    def test_mutation_penalty_shown_when_not_exact_match(self):
        pattern = PatternResult(is_common_password=False)
        mutation = MutationResult(vulnerable=True, base_word="password")
        breakdown = build_score_breakdown(50.0, pattern, mutation, 35.0)
        assert len(breakdown) == 2
        assert breakdown[1].points == -35.0

    def test_multiple_pattern_penalties_all_listed(self):
        pattern = PatternResult(
            has_sequential=True,
            sequential_matches=["123"],
            has_keyboard_walk=True,
            keyboard_matches=["qwerty", "123"],
        )
        breakdown = build_score_breakdown(60.0, pattern, MutationResult(), 0.0)
        assert len(breakdown) == 3
