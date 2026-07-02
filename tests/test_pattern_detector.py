"""Unit tests for the pattern_detector module."""

import pytest

from src.core.pattern_detector import (
    normalize_leetspeak,
    check_common_password,
    detect_sequential,
    detect_keyboard_walk,
    detect_repeated_chars,
    analyze_patterns,
)


class TestNormalizeLeetspeak:
    def test_basic_substitution(self):
        assert normalize_leetspeak("p@ssw0rd") == "password"

    def test_no_substitution_needed(self):
        assert normalize_leetspeak("hello") == "hello"

    def test_mixed_case_normalized(self):
        assert normalize_leetspeak("P@SSW0RD") == "password"


class TestCheckCommonPassword:
    def setup_method(self):
        self.wordlist = {"password", "123456", "qwerty"}

    def test_exact_match(self):
        found, matched = check_common_password("password", self.wordlist)
        assert found is True
        assert matched == "password"

    def test_leetspeak_match(self):
        found, matched = check_common_password("P@ssw0rd", self.wordlist)
        assert found is True
        assert matched == "password"

    def test_no_match(self):
        found, matched = check_common_password("Xk9$mQ2vL", self.wordlist)
        assert found is False
        assert matched is None


class TestDetectSequential:
    def test_ascending_numeric(self):
        assert "123" in detect_sequential("abc123xyz")

    def test_ascending_alpha(self):
        result = detect_sequential("xyzabc123")
        assert "abc" in result and "xyz" in result

    def test_descending(self):
        assert "321" in detect_sequential("test321end")

    def test_no_sequential(self):
        assert detect_sequential("Xk9mQ2vL") == []

    def test_below_min_run_ignored(self):
        assert detect_sequential("a1b2c3") == []


class TestDetectKeyboardWalk:
    def test_qwerty_row(self):
        assert "qwerty" in detect_keyboard_walk("qwerty123")

    def test_asdf_row(self):
        result = detect_keyboard_walk("myasdfpass")
        assert any("asdf" in m for m in result)

    def test_no_walk(self):
        assert detect_keyboard_walk("Xk9mQ2vL") == []

    def test_no_duplicate_substrings(self):
        assert detect_keyboard_walk("qwerty") == ["qwerty"]


class TestDetectRepeatedChars:
    def test_triple_repeat(self):
        assert "aaa" in detect_repeated_chars("paaassword")

    def test_no_repeat(self):
        assert detect_repeated_chars("password") == []

    def test_double_not_flagged(self):
        assert detect_repeated_chars("aabbcc") == []


class TestAnalyzePatterns:
    def test_weak_password_flags_common(self):
        result = analyze_patterns("password", wordlist={"password"})
        assert result.is_common_password is True
        assert result.penalty_bits > 0

    def test_strong_password_no_flags(self):
        result = analyze_patterns("Xk9$mQ2vL7!p", wordlist={"password"})
        assert result.is_common_password is False
        assert result.has_sequential is False
        assert result.penalty_bits == 0.0

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            analyze_patterns("")