"""Unit tests for the entropy module."""

import pytest

from src.core.entropy import (
    detect_charset_size,
    calculate_shannon_entropy,
    classify_strength,
    analyze_entropy,
    StrengthLevel,
)


class TestDetectCharsetSize:
    def test_lowercase_only(self):
        assert detect_charset_size("abcdef") == 26

    def test_lowercase_and_digits(self):
        assert detect_charset_size("abc123") == 36

    def test_all_categories(self):
        assert detect_charset_size("Abc123!@") == 26 + 26 + 10 + 32

    def test_symbols_only(self):
        assert detect_charset_size("!@#$%") == 32


class TestCalculateShannonEntropy:
    def test_empty_password_zero_entropy(self):
        assert calculate_shannon_entropy("", 26) == 0.0

    def test_known_value(self):
        result = calculate_shannon_entropy("abcd", 26)  # 4*log2(26) ≈ 18.8
        assert 18.7 < result < 18.9

    def test_zero_charset_size(self):
        assert calculate_shannon_entropy("abcd", 0) == 0.0


class TestClassifyStrength:
    def test_very_weak(self):
        assert classify_strength(10) == StrengthLevel.VERY_WEAK

    def test_weak_boundary(self):
        assert classify_strength(28) == StrengthLevel.WEAK

    def test_fair(self):
        assert classify_strength(40) == StrengthLevel.FAIR

    def test_strong(self):
        assert classify_strength(65) == StrengthLevel.STRONG

    def test_very_strong(self):
        assert classify_strength(90) == StrengthLevel.VERY_STRONG


class TestAnalyzeEntropy:
    def test_valid_password_returns_result(self):
        result = analyze_entropy("Tr0ub4dor&3")
        assert result.length == 11
        assert result.entropy_bits > 0
        assert isinstance(result.strength, StrengthLevel)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            analyze_entropy("")

    def test_non_string_raises(self):
        with pytest.raises(TypeError):
            analyze_entropy(12345)