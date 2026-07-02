"""Combines entropy and pattern analysis into a single effective strength score."""

from dataclasses import dataclass

from src.core.entropy import analyze_entropy, classify_strength, StrengthLevel, EntropyResult
from src.core.pattern_detector import analyze_patterns, PatternResult


@dataclass
class StrengthReport:
    password_length: int
    raw_entropy_bits: float
    effective_entropy_bits: float
    strength: StrengthLevel
    entropy_detail: EntropyResult
    pattern_detail: PatternResult
    warnings: list[str]


def build_warnings(pattern: PatternResult) -> list[str]:
    warnings = []
    if pattern.is_common_password:
        warnings.append(f"من أكثر الباسوردات شيوعاً (زي: {pattern.matched_common_word})")
    if pattern.has_sequential:
        warnings.append(f"يحتوي تسلسل متوقع: {', '.join(pattern.sequential_matches)}")
    if pattern.has_keyboard_walk:
        warnings.append(f"يحتوي نمط كيبورد متوقع: {', '.join(pattern.keyboard_matches)}")
    if pattern.has_repeated_chars:
        warnings.append(f"يحتوي تكرار حروف: {', '.join(pattern.repeated_matches)}")
    return warnings


def analyze_password(password: str, wordlist: set[str] | None = None) -> StrengthReport:
    """Full analysis: raw entropy reduced by any detected weak patterns."""
    entropy_result = analyze_entropy(password)
    pattern_result = analyze_patterns(password, wordlist=wordlist)

    effective_bits = max(0.0, entropy_result.entropy_bits - pattern_result.penalty_bits)

    return StrengthReport(
        password_length=entropy_result.length,
        raw_entropy_bits=entropy_result.entropy_bits,
        effective_entropy_bits=round(effective_bits, 2),
        strength=classify_strength(effective_bits),
        entropy_detail=entropy_result,
        pattern_detail=pattern_result,
        warnings=build_warnings(pattern_result),
    )