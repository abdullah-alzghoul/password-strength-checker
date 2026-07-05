"""Combines entropy and pattern analysis into a single effective strength score."""

from dataclasses import dataclass, field

from src.core.entropy import analyze_entropy, classify_strength, StrengthLevel, EntropyResult
from src.core.pattern_detector import (
    analyze_patterns,
    PatternResult,
    COMMON_PASSWORD_PENALTY,
    SEQUENTIAL_PENALTY_PER_MATCH,
    KEYBOARD_PENALTY_PER_MATCH,
    REPEATED_PENALTY_PER_MATCH,
    PERSONAL_INFO_PENALTY_PER_MATCH,
)
from src.core.breach_checker import check_breach, BreachResult
from src.core.crack_time import estimate_crack_times, CrackTimeEstimate
from src.core.compliance import check_all_standards, ComplianceCheck
from src.core.mutation_simulator import simulate_mutation_attack, MutationResult

MUTATION_PENALTY = 35.0


@dataclass
class ScoreBreakdownItem:
    label: str
    points: float


@dataclass
class StrengthReport:
    password_length: int
    raw_entropy_bits: float
    effective_entropy_bits: float
    strength: StrengthLevel
    entropy_detail: EntropyResult
    pattern_detail: PatternResult
    breach_detail: BreachResult
    warnings: list[str]
    crack_time_estimates: list[CrackTimeEstimate] = field(default_factory=list)
    compliance_checks: list[ComplianceCheck] = field(default_factory=list)
    mutation_detail: MutationResult = field(default_factory=MutationResult)
    score_breakdown: list[ScoreBreakdownItem] = field(default_factory=list)


def build_warnings(pattern: PatternResult, breach: BreachResult, mutation: MutationResult) -> list[str]:
    warnings = []
    if breach.checked and breach.is_breached:
        warnings.append(f"Found in {breach.breach_count:,} known data breaches — do not use this password")
    elif not breach.checked and breach.error != "skipped":
        warnings.append("Could not verify against breach database (connection issue)")
    if pattern.has_personal_info:
        warnings.append(f"Contains part of your username/email: {', '.join(pattern.personal_info_matches)}")
    if pattern.is_common_password:
        warnings.append(f"One of the most common passwords (matched: {pattern.matched_common_word})")
    elif mutation.vulnerable:
        warnings.append(f"A simple variation of a common password (base word: {mutation.base_word})")
    if pattern.has_sequential:
        warnings.append(f"Contains a predictable sequence: {', '.join(pattern.sequential_matches)}")
    if pattern.has_keyboard_walk:
        warnings.append(f"Contains a predictable keyboard pattern: {', '.join(pattern.keyboard_matches)}")
    if pattern.has_repeated_chars:
        warnings.append(f"Contains repeated characters: {', '.join(pattern.repeated_matches)}")
    return warnings


def build_score_breakdown(
    raw_entropy_bits: float,
    pattern: PatternResult,
    mutation: MutationResult,
    mutation_penalty: float,
) -> list[ScoreBreakdownItem]:
    items = [ScoreBreakdownItem("Base entropy (length \u00d7 character-set size)", round(raw_entropy_bits, 2))]

    if pattern.is_common_password:
        items.append(ScoreBreakdownItem(f"Common password match ({pattern.matched_common_word})", -COMMON_PASSWORD_PENALTY))
    elif mutation_penalty > 0:
        items.append(ScoreBreakdownItem(f"Variation of a common word ({mutation.base_word})", -mutation_penalty))
    if pattern.has_sequential:
        n = len(pattern.sequential_matches)
        items.append(ScoreBreakdownItem(f"Sequential pattern ({n}x)", -SEQUENTIAL_PENALTY_PER_MATCH * n))
    if pattern.has_keyboard_walk:
        n = len(pattern.keyboard_matches)
        items.append(ScoreBreakdownItem(f"Keyboard pattern ({n}x)", -KEYBOARD_PENALTY_PER_MATCH * n))
    if pattern.has_repeated_chars:
        n = len(pattern.repeated_matches)
        items.append(ScoreBreakdownItem(f"Repeated characters ({n}x)", -REPEATED_PENALTY_PER_MATCH * n))
    if pattern.has_personal_info:
        n = len(pattern.personal_info_matches)
        items.append(ScoreBreakdownItem(f"Personal info match ({n}x)", -PERSONAL_INFO_PENALTY_PER_MATCH * n))

    return items


def analyze_password(
    password: str,
    wordlist: set[str] | None = None,
    check_breaches: bool = True,
    username: str | None = None,
    email: str | None = None,
) -> StrengthReport:
    """Full analysis: raw entropy reduced by any detected weak patterns.
    A confirmed breach match overrides the score entirely."""
    entropy_result = analyze_entropy(password)
    pattern_result = analyze_patterns(password, wordlist=wordlist, username=username, email=email)
    mutation_result = simulate_mutation_attack(password, wordlist=wordlist)

    if check_breaches:
        breach_result = check_breach(password)
    else:
        breach_result = BreachResult(checked=False, error="skipped")

    mutation_penalty = MUTATION_PENALTY if mutation_result.vulnerable and not pattern_result.is_common_password else 0.0
    effective_bits = max(0.0, entropy_result.entropy_bits - pattern_result.penalty_bits - mutation_penalty)
    crack_times = estimate_crack_times(effective_bits)
    compliance_results = check_all_standards(password, pattern_result, breach_result.is_breached)
    breakdown = build_score_breakdown(entropy_result.entropy_bits, pattern_result, mutation_result, mutation_penalty)

    if breach_result.checked and breach_result.is_breached:
        strength = StrengthLevel.COMPROMISED
    else:
        strength = classify_strength(effective_bits)

    return StrengthReport(
        password_length=entropy_result.length,
        raw_entropy_bits=entropy_result.entropy_bits,
        effective_entropy_bits=round(effective_bits, 2),
        strength=strength,
        entropy_detail=entropy_result,
        pattern_detail=pattern_result,
        breach_detail=breach_result,
        crack_time_estimates=crack_times,
        compliance_checks=compliance_results,
        mutation_detail=mutation_result,
        score_breakdown=breakdown,
        warnings=build_warnings(pattern_result, breach_result, mutation_result),
    )