"""Core entropy and strength calculation for password analysis."""

import math
from dataclasses import dataclass
from enum import Enum


class StrengthLevel(Enum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    FAIR = "Fair"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"


@dataclass
class EntropyResult:
    entropy_bits: float
    charset_size: int
    length: int
    strength: StrengthLevel


CHARSET_SIZES = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "symbols": 32,  # common printable ASCII symbols
}

# Entropy-bit thresholds (upper bound exclusive)
STRENGTH_THRESHOLDS = [
    (28, StrengthLevel.VERY_WEAK),
    (36, StrengthLevel.WEAK),
    (60, StrengthLevel.FAIR),
    (80, StrengthLevel.STRONG),
    (float("inf"), StrengthLevel.VERY_STRONG),
]


def detect_charset_size(password: str) -> int:
    """Determine the effective character pool size used in the password."""
    size = 0
    if any(c.islower() for c in password):
        size += CHARSET_SIZES["lowercase"]
    if any(c.isupper() for c in password):
        size += CHARSET_SIZES["uppercase"]
    if any(c.isdigit() for c in password):
        size += CHARSET_SIZES["digits"]
    if any(not c.isalnum() and c.isprintable() for c in password):
        size += CHARSET_SIZES["symbols"]
    if any(not c.isascii() for c in password):
        size += 100  # conservative bump for unicode pool expansion
    return size


def calculate_shannon_entropy(password: str, charset_size: int) -> float:
    """bits = length * log2(charset_size), assuming uniform random selection."""
    if not password or charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def classify_strength(entropy_bits: float) -> StrengthLevel:
    for threshold, level in STRENGTH_THRESHOLDS:
        if entropy_bits < threshold:
            return level
    return StrengthLevel.VERY_STRONG


def analyze_entropy(password: str) -> EntropyResult:
    """Entry point. Raises on invalid input instead of failing silently."""
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__}")
    if password == "":
        raise ValueError("password cannot be empty")

    charset_size = detect_charset_size(password)
    entropy_bits = calculate_shannon_entropy(password, charset_size)

    return EntropyResult(
        entropy_bits=round(entropy_bits, 2),
        charset_size=charset_size,
        length=len(password),
        strength=classify_strength(entropy_bits),
    )