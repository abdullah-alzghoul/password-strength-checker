"""Simulate common password-cracking mutation rules against a wordlist,
similar in spirit to hashcat rule-based attacks. Tests whether the
password is a rule-based derivative of a common base word.

Scope note: this checks single-category mutations (case OR suffix OR
reversal OR duplication OR leetspeak) rather than exhaustively chaining
every combination — mirroring a small hashcat rule file, not a full one."""

from dataclasses import dataclass

from src.core.pattern_detector import load_common_passwords

COMMON_SUFFIXES = (
    [str(n) for n in range(10)]
    + [f"{n:02d}" for n in range(100)]
    + [str(y) for y in range(1970, 2031)]
    + ["!", "@", "#", "$", "123", "1234", "!!"]
)

LEET_SUBSTITUTIONS = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}


def apply_mutations(word: str) -> set[str]:
    """Generate common rule-based variants of a base word."""
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    case_variants = set(variants)

    for base in case_variants:
        for suffix in COMMON_SUFFIXES:
            variants.add(base + suffix)
        variants.add(base[::-1])
        variants.add(base + base)

    leet_variants = set()
    for base in variants:
        leet = base
        for letter, sub in LEET_SUBSTITUTIONS.items():
            leet = leet.replace(letter, sub).replace(letter.upper(), sub)
        leet_variants.add(leet)

    return variants | leet_variants


@dataclass
class MutationResult:
    vulnerable: bool
    base_word: str | None = None
    approx_guesses: int | None = None


def simulate_mutation_attack(password: str, wordlist: set[str] | None = None) -> MutationResult:
    """Check whether the password is a rule-based mutation of any wordlist entry."""
    if wordlist is None:
        wordlist = load_common_passwords()

    for base_word in wordlist:
        variants = apply_mutations(base_word)
        if password in variants:
            return MutationResult(vulnerable=True, base_word=base_word, approx_guesses=len(variants))
    return MutationResult(vulnerable=False)