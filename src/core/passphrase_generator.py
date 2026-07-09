"""Diceware-style passphrase generator using cryptographically secure randomness.

Ships with a demo wordlist (160 words, ~7.3 bits/word) for out-of-the-box use.
For real-world entropy (~12.9 bits/word), download EFF's official long
wordlist (7,776 words) from https://www.eff.org/dice and save it as
data/passphrase_words.txt (one word per line), replacing the demo list.
"""

import math
import secrets
from dataclasses import dataclass
from pathlib import Path

DEFAULT_WORDLIST_PATH = Path(__file__).parent.parent.parent / "data" / "passphrase_words.txt"

FALLBACK_WORDLIST = [
    "apple", "river", "cloud", "stone", "forest", "eagle", "silver", "maple",
    "garden", "bridge", "castle", "dragon", "meadow", "canyon", "harbor",
    "island", "jungle", "lantern", "marble", "orchard",
]


@dataclass
class PassphraseResult:
    passphrase: str
    word_count: int
    wordlist_size: int
    entropy_bits: float


def load_wordlist(path: Path | None = None) -> list[str]:
    """Load a newline-separated wordlist. Falls back to a small built-in
    list if the file is missing or empty."""
    target = path or DEFAULT_WORDLIST_PATH
    if target.exists():
        words = [w.strip() for w in target.read_text(encoding="utf-8").splitlines() if w.strip()]
        if words:
            return words
    return FALLBACK_WORDLIST


def generate_passphrase(
    word_count: int = 6,
    separator: str = "-",
    wordlist: list[str] | None = None,
    capitalize_random_word: bool = False,
    append_random_digit: bool = False,
) -> PassphraseResult:
    """Generate a passphrase using secrets.choice (CSPRNG) — never the
    random module, which is not safe for security purposes."""
    if word_count < 1:
        raise ValueError("word_count must be at least 1")

    words_pool = wordlist if wordlist is not None else load_wordlist()
    if len(words_pool) < 2:
        raise ValueError("wordlist must contain at least 2 words")

    chosen = [secrets.choice(words_pool) for _ in range(word_count)]

    if capitalize_random_word:
        idx = secrets.randbelow(word_count)
        chosen[idx] = chosen[idx].capitalize()

    passphrase = separator.join(chosen)
    entropy = word_count * math.log2(len(words_pool))

    if capitalize_random_word:
        entropy += math.log2(word_count)
    if append_random_digit:
        passphrase += str(secrets.randbelow(10))
        entropy += math.log2(10)

    return PassphraseResult(
        passphrase=passphrase,
        word_count=word_count,
        wordlist_size=len(words_pool),
        entropy_bits=round(entropy, 2),
    )