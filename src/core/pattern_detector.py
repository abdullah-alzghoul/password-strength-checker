"""Pattern-based weakness detection: dictionary matches, sequences,
keyboard walks, and repeated characters."""

import re
from dataclasses import dataclass, field
from pathlib import Path


LEET_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
}

KEYBOARD_ROWS = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

DEFAULT_WORDLIST_PATH = Path(__file__).parent.parent.parent / "data" / "common_passwords.txt"


@dataclass
class PatternResult:
    is_common_password: bool = False
    matched_common_word: str | None = None
    has_sequential: bool = False
    sequential_matches: list[str] = field(default_factory=list)
    has_keyboard_walk: bool = False
    keyboard_matches: list[str] = field(default_factory=list)
    has_repeated_chars: bool = False
    repeated_matches: list[str] = field(default_factory=list)
    has_personal_info: bool = False
    personal_info_matches: list[str] = field(default_factory=list)
    penalty_bits: float = 0.0


def normalize_leetspeak(password: str) -> str:
    """Replace common leetspeak substitutions with their letter equivalent, lowercase."""
    result = password.lower()
    for digit, letter in LEET_MAP.items():
        result = result.replace(digit, letter)
    return result


def load_common_passwords(path: Path = DEFAULT_WORDLIST_PATH) -> set[str]:
    """Load a newline-separated wordlist. Returns empty set if file is missing."""
    if not path.exists():
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def check_common_password(password: str, wordlist: set[str]) -> tuple[bool, str | None]:
    """Check exact and leetspeak-normalized match against known common passwords."""
    lower = password.lower()
    if lower in wordlist:
        return True, lower
    normalized = normalize_leetspeak(password)
    if normalized in wordlist:
        return True, normalized
    return False, None


def detect_sequential(password: str, min_run: int = 3) -> list[str]:
    """Detect ascending/descending numeric or alphabetic runs of min_run+ characters."""
    lower = password.lower()
    n = len(lower)
    matches = []

    for step in (1, -1):
        i = 0
        while i < n:
            j = i
            while j + 1 < n and ord(lower[j + 1]) == ord(lower[j]) + step:
                j += 1
            if j - i + 1 >= min_run:
                matches.append(lower[i:j + 1])
            i = j if j > i else i + 1

    return list(dict.fromkeys(matches))


def detect_keyboard_walk(password: str, min_run: int = 3) -> list[str]:
    """Detect substrings matching consecutive QWERTY keys (row-based, forward or reversed)."""
    lower = password.lower()
    raw_matches = []
    for row in KEYBOARD_ROWS:
        for variant in (row, row[::-1]):
            for length in range(len(variant), min_run - 1, -1):
                for i in range(len(variant) - length + 1):
                    chunk = variant[i:i + length]
                    if chunk in lower:
                        raw_matches.append(chunk)

    raw_matches.sort(key=len, reverse=True)
    final = []
    for m in raw_matches:
        if not any(m in longer for longer in final):
            final.append(m)
    return final


def detect_repeated_chars(password: str, min_run: int = 3) -> list[str]:
    """Detect the same character repeated min_run+ times consecutively."""
    pattern = re.compile(r"(.)\1{" + str(min_run - 1) + r",}")
    return list(dict.fromkeys(m.group(0) for m in pattern.finditer(password)))


def extract_context_tokens(username: str | None = None, email: str | None = None) -> list[str]:
    """Extract meaningful substrings from a username/email to check against the password."""
    tokens: set[str] = set()
    if username:
        cleaned = username.strip().lower()
        if len(cleaned) >= 3:
            tokens.add(cleaned)
    if email:
        local_part = email.strip().lower().split("@")[0]
        for piece in re.split(r"[._\-+]", local_part):
            if len(piece) >= 3:
                tokens.add(piece)
    return list(tokens)


def detect_personal_info(password: str, context_tokens: list[str]) -> list[str]:
    """Check whether the password contains any username/email-derived token."""
    lower = password.lower()
    return [token for token in context_tokens if token in lower]


COMMON_PASSWORD_PENALTY = 40.0
SEQUENTIAL_PENALTY_PER_MATCH = 5.0
KEYBOARD_PENALTY_PER_MATCH = 5.0
REPEATED_PENALTY_PER_MATCH = 3.0
PERSONAL_INFO_PENALTY_PER_MATCH = 15.0


def analyze_patterns(
    password: str,
    wordlist: set[str] | None = None,
    username: str | None = None,
    email: str | None = None,
) -> PatternResult:
    """Entry point. Raises on invalid input instead of failing silently."""
    if not password:
        raise ValueError("password cannot be empty")

    if wordlist is None:
        wordlist = load_common_passwords()

    is_common, matched = check_common_password(password, wordlist)
    sequential = detect_sequential(password)
    keyboard = detect_keyboard_walk(password)
    repeated = detect_repeated_chars(password)
    context_tokens = extract_context_tokens(username, email)
    personal_info = detect_personal_info(password, context_tokens)

    penalty = 0.0
    if is_common:
        penalty += COMMON_PASSWORD_PENALTY
    penalty += len(sequential) * SEQUENTIAL_PENALTY_PER_MATCH
    penalty += len(keyboard) * KEYBOARD_PENALTY_PER_MATCH
    penalty += len(repeated) * REPEATED_PENALTY_PER_MATCH
    penalty += len(personal_info) * PERSONAL_INFO_PENALTY_PER_MATCH

    return PatternResult(
        is_common_password=is_common,
        matched_common_word=matched,
        has_sequential=bool(sequential),
        sequential_matches=sequential,
        has_keyboard_walk=bool(keyboard),
        keyboard_matches=keyboard,
        has_repeated_chars=bool(repeated),
        repeated_matches=repeated,
        has_personal_info=bool(personal_info),
        personal_info_matches=personal_info,
        penalty_bits=penalty,
    )