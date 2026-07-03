"""HaveIBeenPwned integration using the k-anonymity model.
Only the first 5 characters of the SHA-1 hash are sent to the API —
the full password (and full hash) never leave the machine."""

import hashlib
from dataclasses import dataclass

import requests

HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 5  # seconds


@dataclass
class BreachResult:
    checked: bool  # False if the API call itself failed (network/timeout/etc.)
    is_breached: bool = False
    breach_count: int = 0
    error: str | None = None


def sha1_hash(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

def check_breach(password: str) -> BreachResult:
    """Query HIBP via k-anonymity: send only the first 5 hex chars of the SHA-1 hash."""
    full_hash = sha1_hash(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    try:
        response = requests.get(
            HIBP_API_URL.format(prefix=prefix),
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "password-strength-checker-portfolio-project"},
        )
        response.raise_for_status()
    except requests.RequestException as e:
        return BreachResult(checked=False, error=str(e))

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return BreachResult(checked=True, is_breached=True, breach_count=int(count))

    return BreachResult(checked=True, is_breached=False, breach_count=0)