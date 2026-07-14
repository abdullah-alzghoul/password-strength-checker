"""Convert effective entropy into human-readable crack-time estimates
under different attack scenarios. Guess rates are illustrative
order-of-magnitude figures, not precise benchmarks."""

from dataclasses import dataclass

GUESS_RATES = {
    "Online (rate-limited)": 100,  # e.g. login form with throttling
    "Offline, slow hash (bcrypt/argon2)": 1e4,  # per GPU
    "Offline, fast hash (unsalted MD5/SHA1)": 1e10,  # GPU cluster
}


@dataclass
class CrackTimeEstimate:
    scenario: str
    guesses_per_second: float
    seconds_to_crack: float
    human_readable: str


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    units = [
        ("century", "centuries", 60 * 60 * 24 * 365 * 100),
        ("year", "years", 60 * 60 * 24 * 365),
        ("day", "days", 60 * 60 * 24),
        ("hour", "hours", 60 * 60),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    ]
    for singular, plural, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            label = singular if value == 1 else plural
            if value > 1e6:
                return f"{value:.1e} {label}"
            return f"{value:,.1f} {label}"
    return "instantly"


def estimate_crack_times(effective_entropy_bits: float) -> list[CrackTimeEstimate]:
    """Average-case guesses needed = half the keyspace (2^bits / 2)."""
    guesses_needed = (2**effective_entropy_bits) / 2

    estimates = []
    for scenario, rate in GUESS_RATES.items():
        seconds = guesses_needed / rate
        estimates.append(
            CrackTimeEstimate(
                scenario=scenario,
                guesses_per_second=rate,
                seconds_to_crack=seconds,
                human_readable=humanize_seconds(seconds),
            )
        )
    return estimates
