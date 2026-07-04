"""Compliance checks against common named password policy standards.
Each standard defines its own criteria; a password can pass one and fail another."""

from dataclasses import dataclass

from src.core.pattern_detector import PatternResult


@dataclass
class ComplianceCheck:
    name: str
    passed: bool
    failed_reasons: list[str]


def _char_categories(password: str) -> dict[str, bool]:
    return {
        "lower": any(c.islower() for c in password),
        "upper": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "special": any(not c.isalnum() for c in password),
    }


def check_nist_800_63b(password: str, pattern: PatternResult, breach_is_breached: bool) -> ComplianceCheck:
    reasons = []
    if len(password) < 8:
        reasons.append("Length below the 8-character minimum")
    if pattern.is_common_password:
        reasons.append("Matches a known common password")
    if breach_is_breached:
        reasons.append("Found in a known data breach")
    return ComplianceCheck(name="NIST SP 800-63B", passed=not reasons, failed_reasons=reasons)


def check_pci_dss_v4(password: str) -> ComplianceCheck:
    reasons = []
    if len(password) < 12:
        reasons.append("Length below the 12-character minimum")
    categories = _char_categories(password)
    missing = [name for name, present in categories.items() if not present]
    if missing:
        reasons.append(f"Missing required character types: {', '.join(missing)}")
    return ComplianceCheck(name="PCI DSS v4.0", passed=not reasons, failed_reasons=reasons)


def check_active_directory_default(password: str, pattern: PatternResult) -> ComplianceCheck:
    reasons = []
    if len(password) < 7:
        reasons.append("Length below the 7-character minimum")
    categories = _char_categories(password)
    if sum(categories.values()) < 3:
        reasons.append("Does not use at least 3 of 4 character categories")
    if pattern.has_personal_info:
        reasons.append("Contains part of the username")
    return ComplianceCheck(name="Active Directory (default policy)", passed=not reasons, failed_reasons=reasons)


def check_all_standards(
    password: str, pattern: PatternResult, breach_is_breached: bool
) -> list[ComplianceCheck]:
    return [
        check_nist_800_63b(password, pattern, breach_is_breached),
        check_pci_dss_v4(password),
        check_active_directory_default(password, pattern),
    ]