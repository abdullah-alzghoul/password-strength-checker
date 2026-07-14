"""Unit tests for the compliance module."""

from src.core.compliance import (
    check_active_directory_default,
    check_all_standards,
    check_nist_800_63b,
    check_pci_dss_v4,
)
from src.core.pattern_detector import PatternResult


class TestCheckNist80063B:
    def test_passes_clean_long_password(self):
        result = check_nist_800_63b(
            "correcthorsebatterystaple", PatternResult(), breach_is_breached=False
        )
        assert result.passed is True

    def test_fails_short_password(self):
        result = check_nist_800_63b("short1", PatternResult(), breach_is_breached=False)
        assert result.passed is False
        assert any("8-character" in r for r in result.failed_reasons)

    def test_fails_breached_password(self):
        result = check_nist_800_63b("longenoughpassword", PatternResult(), breach_is_breached=True)
        assert result.passed is False
        assert any("breach" in r.lower() for r in result.failed_reasons)

    def test_fails_common_password(self):
        result = check_nist_800_63b(
            "password", PatternResult(is_common_password=True), breach_is_breached=False
        )
        assert result.passed is False


class TestCheckPciDssV4:
    def test_passes_full_complexity_12_chars(self):
        result = check_pci_dss_v4("Str0ng!Passw0rd")
        assert result.passed is True

    def test_fails_short_password(self):
        result = check_pci_dss_v4("Short1!")
        assert result.passed is False
        assert any("12-character" in r for r in result.failed_reasons)

    def test_fails_missing_special_char(self):
        result = check_pci_dss_v4("LongEnoughPassword123")
        assert result.passed is False
        assert any("special" in r for r in result.failed_reasons)


class TestCheckActiveDirectoryDefault:
    def test_passes_three_of_four_categories(self):
        result = check_active_directory_default("Passw0rd", PatternResult())
        assert result.passed is True

    def test_fails_only_lowercase(self):
        result = check_active_directory_default("lowercaseonly", PatternResult())
        assert result.passed is False

    def test_fails_contains_username(self):
        result = check_active_directory_default(
            "Abdullah123", PatternResult(has_personal_info=True)
        )
        assert result.passed is False
        assert any("username" in r.lower() for r in result.failed_reasons)


class TestCheckAllStandards:
    def test_returns_three_checks(self):
        results = check_all_standards(
            "Str0ng!Passw0rd123", PatternResult(), breach_is_breached=False
        )
        assert len(results) == 3
        assert {r.name for r in results} == {
            "NIST SP 800-63B",
            "PCI DSS v4.0",
            "Active Directory (default policy)",
        }
