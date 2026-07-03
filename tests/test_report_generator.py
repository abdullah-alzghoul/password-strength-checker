"""Unit tests for the report_generator module."""

import json

from src.core.breach_checker import BreachResult
from src.core.entropy import EntropyResult, StrengthLevel
from src.core.pattern_detector import PatternResult
from src.core.scorer import StrengthReport, analyze_password
from src.report_generator import export_html, export_json, export_report, report_to_dict


class TestReportToDict:
    def test_strength_is_plain_string_not_enum(self):
        report = analyze_password("password", wordlist={"password"}, check_breaches=False)
        data = report_to_dict(report)
        assert isinstance(data["strength"], str)
        assert isinstance(data["entropy_detail"]["strength"], str)

    def test_contains_expected_keys(self):
        report = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        data = report_to_dict(report)
        assert "password_length" in data
        assert "warnings" in data
        assert "generated_at" in data


class TestExportJson:
    def test_writes_valid_json_file(self, tmp_path):
        report = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        out = export_json(report, tmp_path / "report.json")
        assert out.exists()
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["strength"] in ("Strong", "Very Strong")

    def test_creates_missing_parent_directories(self, tmp_path):
        report = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        out = export_json(report, tmp_path / "nested" / "dir" / "report.json")
        assert out.exists()


class TestExportHtml:
    def test_writes_html_file_with_expected_content(self, tmp_path):
        report = analyze_password("password", wordlist={"password"}, check_breaches=False)
        out = export_html(report, tmp_path / "report.html")
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "Password Strength Report" in content

    def test_warnings_are_html_escaped(self, tmp_path):
        crafted_report = StrengthReport(
            password_length=10,
            raw_entropy_bits=50.0,
            effective_entropy_bits=50.0,
            strength=StrengthLevel.FAIR,
            entropy_detail=EntropyResult(entropy_bits=50.0, charset_size=26, length=10, strength=StrengthLevel.FAIR),
            pattern_detail=PatternResult(),
            breach_detail=BreachResult(checked=False, error="skipped"),
            warnings=["<script>alert(1)</script>"],
        )
        out = export_html(crafted_report, tmp_path / "report.html")
        content = out.read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;" in content


class TestExportReport:
    def test_exports_both_formats(self, tmp_path):
        report = analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)
        json_path, html_path = export_report(report, tmp_path / "myreport")
        assert json_path.exists()
        assert html_path.exists()
        assert json_path.suffix == ".json"
        assert html_path.suffix == ".html"