"""Smoke tests for the CLI rendering (interactive prompts are not covered here)."""

from src.cli import render_report
from src.core.scorer import analyze_password


def test_render_report_does_not_raise_for_strong_password():
    report = analyze_password("Xk9$mQ2vL7!p", wordlist=set())
    render_report(report)


def test_render_report_does_not_raise_for_weak_password():
    report = analyze_password("password", wordlist={"password"})
    render_report(report)


def test_render_report_does_not_raise_with_all_warnings():
    report = analyze_password("qwerty123aaa", wordlist={"qwerty123aaa"})
    render_report(report)
    assert len(report.warnings) > 0