"""Tests for CLI argument parsing and non-interactive execution."""

from src.cli import build_arg_parser, run_one_check


class TestBuildArgParser:
    def test_password_flag_parsed(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--password", "test123"])
        assert args.password == "test123"

    def test_short_flags_parsed(self):
        parser = build_arg_parser()
        args = parser.parse_args(["-p", "test123", "-u", "abdullah", "-e", "a@b.com"])
        assert args.password == "test123"
        assert args.username == "abdullah"
        assert args.email == "a@b.com"

    def test_no_network_flag_defaults_false(self):
        parser = build_arg_parser()
        args = parser.parse_args(["-p", "test123"])
        assert args.no_network is False

    def test_no_network_flag_set(self):
        parser = build_arg_parser()
        args = parser.parse_args(["-p", "test123", "--no-network"])
        assert args.no_network is True

    def test_no_arguments_gives_none_password(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.password is None


class TestRunOneCheck:
    def test_does_not_raise_without_output(self):
        run_one_check("Xk9$mQ2vL7!p", username=None, email=None, check_breaches=False, output=None)

    def test_does_not_raise_with_context(self):
        run_one_check("abdullah2026", username="abdullah", email=None, check_breaches=False, output=None)

    def test_saves_report_when_output_given(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        run_one_check("Xk9$mQ2vL7!p", username=None, email=None, check_breaches=False, output="testreport")
        assert (tmp_path / "reports" / "testreport.json").exists()
        assert (tmp_path / "reports" / "testreport.html").exists()