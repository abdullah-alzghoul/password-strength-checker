"""Tests for CLI argument parsing and non-interactive execution."""

from src.cli import build_arg_parser, run_one_check, run_batch_check, export_batch_csv
from src.core.scorer import analyze_password


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

    def test_file_flag_parsed(self):
        parser = build_arg_parser()
        args = parser.parse_args(["--file", "passwords.txt"])
        assert args.file == "passwords.txt"

    def test_file_flag_short(self):
        parser = build_arg_parser()
        args = parser.parse_args(["-f", "passwords.txt"])
        assert args.file == "passwords.txt"


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


class TestExportBatchCsv:
    def test_csv_does_not_contain_plaintext_passwords(self, tmp_path):
        reports = [analyze_password("SuperSecretPassword123!", wordlist=set(), check_breaches=False)]
        csv_path = export_batch_csv(reports, tmp_path / "batch.csv")
        content = csv_path.read_text(encoding="utf-8")
        assert "SuperSecretPassword123!" not in content

    def test_csv_has_expected_columns(self, tmp_path):
        reports = [analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False)]
        csv_path = export_batch_csv(reports, tmp_path / "batch.csv")
        header = csv_path.read_text(encoding="utf-8").splitlines()[0]
        assert "strength" in header
        assert "length" in header

    def test_csv_row_count_matches_report_count(self, tmp_path):
        reports = [
            analyze_password("Xk9$mQ2vL7!p", wordlist=set(), check_breaches=False),
            analyze_password("password", wordlist={"password"}, check_breaches=False),
        ]
        csv_path = export_batch_csv(reports, tmp_path / "batch.csv")
        lines = csv_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3


class TestRunBatchCheck:
    def test_missing_file_does_not_raise(self):
        run_batch_check("nonexistent_file.txt", None, None, False, None)

    def test_empty_file_does_not_raise(self, tmp_path):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("", encoding="utf-8")
        run_batch_check(str(empty_file), None, None, False, None)

    def test_valid_file_processes_all_passwords(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pw_file = tmp_path / "passwords.txt"
        pw_file.write_text("password\nXk9$mQ2vL7!p\nqwerty123\n", encoding="utf-8")
        run_batch_check(str(pw_file), None, None, False, "batch_out")
        rows = (tmp_path / "reports" / "batch_out.csv").read_text(encoding="utf-8").splitlines()
        assert len(rows) == 4

    def test_blank_lines_in_file_ignored(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        pw_file = tmp_path / "passwords.txt"
        pw_file.write_text("password\n\n\nqwerty123\n", encoding="utf-8")
        run_batch_check(str(pw_file), None, None, False, "batch_out2")
        rows = (tmp_path / "reports" / "batch_out2.csv").read_text(encoding="utf-8").splitlines()
        assert len(rows) == 3